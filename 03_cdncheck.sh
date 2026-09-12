#!/usr/bin/env bash
# =============================================================================
# 03_cdncheck.sh — CDN / WAF / Cloud Classification
#
# Phân loại từng IP thành 3 nhóm:
#   - CDN/WAF edge (Cloudflare, Akamai, Fastly, CloudFront proxy)
#     → bỏ qua port scan, cần tìm origin riêng
#   - Cloud compute (EC2, Azure VM, GCP instance, DO droplet)
#     → giữ lại, đây là origin thật
#   - Direct / unknown
#     → giữ lại
#
# KEY: cdn=true OR waf=true → edge (skip)
#      cloud=true nhưng không phải proxy → origin (keep)
#
# INPUT : output/<domain>/all_ips.txt
# OUTPUT: output/<domain>/origin_ips.txt   — IPs để scan tiếp
#         output/<domain>/cdn_ips.txt      — CDN/WAF IPs (skip)
#         output/<domain>/cdn_hostnames.txt — hostname trỏ về CDN
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

[[ $# -lt 1 ]] && { usage "$0 <domain>"; exit 1; }
DOMAIN="$(normalize_domain "$1")"

OUT_DIR="$(output_dir "$DOMAIN")"
INPUT_IPS="${OUT_DIR}/all_ips.txt"
INPUT_RESOLVED="${OUT_DIR}/resolved.txt"
OUT_ORIGIN="${OUT_DIR}/origin_ips.txt"
OUT_CDN="${OUT_DIR}/cdn_ips.txt"
OUT_CDN_HOSTS="${OUT_DIR}/cdn_hostnames.txt"
LOG_FILE="${OUT_DIR}/logs/03_cdncheck.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

[[ -f "$INPUT_IPS" && -s "$INPUT_IPS" ]] || { error "Input not found: $INPUT_IPS — run 02_resolve.sh first"; exit 1; }

> "$OUT_ORIGIN"; > "$OUT_CDN"; > "$OUT_CDN_HOSTS"

banner "03 — CDN / WAF / Cloud Classification" "$DOMAIN"

TOTAL_IPS=$(count_lines "$INPUT_IPS")
info "Input: $INPUT_IPS ($TOTAL_IPS unique IPs)"
info "Rule: cdn|waf → edge (skip port scan); cloud-only → origin (keep)"

START_TIME=$(date +%s)

if cmd_exists cdncheck; then
    info "Tool: cdncheck"
    CDN_JSON="${TEMP_DIR}/cdncheck.json"

    cdncheck \
        -i "$INPUT_IPS" \
        -resp \
        -silent \
        -j \
        -no-color \
        2>/dev/null > "$CDN_JSON" || true

    python3 - "$CDN_JSON" "$OUT_ORIGIN" "$OUT_CDN" <<'PYEOF'
import sys, json

cdn_json   = sys.argv[1]
origin_out = sys.argv[2]
cdn_out    = sys.argv[3]

origins, cdns = [], []

with open(cdn_json) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        ip     = obj.get("input", "")
        is_cdn = bool(obj.get("cdn", False))
        is_waf = bool(obj.get("waf", False))
        name   = (obj.get("cdn_name") or obj.get("waf_name")
                  or obj.get("cloud_name") or "unknown")
        if is_cdn or is_waf:
            cdns.append((ip, name))
        else:
            origins.append((ip, name))

with open(origin_out, "w") as f:
    for ip, name in sorted(origins):
        f.write(ip + "\n")
        print(f"  [ORIGIN]  {ip:<20} {name}")

with open(cdn_out, "w") as f:
    for ip, name in sorted(cdns):
        f.write(ip + "\n")
        print(f"  [CDN/WAF] {ip:<20} {name}")
PYEOF

    # IPs not classified → treat as origin
    comm -23 \
        <(sort -u "$INPUT_IPS") \
        <(sort -u "$OUT_CDN") \
        >> "$OUT_ORIGIN"
    sort -u "$OUT_ORIGIN" -o "$OUT_ORIGIN"

else
    warn "cdncheck not found — treating all IPs as origin"
    warn "Install: go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    cp "$INPUT_IPS" "$OUT_ORIGIN"
fi

# Build cdn_hostnames.txt: hostname → CDN IP (for reference)
if [[ -f "$INPUT_RESOLVED" && -s "$OUT_CDN" ]]; then
    while IFS=' ' read -r host ip; do
        grep -qxF "$ip" "$OUT_CDN" 2>/dev/null && \
            echo "${host} ${ip}" >> "$OUT_CDN_HOSTS" || true
    done < "$INPUT_RESOLVED"
    sort -u "$OUT_CDN_HOSTS" -o "$OUT_CDN_HOSTS"
fi

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

ORIGIN_COUNT=$(count_lines "$OUT_ORIGIN")
CDN_COUNT=$(count_lines "$OUT_CDN")
CDN_HOSTS=$(count_lines "$OUT_CDN_HOSTS")

summary_box "03 CDN CHECK" \
    "Domain" "$DOMAIN" \
    "Total IPs" "$TOTAL_IPS" \
    "Origin IPs" "$ORIGIN_COUNT (will scan)" \
    "CDN/WAF IPs" "$CDN_COUNT (skipped)" \
    "CDN hostnames" "$CDN_HOSTS" \
    "Elapsed" "$ELAPSED_FMT" \
    "Next" "04_vhost.sh $DOMAIN"

if [[ "$CDN_COUNT" -gt 0 ]]; then
    echo ""
    warn "Find origin IPs behind CDN:"
    echo -e "  ${DIM}# Shodan: ssl.cert.subject.cn:${DOMAIN}${RESET}"
    echo -e "  ${DIM}# Censys: parsed.names:${DOMAIN}${RESET}"
    echo -e "  ${DIM}# Then: echo <ip> >> ${OUT_ORIGIN}${RESET}"
fi
