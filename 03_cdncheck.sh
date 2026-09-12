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

# =============================================================================
# CIDR ranges that are definitively NOT origin servers for any target.
# These are managed service endpoints (SaaS/PaaS) that respond differently
# from a random hostname (so baseline-diff in 04_vhost passes), but are
# never the target's own infrastructure.
#
# Microsoft Entra / MDM (enterpriseregistration.windows.net, etc.)
#   20.190.128.0/18, 40.126.0.0/18
# Microsoft Azure global front-door / MSFT CDN
#   13.107.0.0/16, 52.108.0.0/14
# Akamai edge (blocks cdncheck sometimes misses due to timeout)
#   23.0.0.0/8 (partial — only well-known edge ranges below)
#   184.24.0.0/13
# AWS CloudFront (cdncheck catches most, but safety net)
#   13.32.0.0/15, 13.35.0.0/16, 13.224.0.0/14
# =============================================================================
MANAGED_CIDRS=(
    # Microsoft Entra / MDM — verified AzureActiveDirectory service tag
    # Source: Microsoft ServiceTags_Public JSON, tag "AzureActiveDirectory"
    # These IPs serve enterpriseregistration.windows.net, msoid, etc.
    # A target cannot host their own infra on these — they are MSFT-operated.
    "20.190.128.0/18"
    "40.126.0.0/18"

    # Microsoft AzureFrontDoor.FirstParty + AzureFrontDoor.Frontend
    # Verified: entire 13.107.0.0/16 is AS8068/AS8075 (Microsoft Corp)
    # These are CDN/proxy endpoints, not customer-facing compute.
    "13.107.0.0/16"

    # Akamai edge nodes — verified AS16625 + AS20940 throughout 184.24-31.x.x
    # Source: ipinfo.io spot checks on 184.24.0.1, 184.26.91.150, 184.31.0.1
    # NOTE: 23.192.0.0/11 was REMOVED — 23.202.x.x is FPT Telecom (AS18403),
    # not Akamai. cdncheck handles Akamai 23.x ranges more precisely.
    "184.24.0.0/13"

    # AWS CloudFront — exact prefixes from ip-ranges.amazonaws.com (service=CLOUDFRONT)
    # cdncheck already catches most CloudFront; these are a safety net for misses.
    "13.32.0.0/15"
    "13.35.0.0/16"
    "13.224.0.0/14"

    # REMOVED: "52.108.0.0/14" — this is AzureCloud COMPUTE (customer VMs),
    # not a CDN/proxy. A target may legitimately host services on 52.108.x.x.
    # REMOVED: "23.192.0.0/11" — covers 23.192-23.223, includes FPT Telecom
    # (AS18403, 23.202.x.x). Would false-positive Vietnamese ISP origin servers.
)

# Returns 0 (true) if $1 falls inside $2 (CIDR)
# Uses only bash + awk — no ipcalc/python needed at this stage
ip_in_cidr() {
    local ip="$1" cidr="$2"
    awk -v ip="$ip" -v cidr="$cidr" 'BEGIN {
        split(ip,   a, ".")
        split(cidr, c, "/")
        split(c[1], b, ".")
        bits = c[2] + 0
        ip_int  = (a[1]*2^24) + (a[2]*2^16) + (a[3]*2^8) + a[4]
        net_int = (b[1]*2^24) + (b[2]*2^16) + (b[3]*2^8) + b[4]
        mask    = (bits == 0) ? 0 : lshift(0xFFFFFFFF, 32-bits)
        print (and(ip_int, mask) == and(net_int, mask)) ? "1" : "0"
    }' 2>/dev/null
}

is_managed_ip() {
    local ip="$1"
    for cidr in "${MANAGED_CIDRS[@]}"; do
        [[ "$(ip_in_cidr "$ip" "$cidr")" == "1" ]] && return 0
    done
    return 1
}

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
info "Rule: cdn|waf → edge (skip); managed-service CIDR → edge (skip); cloud-only → origin (keep)"

START_TIME=$(date +%s)

# ══════════════════════════════════════════════════════════════════
# PRE-FILTER: Managed service CIDRs (Microsoft, Akamai partial,
# CloudFront) — remove before cdncheck so they never land in origin
# ══════════════════════════════════════════════════════════════════
step "Pre-filter — Managed service CIDRs"
MANAGED_OUT="${TEMP_DIR}/managed_ips.txt"
REMAINING_IPS="${TEMP_DIR}/remaining_ips.txt"
> "$MANAGED_OUT"
> "$REMAINING_IPS"

while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if is_managed_ip "$ip"; then
        warn "MANAGED  ${ip}  (matched CIDR — not target infrastructure)"
        echo "$ip" >> "$MANAGED_OUT"
        echo "$ip" >> "$OUT_CDN"
    else
        echo "$ip" >> "$REMAINING_IPS"
    fi
done < "$INPUT_IPS"

MANAGED_COUNT=$(count_lines "$MANAGED_OUT")
info "Pre-filter: removed ${MANAGED_COUNT} managed-service IPs"

if cmd_exists cdncheck; then
    info "Tool: cdncheck"
    CDN_JSON="${TEMP_DIR}/cdncheck.json"

    cdncheck \
        -i "$REMAINING_IPS" \
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

    # IPs not classified by cdncheck → treat as origin
    # NOTE: comm uses REMAINING_IPS (pre-filtered), not INPUT_IPS
    # so managed-service IPs never slip through here
    comm -23 \
        <(sort -u "$REMAINING_IPS") \
        <(sort -u "$OUT_CDN") \
        >> "$OUT_ORIGIN"
    sort -u "$OUT_ORIGIN" -o "$OUT_ORIGIN"

else
    warn "cdncheck not found — applying CIDR pre-filter only, treating rest as origin"
    warn "Install: go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    cp "$REMAINING_IPS" "$OUT_ORIGIN"
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
    "Managed CIDR" "${MANAGED_COUNT} (pre-filtered)" \
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
