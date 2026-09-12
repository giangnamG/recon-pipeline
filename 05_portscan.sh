#!/usr/bin/env bash
# =============================================================================
# 05_portscan.sh — Port Scanning + Service Fingerprint
#
# Priority:
#   1. gogo  — scan + active fingerprint all-in-one (chainreactors/gogo)
#   2. naabu — fast port scan only (ProjectDiscovery)
#   3. nmap  — fallback
#
# gogo ưu điểm:
#   - Port tags: top2, top3, web, db, win... (không cần liệt kê từng port)
#   - Active fingerprint ngay lúc scan → bỏ được bước nmap -sV một phần
#   - Nuclei POC tích hợp → auto check vuln cơ bản
#   - Output JSON → dễ parse
#
# INPUT : output/<domain>/origin_ips.txt
#         output/<domain>/resolved.txt
# OUTPUT: output/<domain>/ports/open.txt        — ip:port
#         output/<domain>/ports/web.txt         — web ports only
#         output/<domain>/ports/vhost_urls.txt  — http(s)://subdomain:port
#         output/<domain>/ports/gogo.json       — gogo full JSON (nếu dùng gogo)
#         output/<domain>/ports/fingerprint.txt — service fingerprint từ gogo
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

[[ $# -lt 1 ]] && { usage "$0 <domain>"; exit 1; }
DOMAIN="$(normalize_domain "$1")"

OUT_DIR="$(output_dir "$DOMAIN")"
PORT_DIR="${OUT_DIR}/ports"
mkdir -p "$PORT_DIR"

IN_IPS="${OUT_DIR}/origin_ips.txt"
IN_RESOLVED="${OUT_DIR}/resolved.txt"
OUT_OPEN="${PORT_DIR}/open.txt"
OUT_WEB="${PORT_DIR}/web.txt"
OUT_URLS="${PORT_DIR}/vhost_urls.txt"
OUT_GOGO_JSON="${PORT_DIR}/gogo.json"
OUT_FINGERPRINT="${PORT_DIR}/fingerprint.txt"
LOG_FILE="${OUT_DIR}/logs/05_portscan.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

[[ -f "$IN_IPS" && -s "$IN_IPS" ]] || { error "Missing: $IN_IPS — run 03_cdncheck.sh first"; exit 1; }

> "$OUT_OPEN"; > "$OUT_WEB"; > "$OUT_URLS"; > "$OUT_FINGERPRINT"

banner "05 — Port Scanning" "$DOMAIN"

TOTAL_IPS=$(count_lines "$IN_IPS")
info "Input: $IN_IPS ($TOTAL_IPS IPs)"

# Port tags gogo / port list naabu
GOGO_PORTS="top2,top3,db,win,docker"   # gogo port tags
WEB_PORTS="80,443,8080,8443,8000,8001,8008,8888,3000,3001,4000,4443,5000,5001,9000,9001,9090,9443"
ALL_PORTS="${WEB_PORTS},21,22,23,25,53,110,143,389,445,1433,1521,3306,3389,5432,5900,6379,27017,9200,9300,2181,5601"

START_TIME=$(date +%s)

# ══════════════════════════════════════════════════════════════════
# TOOL 1: gogo — scan + fingerprint
# ══════════════════════════════════════════════════════════════════
if cmd_exists gogo; then
    info "Tool: gogo (chainreactors) — scan + active fingerprint"
    info "Port tags: $GOGO_PORTS"

    GOGO_DAT="${TEMP_DIR}/gogo_raw.dat"
    GOGO_RAW="${TEMP_DIR}/gogo_raw.json"

    # gogo scan → .dat (binary format)
    gogo \
        -l "$IN_IPS" \
        -p "$GOGO_PORTS" \
        -f "$GOGO_DAT" \
        2>/dev/null || true

    # Convert .dat → JSON
    if [[ -f "$GOGO_DAT" && -s "$GOGO_DAT" ]]; then
        gogo -F "$GOGO_DAT" -o json -f "$GOGO_RAW" 2>/dev/null || true
    fi

    # Parse gogo JSON → open.txt + fingerprint.txt
    if [[ -f "$GOGO_RAW" && -s "$GOGO_RAW" ]]; then
        cp "$GOGO_RAW" "$OUT_GOGO_JSON"

        python3 - "$GOGO_RAW" "$OUT_OPEN" "$OUT_FINGERPRINT" <<'PYEOF'
import sys, json

raw_file    = sys.argv[1]
open_file   = sys.argv[2]
fp_file     = sys.argv[3]

with open(raw_file) as f:
    try:
        data = json.load(f)
    except json.JSONDecodeError:
        print("  [!] gogo JSON parse error")
        sys.exit(0)

# gogo JSON: {"config": {...}, "data": [...]}
results = data.get("data", []) if isinstance(data, dict) else data

with open(open_file, "a") as of, open(fp_file, "a") as ff:
    for r in results:
        ip       = r.get("ip", "")
        port     = str(r.get("port", ""))
        protocol = r.get("protocol", "")
        status   = str(r.get("status", ""))
        host     = r.get("host", "")        # CN/SAN từ cert
        title    = r.get("title", "")
        banner   = r.get("banner", "")

        if not ip or not port:
            continue

        of.write(f"{ip}:{port}\n")
        print(f"  [+] Open → {ip}:{port}  [{status}]  {protocol}")

        # frameworks: dict of {name: {..., tags: [...]}}
        frameworks = r.get("frameworks", {})
        fw_names = list(frameworks.keys()) if frameworks else []

        # vulns
        vulns = r.get("vulns", [])
        if isinstance(vulns, dict):
            vulns = list(vulns.keys())

        fp_parts = [f"{ip}:{port}"]
        if protocol: fp_parts.append(f"{protocol}")
        if status:   fp_parts.append(f"[{status}]")
        if host:     fp_parts.append(f"host:{host[:50]}")
        if title:    fp_parts.append(f"title:{title[:60]}")
        if banner:   fp_parts.append(f"banner:{banner[:60]}")
        if fw_names: fp_parts.append(f"fw:{','.join(fw_names[:5])}")
        if vulns:
            vuln_str = ",".join(str(v) for v in vulns[:3])
            fp_parts.append(f"VULN:{vuln_str}")
            print(f"  [★] VULN → {ip}:{port} — {vuln_str}")

        ff.write("  ".join(fp_parts) + "\n")
PYEOF
        GOGO_OPEN=$(count_lines "$OUT_OPEN")
        success "gogo: $GOGO_OPEN open ports found"
    else
        warn "gogo produced no output — falling through to naabu"
    fi
fi

# ══════════════════════════════════════════════════════════════════
# TOOL 2: naabu — nếu gogo không có hoặc không ra kết quả
# ══════════════════════════════════════════════════════════════════
if ! cmd_exists gogo || [[ ! -s "$OUT_OPEN" ]]; then
    if cmd_exists naabu; then
        [[ ! cmd_exists gogo ]] && warn "gogo not found — using naabu"
        [[ -s "$OUT_OPEN" ]] || warn "gogo produced no output — using naabu as supplement"
        info "Tool: naabu (ProjectDiscovery)"
        info "Ports: $ALL_PORTS"

        NAABU_RAW="${TEMP_DIR}/naabu_raw.txt"

        naabu \
            -l "$IN_IPS" \
            -p "$ALL_PORTS" \
            -silent \
            -rate 1000 \
            -timeout 5 \
            2>/dev/null > "$NAABU_RAW" || true

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "$line" >> "$OUT_OPEN"
            success "Open → $line"
        done < "$NAABU_RAW"

    # ══════════════════════════════════════════════════════════════
    # TOOL 3: nmap fallback
    # ══════════════════════════════════════════════════════════════
    elif cmd_exists nmap; then
        warn "naabu not found — falling back to nmap"
        info "Tool: nmap"

        nmap -iL "$IN_IPS" -p "$ALL_PORTS" -T4 --open -n -oG - 2>/dev/null \
            | awk '/Ports:/{
                match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, ip)
                split($0, parts, "Ports: ")
                n = split(parts[2], ports, ",")
                for (i=1; i<=n; i++) {
                    split(ports[i], p, "/")
                    if (p[2] == "open") print ip[0] ":" p[1]
                }
            }' >> "$OUT_OPEN"
    else
        error "No scanner found (gogo / naabu / nmap)"
        exit 1
    fi
fi

# Dedup open.txt
sort -u "$OUT_OPEN" -o "$OUT_OPEN"

# ══════════════════════════════════════════════════════════════════
# Extract web ports
# ══════════════════════════════════════════════════════════════════
IFS=',' read -ra WEB_LIST <<< "$WEB_PORTS"
while IFS= read -r entry; do
    port=$(echo "$entry" | cut -d':' -f2)
    for wp in "${WEB_LIST[@]}"; do
        [[ "$port" == "$wp" ]] && echo "$entry" >> "$OUT_WEB" && break
    done
done < "$OUT_OPEN"
sort -u "$OUT_WEB" -o "$OUT_WEB"

# ══════════════════════════════════════════════════════════════════
# Build vhost-aware URL list: ip:port → subdomain:port
# ══════════════════════════════════════════════════════════════════
step "Building vhost URL list"

if [[ -f "$IN_RESOLVED" ]]; then
    while IFS= read -r ip_port; do
        ip=$(echo "$ip_port" | cut -d':' -f1)
        port=$(echo "$ip_port" | cut -d':' -f2)

        grep " ${ip}$" "$IN_RESOLVED" 2>/dev/null | awk '{print $1}' \
        | while IFS= read -r sub; do
            case "$port" in
                443|8443|4443|9443) echo "https://${sub}:${port}" ;;
                80|8080|8000|8001|8008|8888|3000|3001|4000|5000|5001|9000|9001|9090)
                    echo "http://${sub}:${port}" ;;
                *)
                    echo "http://${sub}:${port}"
                    echo "https://${sub}:${port}" ;;
            esac
        done
    done < "$OUT_WEB" | sort -u >> "$OUT_URLS"
fi

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

FP_COUNT=$(count_lines "$OUT_FINGERPRINT")

summary_box "05 PORT SCAN" \
    "Domain" "$DOMAIN" \
    "IPs scanned" "$TOTAL_IPS" \
    "Open ports" "$(count_lines "$OUT_OPEN") ip:port" \
    "Web ports" "$(count_lines "$OUT_WEB")" \
    "Vhost URLs" "$(count_lines "$OUT_URLS")" \
    "Fingerprints" "$FP_COUNT (from gogo)" \
    "Elapsed" "$ELAPSED_FMT" \
    "Next" "06_service.sh $DOMAIN"

# Print vuln findings from gogo
if [[ -f "$OUT_FINGERPRINT" ]] && grep -q "VULN:" "$OUT_FINGERPRINT" 2>/dev/null; then
    step "★ gogo VULN findings"
    grep "VULN:" "$OUT_FINGERPRINT" | while IFS= read -r line; do
        echo -e "  ${RED}▶${RESET}  $line"
    done
fi
