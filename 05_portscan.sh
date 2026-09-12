#!/usr/bin/env bash
# =============================================================================
# 05_portscan.sh — Fast Port Scanning (naabu)
#
# Scan origin IPs cho open ports.
# Build vhost-aware target list: subdomain:port (cho httpx stage)
#
# INPUT : output/<domain>/origin_ips.txt
#         output/<domain>/resolved.txt
# OUTPUT: output/<domain>/ports/open.txt        — ip:port
#         output/<domain>/ports/web.txt         — web ports only
#         output/<domain>/ports/vhost_urls.txt  — https://subdomain:port
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
LOG_FILE="${OUT_DIR}/logs/05_portscan.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

[[ -f "$IN_IPS" && -s "$IN_IPS" ]] || { error "Missing: $IN_IPS — run 03_cdncheck.sh first"; exit 1; }

> "$OUT_OPEN"; > "$OUT_WEB"; > "$OUT_URLS"

banner "05 — Port Scanning" "$DOMAIN"

TOTAL_IPS=$(count_lines "$IN_IPS")
info "Input: $IN_IPS ($TOTAL_IPS IPs)"

# Port definitions
WEB_PORTS="80,443,8080,8443,8000,8001,8008,8888,3000,3001,4000,4443,5000,5001,9000,9001,9090,9443"
ALL_PORTS="${WEB_PORTS},21,22,23,25,53,110,143,389,445,1433,1521,3306,3389,5432,5900,6379,27017,9200,9300,2181,5601"

START_TIME=$(date +%s)

step "Scanning $TOTAL_IPS IPs"

if cmd_exists naabu; then
    info "Tool: naabu (ProjectDiscovery)"
    info "Ports: $ALL_PORTS"

    naabu \
        -l "$IN_IPS" \
        -p "$ALL_PORTS" \
        -silent \
        -rate 1000 \
        -timeout 5 \
        2>/dev/null \
        | tee "$OUT_OPEN" \
        | while IFS= read -r line; do
            success "Open → $line"
          done

elif cmd_exists nmap; then
    warn "naabu not found — falling back to nmap"
    warn "Install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    info "Tool: nmap"

    nmap -iL "$IN_IPS" -p "$ALL_PORTS" -T4 --open -n -oG - 2>/dev/null \
        | grep "Ports:" \
        | while IFS= read -r line; do
            ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+')
            echo "$line" | grep -oP '\d+/open' | cut -d'/' -f1 \
            | while IFS= read -r port; do
                echo "${ip}:${port}" >> "$OUT_OPEN"
                success "Open → ${ip}:${port}"
            done
          done
else
    error "Neither naabu nor nmap found"
    exit 1
fi

# Extract web ports
IFS=',' read -ra WEB_LIST <<< "$WEB_PORTS"
while IFS= read -r entry; do
    port=$(echo "$entry" | cut -d':' -f2)
    for wp in "${WEB_LIST[@]}"; do
        [[ "$port" == "$wp" ]] && echo "$entry" >> "$OUT_WEB" && break
    done
done < "$OUT_OPEN"

# Build vhost-aware URL list: map ip:port → subdomain:port
step "Building vhost URL list"

if [[ -f "$IN_RESOLVED" ]]; then
    while IFS= read -r ip_port; do
        ip=$(echo "$ip_port" | cut -d':' -f1)
        port=$(echo "$ip_port" | cut -d':' -f2)

        # Find all subdomains resolving to this IP
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

summary_box "05 PORT SCAN" \
    "Domain" "$DOMAIN" \
    "IPs scanned" "$TOTAL_IPS" \
    "Open ports" "$(count_lines "$OUT_OPEN") ip:port" \
    "Web ports" "$(count_lines "$OUT_WEB")" \
    "Vhost URLs" "$(count_lines "$OUT_URLS")" \
    "Elapsed" "$ELAPSED_FMT" \
    "Next" "06_service.sh $DOMAIN"
