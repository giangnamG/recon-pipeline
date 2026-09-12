#!/usr/bin/env bash
# =============================================================================
# 06_service.sh — Service Detection (nmap -sV -sC)
#
# Chạy nmap với version detection và default scripts lên open ports.
# Parse XML output → plain text summary.
#
# INPUT : output/<domain>/ports/open.txt     — ip:port
# OUTPUT: output/<domain>/services/raw.xml   — nmap XML
#         output/<domain>/services/raw.txt   — nmap normal output
#         output/<domain>/services/parsed.txt — ip:port service version
#         output/<domain>/services/interesting.txt — non-trivial findings
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

[[ $# -lt 1 ]] && { usage "$0 <domain>"; exit 1; }
DOMAIN="$(normalize_domain "$1")"

OUT_DIR="$(output_dir "$DOMAIN")"
SVC_DIR="${OUT_DIR}/services"
mkdir -p "$SVC_DIR"

IN_PORTS="${OUT_DIR}/ports/open.txt"
OUT_XML="${SVC_DIR}/raw.xml"
OUT_TXT="${SVC_DIR}/raw.txt"
OUT_PARSED="${SVC_DIR}/parsed.txt"
OUT_INTERESTING="${SVC_DIR}/interesting.txt"
LOG_FILE="${OUT_DIR}/logs/06_service.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

[[ -f "$IN_PORTS" && -s "$IN_PORTS" ]] || { error "Missing: $IN_PORTS — run 05_portscan.sh first"; exit 1; }
cmd_exists nmap || { error "nmap not found — install: apt install nmap"; exit 1; }

> "$OUT_XML"; > "$OUT_TXT"; > "$OUT_PARSED"; > "$OUT_INTERESTING"

banner "06 — Service Detection" "$DOMAIN"

START_TIME=$(date +%s)

# Build per-IP port groupings: ip → comma-sep ports
declare -A IP_PORTS
while IFS=':' read -r ip port; do
    [[ -z "$ip" || -z "$port" ]] && continue
    if [[ -n "${IP_PORTS[$ip]+x}" ]]; then
        IP_PORTS[$ip]="${IP_PORTS[$ip]},${port}"
    else
        IP_PORTS[$ip]="$port"
    fi
done < "$IN_PORTS"

TOTAL_IPS="${#IP_PORTS[@]}"
info "Input: $IN_PORTS ($(count_lines "$IN_PORTS") ip:port combos across $TOTAL_IPS IPs)"

IDX=0
for ip in "${!IP_PORTS[@]}"; do
    IDX=$(( IDX + 1 ))
    ports="${IP_PORTS[$ip]}"
    step "[$IDX/$TOTAL_IPS] nmap → ${ip}  ports: ${ports}"

    IP_XML="${TEMP_DIR}/nmap_${ip//\./_}.xml"
    IP_TXT="${TEMP_DIR}/nmap_${ip//\./_}.txt"

    nmap \
        -sV -sC \
        -T4 \
        --open \
        -p "$ports" \
        -oX "$IP_XML" \
        -oN "$IP_TXT" \
        "$ip" \
        2>/dev/null || true

    # Append to combined outputs
    [[ -f "$IP_TXT" ]] && cat "$IP_TXT" >> "$OUT_TXT"

    # Parse XML → parsed.txt
    if [[ -f "$IP_XML" ]]; then
        python3 - "$IP_XML" "$OUT_PARSED" "$OUT_INTERESTING" <<'PYEOF'
import sys, xml.etree.ElementTree as ET

xml_file     = sys.argv[1]
parsed_out   = sys.argv[2]
interest_out = sys.argv[3]

# Services flagged as interesting for pentest
INTERESTING_SVCS = {
    "ftp", "ssh", "telnet", "smtp", "http", "https", "imap",
    "pop3", "ldap", "msrpc", "netbios", "smb", "mssql",
    "mysql", "postgresql", "oracle", "mongodb", "redis",
    "elasticsearch", "kibana", "kafka", "zookeeper",
    "vnc", "rdp", "jenkins", "jmx", "ajp13"
}
INTERESTING_VERSIONS = [
    "openssl", "apache", "nginx", "iis", "tomcat", "jetty",
    "jboss", "websphere", "weblogic", "struts", "spring",
    "2.4", "1.1", "7.", "8.", "9.",  # old versions
    "CVE", "cve", "vulnerable"
]

try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
except ET.ParseError as e:
    print(f"  [!] XML parse error: {e}")
    sys.exit(0)

with open(parsed_out, "a") as pf, open(interest_out, "a") as inf:
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "?")

        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port_el.get("portid", "?")
            proto  = port_el.get("protocol", "tcp")

            svc_el  = port_el.find("service")
            svc_name    = svc_el.get("name", "unknown")  if svc_el is not None else "unknown"
            svc_product = svc_el.get("product", "")       if svc_el is not None else ""
            svc_version = svc_el.get("version", "")       if svc_el is not None else ""
            svc_extra   = svc_el.get("extrainfo", "")     if svc_el is not None else ""

            full_ver = " ".join(filter(None, [svc_product, svc_version, svc_extra])).strip()
            line = f"{ip}:{portid}/{proto:<4}  {svc_name:<16}  {full_ver}"
            pf.write(line + "\n")
            print(f"  [+] {line}")

            # Flag interesting
            is_interesting = (
                svc_name.lower() in INTERESTING_SVCS
                or any(v in full_ver.lower() for v in INTERESTING_VERSIONS)
            )
            if is_interesting:
                inf.write(line + "\n")

            # Also dump script output
            for script_el in port_el.findall("script"):
                script_id  = script_el.get("id", "")
                script_out = script_el.get("output", "").strip()
                if script_out and len(script_out) < 500:
                    note = f"  → {script_id}: {script_out[:200]}"
                    pf.write(note + "\n")
                    if "VULNERABLE" in script_out.upper() or "CVE" in script_out.upper():
                        inf.write(f"{ip}:{portid} [SCRIPT:{script_id}] {script_out[:200]}\n")

PYEOF
    fi
done

# ══════════════════════════════════════════════════════════════════
# CDN banner post-filter
# nmap có thể detect Akamai/Cloudflare node đặt tại ISP local
# mà cdncheck không nhận ra được (ASN local thay vì ASN CDN chuẩn)
# ══════════════════════════════════════════════════════════════════
step "Post-filter — CDN banner detection"

CDN_BANNER_KEYWORDS="akamai\|akamaiGHost\|cloudflare\|fastly\|incapsula\|sucuri\|imperva\|edgecast\|verizon\|limelight\|cdnetworks"
OUT_CDN_BANNER="${SVC_DIR}/cdn_by_banner.txt"
OUT_ORIGIN_CONFIRMED="${SVC_DIR}/origin_confirmed.txt"

> "$OUT_CDN_BANNER"; > "$OUT_ORIGIN_CONFIRMED"

if [[ -f "$OUT_PARSED" && -s "$OUT_PARSED" ]]; then
    # Extract IPs whose service banner reveals CDN
    grep -i "$CDN_BANNER_KEYWORDS" "$OUT_PARSED" 2>/dev/null \
        | grep -oP '^\d+\.\d+\.\d+\.\d+' \
        | sort -u > "$OUT_CDN_BANNER"

    CDN_BANNER_COUNT=$(count_lines "$OUT_CDN_BANNER")

    if [[ "$CDN_BANNER_COUNT" -gt 0 ]]; then
        warn "Found $CDN_BANNER_COUNT CDN IPs missed by cdncheck (detected via banner):"

        # Backup trước khi sửa — tránh mất data nếu script crash
        cp "${OUT_DIR}/origin_ips.txt" "${OUT_DIR}/origin_ips.txt.bak"

        # Build filtered list một lần từ tất cả CDN IPs (không sửa in-place từng IP)
        grep -vFf "$OUT_CDN_BANNER" "${OUT_DIR}/origin_ips.txt" \
            > "${TEMP_DIR}/origin_filtered.txt" 2>/dev/null || true

        # Chỉ replace sau khi filter thành công
        if [[ -f "${TEMP_DIR}/origin_filtered.txt" ]]; then
            cp "${TEMP_DIR}/origin_filtered.txt" "${OUT_DIR}/origin_ips.txt"
        fi

        while IFS= read -r ip; do
            warn "  CDN-by-banner → $ip"
            echo "$ip" >> "${OUT_DIR}/cdn_ips.txt"
        done < "$OUT_CDN_BANNER"
        sort -u "${OUT_DIR}/cdn_ips.txt" -o "${OUT_DIR}/cdn_ips.txt"
        success "Moved $CDN_BANNER_COUNT CDN IPs from origin_ips.txt → cdn_ips.txt"
    else
        success "No hidden CDN IPs found via banner"
    fi

    # Remaining origin IPs after filter
    sort -u "${OUT_DIR}/origin_ips.txt" -o "${OUT_DIR}/origin_ips.txt"
    cp "${OUT_DIR}/origin_ips.txt" "$OUT_ORIGIN_CONFIRMED"
fi

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

PARSED_COUNT=$(count_lines "$OUT_PARSED")
INTERESTING_COUNT=$(count_lines "$OUT_INTERESTING")
CDN_BANNER_COUNT=$(count_lines "$OUT_CDN_BANNER")
ORIGIN_FINAL=$(count_lines "${OUT_DIR}/origin_ips.txt")

summary_box "06 SERVICE DETECTION" \
    "Domain" "$DOMAIN" \
    "IPs scanned" "$TOTAL_IPS" \
    "Services found" "$PARSED_COUNT" \
    "Interesting" "$INTERESTING_COUNT" \
    "CDN by banner" "$CDN_BANNER_COUNT (moved out)" \
    "Origin IPs final" "$ORIGIN_FINAL" \
    "Output dir" "$SVC_DIR" \
    "Elapsed" "$ELAPSED_FMT" \
    "Next" "07_httpx.sh $DOMAIN"

if [[ "$INTERESTING_COUNT" -gt 0 ]]; then
    step "★ Interesting services"
    while IFS= read -r line; do
        echo -e "  ${MAGENTA}★${RESET}  $line"
    done < "$OUT_INTERESTING"
fi
