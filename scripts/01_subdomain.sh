#!/usr/bin/env bash
# =============================================================================
# 01_subdomain.sh — Subdomain Enumeration (Passive + Active)
#
# PASSIVE sources (no direct contact with target):
#   1. subfinder   — queries 50+ passive APIs (Shodan, VirusTotal, etc.)
#   2. amass       — DNS/HTTP/TLS passive mode
#   3. crt.sh      — Certificate Transparency logs
#   4. certspotter — sslmate CT API
#
# ACTIVE sources (sends DNS queries — generates traffic):
#   5. gobuster dns — brute force với 6 wordlists (small → huge)
#
# OUTPUT: output/<domain>/subdomains.txt  (unique, lowercase, sorted)
# =============================================================================

set -uo pipefail

# ─── Lib ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

show_help() {
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║  01 — Subdomain Enumeration (Passive + Active)               ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${BOLD}MÔ TẢ:${RESET}"
    echo -e "  Thu thập tên miền phụ (Subdomain) toàn diện:"
    echo -e "  - Passive: subfinder (50+ APIs), amass, crt.sh, certspotter."
    echo -e "  - Active: gobuster dns brute-force qua 6 tầng wordlist đa cấp."
    echo ""
    echo -e "${BOLD}CÚ PHÁP SỬ DỤNG:${RESET}"
    echo -e "  $0 <domain> [tùy chọn]"
    echo ""
    echo -e "${BOLD}CÁC TÙY CHỌN:${RESET}"
    echo -e "  ${YELLOW}-h, --help${RESET}  Hiển thị hướng dẫn này"
    echo ""
    echo -e "${BOLD}VÍ DỤ:${RESET}"
    echo -e "  $0 mbbank.com.vn"
    echo ""
}

[[ $# -eq 0 ]] && { show_help; exit 1; }

for arg in "$@"; do
    case "$arg" in
        -h|--help|help) show_help; exit 0 ;;
    esac
done

DOMAIN="$(normalize_domain "$1")"

OUT_DIR="$(output_dir "$DOMAIN")"
OUT_FILE="${OUT_DIR}/subdomains.txt"
LOG_FILE="${OUT_DIR}/logs/01_subdomain.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

banner "01 — Subdomain Enumeration" "$DOMAIN"

MERGE="${TEMP_DIR}/merge.txt"
> "$MERGE"

save_results() {
    [[ -f "$MERGE" && -s "$MERGE" ]] || return 0
    cat "$MERGE" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//' \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$OUT_FILE" 2>/dev/null || true
    sort -u "$OUT_FILE" -o "$OUT_FILE"
    > "$MERGE"
}

# ══════════════════════════════════════════════════════════════════
# STAGE 1: PASSIVE
# ══════════════════════════════════════════════════════════════════
step "Stage 1/2 — Passive Enumeration (no target contact)"

# ── subfinder ──────────────────────────────────────────────────────
if cmd_exists subfinder; then
    info "Source: subfinder"
    subfinder -d "$DOMAIN" -silent 2>/dev/null >> "$MERGE" || true
    success "subfinder done"
else
    warn "subfinder not found — skip (install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)"
fi

# ── amass ──────────────────────────────────────────────────────────
if cmd_exists amass; then
    info "Source: amass (passive)"
    amass enum -passive -d "$DOMAIN" -silent 2>/dev/null >> "$MERGE" || true
    success "amass done"
else
    warn "amass not found — skip (install: go install -v github.com/owasp-amass/amass/v4/...@master)"
fi

# ── crt.sh ─────────────────────────────────────────────────────────
info "Source: crt.sh (Certificate Transparency)"
CRT_RAW="${TEMP_DIR}/crt_raw.json"
for attempt in 1 2 3; do
    curl -s --max-time 30 -H "Accept: application/json" \
        "https://crt.sh/?q=${DOMAIN}&output=json" -o "$CRT_RAW" 2>/dev/null || true
    ENTRIES=$(jq 'if type=="array" then length else 0 end' "$CRT_RAW" 2>/dev/null || echo 0)
    if [[ "$ENTRIES" -gt 0 ]]; then
        jq -r '.[] | .name_value, .common_name' "$CRT_RAW" 2>/dev/null \
            | sed 's/\\n/\n/g' | sed 's/^\*\.//' \
            | tr '[:upper:]' '[:lower:]' \
            | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$MERGE" || true
        success "crt.sh: ${ENTRIES} cert records"
        break
    fi
    warn "crt.sh attempt ${attempt}/3 failed — retry in 5s"
    sleep 5
done

# ── certspotter ────────────────────────────────────────────────────
info "Source: certspotter"
curl -s --max-time 30 \
    "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" \
    2>/dev/null \
    | jq -r '.[].dns_names[]' 2>/dev/null \
    | sed 's/^\*\.//' | tr '[:upper:]' '[:lower:]' \
    | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$MERGE" || true
success "certspotter done"

save_results
PASSIVE_COUNT=$(count_lines "$OUT_FILE")
success "Passive total: ${PASSIVE_COUNT} unique subdomains (saved → ${OUT_FILE})"

# ══════════════════════════════════════════════════════════════════
# STAGE 2: ACTIVE (DNS brute force)
# ══════════════════════════════════════════════════════════════════
step "Stage 2/2 — Active Enumeration (DNS brute force)"
warn "Generates DNS traffic — ensure authorization"

if ! cmd_exists gobuster; then
    warn "gobuster not found — skipping active stage (apt install gobuster)"
else
    # Danh sách wordlist tối ưu tốc độ & độ phủ (20k words siêu nhẹ + 110k words mở rộng)
    CANDIDATES=(
        "SecLists-20k:/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
        "SecLists-110k:/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    )

    VALID_WLS=()
    VALID_NAMES=()

    for item in "${CANDIDATES[@]}"; do
        IFS=':' read -r name path1 path2 <<< "$item"
        if [[ -f "$path1" ]]; then
            VALID_WLS+=("$path1")
            VALID_NAMES+=("$name")
        elif [[ -n "$path2" && -f "$path2" ]]; then
            VALID_WLS+=("$path2")
            VALID_NAMES+=("$name")
        fi
    done

    if [[ ${#VALID_WLS[@]} -eq 0 ]]; then
        warn "No standard DNS wordlists found in /usr/share/seclists — skipping active stage"
    else
        for i in "${!VALID_WLS[@]}"; do
            WL="${VALID_WLS[$i]}"
            WL_NAME="${VALID_NAMES[$i]}"
            WL_LINES=$(count_lines "$WL")

            info "Pass $((i+1))/${#VALID_WLS[@]} — ${WL_NAME} (${WL_LINES} words)"
            # Tối ưu hóa gobuster với 80 threads, direct resolver 1.1.1.1 để tránh router DNS throttling
            gobuster dns -d "$DOMAIN" -w "$WL" -t 80 -r 1.1.1.1,8.8.8.8 --timeout 2s --wildcard --no-color -q 2>/dev/null \
                | grep -oP '(?<=Found: )\S+' >> "$MERGE" || true
            save_results
            success "Pass $((i+1)) done — Current total: $(count_lines "$OUT_FILE") subdomains (saved → ${OUT_FILE})"
        done
    fi
fi

# ══════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════
save_results
TOTAL=$(count_lines "$OUT_FILE")

summary_box "01 SUBDOMAIN ENUMERATION" \
    "Domain" "$DOMAIN" \
    "Passive" "${PASSIVE_COUNT} subdomains" \
    "Total unique" "$TOTAL" \
    "Output" "$OUT_FILE" \
    "Next" "02_resolve.sh $DOMAIN"
