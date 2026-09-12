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

# ─── Args ────────────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && { usage "$0 <domain>"; exit 1; }
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

PASSIVE_COUNT=$(sort -u "$MERGE" | wc -l | tr -d ' ')
success "Passive total: ${PASSIVE_COUNT} unique subdomains"

# ══════════════════════════════════════════════════════════════════
# STAGE 2: ACTIVE (DNS brute force)
# ══════════════════════════════════════════════════════════════════
step "Stage 2/2 — Active Enumeration (DNS brute force)"
warn "Generates DNS traffic — ensure authorization"

if ! cmd_exists gobuster; then
    warn "gobuster not found — skipping active stage (apt install gobuster)"
else
    WORDLISTS=(
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        "/usr/share/wordlists/n0kovo_subdomains/n0kovo_subdomains_large.txt"
    )
    WORDLIST_NAMES=("SecLists-110k" "n0kovo-tiny" "n0kovo-small" "n0kovo-medium" "n0kovo-large" "n0kovo-huge")

    for i in "${!WORDLISTS[@]}"; do
        WL="${WORDLISTS[$i]}"
        WL_NAME="${WORDLIST_NAMES[$i]}"
        [[ -f "$WL" ]] || { warn "Wordlist not found, skip: $WL"; continue; }

        info "Pass $((i+1))/${#WORDLISTS[@]} — ${WL_NAME} ($(wc -l < "$WL") words)"
        gobuster dns -d "$DOMAIN" -w "$WL" --wildcard --no-color -q 2>/dev/null \
            | grep -oP '(?<=Found: )\S+' >> "$MERGE" || true
        success "Pass $((i+1)) done"
    done
fi

# ══════════════════════════════════════════════════════════════════
# MERGE + DEDUP
# ══════════════════════════════════════════════════════════════════
step "Merging & deduplicating"

# Append to existing file (preserve previous runs), then dedup in-place
cat "$MERGE" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//' \
    | grep -E "(^|\.)${DOMAIN//./\\.}$" >> "$OUT_FILE" 2>/dev/null || true
sort -u "$OUT_FILE" -o "$OUT_FILE"

TOTAL=$(wc -l < "$OUT_FILE" | tr -d ' ')

summary_box "01 SUBDOMAIN ENUMERATION" \
    "Domain" "$DOMAIN" \
    "Passive" "${PASSIVE_COUNT} subdomains" \
    "Total unique" "$TOTAL" \
    "Output" "$OUT_FILE" \
    "Next" "02_resolve.sh $DOMAIN"
