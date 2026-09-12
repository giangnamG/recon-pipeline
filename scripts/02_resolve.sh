#!/usr/bin/env bash
# =============================================================================
# 02_resolve.sh — DNS Resolution + Wildcard Filter
#
# 1. dnsx   — resolve subdomains → IP mapping
# 2. puredns — wildcard DNS filter (loại false positive do wildcard DNS)
#
# INPUT : output/<domain>/subdomains.txt
# OUTPUT: output/<domain>/resolved.txt      — "hostname ip" pairs
#         output/<domain>/unresolved.txt    — hostname không resolve được
#         output/<domain>/all_ips.txt       — unique IPs
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

[[ $# -lt 1 ]] && { usage "$0 <domain>"; exit 1; }
DOMAIN="$(normalize_domain "$1")"

OUT_DIR="$(output_dir "$DOMAIN")"
INPUT="${OUT_DIR}/subdomains.txt"
OUT_RESOLVED="${OUT_DIR}/resolved.txt"
OUT_UNRESOLVED="${OUT_DIR}/unresolved.txt"
OUT_WILDCARD="${OUT_DIR}/wildcard_filtered.txt"
OUT_IPS="${OUT_DIR}/all_ips.txt"
LOG_FILE="${OUT_DIR}/logs/02_resolve.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

[[ -f "$INPUT" && -s "$INPUT" ]] || { error "Input not found: $INPUT — run 01_subdomain.sh first"; exit 1; }

> "$OUT_RESOLVED"; > "$OUT_UNRESOLVED"; > "$OUT_IPS"

banner "02 — DNS Resolution" "$DOMAIN"
info "Input: $INPUT ($(count_lines "$INPUT") subdomains)"

TOTAL_INPUT=$(count_lines "$INPUT")
START_TIME=$(date +%s)

# ══════════════════════════════════════════════════════════════════
# STAGE 1: Wildcard detection (puredns)
# ══════════════════════════════════════════════════════════════════
step "Stage 1/2 — Wildcard DNS Detection (puredns)"

CLEAN_LIST="${TEMP_DIR}/clean.txt"
cp "$INPUT" "$CLEAN_LIST"

if cmd_exists puredns; then
    info "Tool: puredns — filters wildcard DNS false positives"
    RESOLVERS="/usr/share/wordlists/resolvers.txt"
    [[ ! -f "$RESOLVERS" ]] && RESOLVERS="${TEMP_DIR}/resolvers.txt" && \
        curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -o "$RESOLVERS" 2>/dev/null || true

    if [[ -f "$RESOLVERS" ]]; then
        puredns resolve "$CLEAN_LIST" \
            -r "$RESOLVERS" \
            --write "${TEMP_DIR}/puredns_clean.txt" \
            --quiet 2>/dev/null || true

        if [[ -s "${TEMP_DIR}/puredns_clean.txt" ]]; then
            # Lưu các domain bị loại do wildcard DNS
            comm -23 \
                <(sort -u "$CLEAN_LIST") \
                <(sort -u "${TEMP_DIR}/puredns_clean.txt") \
                > "$OUT_WILDCARD"

            CLEAN_LIST="${TEMP_DIR}/puredns_clean.txt"

            AFTER=$(count_lines "$CLEAN_LIST")
            WILDCARD_COUNT=$(count_lines "$OUT_WILDCARD")
            success "puredns: ${TOTAL_INPUT} → ${AFTER} (removed ${WILDCARD_COUNT} wildcard FPs → wildcard_filtered.txt)"
        else
            # puredns chạy nhưng không ra output — resolver list lỗi, crash, hoặc timeout
            # CLEAN_LIST giữ nguyên list gốc → dnsx sẽ resolve tất cả kể cả wildcard FP
            # → bước 04 cross-product có thể phình to bất thường
            warn "puredns không tạo ra output — wildcard filter bị skip"
            warn "Nguyên nhân thường gặp: resolver list hỏng, network timeout, puredns crash"
            warn "Tiếp tục với list gốc (${TOTAL_INPUT} subdomains) — kết quả có thể có wildcard FP"
        fi
    else
        warn "No resolver list found — skipping wildcard filter"
    fi
else
    warn "puredns not found — skipping wildcard filter"
    warn "Install: go install github.com/d3mondev/puredns/v2@latest"
fi

# ══════════════════════════════════════════════════════════════════
# STAGE 2: Resolve with dnsx
# ══════════════════════════════════════════════════════════════════
step "Stage 2/2 — DNS Resolution (dnsx)"

DNSX_RAW="${TEMP_DIR}/dnsx_raw.txt"

if cmd_exists dnsx; then
    info "Tool: dnsx"
    dnsx \
        -l "$CLEAN_LIST" \
        -a \
        -resp \
        -no-color \
        -silent \
        -timeout 10s \
        -retry 3 \
        -t 100 \
        > "$DNSX_RAW" 2>/dev/null || true

    # Parse: "hostname [A] [ip]"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        host=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | grep -oP '\[\K[0-9][0-9.]+(?=\])' | tail -1)
        [[ -z "$ip" ]] && continue
        echo "${host} ${ip}" >> "$OUT_RESOLVED"
        echo "$ip" >> "$OUT_IPS"
        success "Resolved → ${host} → ${ip}"
    done < "$DNSX_RAW"

else
    warn "dnsx not found — falling back to dig"
    warn "Install: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        ip=$(dig +short A "$host" 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        [[ -z "$ip" ]] && continue
        echo "${host} ${ip}" >> "$OUT_RESOLVED"
        echo "$ip" >> "$OUT_IPS"
        success "Resolved → ${host} → ${ip}"
    done < "$CLEAN_LIST"
fi

sort -u "$OUT_RESOLVED" -o "$OUT_RESOLVED"
sort -u "$OUT_IPS" -o "$OUT_IPS"

# Unresolved = clean list - resolved
comm -23 \
    <(sort -u "$CLEAN_LIST") \
    <(awk '{print $1}' "$OUT_RESOLVED" | sort -u) \
    > "$OUT_UNRESOLVED"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

RESOLVED_COUNT=$(count_lines "$OUT_RESOLVED")
UNRESOLVED_COUNT=$(count_lines "$OUT_UNRESOLVED")
IP_COUNT=$(count_lines "$OUT_IPS")

WILDCARD_COUNT=$(count_lines "$OUT_WILDCARD")

summary_box "02 RESOLVE" \
    "Domain" "$DOMAIN" \
    "Input" "$TOTAL_INPUT subdomains" \
    "Wildcard filtered" "$WILDCARD_COUNT (→ wildcard_filtered.txt)" \
    "Resolved" "$RESOLVED_COUNT hosts" \
    "Unresolved" "$UNRESOLVED_COUNT (vhost candidates)" \
    "Unique IPs" "$IP_COUNT" \
    "Elapsed" "$ELAPSED_FMT" \
    "Next" "03_cdncheck.sh $DOMAIN"
