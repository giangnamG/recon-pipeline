#!/usr/bin/env bash
# =============================================================================
# 04_vhost.sh — Virtual Host Discovery (3-layer approach)
#
# LAYER 1: Baseline-diff verify (curl --resolve)
#   → Test known subdomains against their own IPs
#   → Cross-product: unresolved subdomains × origin IPs
#
# LAYER 2: ffuf Host header fuzzing (wordlist-based)
#   → Tìm hostname CHƯA trong subdomain list
#   → Dùng -ac (auto-calibrate) để tự học baseline, cắt false positive
#
# LAYER 3: SNItch SNI-level fuzzing
#   → Bắt vhost validate ở tầng TLS handshake (bỏ sót bởi HTTP fuzzing)
#   → Iterative: extract SANs → query CT → re-fuzz
#
# LAYER 4: Ripgen permutation
#   → Generate biến thể từ hostname đã tìm → verify lại
#
# INPUT : output/<domain>/resolved.txt
#         output/<domain>/unresolved.txt
#         output/<domain>/origin_ips.txt
# OUTPUT: output/<domain>/vhosts/verified.txt     — hostname<TAB>ip<TAB>proto
#         output/<domain>/vhosts/ffuf.txt          — ffuf findings
#         output/<domain>/vhosts/snitched.txt      — SNItch findings
#         output/<domain>/vhosts/permutations.txt  — permutation findings
#         output/<domain>/vhosts/all_vhosts.txt    — merged all layers
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

[[ $# -lt 1 ]] && { usage "$0 <domain>"; exit 1; }
DOMAIN="$(normalize_domain "$1")"

OUT_DIR="$(output_dir "$DOMAIN")"
VHOST_DIR="${OUT_DIR}/vhosts"
mkdir -p "$VHOST_DIR"

IN_RESOLVED="${OUT_DIR}/resolved.txt"
IN_UNRESOLVED="${OUT_DIR}/unresolved.txt"
IN_ORIGIN_IPS="${OUT_DIR}/origin_ips.txt"
IN_SUBDOMAINS="${OUT_DIR}/subdomains.txt"

OUT_VERIFIED="${VHOST_DIR}/verified.txt"
OUT_FFUF="${VHOST_DIR}/ffuf.txt"
OUT_SNITCHED="${VHOST_DIR}/snitched.txt"
OUT_PERMS="${VHOST_DIR}/permutations.txt"
OUT_ALL="${VHOST_DIR}/all_vhosts.txt"
LOG_FILE="${OUT_DIR}/logs/04_vhost.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

for f in "$IN_RESOLVED" "$IN_ORIGIN_IPS"; do
    [[ -f "$f" ]] || { error "Missing: $f — run previous steps first"; exit 1; }
done

> "$OUT_VERIFIED"; > "$OUT_FFUF"; > "$OUT_SNITCHED"; > "$OUT_PERMS"; > "$OUT_ALL"

banner "04 — Virtual Host Discovery" "$DOMAIN"

ORIGIN_COUNT=$(count_lines "$IN_ORIGIN_IPS")
RESOLVED_COUNT=$(count_lines "$IN_RESOLVED")
UNRESOLVED_COUNT=$(count_lines "$IN_UNRESOLVED" 2>/dev/null || echo 0)

info "Origin IPs  : $ORIGIN_COUNT"
info "Resolved    : $RESOLVED_COUNT"
info "Unresolved  : $UNRESOLVED_COUNT (vhost candidates)"

START_TIME=$(date +%s)

# ══════════════════════════════════════════════════════════════════
# LAYER 1: Baseline-diff verify (curl --resolve)
# ══════════════════════════════════════════════════════════════════
step "Layer 1/4 — Baseline-diff Verification (curl)"
info "Logic: body(random_host) ≠ body(real_host) → confirmed vhost"

verify_vhost() {
    local ip="$1" host="$2" proto="${3:-https}"
    local port=443; [[ "$proto" == "http" ]] && port=80
    local rnd="zz${RANDOM}notreal.${DOMAIN}"
    local empty_md5="d41d8cd98f00b204e9800998ecf8427e"

    local baseline
    baseline=$(curl -sk -m 8 --resolve "${rnd}:${port}:${ip}" \
        "${proto}://${rnd}/" 2>/dev/null \
        | tr -d '[:space:]' | md5sum | cut -d' ' -f1)

    local real
    real=$(curl -sk -m 8 --resolve "${host}:${port}:${ip}" \
        "${proto}://${host}/" 2>/dev/null \
        | tr -d '[:space:]' | md5sum | cut -d' ' -f1)

    [[ -z "$real" || "$real" == "$empty_md5" ]] && return 1
    [[ "$baseline" != "$real" ]] && return 0
    return 1
}
export -f verify_vhost
export DOMAIN

# 1a: Resolved hostnames vs their own IP
info "1a — Resolved hosts vs their IP..."
while IFS=' ' read -r host ip; do
    grep -qxF "$ip" "$IN_ORIGIN_IPS" 2>/dev/null || continue
    for proto in https http; do
        if verify_vhost "$ip" "$host" "$proto"; then
            found "VERIFIED  ${host}  →  ${ip}  (${proto})"
            printf '%s\t%s\t%s\n' "$host" "$ip" "$proto" >> "$OUT_VERIFIED"
            break
        fi
    done
done < "$IN_RESOLVED"

# 1b: Unresolved hostnames × all origin IPs (cross-product)
if [[ "$UNRESOLVED_COUNT" -gt 0 && "$ORIGIN_COUNT" -gt 0 ]]; then
    CROSS_TOTAL=$(( UNRESOLVED_COUNT * ORIGIN_COUNT ))
    info "1b — Cross-product: ${UNRESOLVED_COUNT} unresolved × ${ORIGIN_COUNT} IPs = ${CROSS_TOTAL} checks"
    COUNT=0
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            COUNT=$(( COUNT + 1 ))
            printf "\r  ${DIM}[%d/%d] %s @ %s${RESET}" "$COUNT" "$CROSS_TOTAL" "$host" "$ip"
            for proto in https http; do
                if verify_vhost "$ip" "$host" "$proto"; then
                    echo ""
                    found "VERIFIED  ${host}  →  ${ip}  (${proto})  [no-dns]"
                    printf '%s\t%s\t%s\tno-dns\n' "$host" "$ip" "$proto" >> "$OUT_VERIFIED"
                    break
                fi
            done
        done < "$IN_ORIGIN_IPS"
    done < "$IN_UNRESOLVED"
    echo ""
fi

VERIFIED_L1=$(count_lines "$OUT_VERIFIED")
success "Layer 1: ${VERIFIED_L1} verified vhosts"

# ══════════════════════════════════════════════════════════════════
# LAYER 2: ffuf Host header fuzzing
# ══════════════════════════════════════════════════════════════════
step "Layer 2/4 — ffuf Host Header Fuzzing (wordlist-based)"
info "Finds hostnames NOT in our subdomain list"

FFUF_WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
[[ ! -f "$FFUF_WORDLIST" ]] && FFUF_WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"

if ! cmd_exists ffuf; then
    warn "ffuf not found — skipping layer 2"
    warn "Install: go install github.com/ffuf/ffuf/v2@latest"
elif [[ ! -f "$FFUF_WORDLIST" ]]; then
    warn "ffuf wordlist not found — skipping layer 2"
else
    info "Wordlist: $FFUF_WORDLIST"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        info "ffuf → $ip"
        FFUF_JSON="${TEMP_DIR}/ffuf_${ip//\./_}.json"

        ffuf \
            -w "$FFUF_WORDLIST:FUZZ" \
            -u "https://${ip}/" \
            -H "Host: FUZZ.${DOMAIN}" \
            -ac \
            -mc 200,201,204,301,302,307,308,401,403,405 \
            -t 50 \
            -timeout 8 \
            -o "$FFUF_JSON" \
            -of json \
            -s \
            2>/dev/null || true

        # Parse ffuf JSON output
        if [[ -f "$FFUF_JSON" ]]; then
            python3 - "$FFUF_JSON" "$DOMAIN" "$ip" "$OUT_FFUF" <<'PYEOF'
import sys, json

ffuf_file = sys.argv[1]
domain    = sys.argv[2]
ip        = sys.argv[3]
out_file  = sys.argv[4]

try:
    with open(ffuf_file) as f:
        data = json.load(f)
    results = data.get("results", [])
    with open(out_file, "a") as out:
        for r in results:
            host = f"{r['input']['FUZZ']}.{domain}"
            status = r.get("status", 0)
            size = r.get("length", 0)
            print(f"  [ffuf] {host} → {ip} [{status}] ({size} bytes)")
            out.write(f"{host}\t{ip}\thttps\tffuf-{status}\n")
except Exception as e:
    print(f"  [!] ffuf parse error: {e}")
PYEOF
        fi
    done < "$IN_ORIGIN_IPS"

    FFUF_COUNT=$(count_lines "$OUT_FFUF")
    success "Layer 2: ${FFUF_COUNT} ffuf findings"
fi

# ══════════════════════════════════════════════════════════════════
# LAYER 3: SNItch SNI-level fuzzing
# ══════════════════════════════════════════════════════════════════
step "Layer 3/4 — SNItch SNI-Level Fuzzing"
info "Finds vhosts that validate at TLS handshake layer (missed by HTTP fuzzing)"

if cmd_exists SNItch; then
    info "Tool: SNItch"
    SNITCHED_RAW="${TEMP_DIR}/snitched_raw.txt"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        info "SNItch → $ip:443"
        SNItch -t "${ip}:443" -d "$DOMAIN" \
            2>/dev/null >> "$SNITCHED_RAW" || true
    done < "$IN_ORIGIN_IPS"

    # Parse SNItch output → verified format
    if [[ -f "$SNITCHED_RAW" ]]; then
        grep -oP '[a-z0-9._-]+\.'"${DOMAIN//./\\.}" "$SNITCHED_RAW" 2>/dev/null \
            | sort -u \
            | while IFS= read -r host; do
                # Try to find which IP serves it
                while IFS= read -r ip; do
                    if verify_vhost "$ip" "$host" "https"; then
                        found "SNItch VERIFIED  ${host}  →  ${ip}"
                        printf '%s\t%s\thttps\tsnitched\n' "$host" "$ip" >> "$OUT_SNITCHED"
                        break
                    fi
                done < "$IN_ORIGIN_IPS"
              done
    fi

    SNITCHED_COUNT=$(count_lines "$OUT_SNITCHED")
    success "Layer 3: ${SNITCHED_COUNT} SNItch findings"
else
    warn "SNItch not found — skipping layer 3"
    warn "Install: https://github.com/Un1cornF4rt/SNItch"
fi

# ══════════════════════════════════════════════════════════════════
# LAYER 4: Ripgen permutation
# ══════════════════════════════════════════════════════════════════
step "Layer 4/4 — Permutation Generation (ripgen)"
info "Generate hostname variants from known subdomains → verify"

if cmd_exists ripgen; then
    info "Tool: ripgen"
    PERM_LIST="${TEMP_DIR}/permutations.txt"

    # Feed all verified hostnames into ripgen
    {
        awk '{print $1}' "$OUT_VERIFIED" 2>/dev/null
        awk '{print $1}' "$OUT_FFUF" 2>/dev/null
    } | sort -u | ripgen 2>/dev/null \
        | grep -E "(^|\.)${DOMAIN//./\\.}$" \
        | sort -u > "$PERM_LIST" || true

    PERM_TOTAL=$(count_lines "$PERM_LIST")
    info "Generated ${PERM_TOTAL} permutations — verifying..."

    COUNT=0
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        COUNT=$(( COUNT + 1 ))
        printf "\r  ${DIM}[%d/%d] %s${RESET}" "$COUNT" "$PERM_TOTAL" "$host"

        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            for proto in https http; do
                if verify_vhost "$ip" "$host" "$proto"; then
                    echo ""
                    found "PERMUTATION  ${host}  →  ${ip}  (${proto})"
                    printf '%s\t%s\t%s\tpermutation\n' "$host" "$ip" "$proto" >> "$OUT_PERMS"
                    break 2
                fi
            done
        done < "$IN_ORIGIN_IPS"
    done < "$PERM_LIST"
    echo ""

    PERM_COUNT=$(count_lines "$OUT_PERMS")
    success "Layer 4: ${PERM_COUNT} permutation findings"
else
    warn "ripgen not found — skipping layer 4"
    warn "Install: cargo install ripgen"
fi

# ══════════════════════════════════════════════════════════════════
# MERGE all layers
# ══════════════════════════════════════════════════════════════════
step "Merging all layers"

cat "$OUT_VERIFIED" "$OUT_FFUF" "$OUT_SNITCHED" "$OUT_PERMS" 2>/dev/null \
    | sort -u > "$OUT_ALL"

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

ALL_COUNT=$(count_lines "$OUT_ALL")

summary_box "04 VHOST DISCOVERY" \
    "Domain" "$DOMAIN" \
    "Layer 1 (curl)" "$(count_lines "$OUT_VERIFIED") verified" \
    "Layer 2 (ffuf)" "$(count_lines "$OUT_FFUF") found" \
    "Layer 3 (SNItch)" "$(count_lines "$OUT_SNITCHED") found" \
    "Layer 4 (ripgen)" "$(count_lines "$OUT_PERMS") found" \
    "Total unique" "$ALL_COUNT vhosts" \
    "Elapsed" "$ELAPSED_FMT" \
    "Next" "05_portscan.sh $DOMAIN"

if [[ "$ALL_COUNT" -gt 0 ]]; then
    step "All verified vhosts"
    printf "  ${DIM}%-40s %-18s %-9s %s${RESET}\n" "hostname" "ip" "proto" "source"
    printf "  ${DIM}%s${RESET}\n" "$(printf '%.0s─' {1..78})"
    while IFS=$'\t' read -r host ip proto src; do
        src="${src:-direct}"
        printf "  ${MAGENTA}★${RESET}  %-38s %-18s %-9s %s\n" "$host" "$ip" "$proto" "$src"
    done < "$OUT_ALL"
fi
