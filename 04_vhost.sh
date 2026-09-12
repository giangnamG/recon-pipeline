#!/usr/bin/env bash
# =============================================================================
# 04_vhost.sh — Virtual Host Discovery (5-layer approach)
#
# LAYER 0: Reverse DNS PTR lookup
#   → Từ origin IPs → hostname ngược (không qua DNS forward)
#   → Bắt được hostname share-hosting không có CT/DNS record
#
# LAYER 1: Baseline-diff verify (curl --resolve)
#   → Test known subdomains against their own IPs
#   → Cross-product: unresolved subdomains × origin IPs
#   → Verify PTR candidates từ Layer 0
#
# LAYER 2: ffuf Host header fuzzing (wordlist-based)
#   → Tìm hostname CHƯA trong subdomain list
#   → Dùng -ac (auto-calibrate) để tự học baseline, cắt false positive
#   → Fallback -fs filter khi -ac flood (>150 results)
#
# LAYER 3: TLS Cert SAN extraction (tlsx)
#   → Extract SANs từ cert của origin IPs
#   → Wildcard SAN → scoped ffuf cho từng namespace
#
# LAYER 4: Ripgen permutation
#   → Generate biến thể từ hostname đã tìm → verify lại
#
# INPUT : output/<domain>/resolved.txt
#         output/<domain>/unresolved.txt
#         output/<domain>/origin_ips.txt
# OUTPUT: output/<domain>/vhosts/verified.txt     — host\tip\tproto\tsource{direct|no-dns|ptr-lookup}
#         output/<domain>/vhosts/ffuf.txt          — host\tip\thttps\tffuf-{status}
#         output/<domain>/vhosts/snitched.txt      — host\tip\thttps\t{tlsx-san|wildcard-expanded-{status}}
#         output/<domain>/vhosts/permutations.txt  — host\tip\tproto\tpermutation
#         output/<domain>/vhosts/all_vhosts.txt    — merged: host\tip\tproto\tsource\tdns_status
#
# NOTE: snitched.txt chứa 2 loại cùng nguồn gốc TLS/cert:
#   tlsx-san          — hostname từ SAN/CN của cert, verified qua baseline-diff
#   wildcard-expanded — hostname fuzzing trong namespace của wildcard SAN (*.x.domain.com)
#   → cả 2 đều được merge vào all_vhosts.txt với tag tương ứng
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
OUT_SNITCHED="${VHOST_DIR}/snitched.txt"   # tlsx-san AND wildcard-expanded — cùng nguồn TLS/cert
OUT_PERMS="${VHOST_DIR}/permutations.txt"
OUT_ALL="${VHOST_DIR}/all_vhosts.txt"
FFUF_FILTERED_WL=""   # set bởi Layer 2; đọc bởi Layer 3 wildcard — khai báo sớm tránh unbound
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
# HELPERS
# ══════════════════════════════════════════════════════════════════

# Hostname patterns that are definitively Microsoft-managed endpoints —
# they pass baseline-diff (server responds differently from random host)
# but the server is owned by Microsoft, not the target.
# Only patterns where we are 100% certain it's not target infra.
SKIP_HOST_PATTERNS=(
    "^enterpriseregistration\."    # Microsoft MDM/Intune — always windows.net
    "^enterpriseenrollment\."      # Microsoft MDM — always windows.net
    "^msoid\."                     # Microsoft Online ID — always msft
    "^lyncdiscover\."              # Microsoft Skype for Business — always msft
)

# PTR candidates từ mail/SMTP server sẽ verify thành công trên mọi IP
# vì server trả về trang SMTP-redirect khác random host → baseline-diff FP.
# Filter bỏ trước khi cross-product với origin_ips.
PTR_SKIP_PATTERNS=(
    "^mx[0-9]*\."      # mail exchanger
    "^mail[0-9]*\."    # mail server
    "^smtp[0-9]*\."    # SMTP relay
    "^pop[0-9]*\."     # POP3
    "^imap[0-9]*\."    # IMAP
)

is_skip_host() {
    local host="$1"
    for pat in "${SKIP_HOST_PATTERNS[@]}"; do
        echo "$host" | grep -qE "$pat" && return 0
    done
    return 1
}

is_ptr_skip_host() {
    local host="$1"
    for pat in "${PTR_SKIP_PATTERNS[@]}"; do
        echo "$host" | grep -qE "$pat" && return 0
    done
    return 1
}

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
export DOMAIN
# NOTE: verify_vhost không export-f vì worker script inline logic riêng

# ── Parallel Layer 1 worker ────────────────────────────────────────
# Ghi worker script vào TEMP_DIR để xargs -P có thể gọi
# Input (4 args): ip host proto source_tag
# Output: ghi vào OUT_VERIFIED (dùng flock tránh race condition)
L1_WORKER="${TEMP_DIR}/l1_worker.sh"
L1_LOCK="${TEMP_DIR}/verified.lock"
L1_COUNTER="${TEMP_DIR}/counter"      # file đếm số task đã chạy xong
touch "$L1_LOCK" "$L1_COUNTER"

cat > "$L1_WORKER" <<'WORKER_EOF'
#!/usr/bin/env bash
# Positional args (từ xargs -L 1): ip host proto tag
# Env vars (export từ parent):      L1_OUT L1_LOCK L1_CNTLOCK DOMAIN
ip="$1" host="$2" proto="$3" tag="$4"

# Inline verify_vhost — không dùng export -f để tránh bash version issues
port=443; [[ "$proto" == "http" ]] && port=80
rnd="zz${RANDOM}notreal.${DOMAIN}"
empty_md5="d41d8cd98f00b204e9800998ecf8427e"

baseline=$(curl -sk -m 8 --resolve "${rnd}:${port}:${ip}" \
    "${proto}://${rnd}/" 2>/dev/null \
    | tr -d '[:space:]' | md5sum | cut -d' ' -f1)

real=$(curl -sk -m 8 --resolve "${host}:${port}:${ip}" \
    "${proto}://${host}/" 2>/dev/null \
    | tr -d '[:space:]' | md5sum | cut -d' ' -f1)

if [[ -n "$real" && "$real" != "$empty_md5" && "$baseline" != "$real" ]]; then
    ( flock -x 9
      printf '%s\t%s\t%s\t%s\n' "$host" "$ip" "$proto" "$tag" >> "$L1_OUT"
    ) 9>>"$L1_LOCK"
    echo "FOUND:${tag}:${host}:${ip}:${proto}"
fi
( flock -x 9
  n=$(cat "$L1_CNTLOCK" 2>/dev/null || echo 0)
  echo $((n+1)) > "$L1_CNTLOCK"
) 9>>"${L1_CNTLOCK}.lk"
WORKER_EOF
chmod +x "$L1_WORKER"

# Hàm chạy một batch task file song song, in progress + summary
# task_file: mỗi dòng = "ip host proto tag"
run_parallel_l1() {
    local task_file="$1" total="$2" label="$3"
    [[ ! -s "$task_file" ]] && return
    echo 0 > "$L1_COUNTER"

    # Export env vars cần thiết cho worker
    export L1_OUT="$OUT_VERIFIED"
    export L1_LOCK="$L1_LOCK"
    export L1_CNTLOCK="$L1_COUNTER"
    # DOMAIN và verify_vhost đã export từ trước

    # -P 30: 30 concurrent workers; -L 1: mỗi invocation nhận 1 dòng (split thành args)
    xargs -a "$task_file" -P 30 -L 1 bash "$L1_WORKER" \
        2>/dev/null | while IFS=: read -r flag tag host ip proto _; do
            [[ "$flag" == "FOUND" ]] && \
                found "${label}  ${host}  →  ${ip}  (${proto})  [${tag}]"
        done

    local done_count
    done_count=$(cat "$L1_COUNTER" 2>/dev/null || echo 0)
    info "  ${label}: ${done_count}/${total} tasks done"
}

# ══════════════════════════════════════════════════════════════════
# LAYER 0: Reverse DNS PTR lookup
# Nguyên lý: IP → hostname ngược, không qua DNS forward.
# Bắt được hostname bind với IP nhưng không có CT log / DNS A record.
# ══════════════════════════════════════════════════════════════════
step "Layer 0/4 — Reverse DNS PTR Lookup"
info "IP → hostname ngược (bắt share-hosting không có DNS forward)"

PTR_CANDIDATES="${TEMP_DIR}/ptr_candidates.txt"
> "$PTR_CANDIDATES"

while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    # host <ip> trả về: "<reversed>.in-addr.arpa domain name pointer <hostname>."
    host "$ip" 2>/dev/null \
        | grep -oP '[a-zA-Z0-9._-]+\.'"${DOMAIN//./\\.}"'\.?' \
        | sed 's/\.$//' \
        | tr '[:upper:]' '[:lower:]' \
        >> "$PTR_CANDIDATES" || true
done < "$IN_ORIGIN_IPS"

sort -u "$PTR_CANDIDATES" -o "$PTR_CANDIDATES"

# Filter luôn tại đây để count chính xác
PTR_FILTERED="${TEMP_DIR}/ptr_filtered.txt"
> "$PTR_FILTERED"
while IFS= read -r h; do
    if is_ptr_skip_host "$h"; then
        info "  PTR SKIP  ${h}  (mail/SMTP — sẽ FP trên baseline-diff)"
    else
        echo "$h" >> "$PTR_FILTERED"
    fi
done < "$PTR_CANDIDATES"
cp "$PTR_FILTERED" "$PTR_CANDIDATES"

PTR_COUNT=$(count_lines "$PTR_CANDIDATES")

if [[ "$PTR_COUNT" -gt 0 ]]; then
    info "PTR: ${PTR_COUNT} hostname candidates từ ${ORIGIN_COUNT} IPs (sau khi filter)"
    while IFS= read -r h; do info "  → $h"; done < "$PTR_CANDIDATES"
else
    info "PTR: không tìm được hostname mới từ ${ORIGIN_COUNT} IPs (sau khi filter)"
fi

# ══════════════════════════════════════════════════════════════════
# LAYER 1: Baseline-diff verify (curl --resolve)
# ══════════════════════════════════════════════════════════════════
step "Layer 1/4 — Baseline-diff Verification (curl)"
info "Logic: body(random_host) ≠ body(real_host) → confirmed vhost"

# 1a: Resolved hostnames vs their own IP
info "1a — Resolved hosts vs their IP (parallel)..."
L1A_TASKS="${TEMP_DIR}/l1a_tasks.txt"
> "$L1A_TASKS"
while IFS=' ' read -r host ip; do
    grep -qxF "$ip" "$IN_ORIGIN_IPS" 2>/dev/null || continue
    if is_skip_host "$host"; then
        info "  SKIP  ${host}  (managed service — not target infra)"
        continue
    fi
    # Thử https trước — nếu https pass thì http không cần thiết.
    # Worker chỉ ghi khi verify thành công, không có short-circuit qua proto.
    # → Sinh 2 task (https + http); sau đó dedup theo hostname khi merge.
    printf '%s %s https direct\n' "$ip" "$host" >> "$L1A_TASKS"
    printf '%s %s http  direct\n' "$ip" "$host" >> "$L1A_TASKS"
done < "$IN_RESOLVED"
L1A_TOTAL=$(wc -l < "$L1A_TASKS" 2>/dev/null || echo 0)
run_parallel_l1 "$L1A_TASKS" "$L1A_TOTAL" "1a"

# Dedup 1a: cùng (host, ip) pair → giữ https ưu tiên
# Load balancer thật sự có nhiều IPs → giữ mọi (host, ip) unique
# Chỉ dedup khi cùng (host, ip) có cả https lẫn http → bỏ http
sort -t$'\t' -k1,1 -k2,2 -k3,3r "$OUT_VERIFIED" \
    | awk -F'\t' '!seen[$1"\t"$2]++' \
    > "${TEMP_DIR}/verified_dedup.txt" 2>/dev/null || true
[[ -s "${TEMP_DIR}/verified_dedup.txt" ]] && cp "${TEMP_DIR}/verified_dedup.txt" "$OUT_VERIFIED"

# 1b: Unresolved hostnames × all origin IPs (cross-product)
if [[ "$UNRESOLVED_COUNT" -gt 0 && "$ORIGIN_COUNT" -gt 0 ]]; then
    CROSS_TOTAL=$(( UNRESOLVED_COUNT * ORIGIN_COUNT * 2 ))   # ×2 protos
    info "1b — Cross-product: ${UNRESOLVED_COUNT} unresolved × ${ORIGIN_COUNT} IPs = ${CROSS_TOTAL} tasks (parallel)"
    L1B_TASKS="${TEMP_DIR}/l1b_tasks.txt"
    > "$L1B_TASKS"
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        if is_skip_host "$host"; then
            info "  SKIP  ${host}  (managed service)"
            continue
        fi
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            printf '%s %s https no-dns\n' "$ip" "$host" >> "$L1B_TASKS"
            printf '%s %s http  no-dns\n' "$ip" "$host" >> "$L1B_TASKS"
        done < "$IN_ORIGIN_IPS"
    done < "$IN_UNRESOLVED"
    run_parallel_l1 "$L1B_TASKS" "$CROSS_TOTAL" "1b"
fi

# 1c: PTR candidates — chỉ verify trên IP mà host thực sự resolve về
# Lý do: PTR từ IP → hostname, nhưng hostname có thể resolve về IP khác
# (mail server mx1 resolve về dedicated mail IP, không phải web IP).
# Cross-product toàn bộ origin_ips → FP vì mx server trả trang khác random host.
# Logic đúng: dig A <ptr_host> → lấy IP → nếu IP đó trong origin_ips thì verify.
# Fallback: nếu không resolve → thử cross-product (hostname thực sự hidden).
if [[ "$PTR_COUNT" -gt 0 ]]; then
    info "1c — PTR candidates verification (chỉ test trên IP thực)..."
    L1C_TASKS="${TEMP_DIR}/l1c_tasks.txt"
    > "$L1C_TASKS"
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        if is_skip_host "$host"; then
            info "  SKIP  ${host}  (managed service)"
            continue
        fi
        # Filter mail server — baseline-diff FP vì SMTP response khác random host
        if is_ptr_skip_host "$host"; then
            info "  SKIP  ${host}  (mail/SMTP server — PTR FP risk)"
            continue
        fi
        # Skip nếu đã verified ở 1a
        grep -qP "^${host}\t" "$OUT_VERIFIED" 2>/dev/null && continue

        # Resolve forward: lấy IP thực của PTR host
        PTR_REAL_IPS=$(dig +short +time=2 +tries=1 A "$host" 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')

        if [[ -n "$PTR_REAL_IPS" ]]; then
            # Có forward DNS → chỉ test trên IP thuộc origin_ips
            while IFS= read -r resolved_ip; do
                grep -qxF "$resolved_ip" "$IN_ORIGIN_IPS" 2>/dev/null || continue
                printf '%s %s https ptr-lookup\n' "$resolved_ip" "$host" >> "$L1C_TASKS"
                printf '%s %s http  ptr-lookup\n' "$resolved_ip" "$host" >> "$L1C_TASKS"
            done <<< "$PTR_REAL_IPS"
        else
            # Không resolve → hidden hostname, thử cross-product toàn bộ origin_ips
            info "  ${host}: không resolve → cross-product origin IPs"
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                printf '%s %s https ptr-lookup\n' "$ip" "$host" >> "$L1C_TASKS"
                printf '%s %s http  ptr-lookup\n' "$ip" "$host" >> "$L1C_TASKS"
            done < "$IN_ORIGIN_IPS"
        fi
    done < "$PTR_CANDIDATES"
    L1C_TOTAL=$(wc -l < "$L1C_TASKS" 2>/dev/null || echo 0)
    if [[ "$L1C_TOTAL" -gt 0 ]]; then
        run_parallel_l1 "$L1C_TASKS" "$L1C_TOTAL" "1c"
    else
        info "1c: không có task nào sau khi filter (tất cả PTR đã skip hoặc resolve về non-origin IP)"
    fi
fi

# Dedup toàn bộ verified.txt: cùng (host, ip) pair → giữ https ưu tiên
sort -t$'\t' -k1,1 -k2,2 -k3,3r "$OUT_VERIFIED" \
    | awk -F'\t' '!seen[$1"\t"$2]++' \
    > "${TEMP_DIR}/verified_final.txt" 2>/dev/null || true
[[ -s "${TEMP_DIR}/verified_final.txt" ]] && cp "${TEMP_DIR}/verified_final.txt" "$OUT_VERIFIED"

VERIFIED_L1=$(count_lines "$OUT_VERIFIED")
success "Layer 1: ${VERIFIED_L1} verified vhosts"

# ══════════════════════════════════════════════════════════════════
# LAYER 2: ffuf Host header fuzzing
# ══════════════════════════════════════════════════════════════════
step "Layer 2/4 — ffuf Host Header Fuzzing (wordlist-based)"
info "Finds hostnames NOT in our subdomain list"

FFUF_WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
[[ ! -f "$FFUF_WORDLIST" ]] && FFUF_WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"

# Helper: parse một ffuf JSON file → append vào output file
# Args: <json_file> <namespace_or_domain> <ip> <out_file> <tag_prefix>
parse_ffuf_json() {
    local json_file="$1" namespace="$2" ip="$3" out_file="$4" tag="$5"
    [[ -f "$json_file" ]] || return 0
    python3 - "$json_file" "$namespace" "$ip" "$out_file" "$tag" <<'PYEOF'
import sys, json, collections

json_file, namespace, ip, out_file, tag = sys.argv[1:]

try:
    with open(json_file) as f:
        data = json.load(f)
    results = data.get("results", [])

    # Fallback FP detection: nếu >150 results, filter size phổ biến nhất
    FP_THRESHOLD = 150
    if len(results) > FP_THRESHOLD:
        sizes = [r.get("length", 0) for r in results]
        common_size = collections.Counter(sizes).most_common(1)[0][0]
        original_count = len(results)
        results = [r for r in results if r.get("length", 0) != common_size]
        print(f"  [!] {original_count} results — FP filter: removed size={common_size}, kept {len(results)}")

    # Filter ffuf calibration probe words (bắt đầu bằng dấu chấm: .htaccessXXX, .phpXXX)
    # Đây là request ffuf tự gửi để học baseline, không phải real vhost
    results = [r for r in results if not r["input"].get("FUZZ", "").startswith(".")]

    with open(out_file, "a") as out:
        for r in results:
            word = r["input"].get("FUZZ", "")
            host = f"{word}.{namespace}" if word else namespace
            status = r.get("status", 0)
            size = r.get("length", 0)
            print(f"  [{tag}] {host} → {ip} [{status}] ({size}b)")
            out.write(f"{host}\t{ip}\thttps\t{tag}-{status}\n")
except Exception as e:
    print(f"  [!] parse error: {e}")
PYEOF
}
if ! cmd_exists ffuf; then
    warn "ffuf not found — skipping layer 2"
    warn "Install: go install github.com/ffuf/ffuf/v2@latest"
elif [[ ! -f "$FFUF_WORDLIST" ]]; then
    warn "ffuf wordlist not found — skipping layer 2"
else
    info "Wordlist: $FFUF_WORDLIST"

    # Lọc bỏ subdomain đã biết khỏi wordlist — gán vào biến đã khai báo ngoài
    FFUF_FILTERED_WL="${TEMP_DIR}/ffuf_wordlist_filtered.txt"
    if [[ -f "$IN_SUBDOMAINS" ]]; then
        KNOWN_PREFIXES="${TEMP_DIR}/known_prefixes.txt"
        sed "s/\.${DOMAIN}$//" "$IN_SUBDOMAINS" 2>/dev/null \
            | awk '{print tolower($0)}' | sort -u > "$KNOWN_PREFIXES"
        comm -23 \
            <(awk '{print tolower($0)}' "$FFUF_WORDLIST" | sort -u) \
            "$KNOWN_PREFIXES" > "$FFUF_FILTERED_WL"
        ORIG=$(wc -l < "$FFUF_WORDLIST")
        AFTER=$(wc -l < "$FFUF_FILTERED_WL")
        info "Wordlist filtered: $ORIG → $AFTER words (removed $((ORIG - AFTER)) known)"
    else
        cp "$FFUF_WORDLIST" "$FFUF_FILTERED_WL"
    fi

    # ── Dedup IPs theo /24 subnet — tránh fuzz N IPs cùng server ──────
    # Nhiều IPs trong cùng /24 thường là load balancer member, respond giống nhau.
    # Chỉ lấy 1 IP đại diện mỗi /24 → giảm ffuf jobs đáng kể.
    # Nếu cần fuzz tất cả: xóa block này và dùng IN_ORIGIN_IPS trực tiếp.
    FFUF_TARGET_IPS="${TEMP_DIR}/ffuf_target_ips.txt"
    > "$FFUF_TARGET_IPS"
    declare -A seen_subnet
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        subnet="${ip%.*}"   # lấy /24 prefix: x.x.x
        if [[ -z "${seen_subnet[$subnet]+_}" ]]; then
            seen_subnet[$subnet]=1
            echo "$ip" >> "$FFUF_TARGET_IPS"
        fi
    done < "$IN_ORIGIN_IPS"
    FFUF_TARGET_COUNT=$(wc -l < "$FFUF_TARGET_IPS")
    ORIGIN_TOTAL=$(wc -l < "$IN_ORIGIN_IPS")
    info "IP dedup /24: ${ORIGIN_TOTAL} → ${FFUF_TARGET_COUNT} unique subnets to fuzz"

    # ── ffuf runner với -ac + fallback -fs ─────────────────────────────
    run_ffuf_on_ip() {
        local ip="$1" domain="$2" wl="$3" out_file="$4" temp_dir="$5"
        local safe_ip="${ip//\./_}"
        local json_ac="${temp_dir}/ffuf_${safe_ip}.json"

        # ── Pre-check: catch-all server detection ──────────────────────────
        # Gửi 2 random hostname hoàn toàn khác nhau.
        # Nếu cả 2 đều respond 2xx/3xx → server là catch-all → skip ffuf
        # (ffuf sẽ cho toàn bộ wordlist là "found" → noise, không có giá trị)
        local rnd1="zzcatchall${RANDOM}aa.${domain}"
        local rnd2="zzcatchall${RANDOM}bb.${domain}"
        local sz1 sz2
        sz1=$(curl -sk -m 6 -o /dev/null -w '%{http_code}' \
            -H "Host: ${rnd1}" --resolve "${rnd1}:443:${ip}" \
            "https://${ip}/" 2>/dev/null || echo 0)
        sz2=$(curl -sk -m 6 -o /dev/null -w '%{http_code}' \
            -H "Host: ${rnd2}" --resolve "${rnd2}:443:${ip}" \
            "https://${ip}/" 2>/dev/null || echo 0)

        # Nếu cả 2 random host đều 2xx/3xx → catch-all, bỏ qua
        local is_2xx_3xx='2[0-9][0-9]\|3[0-9][0-9]'
        if echo "$sz1" | grep -qE '^(2|3)[0-9]{2}$' && \
           echo "$sz2" | grep -qE '^(2|3)[0-9]{2}$'; then
            echo "  [ffuf] ${ip}: SKIP — catch-all server (${sz1}/${sz2} on random hosts)"
            return 0
        fi

        # Pass 1: -ac auto-calibrate (với -acc để force aggressive calibration)
        ffuf \
            -w "${wl}:FUZZ" \
            -u "https://${ip}/" \
            -H "Host: FUZZ.${domain}" \
            -ac -acc \
            -mc 200,201,204,301,302,307,308,401,403,405 \
            -t 50 -timeout 8 \
            -o "$json_ac" -of json -s \
            2>/dev/null || true

        local ac_count=0
        if [[ -f "$json_ac" ]]; then
            ac_count=$(python3 -c "
import json,sys
try: print(len(json.load(open('$json_ac')).get('results',[])))
except: print(0)" 2>/dev/null || echo 0)
        fi

        if [[ "$ac_count" -gt 0 ]]; then
            echo "  [ffuf] ${ip}: ${ac_count} results (ac pass)"
            return 0   # parse_ffuf_json caller handles writing
        fi

        # Pass 2: -ac missed everything → probe baseline size, retry with -fs
        local rnd_host="zznotreal${RANDOM}.${domain}"
        local baseline_size
        baseline_size=$(curl -sk -m 8 \
            -H "Host: ${rnd_host}" \
            --resolve "${rnd_host}:443:${ip}" \
            "https://${ip}/" \
            -w '%{size_download}' -o /dev/null 2>/dev/null || echo 0)

        if [[ "$baseline_size" -gt 0 ]]; then
            local json_fs="${temp_dir}/ffuf_${safe_ip}_fs.json"
            ffuf \
                -w "${wl}:FUZZ" \
                -u "https://${ip}/" \
                -H "Host: FUZZ.${domain}" \
                -fs "$baseline_size" \
                -mc 200,201,204,301,302,307,308,401,403,405 \
                -t 50 -timeout 8 \
                -o "$json_fs" -of json -s \
                2>/dev/null || true
            # Merge json_fs → json_ac slot so caller parses it
            [[ -f "$json_fs" ]] && cp "$json_fs" "$json_ac"
            local fs_count=0
            [[ -f "$json_ac" ]] && fs_count=$(python3 -c "
import json
try: print(len(json.load(open('$json_ac')).get('results',[])))
except: print(0)" 2>/dev/null || echo 0)
            echo "  [ffuf] ${ip}: ac=0, fs fallback (size=${baseline_size}b) → ${fs_count} results"
        fi
    }

    # Parallel ffuf: chạy tối đa L2_PARALLEL jobs đồng thời
    # Mỗi job = 1 ffuf instance trên 1 IP (ffuf tự dùng -t 50 thread nội bộ)
    # Không cần flock cho output vì parse_ffuf_json chạy SAU khi tất cả xong
    L2_PARALLEL=5   # 5 IPs × 50 threads = 250 concurrent HTTP requests tới target
                    # Tăng nếu target chịu được; giảm nếu bị rate-limit/block

    FFUF_DONE_DIR="${TEMP_DIR}/ffuf_done"
    mkdir -p "$FFUF_DONE_DIR"
    FFUF_LOCK="${TEMP_DIR}/ffuf_out.lock"
    touch "$FFUF_LOCK"

    # Chạy ffuf background jobs với semaphore
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue

        # Giới hạn concurrent jobs (semaphore)
        while (( $(jobs -r | wc -l) >= L2_PARALLEL )); do
            wait -n 2>/dev/null || sleep 0.5   # wait -n: bash 4.3+; fallback poll
        done

        info "ffuf → $ip [background]"
        (
            run_ffuf_on_ip "$ip" "$DOMAIN" "$FFUF_FILTERED_WL" "$OUT_FFUF" "$TEMP_DIR"
            FFUF_JSON="${TEMP_DIR}/ffuf_${ip//\./_}.json"
            # flock để append vào OUT_FFUF an toàn
            (
                flock -x 9
                parse_ffuf_json "$FFUF_JSON" "$DOMAIN" "$ip" "$OUT_FFUF" "ffuf"
            ) 9>>"$FFUF_LOCK"
            touch "${FFUF_DONE_DIR}/${ip//\./_}"
        ) &
    done < "$FFUF_TARGET_IPS"

    # Chờ tất cả jobs còn lại
    wait
    info "ffuf: tất cả ${FFUF_TARGET_COUNT} jobs xong"

    FFUF_COUNT=$(count_lines "$OUT_FFUF")
    success "Layer 2: ${FFUF_COUNT} ffuf findings"
fi

# ══════════════════════════════════════════════════════════════════
# LAYER 3: TLS Cert SAN extraction (tlsx)
# Extract SANs → verify → Wildcard SAN → scoped ffuf
# ══════════════════════════════════════════════════════════════════
step "Layer 3/4 — TLS Cert SAN Extraction (tlsx)"
info "Extract SANs từ TLS cert → verify → wildcard namespace fuzz"

if cmd_exists tlsx; then
    info "Tool: tlsx (ProjectDiscovery)"
    TLSX_RAW="${TEMP_DIR}/tlsx_raw.txt"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        for port in 443 8443; do
            tlsx \
                -u "${ip}:${port}" \
                -san -cn \
                -silent \
                -no-color \
                2>/dev/null >> "$TLSX_RAW" || true
        done
    done < "$IN_ORIGIN_IPS"

    if [[ -f "$TLSX_RAW" && -s "$TLSX_RAW" ]]; then

        # 3a: Non-wildcard SANs → verify
        grep -oP '[a-z0-9*._-]+\.'"${DOMAIN//./\\.}" "$TLSX_RAW" 2>/dev/null \
            | grep -v '^\*\.' \
            | sort -u \
            | while IFS= read -r host; do
                while IFS= read -r ip; do
                    if verify_vhost "$ip" "$host" "https"; then
                        found "TLS-SAN VERIFIED  ${host}  →  ${ip}"
                        printf '%s\t%s\thttps\ttlsx-san\n' "$host" "$ip" >> "$OUT_SNITCHED"
                        break
                    fi
                done < "$IN_ORIGIN_IPS"
              done

        # 3b: Wildcard SANs → scoped ffuf cho từng namespace
        # Ví dụ: *.apps.internal.example.com → fuzz FUZZ.apps.internal.example.com
        WILDCARD_SANS=$(grep -oP '\*\.[a-z0-9._-]+\.'"${DOMAIN//./\\.}" "$TLSX_RAW" 2>/dev/null | sort -u)

        if [[ -n "$WILDCARD_SANS" ]]; then
            info "Wildcard SANs → scoped ffuf cho từng namespace:"
            echo "$WILDCARD_SANS" | while IFS= read -r wildcard; do
                namespace="${wildcard#\*.}"
                info "  Namespace: ${namespace}"

                if ! cmd_exists ffuf || [[ ! -f "${FFUF_FILTERED_WL:-}" ]]; then
                    warn "  ffuf/wordlist không có — skip namespace fuzz"
                    continue
                fi

                while IFS= read -r ip; do
                    [[ -z "$ip" ]] && continue
                    WC_JSON="${TEMP_DIR}/ffuf_wc_${ip//\./_}_${namespace//\./_}.json"

                    ffuf \
                        -w "${FFUF_FILTERED_WL}:FUZZ" \
                        -u "https://${ip}/" \
                        -H "Host: FUZZ.${namespace}" \
                        -ac \
                        -mc 200,201,204,301,302,307,308,401,403,405 \
                        -t 30 -timeout 8 \
                        -o "$WC_JSON" -of json -s 2>/dev/null || true

                    parse_ffuf_json "$WC_JSON" "$namespace" "$ip" "$OUT_SNITCHED" "wildcard-expanded"
                done < "$IN_ORIGIN_IPS"
            done
        else
            info "Không tìm thấy wildcard SAN"
        fi
    fi

    SNITCHED_COUNT=$(count_lines "$OUT_SNITCHED")
    success "Layer 3: ${SNITCHED_COUNT} TLS-SAN findings"
else
    warn "tlsx not found — skipping layer 3"
    warn "Install: go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
fi

# ══════════════════════════════════════════════════════════════════
# LAYER 4: Ripgen permutation
# ══════════════════════════════════════════════════════════════════
step "Layer 4/4 — Permutation Generation (ripgen)"
info "Generate hostname variants from known subdomains → verify"

if cmd_exists ripgen; then
    info "Tool: ripgen"
    PERM_LIST="${TEMP_DIR}/permutations.txt"

    {
        awk '{print $1}' "$OUT_VERIFIED" 2>/dev/null
        awk '{print $1}' "$OUT_FFUF" 2>/dev/null
        awk '{print $1}' "$OUT_SNITCHED" 2>/dev/null
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
# MERGE all layers + dns_status classification
# ══════════════════════════════════════════════════════════════════
step "Merging all layers + DNS status classification"
info "Phân loại: dns-resolvable (có A record công khai) vs hidden-vhost"

python3 - "$OUT_VERIFIED" "$OUT_FFUF" "$OUT_SNITCHED" "$OUT_PERMS" "$OUT_ALL" <<'PYEOF'
import sys, subprocess

files   = sys.argv[1:5]
out_all = sys.argv[5]

# Dedup theo hostname, ưu tiên: verified > ffuf > tlsx > permutation
seen_hosts = {}
for fpath in files:
    try:
        with open(fpath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('\t')
                host = parts[0].lower() if parts else ""
                if not host:
                    continue
                if host not in seen_hosts:
                    seen_hosts[host] = line
    except FileNotFoundError:
        pass

def has_public_dns(hostname):
    """True nếu hostname có A record công khai (dig +short)."""
    try:
        r = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", hostname, "A"],
            capture_output=True, text=True, timeout=4
        )
        # Kết quả có ít nhất 1 IP → resolvable
        return any(
            line.strip() and line.strip()[0].isdigit()
            for line in r.stdout.splitlines()
        )
    except Exception:
        return False

hidden_count = 0
resolvable_count = 0

with open(out_all, 'w') as f:
    for host, line in sorted(seen_hosts.items()):
        dns_status = "dns-resolvable" if has_public_dns(host) else "hidden-vhost"
        if dns_status == "hidden-vhost":
            hidden_count += 1
        else:
            resolvable_count += 1
        f.write(line + f'\t{dns_status}\n')

total = len(seen_hosts)
print(f"  Merged  : {total} unique hostnames")
print(f"  Resolvable : {resolvable_count}  |  Hidden : {hidden_count}")
PYEOF

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

ALL_COUNT=$(count_lines "$OUT_ALL")
HIDDEN_COUNT=$(grep -c 'hidden-vhost' "$OUT_ALL" 2>/dev/null || echo 0)
RESOLVABLE_COUNT=$(grep -c 'dns-resolvable' "$OUT_ALL" 2>/dev/null || echo 0)

summary_box "04 VHOST DISCOVERY" \
    "Domain" "$DOMAIN" \
    "Layer 0 (PTR)" "${PTR_COUNT} candidates" \
    "Layer 1 (curl)" "$(count_lines "$OUT_VERIFIED") verified" \
    "Layer 2 (ffuf)" "$(count_lines "$OUT_FFUF") found" \
    "Layer 3 (TLS-SAN)" "$(count_lines "$OUT_SNITCHED") found" \
    "Layer 4 (ripgen)" "$(count_lines "$OUT_PERMS") found" \
    "Total unique" "$ALL_COUNT vhosts" \
    "  hidden-vhost" "$HIDDEN_COUNT (no public DNS)" \
    "  dns-resolvable" "$RESOLVABLE_COUNT" \
    "Elapsed" "$ELAPSED_FMT" \
    "Next" "05_portscan.sh $DOMAIN"

if [[ "$ALL_COUNT" -gt 0 ]]; then
    step "All verified vhosts"
    printf "  ${DIM}%-40s %-18s %-9s %-22s %s${RESET}\n" \
        "hostname" "ip" "proto" "source" "dns_status"
    printf "  ${DIM}%s${RESET}\n" "$(printf '%.0s─' {1..100})"
    while IFS=$'\t' read -r host ip proto src dns_status; do
        src="${src:-direct}"
        dns_status="${dns_status:-unknown}"
        # hidden-vhost in yellow, resolvable in normal
        if [[ "$dns_status" == "hidden-vhost" ]]; then
            printf "  ${MAGENTA}★${RESET}  %-38s %-18s %-9s %-22s ${YELLOW}%s${RESET}\n" \
                "$host" "$ip" "$proto" "$src" "$dns_status"
        else
            printf "  ${MAGENTA}★${RESET}  %-38s %-18s %-9s %-22s %s\n" \
                "$host" "$ip" "$proto" "$src" "$dns_status"
        fi
    done < "$OUT_ALL"
fi
