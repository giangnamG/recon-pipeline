#!/usr/bin/env bash
# =============================================================================
# setup_templates.sh — Download & sync nuclei templates về pipeline/templates/
#
# NGUỒN ĐÃ ĐƯỢC ĐÁNH GIÁ & PHÂN LOẠI:
#
# ── TIER 1: LUÔN CÀI (chất lượng cao, maintained) ───────────────────────────
#   [A] projectdiscovery/nuclei-templates    ~9,000+ | official, verified
#   [B] topscoder/nuclei-wordfence-cve       ~82,000 | WordPress CVE, daily update
#   [C] geeknik/the-nuclei-templates         ~80+    | 1-day CVE, bug bounty
#
# ── TIER 2: OPT-IN (chất lượng tốt, use-case cụ thể) ────────────────────────
#   [D] xm1k3/cent                           aggregator tool (không phải template)
#   [E] edoardottt/missing-cve-nuclei-templates  67k+ missing CVE list (reference)
#   [F] 0x727/FingerprintHub                 1,400+ fingerprint templates
#   [G] 0xKayala/Custom-Nuclei-Templates     general community
#   [H] daffainfo/my-nuclei-templates        cá nhân, nhỏ nhưng unique
#
# ── TIER 3: OPT-IN (specialized / risky) ────────────────────────────────────
#   [I] projectdiscovery/fuzzing-templates   fuzz only, KHÔNG chạy mặc định
#   [J] projectdiscovery/nuclei-templates-ai AI-generated, CHƯA verified
#
# ── LOẠI BỎ (không đáng dùng) ───────────────────────────────────────────────
#   ✗ emadshanab/nuclei-templates-collection → chỉ là index/link, không phải templates
#   ✗ mehdihasan/nuclei-templates            → repo 404 (deleted/private)
#   ✗ 0x727/ObserverWard_0x727              → repo 404, đã migrate sang FingerprintHub
#   ✗ cyb3r-w0lf/nuclei-template-collection → 91k templates nhưng 13 stars, unverified bulk
#
# DISK SPACE ƯỚC TÍNH:
#   [A] ~150MB  [B] ~300MB  [C] ~5MB  [F] ~20MB  [G] ~5MB
#   Total Tier1+Tier2: ~500MB
#
# STORAGE:
#   Templates lưu tại /opt/nuclei-pipeline/ (Linux ext4, không phải NTFS/WSL mount)
#   Nếu /opt không writable → tự fallback sang ~/nuclei-pipeline/
#   Override: export NUCLEI_TEMPLATES_DIR=/path/to/dir
#
#   Lần đầu cần tạo thư mục /opt:
#     sudo mkdir -p /opt/nuclei-pipeline && sudo chown $USER:$USER /opt/nuclei-pipeline
#
# Usage:
#   ./setup_templates.sh                # install/update Tier 1
#   ./setup_templates.sh --tier 1       # chỉ Tier 1
#   ./setup_templates.sh --tier 2       # Tier 1 + Tier 2
#   ./setup_templates.sh --tier 3       # tất cả (bao gồm fuzzing + AI)
#   ./setup_templates.sh --source B     # chỉ install/update một source
#   ./setup_templates.sh --remove B     # xóa một source đã cài
#   ./setup_templates.sh --check        # check updates, không pull
#   ./setup_templates.sh --list         # thống kê template counts
#   ./setup_templates.sh --status       # health check: disk, age, outdated
#   ./setup_templates.sh --validate     # lint tất cả templates (nuclei -validate)
#   ./setup_templates.sh --init         # tạo /opt/nuclei-pipeline + chown (cần sudo)
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# ─── Paths ────────────────────────────────────────────────────────────────────
# Templates được lưu trên Linux filesystem (/opt) để tránh NTFS/WSL git issue.
# Có thể override bằng env var NUCLEI_TEMPLATES_DIR.
#
#   Ưu tiên:
#   1. $NUCLEI_TEMPLATES_DIR  (env override)
#   2. /opt/nuclei-pipeline/  (mặc định, yêu cầu sudo mkdir hoặc chown trước)
#   3. ~/nuclei-pipeline/     (fallback nếu /opt không writable)
#
if [[ -n "${NUCLEI_TEMPLATES_DIR:-}" ]]; then
    TEMPLATES_BASE="$NUCLEI_TEMPLATES_DIR"
elif [[ -w "/opt" || -d "/opt/nuclei-pipeline" ]]; then
    TEMPLATES_BASE="/opt/nuclei-pipeline"
else
    TEMPLATES_BASE="${HOME}/nuclei-pipeline"
fi

META_DIR="${TEMPLATES_BASE}/.meta"

# ─── Source registry ──────────────────────────────────────────────────────────
# Format: SRC_URL[id], SRC_DIR[id], SRC_DESC[id], SRC_TIER[id]
declare -A SRC_URL SRC_DIR SRC_DESC SRC_TIER SRC_NOTE

# ── TIER 1 ────────────────────────────────────────────────────────────────────
SRC_URL[A]="https://github.com/projectdiscovery/nuclei-templates"
SRC_DIR[A]="${TEMPLATES_BASE}/nuclei-templates"
SRC_DESC[A]="ProjectDiscovery official"
SRC_TIER[A]=1
SRC_NOTE[A]="~9,000 templates | verified | 13k stars | updated daily"

SRC_URL[B]="https://github.com/topscoder/nuclei-wordfence-cve"
SRC_DIR[B]="${TEMPLATES_BASE}/community/wordfence-cve"
SRC_DESC[B]="Wordfence WordPress CVE templates"
SRC_TIER[B]=1
SRC_NOTE[B]="~82,700 templates | WordPress only | daily update from Wordfence intel | 1.3k stars"

SRC_URL[C]="https://github.com/geeknik/the-nuclei-templates"
SRC_DIR[C]="${TEMPLATES_BASE}/community/geeknik"
SRC_DESC[C]="geeknik community templates"
SRC_TIER[C]=1
SRC_NOTE[C]="~80 templates | 1-day CVE + bug bounty research | YAML lint CI | 303 stars"

# ── TIER 2 ────────────────────────────────────────────────────────────────────
SRC_URL[F]="https://github.com/0x727/FingerprintHub"
SRC_DIR[F]="${TEMPLATES_BASE}/community/fingerprinthub"
SRC_DESC[F]="ObserverWard FingerprintHub"
SRC_TIER[F]=2
SRC_NOTE[F]="~1,400 fingerprint templates | tech detection | 1.4k stars | updated 2024"

SRC_URL[G]="https://github.com/0xKayala/Custom-Nuclei-Templates"
SRC_DIR[G]="${TEMPLATES_BASE}/community/kayala"
SRC_DESC[G]="0xKayala custom templates"
SRC_TIER[G]=2
SRC_NOTE[G]="general community templates | 111 stars | updated 2025"

SRC_URL[H]="https://github.com/daffainfo/my-nuclei-templates"
SRC_DIR[H]="${TEMPLATES_BASE}/community/daffainfo"
SRC_DESC[H]="daffainfo personal templates"
SRC_TIER[H]=2
SRC_NOTE[H]="personal collection | small but unique findings | 64 stars | active 2026"

# ── TIER 3 (opt-in, specialized) ──────────────────────────────────────────────
SRC_URL[I]="https://github.com/projectdiscovery/fuzzing-templates"
SRC_DIR[I]="${TEMPLATES_BASE}/fuzzing"
SRC_DESC[I]="ProjectDiscovery fuzzing templates"
SRC_TIER[I]=3
SRC_NOTE[I]="fuzzing only | KHÔNG dùng mặc định (gây nhiều traffic) | opt-in"

SRC_URL[J]="https://github.com/projectdiscovery/nuclei-templates-ai"
SRC_DIR[J]="${TEMPLATES_BASE}/ai-generated"
SRC_DESC[J]="AI-generated templates (unverified)"
SRC_TIER[J]=3
SRC_NOTE[J]="AI-generated | CHƯA verified | proof-of-concept | 126 stars | dùng cẩn thận"

# Thứ tự source IDs theo tier
ALL_SOURCES=(A B C F G H I J)
TIER1_SOURCES=(A B C)
TIER2_SOURCES=(A B C F G H)
TIER3_SOURCES=(A B C F G H I J)

# ─── Args ─────────────────────────────────────────────────────────────────────
MODE="install"
TARGET_SOURCE=""
REMOVE_SOURCE=""
INSTALL_TIER=1  # mặc định chỉ Tier 1
ORIG_ARGC=$#    # lưu lại trước khi shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)    MODE="check";    shift ;;
        --list)     MODE="list";     shift ;;
        --status)   MODE="status";   shift ;;
        --validate) MODE="validate"; shift ;;
        --init)     MODE="init";     shift ;;
        --update)   MODE="install";  shift ;;   # alias rõ nghĩa hơn
        --tier)     INSTALL_TIER="${2:-1}"; shift 2 ;;
        --source)   TARGET_SOURCE="${2:-}"; shift 2 ;;
        --remove)   REMOVE_SOURCE="${2:-}"; MODE="remove"; shift 2 ;;
        --help|-h)  MODE="help"; shift ;;
        *) shift ;;
    esac
done

# Không có argument → hiện help thay vì chạy ngầm
[[ "$ORIG_ARGC" -eq 0 ]] && MODE="help"

# Chọn danh sách sources theo tier
case "$INSTALL_TIER" in
    1) ACTIVE_SOURCES=("${TIER1_SOURCES[@]}") ;;
    2) ACTIVE_SOURCES=("${TIER2_SOURCES[@]}") ;;
    3) ACTIVE_SOURCES=("${TIER3_SOURCES[@]}") ;;
    *) ACTIVE_SOURCES=("${TIER1_SOURCES[@]}") ;;
esac

mkdir -p "$TEMPLATES_BASE" "$META_DIR"
# (custom/ nằm trong pipeline/templates/custom/ — không tạo ở đây)

# =============================================================================
# MODE: INIT — tạo /opt/nuclei-pipeline với đúng permission
# =============================================================================
if [[ "$MODE" == "init" ]]; then
    TARGET_OPT="/opt/nuclei-pipeline"
    echo ""
    info "Khởi tạo thư mục template tại ${TARGET_OPT}"

    if [[ -d "$TARGET_OPT" ]]; then
        success "Đã tồn tại: ${TARGET_OPT}"
        ls -la "$TARGET_OPT" | head -5
    else
        if [[ -w "/opt" ]]; then
            mkdir -p "$TARGET_OPT"
            success "Tạo thành công: ${TARGET_OPT}"
        else
            info "Cần sudo để tạo ${TARGET_OPT} — đang chạy..."
            if sudo mkdir -p "$TARGET_OPT" && sudo chown "${USER}:${USER}" "$TARGET_OPT"; then
                success "Tạo thành công: ${TARGET_OPT}  (owner: ${USER})"
            else
                warn "sudo thất bại — dùng fallback: ${HOME}/nuclei-pipeline"
                mkdir -p "${HOME}/nuclei-pipeline"
                success "Tạo thành công: ${HOME}/nuclei-pipeline"
                info "Để dùng /opt, chạy thủ công:"
                echo -e "  ${DIM}sudo mkdir -p /opt/nuclei-pipeline && sudo chown \$USER:\$USER /opt/nuclei-pipeline${RESET}"
            fi
        fi
    fi

    # Kiểm tra disk space
    echo ""
    info "Disk space tại $(dirname "$TARGET_OPT"):"
    df -h "$TARGET_OPT" 2>/dev/null || df -h "$(dirname "$TARGET_OPT")"
    echo ""
    info "Ước tính dung lượng cần:"
    echo -e "  ${DIM}Tier 1 (A+B+C): ~455MB  |  +Tier 2 (+F+G+H): ~480MB  |  +Tier 3: ~510MB${RESET}"
    echo ""
    info "Tiếp theo:"
    echo -e "  ${DIM}./setup_templates.sh --tier 1${RESET}"
    exit 0
fi

# =============================================================================
# MODE: REMOVE — xóa một source đã cài
# =============================================================================
if [[ "$MODE" == "remove" ]]; then
    [[ -z "$REMOVE_SOURCE" ]] && { error "Thiếu source ID. Dùng: --remove <ID>"; exit 1; }
    [[ -v "SRC_URL[$REMOVE_SOURCE]" ]] || {
        error "ID không hợp lệ: $REMOVE_SOURCE  (hợp lệ: A B C F G H I J)"
        exit 1
    }
    dir="${SRC_DIR[$REMOVE_SOURCE]}"
    desc="${SRC_DESC[$REMOVE_SOURCE]}"
    echo ""
    warn "Sắp xóa [$REMOVE_SOURCE] $desc"
    warn "Thư mục: $dir"
    if [[ ! -d "$dir" ]]; then
        info "Chưa được cài — không có gì để xóa"
        exit 0
    fi
    SIZE=$(du -sh "$dir" 2>/dev/null | cut -f1)
    warn "Kích thước: ${SIZE}"
    read -r -p "$(echo -e "${YELLOW}Xác nhận xóa? [y/N]:${RESET} ")" confirm
    if [[ "${confirm,,}" == "y" ]]; then
        rm -rf "$dir"
        # Rebuild index sau khi xóa
        find "$TEMPLATES_BASE" -name "*.yaml" \
            ! -path "*/fuzzing/*" ! -path "*/ai-generated/*" ! -path "*/.git/*" \
            | sort > "${META_DIR}/all_templates.txt"
        success "[$REMOVE_SOURCE] Đã xóa — index đã rebuild"
    else
        info "Hủy."
    fi
    exit 0
fi

# =============================================================================
# MODE: STATUS — health check tổng quan
# =============================================================================
if [[ "$MODE" == "status" ]]; then
    echo ""
    step "Template Store Health Check"

    # Disk usage
    echo ""
    info "Storage: ${TEMPLATES_BASE}"
    if [[ -d "$TEMPLATES_BASE" ]]; then
        TOTAL_SIZE=$(du -sh "$TEMPLATES_BASE" 2>/dev/null | cut -f1)
        AVAIL=$(df -h "$TEMPLATES_BASE" 2>/dev/null | awk 'NR==2{print $4}')
        echo -e "  Used : ${BOLD}${TOTAL_SIZE}${RESET}"
        echo -e "  Avail: ${BOLD}${AVAIL}${RESET} free on partition"
    fi

    # Per-source status
    echo ""
    printf "  ${BOLD}%-4s %-28s %-8s %-12s %s${RESET}\n" "ID" "Description" "Size" "Templates" "Age"
    printf "  %s\n" "$(printf '%.0s─' {1..70})"
    NOW_EPOCH=$(date +%s)
    ALL_CURRENT=true
    for id in "${ALL_SOURCES[@]}"; do
        dir="${SRC_DIR[$id]}"
        desc="${SRC_DESC[$id]}"
        if [[ ! -d "${dir}/.git" ]]; then
            printf "  ${DIM}%-4s %-28s %-8s %-12s %s${RESET}\n" \
                "[$id]" "$desc" "-" "-" "NOT INSTALLED"
            continue
        fi
        sz=$(du -sh "$dir" 2>/dev/null | cut -f1)
        ct=$(find "$dir" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
        # Age: seconds since last commit
        last_ts=$(cd "$dir" && git log -1 --format='%ct' 2>/dev/null || echo 0)
        age_days=$(( (NOW_EPOCH - last_ts) / 86400 ))
        if [[ "$age_days" -gt 30 ]]; then
            age_str="${YELLOW}${age_days}d old${RESET}"
            ALL_CURRENT=false
        else
            age_str="${GREEN}${age_days}d old${RESET}"
        fi
        printf "  ${GREEN}%-4s${RESET} %-28s %-8s %-12s " "[$id]" "$desc" "$sz" "$ct templates"
        echo -e "$age_str"
    done

    # Last setup run
    echo ""
    if [[ -f "${META_DIR}/last_update.txt" ]]; then
        LAST=$(cat "${META_DIR}/last_update.txt")
        info "Last setup run : $LAST"
    else
        warn "Chưa chạy setup lần nào"
    fi

    # Sources log (last 5 entries)
    if [[ -f "${META_DIR}/sources.txt" && -s "${META_DIR}/sources.txt" ]]; then
        echo ""
        info "Lịch sử clone/pull gần nhất:"
        tail -5 "${META_DIR}/sources.txt" | while IFS= read -r line; do
            echo -e "  ${DIM}$line${RESET}"
        done
    fi

    # Summary verdict
    echo ""
    if $ALL_CURRENT; then
        success "Tất cả sources đã cài đều up-to-date (< 30 ngày)"
    else
        warn "Một số sources > 30 ngày — chạy: ./setup_templates.sh --check"
    fi
    exit 0
fi

# =============================================================================
# MODE: VALIDATE — nuclei -validate trên từng source
# =============================================================================
if [[ "$MODE" == "validate" ]]; then
    echo ""
    if ! cmd_exists nuclei; then
        error "nuclei không tìm thấy — cần cài nuclei trước khi validate"
        exit 1
    fi
    step "Validating templates (nuclei -validate)"
    FAIL=0
    PASS=0
    for id in "${ALL_SOURCES[@]}"; do
        dir="${SRC_DIR[$id]}"
        desc="${SRC_DESC[$id]}"
        [[ -d "$dir" ]] || { info "[$id] NOT INSTALLED — skip"; continue; }
        ct=$(find "$dir" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
        info "[$id] Validating $desc ($ct templates)..."
        # nuclei -validate in từng template lỗi vào stderr
        ERR_OUT=$(nuclei -validate -t "$dir" 2>&1 | grep -i "error\|invalid\|failed" | head -10 || true)
        if [[ -z "$ERR_OUT" ]]; then
            success "[$id] OK — $ct templates valid"
            (( PASS++ )) || true
        else
            warn "[$id] Có lỗi validation:"
            echo "$ERR_OUT" | while IFS= read -r line; do
                echo -e "    ${YELLOW}$line${RESET}"
            done
            (( FAIL++ )) || true
        fi
    done
    echo ""
    [[ "$FAIL" -eq 0 ]] && success "Validate xong: $PASS sources OK" || \
        warn "Validate xong: $PASS OK, $FAIL có lỗi"
    exit 0
fi

# =============================================================================
# MODE: HELP
# =============================================================================
if [[ "$MODE" == "help" ]]; then
    echo ""
    echo -e "${BOLD}${CYAN}setup_templates.sh${RESET} — Tải & quản lý nuclei templates"
    echo ""
    echo -e "${BOLD}INSTALL / UPDATE${RESET}"
    echo -e "  ${GREEN}./setup_templates.sh --tier 1${RESET}        Tier 1: official + wordfence + geeknik (~96k templates)"
    echo -e "  ${GREEN}./setup_templates.sh --tier 2${RESET}        Tier 1 + fingerprinthub + kayala + daffainfo"
    echo -e "  ${GREEN}./setup_templates.sh --tier 3${RESET}        Tất cả, bao gồm fuzzing + AI-generated"
    echo -e "  ${GREEN}./setup_templates.sh --source B${RESET}      Chỉ install/update một source cụ thể"
    echo -e "  ${GREEN}./setup_templates.sh --update${RESET}        Update tất cả sources đã cài (Tier 1)"
    echo ""
    echo -e "${BOLD}QUẢN LÝ${RESET}"
    echo -e "  ${GREEN}./setup_templates.sh --init${RESET}          Tạo /opt/nuclei-pipeline + chown (lần đầu)"
    echo -e "  ${GREEN}./setup_templates.sh --remove B${RESET}      Xóa một source đã cài"
    echo ""
    echo -e "${BOLD}KIỂM TRA${RESET}"
    echo -e "  ${GREEN}./setup_templates.sh --list${RESET}          Thống kê số template từng source"
    echo -e "  ${GREEN}./setup_templates.sh --status${RESET}        Health check: disk, tuổi, outdated"
    echo -e "  ${GREEN}./setup_templates.sh --check${RESET}         Kiểm tra updates có sẵn (không pull)"
    echo -e "  ${GREEN}./setup_templates.sh --validate${RESET}      Lint tất cả templates (nuclei -validate)"
    echo ""
    echo -e "${BOLD}SOURCE IDs${RESET}"
    printf "  ${DIM}%-4s T%s  %-38s %s${RESET}\n" \
        "[A]" "1" "projectdiscovery/nuclei-templates"  "~13,700 official" \
        "[B]" "1" "topscoder/nuclei-wordfence-cve"     "~82,700 WordPress CVE" \
        "[C]" "1" "geeknik/the-nuclei-templates"       "~224 1-day CVE" \
        "[F]" "2" "0x727/FingerprintHub"               "~1,400 fingerprint" \
        "[G]" "2" "0xKayala/Custom-Nuclei-Templates"   "general community" \
        "[H]" "2" "daffainfo/my-nuclei-templates"      "personal unique" \
        "[I]" "3" "projectdiscovery/fuzzing-templates" "fuzzing opt-in" \
        "[J]" "3" "projectdiscovery/nuclei-templates-ai" "AI-gen unverified"
    echo ""
    echo -e "${BOLD}STORAGE${RESET}"
    echo -e "  Templates dir : ${CYAN}${TEMPLATES_BASE}${RESET}"
    if [[ -f "${META_DIR}/last_update.txt" ]]; then
        echo -e "  Last update   : $(cat "${META_DIR}/last_update.txt")"
        INSTALLED=$(find "$TEMPLATES_BASE" -name "*.yaml" ! -path "*/.git/*" 2>/dev/null | wc -l | tr -d ' ')
        echo -e "  Installed     : ${GREEN}${INSTALLED} templates${RESET}"
    else
        echo -e "  Status        : ${YELLOW}Chưa cài — chạy: ./setup_templates.sh --tier 1${RESET}"
    fi
    echo ""
    exit 0
fi

banner "Template Setup" "${TEMPLATES_BASE} — Tier ${INSTALL_TIER}"

# =============================================================================
# MODE: LIST
# =============================================================================
if [[ "$MODE" == "list" ]]; then
    step "Template inventory"

    echo ""
    printf "  ${BOLD}%-4s %-5s %-38s %s${RESET}\n" "ID" "Tier" "Description" "Status"
    printf "  %s\n" "$(printf '%.0s─' {1..75})"

    for id in "${ALL_SOURCES[@]}"; do
        dir="${SRC_DIR[$id]}"
        desc="${SRC_DESC[$id]}"
        tier="${SRC_TIER[$id]}"
        note="${SRC_NOTE[$id]}"

        if [[ -d "${dir}/.git" ]]; then
            count=$(find "$dir" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
            commit=$(cd "$dir" && git rev-parse --short HEAD 2>/dev/null || echo "?")
            last=$(cd "$dir" && git log -1 --format='%cr' 2>/dev/null || echo "?")
            printf "  ${GREEN}[%s]${RESET} T%s  %-38s ${GREEN}%s templates${RESET} | %s | %s\n" \
                "$id" "$tier" "$desc" "$count" "$commit" "$last"
        else
            printf "  ${DIM}[%s]${RESET} T%s  %-38s ${DIM}NOT INSTALLED${RESET}\n" "$id" "$tier" "$desc"
            printf "       ${DIM}%s${RESET}\n" "$note"
        fi
    done

    echo ""
    step "Custom templates (pipeline/templates/custom/)"
    PIPELINE_CUSTOM="${SCRIPT_DIR}/templates/custom"
    for d in "${PIPELINE_CUSTOM}"/*/; do
        [[ -d "$d" ]] || continue
        n=$(find "$d" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
        printf "  ${MAGENTA}★${RESET}  %-30s %s templates\n" "$(basename "$d")" "$n"
    done

    echo ""
    step "Category breakdown (official)"
    official="${SRC_DIR[A]}"
    if [[ -d "$official" ]]; then
        for cat in cves exposures misconfiguration vulnerabilities network default-logins technologies takeovers; do
            n=$(find "${official}/${cat}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
            [[ "$n" -gt 0 ]] && printf "  %-26s %s templates\n" "$cat" "$n"
        done
    fi

    echo ""
    if [[ -f "${META_DIR}/last_update.txt" ]]; then
        info "Last update: $(cat "${META_DIR}/last_update.txt")"
    fi
    exit 0
fi

# =============================================================================
# HELPER: kiểm tra disk space trước khi clone
# =============================================================================
check_disk_space() {
    local target_dir="$1"
    local required_mb="${2:-500}"   # MB tối thiểu cần có
    local parent
    parent="$(dirname "$target_dir")"
    [[ -d "$parent" ]] || parent="$TEMPLATES_BASE"
    local avail_kb
    avail_kb=$(df -k "$parent" 2>/dev/null | awk 'NR==2{print $4}')
    local avail_mb=$(( avail_kb / 1024 ))
    if [[ "$avail_mb" -lt "$required_mb" ]]; then
        warn "Disk space thấp: ${avail_mb}MB còn lại, cần ~${required_mb}MB"
        warn "Partition: $(df -h "$parent" 2>/dev/null | awk 'NR==2{print $1" ("$4" free)"}')"
        return 1
    fi
    return 0
}

# =============================================================================
# HELPER: hiển thị progress trong khi git chạy nền
# =============================================================================
run_with_spinner() {
    local msg="$1"; shift
    local spin_chars=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    # Chạy lệnh ở background, capture output vào temp file
    local tmp_out; tmp_out=$(mktemp)
    "$@" > "$tmp_out" 2>&1 &
    local pid=$!
    # Spinner loop
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}%s${RESET} %s " "${spin_chars[$i]}" "$msg"
        i=$(( (i + 1) % ${#spin_chars[@]} ))
        sleep 0.15
    done
    wait "$pid"
    local rc=$?
    printf "\r%-70s\r" " "   # xóa dòng spinner
    # In output của lệnh nếu có lỗi
    if [[ $rc -ne 0 ]] && [[ -s "$tmp_out" ]]; then
        cat "$tmp_out" >&2
    fi
    rm -f "$tmp_out"
    return $rc
}

# =============================================================================
# HELPER: clone or pull a single source
# =============================================================================
sync_source() {
    local id="$1"
    local url="${SRC_URL[$id]}"
    local dir="${SRC_DIR[$id]}"
    local desc="${SRC_DESC[$id]}"
    local note="${SRC_NOTE[$id]}"

    step "[$id] $desc"
    info "Note : $note"
    info "URL  : $url"
    info "Dir  : $dir"

    if [[ -d "${dir}/.git" ]]; then
        info "Already cloned — pulling updates"
        run_with_spinner "git pull $desc..." \
            git -C "$dir" pull --ff-only --quiet && \
            success "[$id] Updated" || warn "[$id] Pull failed (may have local changes)"
    else
        # Xóa partial clone (thư mục có nhưng không có .git)
        if [[ -d "$dir" && ! -d "${dir}/.git" ]]; then
            warn "Incomplete clone found at $dir — removing"
            rm -rf "$dir"
        fi
        # Disk space check — Wordfence ~300MB, official ~150MB
        local req_mb=200
        [[ "$id" == "B" ]] && req_mb=350   # Wordfence ~300MB
        check_disk_space "$dir" "$req_mb" || {
            warn "[$id] Bỏ qua do disk không đủ"
            return 1
        }
        info "Cloning (depth=1)..."
        mkdir -p "$(dirname "$dir")"
        run_with_spinner "git clone $desc..." \
            git clone --depth=1 "$url" "$dir" && \
            success "[$id] Cloned" || {
                warn "[$id] Clone failed — skipping"
                return 1
            }
    fi

    # Record metadata
    local commit count
    commit=$(cd "$dir" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    count=$(find "$dir" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
    echo "[$id] $(date '+%Y-%m-%d %H:%M:%S')  commit=${commit}  templates=${count}  ${url}" \
        >> "${META_DIR}/sources.txt"
    success "[$id] $count templates  (commit: $commit)"
}

# =============================================================================
# MODE: CHECK (fetch only, no merge)
# =============================================================================
if [[ "$MODE" == "check" ]]; then
    step "Checking for updates (no pull)"
    for id in "${ACTIVE_SOURCES[@]}"; do
        dir="${SRC_DIR[$id]}"
        desc="${SRC_DESC[$id]}"
        if [[ ! -d "${dir}/.git" ]]; then
            warn "[$id] NOT INSTALLED — $desc"
            continue
        fi
        (cd "$dir" && git fetch --quiet 2>/dev/null) || true
        local_h=$(cd "$dir" && git rev-parse HEAD 2>/dev/null || echo "?")
        remote_h=$(cd "$dir" && git rev-parse '@{u}' 2>/dev/null || echo "?")
        if [[ "$local_h" == "$remote_h" ]]; then
            success "[$id] Up to date — $desc"
        else
            warn "[$id] Updates available — $desc"
            echo "     local : $local_h"
            echo "     remote: $remote_h"
        fi
    done
    exit 0
fi

# =============================================================================
# MODE: INSTALL / UPDATE
# =============================================================================
> "${META_DIR}/sources.txt"

echo ""
info "Installing Tier ${INSTALL_TIER} sources: ${ACTIVE_SOURCES[*]}"
echo ""

if [[ -n "$TARGET_SOURCE" ]]; then
    [[ -v "SRC_URL[$TARGET_SOURCE]" ]] || {
        error "Unknown source ID: $TARGET_SOURCE"
        error "Valid IDs: A B C F G H I J"
        exit 1
    }
    sync_source "$TARGET_SOURCE"
else
    for id in "${ACTIVE_SOURCES[@]}"; do
        sync_source "$id" || true  # continue on failure
        echo ""
    done
fi

# =============================================================================
# POST-INSTALL: build index + stats
# =============================================================================
step "Building template index"

date '+%Y-%m-%d %H:%M:%S' > "${META_DIR}/last_update.txt"

# Flat index của tất cả templates (trừ fuzzing + ai-generated nếu không opt-in)
find "$TEMPLATES_BASE" -name "*.yaml" \
    ! -path "*/fuzzing/*" \
    ! -path "*/ai-generated/*" \
    ! -path "*/.git/*" \
    | sort > "${META_DIR}/all_templates.txt"

# Separate index cho fuzzing (opt-in)
find "${TEMPLATES_BASE}/fuzzing" -name "*.yaml" \
    ! -path "*/.git/*" 2>/dev/null \
    | sort > "${META_DIR}/fuzzing_templates.txt" || true

# Stats
T_OFFICIAL=$(find "${SRC_DIR[A]}"  -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
T_WORDFENCE=$(find "${SRC_DIR[B]}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
T_COMMUNITY=$(find "${TEMPLATES_BASE}/community" -name "*.yaml" \
    ! -path "*/wordfence-cve/*" 2>/dev/null | wc -l | tr -d ' ')
T_CUSTOM=$(find "${SCRIPT_DIR}/templates/custom" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
T_FUZZING=$(wc -l < "${META_DIR}/fuzzing_templates.txt" 2>/dev/null | tr -d ' ' || echo 0)
T_INDEX=$(wc -l < "${META_DIR}/all_templates.txt" | tr -d ' ')

summary_box "TEMPLATE SETUP COMPLETE" \
    "Official [A]"    "$T_OFFICIAL templates" \
    "Wordfence [B]"   "$T_WORDFENCE templates (WordPress CVE)" \
    "Community [C+]"  "$T_COMMUNITY templates" \
    "Custom"          "$T_CUSTOM templates" \
    "Index total"     "$T_INDEX (excl. fuzzing/AI)" \
    "Fuzzing [I]"     "$T_FUZZING (opt-in only)" \
    "Last update"     "$(cat "${META_DIR}/last_update.txt")"

echo ""
echo -e "  ${BOLD}Template dir :${RESET} ${TEMPLATES_BASE}"
echo -e "  ${BOLD}Index file   :${RESET} ${META_DIR}/all_templates.txt"
echo ""
info "Update tips:"
echo -e "  ${DIM}./setup_templates.sh                # update Tier 1 (default)${RESET}"
echo -e "  ${DIM}./setup_templates.sh --tier 2       # Tier 1 + Tier 2 (recommended)${RESET}"
echo -e "  ${DIM}./setup_templates.sh --source B     # update only Wordfence CVE${RESET}"
echo -e "  ${DIM}./setup_templates.sh --list         # show all counts${RESET}"
echo -e "  ${DIM}./setup_templates.sh --check        # check for updates${RESET}"
