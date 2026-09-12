#!/usr/bin/env bash
# =============================================================================
# recon.sh — Master Recon Pipeline
#
# Usage: ./recon.sh <domain> [--from <step>] [--only <step>]
#
# Steps:
#   01  subdomain enumeration   (passive + active)
#   02  DNS resolution          (puredns wildcard filter + dnsx)
#   03  CDN/WAF classification  (cdncheck)
#   04  vhost discovery         (curl/ffuf/SNItch/ripgen)
#   05  port scan               (naabu)
#   06  service detection       (nmap -sV -sC)
#   07  HTTP probing            (httpx)
#   08  triage & JS analysis    (tiering + endpoints + secrets)
#
# Examples:
#   ./recon.sh mbbank.com.vn               # full run
#   ./recon.sh mbbank.com.vn --from 05     # resume from step 5
#   ./recon.sh mbbank.com.vn --only 07     # run only step 7
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

PIPELINE_STEPS=(
    "01:01_subdomain.sh:Subdomain Enumeration"
    "02:02_resolve.sh:DNS Resolution"
    "03:03_cdncheck.sh:CDN/WAF Classification"
    "04:04_vhost.sh:Virtual Host Discovery"
    "05:05_portscan.sh:Port Scanning"
    "06:06_service.sh:Service Detection"
    "07:07_httpx.sh:HTTP Probing"
    "08:08_triage.sh:Triage & JS Analysis"
    "09:09_nuclei.sh:Nuclei Vulnerability Scan"
)

show_help() {
    echo -e "${BOLD}${CYAN}"
    cat << 'SPLASH'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
SPLASH
    echo -e "${RESET}"
    echo -e "${BOLD}Recon Pipeline Master Controller${RESET}"
    echo ""
    echo -e "${BOLD}CÚ PHÁP SỬ DỤNG:${RESET}"
    echo -e "  $0 <domain> [tùy chọn]"
    echo ""
    echo -e "${BOLD}TÙY CHỌN:${RESET}"
    echo -e "  ${YELLOW}--only <bước>${RESET}     Chỉ chạy duy nhất 1 bước (ví dụ: --only 05 hoặc --only 5)"
    echo -e "  ${YELLOW}--from <bước>${RESET}     Bắt đầu chạy từ bước chỉ định đến hết (ví dụ: --from 03)"
    echo -e "  ${YELLOW}-h, --help${RESET}        Hiển thị hướng dẫn tổng quan (hoặc kết hợp với --only để xem helper từng bước)"
    echo ""
    echo -e "${BOLD}DANH SÁCH CÁC BƯỚC TRONG PIPELINE:${RESET}"
    echo -e "  ${GREEN}01${RESET} | ${CYAN}01_subdomain.sh${RESET}  : Thu thập subdomain (Passive: subfinder/crt.sh + Active: puredns/alterx/tls)"
    echo -e "  ${GREEN}02${RESET} | ${CYAN}02_resolve.sh${RESET}    : Phân giải DNS & lọc Wildcard DNS nghiêm ngặt (puredns-resolve + dnsx)"
    echo -e "  ${GREEN}03${RESET} | ${CYAN}03_cdncheck.sh${RESET}   : Phân loại IP CDN/WAF vs Origin IPs (cdncheck + CIDR filtering)"
    echo -e "  ${GREEN}04${RESET} | ${CYAN}04_vhost.sh${RESET}      : Dò tìm Virtual Hosts trên Origin IPs (TLS SAN + SNItch + ripgen)"
    echo -e "  ${GREEN}05${RESET} | ${CYAN}05_portscan.sh${RESET}   : Quét cổng & nhận diện dịch vụ trên Origin IPs (gogo/naabu/nmap)"
    echo -e "  ${GREEN}06${RESET} | ${CYAN}06_service.sh${RESET}    : Quét sâu phiên bản dịch vụ & lọc CDN banner (nmap -sV -sC)"
    echo -e "  ${GREEN}07${RESET} | ${CYAN}07_httpx.sh${RESET}      : Dò quét HTTP/HTTPS, lấy title, server banner, tech stack (httpx)"
    echo -e "  ${GREEN}08${RESET} | ${CYAN}08_triage.sh${RESET}     : Phân tầng mục tiêu (Tier 1/2/3), trích xuất JS Endpoints & Secrets"
    echo -e "  ${GREEN}09${RESET} | ${CYAN}09_nuclei.sh${RESET}     : Quét lỗ hổng tự động theo Tech stack, CVE, Misconfig, Exposure (nuclei)"
    echo ""
    echo -e "${BOLD}HƯỚNG DẪN CÁCH CHẠY:${RESET}"
    echo -e "  ${BOLD}1. Chạy toàn bộ pipeline tự động:${RESET}"
    echo -e "     $0 mbbank.com.vn"
    echo ""
    echo -e "  ${BOLD}2. Chạy duy nhất 1 bước qua Master script (Khuyên dùng):${RESET}"
    echo -e "     $0 mbbank.com.vn --only 05       # Chỉ quét port"
    echo -e "     $0 mbbank.com.vn --only 07       # Chỉ probe HTTP"
    echo -e "     $0 mbbank.com.vn --only 09       # Chỉ quét nuclei"
    echo ""
    echo -e "  ${BOLD}3. Xem helper của từng bước cụ thể:${RESET}"
    echo -e "     $0 --only 05 --help              # Xem chi tiết options của bước 05"
    echo -e "     $0 --only 09 --help              # Xem chi tiết options của bước 09 (nuclei)"
    echo ""
    echo -e "  ${BOLD}4. Chạy tiếp tục từ 1 bước cụ thể:${RESET}"
    echo -e "     $0 mbbank.com.vn --from 03       # Bỏ qua bước 01, 02 và chạy từ 03 đến hết"
    echo ""
}

# ─── Args ─────────────────────────────────────────────────────────────────────
DOMAIN=""
FROM_STEP=1
ONLY_STEP=""
HELP_REQUESTED=0

[[ $# -eq 0 ]] && { show_help; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help|help)
            HELP_REQUESTED=1
            shift
            ;;
        --from)
            FROM_STEP="$(echo "${2:-1}" | tr -dc '0-9')"
            shift 2
            ;;
        --only)
            ONLY_STEP="$(echo "${2:-}" | tr -dc '0-9')"
            shift 2
            ;;
        -*)
            echo -e "${RED}[-]${RESET} Unknown option: $1" >&2
            echo -e "Sử dụng ${YELLOW}$0 --help${RESET} để xem hướng dẫn chi tiết." >&2
            exit 1
            ;;
        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$(normalize_domain "$1")"
            else
                echo -e "${RED}[-]${RESET} Unexpected argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ "$HELP_REQUESTED" -eq 1 ]]; then
    if [[ -n "$ONLY_STEP" ]]; then
        PADDED_STEP=$(printf '%02d' "$(( 10#${ONLY_STEP} ))")
        MATCHED_SCRIPT=""
        for entry in "${PIPELINE_STEPS[@]}"; do
            IFS=':' read -r step_num script_file step_name <<< "$entry"
            if [[ "$step_num" == "$PADDED_STEP" ]]; then
                MATCHED_SCRIPT="${SCRIPT_DIR}/scripts/${script_file}"
                break
            fi
        done
        if [[ -n "$MATCHED_SCRIPT" && -f "$MATCHED_SCRIPT" ]]; then
            bash "$MATCHED_SCRIPT" --help
            exit 0
        else
            echo -e "${RED}[-]${RESET} Không tìm thấy script cho bước: ${ONLY_STEP}" >&2
            exit 1
        fi
    else
        show_help
        exit 0
    fi
fi

if [[ -z "$DOMAIN" ]]; then
    show_help
    exit 1
fi

# ─── Setup ────────────────────────────────────────────────────────────────────
OUT_DIR="$(output_dir "$DOMAIN")"
MASTER_LOG="${OUT_DIR}/logs/recon.log"
mkdir -p "${OUT_DIR}/logs"

exec > >(tee -a "$MASTER_LOG") 2>&1

# ─── Splash ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
cat << 'SPLASH'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
SPLASH
echo -e "${RESET}"

echo -e "  ${BOLD}Target  :${RESET} ${DOMAIN}"
echo -e "  ${BOLD}Output  :${RESET} ${OUT_DIR}"
echo -e "  ${BOLD}Log     :${RESET} ${MASTER_LOG}"
echo -e "  ${BOLD}Started :${RESET} $(date '+%Y-%m-%d %H:%M:%S')"

if [[ -n "$ONLY_STEP" ]]; then
    echo -e "  ${BOLD}Mode    :${RESET} ONLY step ${ONLY_STEP}"
elif [[ "$FROM_STEP" -gt 1 ]]; then
    echo -e "  ${BOLD}Mode    :${RESET} RESUME from step ${FROM_STEP}"
else
    echo -e "  ${BOLD}Mode    :${RESET} FULL pipeline"
fi
echo ""

MASTER_START=$(date +%s)
PASSED=()
FAILED=()
SKIPPED=()

# ─── Resume state ─────────────────────────────────────────────────────────────
RESUME_FILE="${OUT_DIR}/resume.cfg"

save_resume() {
    local step="$1"
    echo "last_completed_step=${step}" > "$RESUME_FILE"
    echo "domain=${DOMAIN}" >> "$RESUME_FILE"
    echo "timestamp=$(date '+%Y-%m-%d %H:%M:%S')" >> "$RESUME_FILE"
}

# Auto-detect resume nếu không có --from và có resume.cfg
if [[ -z "$ONLY_STEP" && "$FROM_STEP" -eq 1 && -f "$RESUME_FILE" ]]; then
    LAST_STEP=$(grep '^last_completed_step=' "$RESUME_FILE" 2>/dev/null | cut -d'=' -f2 | tr -dc '0-9')
    if [[ -n "$LAST_STEP" && "$LAST_STEP" -gt 0 ]]; then
        NEXT_STEP=$(( LAST_STEP + 1 ))
        warn "resume.cfg found: last completed step = ${LAST_STEP}"
        warn "Auto-resuming from step ${NEXT_STEP} (use --from 01 to restart from beginning)"
        FROM_STEP=$NEXT_STEP
    fi
fi

# ─── Run steps ────────────────────────────────────────────────────────────────
for entry in "${PIPELINE_STEPS[@]}"; do
    IFS=':' read -r step_num script_file step_name <<< "$entry"

    # Determine whether to run
    if [[ -n "$ONLY_STEP" ]]; then
        [[ "$step_num" != "$ONLY_STEP" ]] && { SKIPPED+=("$step_num"); continue; }
    else
        [[ "$step_num" -lt "$FROM_STEP" ]] && { SKIPPED+=("$step_num"); continue; }
    fi

    SCRIPT_PATH="${SCRIPT_DIR}/scripts/${script_file}"
    if [[ ! -f "$SCRIPT_PATH" ]]; then
        warn "Script not found: $SCRIPT_PATH — skipping"
        SKIPPED+=("$step_num")
        continue
    fi

    TOTAL_COUNT=$(printf '%02d' "${#PIPELINE_STEPS[@]}")
    echo ""
    echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BOLD}${CYAN}│  STEP ${step_num}/${TOTAL_COUNT} — ${step_name}${RESET}"
    echo -e "${BOLD}${CYAN}│  $(date '+%H:%M:%S')${RESET}"
    echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────────┘${RESET}"

    STEP_START=$(date +%s)

    if (cd "${SCRIPT_DIR}/scripts" && bash "$SCRIPT_PATH" "$DOMAIN"); then
        STEP_END=$(date +%s)
        STEP_ELAPSED=$(( STEP_END - STEP_START ))
        STEP_FMT=$(printf '%02d:%02d' $((STEP_ELAPSED/60)) $((STEP_ELAPSED%60)))
        success "Step ${step_num} done in ${STEP_FMT}"
        PASSED+=("${step_num}:${STEP_FMT}")
        save_resume "$step_num"
    else
        EXIT_CODE=$?
        STEP_END=$(date +%s)
        STEP_ELAPSED=$(( STEP_END - STEP_START ))
        STEP_FMT=$(printf '%02d:%02d' $((STEP_ELAPSED/60)) $((STEP_ELAPSED%60)))
        warn "Step ${step_num} exited with code ${EXIT_CODE} (${STEP_FMT})"
        FAILED+=("${step_num}:exit${EXIT_CODE}")

        # Ask continue or abort (non-interactive fallback: continue)
        if [[ -t 0 ]]; then
            read -t 30 -rp "  Continue to next step? [Y/n] " CONT || CONT="y"
            [[ "${CONT,,}" == "n" ]] && { error "Aborted by user"; break; }
        else
            warn "Non-interactive mode — continuing despite error"
        fi
    fi
done

# ─── Final summary ────────────────────────────────────────────────────────────
MASTER_END=$(date +%s)
MASTER_ELAPSED=$(( MASTER_END - MASTER_START ))
MASTER_FMT=$(printf '%02d:%02d:%02d' $((MASTER_ELAPSED/3600)) $(((MASTER_ELAPSED%3600)/60)) $((MASTER_ELAPSED%60)))

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${GREEN}║  RECON COMPLETE — ${DOMAIN}${RESET}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Total time :${RESET} ${MASTER_FMT}"
echo -e "  ${BOLD}Finished   :${RESET} $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

if [[ "${#PASSED[@]}" -gt 0 ]]; then
    echo -e "  ${GREEN}Passed${RESET}:"
    for s in "${PASSED[@]}"; do
        IFS=':' read -r n t <<< "$s"
        echo -e "    ${GREEN}✓${RESET} Step ${n}  (${t})"
    done
fi

if [[ "${#FAILED[@]}" -gt 0 ]]; then
    echo ""
    echo -e "  ${RED}Failed${RESET}:"
    for s in "${FAILED[@]}"; do
        IFS=':' read -r n e <<< "$s"
        echo -e "    ${RED}✗${RESET} Step ${n}  [${e}]"
    done
    echo -e "  ${DIM}Run individual steps for details, or check the log${RESET}"
fi

if [[ "${#SKIPPED[@]}" -gt 0 ]]; then
    echo ""
    echo -e "  ${DIM}Skipped: ${SKIPPED[*]}${RESET}"
fi

echo ""
echo -e "  ${BOLD}Output   :${RESET} ${OUT_DIR}"
echo -e "  ${BOLD}Log      :${RESET} ${MASTER_LOG}"

# Print final stats if report exists
REPORT="${OUT_DIR}/triage/report.md"
if [[ -f "$REPORT" ]]; then
    echo ""
    echo -e "  ${BOLD}Report   :${RESET} ${REPORT}"

    # Extract key numbers from report
    echo ""
    echo -e "  ${BOLD}${CYAN}Key findings:${RESET}"
    grep -E '^\| (Subdomains|Live HTTP|Tier 1|Tier 2|Potential secrets)' "$REPORT" 2>/dev/null \
        | awk -F'|' '{printf "    %-30s %s\n", $2, $3}' || true
fi

echo ""
