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

# ─── Args ─────────────────────────────────────────────────────────────────────
DOMAIN=""
FROM_STEP=1
ONLY_STEP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from) FROM_STEP="$(echo "${2:-1}" | tr -dc '0-9')"; shift 2 ;;
        --only) ONLY_STEP="$(echo "${2:-}"  | tr -dc '0-9')"; shift 2 ;;
        -*)     echo -e "${RED}[-]${RESET} Unknown option: $1" >&2; exit 1 ;;
        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$(normalize_domain "$1")"
            else
                echo -e "${RED}[-]${RESET} Unexpected argument: $1" >&2; exit 1
            fi
            shift ;;
    esac
done

if [[ -z "$DOMAIN" ]]; then
    echo -e "${BOLD}Usage:${RESET} $0 <domain> [--from <step>] [--only <step>]"
    echo ""
    echo "  --from N    Start from step N (skip 01..N-1)"
    echo "  --only N    Run only step N"
    echo ""
    echo "Steps: 01=subdomain 02=resolve 03=cdn 04=vhost 05=portscan 06=service 07=httpx 08=triage"
    echo ""
    echo "Examples:"
    echo "  $0 mbbank.com.vn"
    echo "  $0 mbbank.com.vn --from 05"
    echo "  $0 mbbank.com.vn --only 07"
    echo "  $0 --from 02 mbbank.com.vn    # flags can come before or after domain"
    exit 1
fi

# ─── Setup ────────────────────────────────────────────────────────────────────
OUT_DIR="$(output_dir "$DOMAIN")"
MASTER_LOG="${OUT_DIR}/logs/recon.log"
mkdir -p "${OUT_DIR}/logs"

exec > >(tee -a "$MASTER_LOG") 2>&1

PIPELINE_STEPS=(
    "01:01_subdomain.sh:Subdomain Enumeration"
    "02:02_resolve.sh:DNS Resolution"
    "03:03_cdncheck.sh:CDN/WAF Classification"
    "04:04_vhost.sh:Virtual Host Discovery"
    "05:05_portscan.sh:Port Scanning"
    "06:06_service.sh:Service Detection"
    "07:07_httpx.sh:HTTP Probing"
    "08:08_triage.sh:Triage & JS Analysis"
)

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

    SCRIPT_PATH="${SCRIPT_DIR}/${script_file}"
    if [[ ! -f "$SCRIPT_PATH" ]]; then
        warn "Script not found: $SCRIPT_PATH — skipping"
        SKIPPED+=("$step_num")
        continue
    fi

    echo ""
    echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BOLD}${CYAN}│  STEP ${step_num}/08 — ${step_name}${RESET}"
    echo -e "${BOLD}${CYAN}│  $(date '+%H:%M:%S')${RESET}"
    echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────────┘${RESET}"

    STEP_START=$(date +%s)

    if (cd "$SCRIPT_DIR" && bash "$SCRIPT_PATH" "$DOMAIN"); then
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
