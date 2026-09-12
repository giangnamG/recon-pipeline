#!/usr/bin/env bash
# =============================================================================
# 09_nuclei.sh — Nuclei Vulnerability Scanning
#
# Chiến lược 3 pha theo input source:
#
#   PHASE 1: Tech-aware scan (httpx JSON → detect stack → chọn template)
#     → Đọc http/all.json, group target theo tech (tomcat, nginx, f5, iis...)
#     → Chạy nuclei với template set phù hợp từng tech
#
#   PHASE 2: Broad CVE + exposure sweep
#     → Tất cả live HTTP targets với CVE + exposures + misconfig templates
#     → Rate-limited để tránh IDS trigger
#
#   PHASE 3: Network-level scan (origin IPs)
#     → nuclei network templates: redis, mongodb, elastic, smb...
#     → Dùng ip:port từ ports/open.txt
#
# Template strategy:
#   - Chỉ dùng severity: critical,high,medium (bỏ low/info để giảm noise)
#   - Exclude dos, fuzz (không muốn gây impact thật)
#   - Tech-specific templates chạy TRƯỚC broad sweep
#   - Mỗi pha output riêng để dễ triage
#
# INPUT:
#   output/<domain>/http/all.json         — httpx JSON (tech fingerprint)
#   output/<domain>/http/live.txt         — live HTTP targets
#   output/<domain>/triage/tier1.txt      — high-value targets
#   output/<domain>/ports/open.txt        — ip:port cho network scan
#   output/<domain>/origin_ips.txt        — origin IPs
#
# OUTPUT:
#   output/<domain>/nuclei/
#     phase1_tech/
#       tomcat.txt  nginx.txt  f5.txt  iis.txt  php.txt  spring.txt  ...
#     phase2_cve.txt          — CVE findings trên tất cả live targets
#     phase2_exposure.txt     — Exposed files / configs
#     phase2_misconfig.txt    — Misconfigurations
#     phase3_network.txt      — Network service vulnerabilities
#     all_findings.txt        — Merged, sorted by severity
#     all_findings.json       — JSON format cho integration
#     report.md               — Triage-ready report
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

[[ $# -lt 1 ]] && { usage "$0 <domain> [--tech] [--cve] [--network] [--severity critical,high,medium] [--rate N] [--ai-templates]"; exit 1; }
DOMAIN="$(normalize_domain "$1")"

# ─── Options ─────────────────────────────────────────────────────────────────
RUN_TECH=0
RUN_CVE=0
RUN_NETWORK=0
EXPLICIT_PHASE=0

SEVERITY="critical,high,medium"
RATE_LIMIT=50        # requests/second — giảm xuống nếu bị rate limit / IDS alert
CONCURRENCY=10       # parallel targets
TIMEOUT=10           # seconds per request
BULK_SIZE=25         # targets per nuclei batch
USE_AI_TEMPLATES=0   # --ai-templates: opt-in cho AI-generated templates (unverified)

shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tech)          RUN_TECH=1; EXPLICIT_PHASE=1; shift ;;
        --cve)           RUN_CVE=1; EXPLICIT_PHASE=1; shift ;;
        --network)       RUN_NETWORK=1; EXPLICIT_PHASE=1; shift ;;
        --all)           RUN_TECH=1; RUN_CVE=1; RUN_NETWORK=1; EXPLICIT_PHASE=1; shift ;;
        --phase)
            case "${2:-}" in
                1|tech)    RUN_TECH=1; EXPLICIT_PHASE=1 ;;
                2|cve)     RUN_CVE=1; EXPLICIT_PHASE=1 ;;
                3|network) RUN_NETWORK=1; EXPLICIT_PHASE=1 ;;
                all)       RUN_TECH=1; RUN_CVE=1; RUN_NETWORK=1; EXPLICIT_PHASE=1 ;;
                *)         warn "Unknown phase: ${2:-}" ;;
            esac
            shift 2 ;;
        --severity)      SEVERITY="$2"; shift 2 ;;
        --rate)          RATE_LIMIT="$2"; shift 2 ;;
        --ai-templates)  USE_AI_TEMPLATES=1; shift ;;
        -*)              warn "Unknown option: $1"; shift ;;
        *)               shift ;;
    esac
done

# If no explicit phase flag was passed, run all 3 phases by default
if [[ "$EXPLICIT_PHASE" -eq 0 ]]; then
    RUN_TECH=1
    RUN_CVE=1
    RUN_NETWORK=1
fi

# ─── Paths ───────────────────────────────────────────────────────────────────
OUT_DIR="$(output_dir "$DOMAIN")"
NUCLEI_DIR="${OUT_DIR}/nuclei"
PHASE1_DIR="${NUCLEI_DIR}/phase1_tech"
mkdir -p "$NUCLEI_DIR" "$PHASE1_DIR"

IN_HTTPX_JSON="${OUT_DIR}/http/all.json"
IN_LIVE="${OUT_DIR}/http/live.txt"
IN_TIER1="${OUT_DIR}/triage/tier1.txt"
IN_OPEN_PORTS="${OUT_DIR}/ports/open.txt"
IN_ORIGIN_IPS="${OUT_DIR}/origin_ips.txt"

OUT_PHASE2_CVE="${NUCLEI_DIR}/phase2_cve.txt"
OUT_PHASE2_EXP="${NUCLEI_DIR}/phase2_exposure.txt"
OUT_PHASE2_MISC="${NUCLEI_DIR}/phase2_misconfig.txt"
OUT_PHASE3_NET="${NUCLEI_DIR}/phase3_network.txt"
OUT_ALL="${NUCLEI_DIR}/all_findings.txt"
OUT_ALL_JSON="${NUCLEI_DIR}/all_findings.json"
OUT_REPORT="${NUCLEI_DIR}/report.md"
LOG_FILE="${OUT_DIR}/logs/09_nuclei.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

# ─── Preflight ───────────────────────────────────────────────────────────────
banner "09 — Nuclei Vulnerability Scan" "$DOMAIN"

if ! cmd_exists nuclei; then
    error "nuclei not found"
    error "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

NUCLEI_VERSION=$(nuclei -version 2>&1 | grep -oP 'v\d+\.\d+\.\d+' | head -1 || echo "unknown")
info "nuclei version: $NUCLEI_VERSION"

# ─── Template resolution: pipeline/templates/ là nguồn chính ─────────────────
# Thứ tự ưu tiên:
#   1. pipeline/templates/nuclei-templates/  (local, được sync bởi setup_templates.sh)
#   2. ~/nuclei-templates/                   (nuclei default location, fallback)
#   3. nuclei -update-templates              (last resort)

# ─── Template base: ưu tiên /opt/nuclei-pipeline/ (Linux ext4, không NTFS) ────
# Thứ tự resolve:
#   1. $NUCLEI_TEMPLATES_DIR  (env override, khớp với setup_templates.sh)
#   2. /opt/nuclei-pipeline/  (mặc định)
#   3. ~/nuclei-pipeline/     (fallback nếu /opt chưa setup)
if [[ -n "${NUCLEI_TEMPLATES_DIR:-}" ]]; then
    PIPELINE_TEMPLATES="$NUCLEI_TEMPLATES_DIR"
elif [[ -d "/opt/nuclei-pipeline" ]]; then
    PIPELINE_TEMPLATES="/opt/nuclei-pipeline"
elif [[ -d "${HOME}/nuclei-pipeline" ]]; then
    PIPELINE_TEMPLATES="${HOME}/nuclei-pipeline"
else
    PIPELINE_TEMPLATES="${SCRIPT_DIR}/../templates"  # last resort (NTFS — có thể fail)
fi

OFFICIAL_LOCAL="${PIPELINE_TEMPLATES}/nuclei-templates"
COMMUNITY_LOCAL="${PIPELINE_TEMPLATES}/community"
CUSTOM_LOCAL="${SCRIPT_DIR}/../templates/custom"   # custom luôn nằm trong pipeline/templates/
FUZZING_LOCAL="${PIPELINE_TEMPLATES}/fuzzing"

# Sub-community directories (từ setup_templates.sh)
WORDFENCE_LOCAL="${PIPELINE_TEMPLATES}/community/wordfence-cve"    # [B] WordPress CVE ~82k
GEEKNIK_LOCAL="${PIPELINE_TEMPLATES}/community/geeknik"            # [C] 1-day CVE ~80+
FINGERPRINT_LOCAL="${PIPELINE_TEMPLATES}/community/fingerprinthub" # [F] tech fingerprint ~1.4k
KAYALA_LOCAL="${PIPELINE_TEMPLATES}/community/kayala"              # [G] general community
DAFFAINFO_LOCAL="${PIPELINE_TEMPLATES}/community/daffainfo"        # [H] personal unique
AI_LOCAL="${PIPELINE_TEMPLATES}/ai-generated"                      # [J] AI-gen, unverified

if [[ -d "$OFFICIAL_LOCAL" ]]; then
    TEMPLATES_DIR="$OFFICIAL_LOCAL"
    info "Templates: ${TEMPLATES_DIR} (✓ ${PIPELINE_TEMPLATES})"
    LAST_UPDATE=$(cat "${PIPELINE_TEMPLATES}/.meta/last_update.txt" 2>/dev/null || echo "unknown")
    info "Last update: $LAST_UPDATE"
else
    warn "Templates chưa được tải — chạy: ./setup_templates.sh"
    warn "  sudo mkdir -p /opt/nuclei-pipeline && sudo chown \$USER:\$USER /opt/nuclei-pipeline"
    warn "  ./setup_templates.sh --tier 1"
    warn "Falling back to default nuclei-templates location"
    TEMPLATES_DIR=""
    for candidate in \
        "${HOME}/nuclei-pipeline/nuclei-templates" \
        "/opt/nuclei-pipeline/nuclei-templates" \
        "${HOME}/nuclei-templates" \
        "/opt/nuclei-templates" \
        "/usr/share/nuclei-templates"; do
        [[ -d "$candidate" ]] && TEMPLATES_DIR="$candidate" && break
    done
    if [[ -z "$TEMPLATES_DIR" ]]; then
        warn "No templates found — running: nuclei -update-templates"
        nuclei -update-templates 2>/dev/null || true
        TEMPLATES_DIR="${HOME}/nuclei-templates"
    fi
    OFFICIAL_LOCAL="$TEMPLATES_DIR"
    COMMUNITY_LOCAL=""
    CUSTOM_LOCAL=""
fi

[[ -d "$TEMPLATES_DIR" ]] || { error "Cannot find nuclei-templates"; exit 1; }
info "Official templates : $TEMPLATES_DIR"
[[ -d "$COMMUNITY_LOCAL" ]] && info "Community templates: $COMMUNITY_LOCAL"
[[ -d "$CUSTOM_LOCAL" ]]    && info "Custom templates   : $CUSTOM_LOCAL"

# Count template categories
CVE_COUNT=$(find "${TEMPLATES_DIR}/cves"             -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
EXP_COUNT=$(find "${TEMPLATES_DIR}/exposures"        -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
MISC_COUNT=$(find "${TEMPLATES_DIR}/misconfiguration" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
NET_COUNT=$(find "${TEMPLATES_DIR}/network"           -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
COMM_COUNT=$([[ -d "$COMMUNITY_LOCAL" ]] && find "$COMMUNITY_LOCAL" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
CUST_COUNT=$([[ -d "$CUSTOM_LOCAL" ]]    && find "$CUSTOM_LOCAL"    -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ' || echo 0)

info "Template counts — CVE:${CVE_COUNT}  Exposure:${EXP_COUNT}  Misconfig:${MISC_COUNT}  Network:${NET_COUNT}  Community:${COMM_COUNT}  Custom:${CUST_COUNT}"

# ─── Helper: run nuclei ───────────────────────────────────────────────────────
# run_nuclei <input_file> <output_file> <json_output> <template_args...>
run_nuclei() {
    local input_file="$1"
    local out_txt="$2"
    local out_json="$3"
    shift 3
    # remaining args = template flags

    [[ -f "$input_file" && -s "$input_file" ]] || {
        warn "Input empty/missing: $input_file — skip"
        return 0
    }

    local count
    count=$(wc -l < "$input_file" | tr -d ' ')
    info "Targets: $count  |  Output: $(basename "$out_txt")"

    nuclei \
        -l "$input_file" \
        -severity "$SEVERITY" \
        -rate-limit "$RATE_LIMIT" \
        -c "$CONCURRENCY" \
        -timeout "$TIMEOUT" \
        -bulk-size "$BULK_SIZE" \
        -no-color \
        -silent \
        -exclude-tags dos,fuzz,headless \
        -o "$out_txt" \
        -json-export "$out_json" \
        -stats \
        "$@" \
        2>/dev/null || true

    local found=0
    [[ -f "$out_txt" ]] && found=$(wc -l < "$out_txt" | tr -d ' ')

    if [[ "$found" -gt 0 ]]; then
        found "$(basename "$out_txt"): ${found} findings"
        while IFS= read -r line; do
            echo -e "  ${RED}▶${RESET}  $line"
        done < "$out_txt"
    else
        success "$(basename "$out_txt"): 0 findings"
    fi
}

START_TIME=$(date +%s)

# =============================================================================
# BUILD PROBE TARGET LIST
# =============================================================================
step "Building probe target list"

LIVE_URLS="${TEMP_DIR}/live_urls.txt"
TIER1_URLS="${TEMP_DIR}/tier1_urls.txt"

# Extract clean URLs from httpx JSON (most reliable source)
if [[ -f "$IN_HTTPX_JSON" && -s "$IN_HTTPX_JSON" ]]; then
    python3 -c "
import sys, json
for line in open('$IN_HTTPX_JSON'):
    try:
        obj = json.loads(line.strip())
        url = obj.get('url', obj.get('input', ''))
        if url: print(url)
    except: pass
" | sort -u > "$LIVE_URLS" 2>/dev/null || true
elif [[ -f "$IN_LIVE" && -s "$IN_LIVE" ]]; then
    # Fallback: extract URLs from httpx plain output
    grep -oP 'https?://\S+' "$IN_LIVE" | sort -u > "$LIVE_URLS" || true
fi

# Tier 1 targets (admin/api/dev) — scan these with extra templates
if [[ -f "$IN_TIER1" && -s "$IN_TIER1" ]]; then
    grep -oP 'https?://\S+' "$IN_TIER1" | sort -u > "$TIER1_URLS" 2>/dev/null || true
fi

TOTAL_LIVE=$(wc -l < "$LIVE_URLS" 2>/dev/null | tr -d ' ' || echo 0)
TOTAL_TIER1=$(wc -l < "$TIER1_URLS" 2>/dev/null | tr -d ' ' || echo 0)
info "Live targets: $TOTAL_LIVE  |  Tier 1 targets: $TOTAL_TIER1"

[[ "$TOTAL_LIVE" -eq 0 ]] && {
    error "No live targets found — run 07_httpx.sh first"
    exit 1
}

# =============================================================================
# PHASE 1: TECH-AWARE SCAN
# =============================================================================
if [[ "$RUN_TECH" -eq 1 ]]; then
    step "PHASE 1 — Tech-aware Template Selection"
    info "Strategy: parse httpx tech fingerprint → map to specific template dirs"

    # ── Extract tech → URL mapping from httpx JSON ────────────────────────────
    python3 - "$IN_HTTPX_JSON" "$TEMP_DIR" <<'PYEOF'
import sys, json, os
from collections import defaultdict

json_file = sys.argv[1]
temp_dir  = sys.argv[2]

# Tech keyword → template tag / path mapping
TECH_MAP = {
    # Web servers
    "tomcat":     ["tech/tomcat.yaml", "cves/", "tags=tomcat"],
    "nginx":      ["tech/nginx.yaml",  "cves/", "tags=nginx"],
    "apache":     ["tech/apache.yaml", "cves/", "tags=apache"],
    "iis":        ["tech/iis.yaml",    "cves/", "tags=iis"],
    "jetty":      ["tags=jetty"],
    "jboss":      ["tags=jboss"],
    "weblogic":   ["cves/", "tags=weblogic"],
    "websphere":  ["tags=websphere"],
    # Frameworks
    "spring":     ["cves/", "tags=springboot,spring"],
    "struts":     ["cves/", "tags=struts"],
    "laravel":    ["tags=laravel"],
    "wordpress":  ["cves/", "tags=wordpress,wp"],
    "drupal":     ["cves/", "tags=drupal"],
    "jira":       ["cves/", "tags=jira"],
    "confluence": ["cves/", "tags=confluence"],
    "gitlab":     ["cves/", "tags=gitlab"],
    "jenkins":    ["cves/", "tags=jenkins"],
    "grafana":    ["cves/", "tags=grafana"],
    "kibana":     ["cves/", "tags=kibana"],
    "elasticsearch": ["cves/", "tags=elasticsearch"],
    # Security appliances
    "f5":         ["tags=f5,bigip"],
    "imperva":    ["tags=imperva"],
    "fortinet":   ["tags=fortinet,fortigate"],
    "cisco":      ["tags=cisco"],
    # Languages/runtimes
    "php":        ["tags=php", "cves/"],
    "python":     ["tags=python,django,flask"],
    "node":       ["tags=node,express,nodejs"],
    # Common infra
    "redis":      ["cves/", "tags=redis"],
    "mongodb":    ["tags=mongodb"],
    "mysql":      ["tags=mysql"],
    "postgresql": ["tags=postgresql"],
}

tech_urls = defaultdict(set)

try:
    with open(json_file) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
            except: continue
            url   = obj.get("url", obj.get("input", ""))
            techs = obj.get("tech", obj.get("technologies", []))
            if isinstance(techs, dict): techs = list(techs.keys())

            for tech in techs:
                tech_lower = tech.lower()
                for key in TECH_MAP:
                    if key in tech_lower:
                        tech_urls[key].add(url)
                        break

    # Write per-tech URL files
    for tech, urls in tech_urls.items():
        out = os.path.join(temp_dir, f"tech_{tech}.txt")
        with open(out, "w") as f:
            for u in sorted(urls):
                f.write(u + "\n")
        print(f"  [tech] {tech}: {len(urls)} targets → {out}")

except Exception as e:
    print(f"  [!] tech parse error: {e}")
PYEOF

    # ── Per-tech nuclei runs ──────────────────────────────────────────────────
    declare -A TECH_TEMPLATES=(
        ["tomcat"]="tags=tomcat,apache"
        ["nginx"]="tags=nginx"
        ["apache"]="tags=apache"
        ["iis"]="tags=iis,microsoft"
        ["spring"]="tags=springboot,spring,java"
        ["jboss"]="tags=jboss,java"
        ["weblogic"]="tags=weblogic,oracle"
        ["wordpress"]="tags=wordpress,wp"
        ["jira"]="tags=jira,atlassian"
        ["confluence"]="tags=confluence,atlassian"
        ["jenkins"]="tags=jenkins"
        ["gitlab"]="tags=gitlab"
        ["grafana"]="tags=grafana"
        ["kibana"]="tags=kibana,elasticsearch"
        ["php"]="tags=php"
        ["f5"]="tags=f5,bigip"
    )

    for tech in "${!TECH_TEMPLATES[@]}"; do
        tech_input="${TEMP_DIR}/tech_${tech}.txt"
        [[ -f "$tech_input" && -s "$tech_input" ]] || continue

        tags="${TECH_TEMPLATES[$tech]}"
        out_txt="${PHASE1_DIR}/${tech}.txt"
        out_json="${PHASE1_DIR}/${tech}.json"

        step "  Phase 1 → ${tech} ($(wc -l < "$tech_input") targets)"
        run_nuclei "$tech_input" "$out_txt" "$out_json" \
            -tags "${tags//tags=/}" \
            -t "${TEMPLATES_DIR}/cves/" \
            -t "${TEMPLATES_DIR}/vulnerabilities/" \
            -t "${TEMPLATES_DIR}/misconfiguration/"
    done

    # ── Tier 1 targets: extra templates ──────────────────────────────────────
    if [[ -s "$TIER1_URLS" ]]; then
        step "  Phase 1 → Tier 1 extra scan (admin/api/dev/staging)"
        out_txt="${PHASE1_DIR}/tier1_extra.txt"
        out_json="${PHASE1_DIR}/tier1_extra.json"
        run_nuclei "$TIER1_URLS" "$out_txt" "$out_json" \
            -t "${TEMPLATES_DIR}/exposures/configs/" \
            -t "${TEMPLATES_DIR}/exposures/files/" \
            -t "${TEMPLATES_DIR}/default-logins/" \
            -t "${TEMPLATES_DIR}/misconfiguration/" \
            -tags "panel,login,admin,api,debug,backup"
    fi

    # ── FingerprintHub — tech detection bổ sung ───────────────────────────────
    # Chạy trước community để có thêm context về tech stack
    if [[ -d "$FINGERPRINT_LOCAL" && -s "$LIVE_URLS" ]]; then
        step "  Phase 1 → FingerprintHub tech detection"
        FP_COUNT=$(find "$FINGERPRINT_LOCAL" -name "*.yaml" | wc -l | tr -d ' ')
        info "FingerprintHub: $FP_COUNT fingerprint templates"
        out_txt="${PHASE1_DIR}/fingerprinthub.txt"
        out_json="${PHASE1_DIR}/fingerprinthub.json"
        # Fingerprint templates thường severity=info — bỏ severity filter
        nuclei \
            -l "$LIVE_URLS" \
            -t "$FINGERPRINT_LOCAL" \
            -rate-limit "$RATE_LIMIT" \
            -c "$CONCURRENCY" \
            -timeout "$TIMEOUT" \
            -no-color \
            -silent \
            -exclude-tags dos,fuzz \
            -o "$out_txt" \
            -json-export "$out_json" \
            2>/dev/null || true
        FP_FOUND=$(wc -l < "$out_txt" 2>/dev/null | tr -d ' ' || echo 0)
        [[ "$FP_FOUND" -gt 0 ]] && found "FingerprintHub: $FP_FOUND tech detections" || \
            success "FingerprintHub: 0 new detections"
    fi

    # ── Wordfence WordPress CVE — chỉ chạy nếu detect WordPress ──────────────
    if [[ -d "$WORDFENCE_LOCAL" && -s "$LIVE_URLS" ]]; then
        # Detect WordPress từ httpx JSON
        WP_URLS="${TEMP_DIR}/wordpress_targets.txt"
        if [[ -f "$IN_HTTPX_JSON" ]]; then
            python3 -c "
import sys, json
for line in open('$IN_HTTPX_JSON'):
    try:
        obj = json.loads(line.strip())
        techs = obj.get('tech', obj.get('technologies', []))
        if isinstance(techs, dict): techs = list(techs.keys())
        tech_str = ' '.join(str(t).lower() for t in techs)
        if 'wordpress' in tech_str or 'wp' in tech_str:
            print(obj.get('url', obj.get('input', '')))
    except: pass
" 2>/dev/null | sort -u > "$WP_URLS" || true
        fi

        WP_COUNT=$(wc -l < "$WP_URLS" 2>/dev/null | tr -d ' ' || echo 0)
        if [[ "$WP_COUNT" -gt 0 ]]; then
            step "  Phase 1 → Wordfence WordPress CVE scan ($WP_COUNT WP targets)"
            WF_TOTAL=$(find "$WORDFENCE_LOCAL" -name "*.yaml" | wc -l | tr -d ' ')
            info "Wordfence templates: $WF_TOTAL (~82k WordPress CVE)"
            out_txt="${PHASE1_DIR}/wordfence_cve.txt"
            out_json="${PHASE1_DIR}/wordfence_cve.json"
            run_nuclei "$WP_URLS" "$out_txt" "$out_json" \
                -t "$WORDFENCE_LOCAL" \
                -tags "wordpress,wp,plugin,theme"
        else
            info "No WordPress targets detected — skipping Wordfence CVE scan"
        fi
    fi

    # ── geeknik + kayala + daffainfo — community 1-day CVE ────────────────────
    for comm_id in geeknik kayala daffainfo; do
        comm_dir="${COMMUNITY_LOCAL}/${comm_id}"
        [[ -d "$comm_dir" && -s "$LIVE_URLS" ]] || continue
        comm_count=$(find "$comm_dir" -name "*.yaml" | wc -l | tr -d ' ')
        step "  Phase 1 → Community [$comm_id] ($comm_count templates)"
        out_txt="${PHASE1_DIR}/community_${comm_id}.txt"
        out_json="${PHASE1_DIR}/community_${comm_id}.json"
        run_nuclei "$LIVE_URLS" "$out_txt" "$out_json" -t "$comm_dir"
    done

    # ── AI-generated templates (opt-in, UNVERIFIED) ───────────────────────────
    # Chỉ chạy khi --ai-templates được truyền vào 09_nuclei.sh
    if [[ "${USE_AI_TEMPLATES:-0}" == "1" && -d "$AI_LOCAL" && -s "$LIVE_URLS" ]]; then
        AI_COUNT=$(find "$AI_LOCAL" -name "*.yaml" | wc -l | tr -d ' ')
        warn "  Phase 1 → AI-generated templates ($AI_COUNT) — UNVERIFIED, use with caution"
        out_txt="${PHASE1_DIR}/ai_generated.txt"
        out_json="${PHASE1_DIR}/ai_generated.json"
        run_nuclei "$LIVE_URLS" "$out_txt" "$out_json" -t "$AI_LOCAL"
    fi

    # ── Custom templates cho target cụ thể ────────────────────────────────────
    if [[ -d "$CUSTOM_LOCAL" && -s "$LIVE_URLS" ]]; then
        step "  Phase 1 → Custom target-specific templates"
        # Chạy tất cả custom templates, ưu tiên mbbank/ nếu đang scan mbbank
        CUSTOM_TARGET_DIR="${CUSTOM_LOCAL}/${DOMAIN%%.*}"  # vd: custom/mbbank/
        if [[ -d "$CUSTOM_TARGET_DIR" ]]; then
            CUST_T=$(find "$CUSTOM_TARGET_DIR" -name "*.yaml" | wc -l | tr -d ' ')
            info "Custom templates for ${DOMAIN%%.*}: $CUST_T templates"
            out_txt="${PHASE1_DIR}/custom_${DOMAIN%%.*}.txt"
            out_json="${PHASE1_DIR}/custom_${DOMAIN%%.*}.json"
            # Custom templates thường không cần severity filter — chạy info cũng OK
            nuclei \
                -l "$LIVE_URLS" \
                -t "$CUSTOM_TARGET_DIR" \
                -rate-limit "$RATE_LIMIT" \
                -c "$CONCURRENCY" \
                -timeout "$TIMEOUT" \
                -no-color \
                -silent \
                -exclude-tags dos,fuzz \
                -o "$out_txt" \
                -json-export "$out_json" \
                2>/dev/null || true
            CUST_FOUND=$(wc -l < "$out_txt" 2>/dev/null | tr -d ' ' || echo 0)
            [[ "$CUST_FOUND" -gt 0 ]] && found "Custom templates: $CUST_FOUND findings" || \
                success "Custom templates: 0 findings"
        fi

        # Generic custom templates (không theo target)
        CUSTOM_GENERIC="${CUSTOM_LOCAL}/generic"
        if [[ -d "$CUSTOM_GENERIC" ]]; then
            out_txt="${PHASE1_DIR}/custom_generic.txt"
            out_json="${PHASE1_DIR}/custom_generic.json"
            run_nuclei "$LIVE_URLS" "$out_txt" "$out_json" -t "$CUSTOM_GENERIC"
        fi
    fi

    PHASE1_TOTAL=$(find "$PHASE1_DIR" -name "*.txt" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo 0)
    success "Phase 1 complete — $PHASE1_TOTAL total findings"
fi

# =============================================================================
# PHASE 2: BROAD CVE + EXPOSURE SWEEP
# =============================================================================
if [[ "$RUN_CVE" -eq 1 ]]; then
    step "PHASE 2 — CVE + Exposure Sweep (all live targets)"

    # 2a: CVE scan — latest 3 years (most relevant, not too noisy)
    step "  Phase 2a → CVE scan (2022–2025)"
    CVE_TARGETS="${TEMP_DIR}/phase2_targets.txt"
    cp "$LIVE_URLS" "$CVE_TARGETS"

    CVE_DIRS=()
    for year in 2022 2023 2024 2025; do
        [[ -d "${TEMPLATES_DIR}/cves/${year}" ]] && CVE_DIRS+=("-t" "${TEMPLATES_DIR}/cves/${year}/")
    done
    # Also include older CVEs for known targets (tomcat, jboss, struts are often old)
    [[ -d "${TEMPLATES_DIR}/cves/2021" ]] && CVE_DIRS+=("-t" "${TEMPLATES_DIR}/cves/2021/")
    [[ -d "${TEMPLATES_DIR}/cves/2020" ]] && CVE_DIRS+=("-t" "${TEMPLATES_DIR}/cves/2020/")

    if [[ "${#CVE_DIRS[@]}" -gt 0 ]]; then
        run_nuclei "$CVE_TARGETS" \
            "$OUT_PHASE2_CVE" \
            "${OUT_PHASE2_CVE%.txt}.json" \
            "${CVE_DIRS[@]}"
    else
        # Fallback: full CVE dir
        run_nuclei "$CVE_TARGETS" \
            "$OUT_PHASE2_CVE" \
            "${OUT_PHASE2_CVE%.txt}.json" \
            -t "${TEMPLATES_DIR}/cves/"
    fi

    # 2b: Exposures — sensitive file/config leaks
    step "  Phase 2b → Exposure scan (configs, files, tokens, logs)"
    run_nuclei "$LIVE_URLS" \
        "$OUT_PHASE2_EXP" \
        "${OUT_PHASE2_EXP%.txt}.json" \
        -t "${TEMPLATES_DIR}/exposures/" \
        -tags "exposure,config,token,log,backup,env,git,aws,cloud"

    # 2c: Misconfiguration
    step "  Phase 2c → Misconfiguration scan"
    run_nuclei "$LIVE_URLS" \
        "$OUT_PHASE2_MISC" \
        "${OUT_PHASE2_MISC%.txt}.json" \
        -t "${TEMPLATES_DIR}/misconfiguration/" \
        -t "${TEMPLATES_DIR}/default-logins/"

    # 2d: Specific high-value checks
    step "  Phase 2d → Specific checks (CORS, SSRF, JWT, takeover)"
    OUT_PHASE2_SPECIFIC="${NUCLEI_DIR}/phase2_specific.txt"
    run_nuclei "$LIVE_URLS" \
        "$OUT_PHASE2_SPECIFIC" \
        "${OUT_PHASE2_SPECIFIC%.txt}.json" \
        -tags "cors,ssrf,redirect,jwt,takeover,xxe,ssti,lfi,xss,sqli" \
        -t "${TEMPLATES_DIR}/vulnerabilities/"

    CVE_FOUND=$(wc -l < "$OUT_PHASE2_CVE" 2>/dev/null | tr -d ' ' || echo 0)
    EXP_FOUND=$(wc -l < "$OUT_PHASE2_EXP" 2>/dev/null | tr -d ' ' || echo 0)
    MISC_FOUND=$(wc -l < "$OUT_PHASE2_MISC" 2>/dev/null | tr -d ' ' || echo 0)
    success "Phase 2 — CVE:${CVE_FOUND}  Exposure:${EXP_FOUND}  Misconfig:${MISC_FOUND}"
fi

# =============================================================================
# PHASE 3: NETWORK-LEVEL SCAN
# =============================================================================
if [[ "$RUN_NETWORK" -eq 1 ]]; then
    step "PHASE 3 — Network Service Scan (origin IPs)"
    info "Targets: ports/open.txt + origin_ips.txt"

    # Build host:port list from open ports
    NETWORK_TARGETS="${TEMP_DIR}/network_targets.txt"
    > "$NETWORK_TARGETS"

    if [[ -f "$IN_OPEN_PORTS" && -s "$IN_OPEN_PORTS" ]]; then
        # nuclei network templates use host:port format
        while IFS=':' read -r ip port; do
            [[ -z "$ip" || -z "$port" ]] && continue
            # Only non-web ports for network templates
            case "$port" in
                80|443|8080|8443|8000|8001|8888|3000|4000|5000|9090) continue ;;
                *) echo "${ip}:${port}" >> "$NETWORK_TARGETS" ;;
            esac
        done < "$IN_OPEN_PORTS"
    fi

    # Also add bare IPs for network sweeps
    if [[ -f "$IN_ORIGIN_IPS" && -s "$IN_ORIGIN_IPS" ]]; then
        cat "$IN_ORIGIN_IPS" >> "$NETWORK_TARGETS"
    fi
    sort -u "$NETWORK_TARGETS" -o "$NETWORK_TARGETS"

    NET_TOTAL=$(wc -l < "$NETWORK_TARGETS" | tr -d ' ')

    if [[ "$NET_TOTAL" -gt 0 ]] && [[ -d "${TEMPLATES_DIR}/network" ]]; then
        info "Network targets: $NET_TOTAL"
        run_nuclei "$NETWORK_TARGETS" \
            "$OUT_PHASE3_NET" \
            "${OUT_PHASE3_NET%.txt}.json" \
            -t "${TEMPLATES_DIR}/network/" \
            -t "${TEMPLATES_DIR}/default-logins/ssh/" \
            -t "${TEMPLATES_DIR}/default-logins/ftp/" \
            -t "${TEMPLATES_DIR}/default-logins/redis.yaml" \
            2>/dev/null || true
    else
        warn "No network targets or no network templates — skipping phase 3"
    fi
fi

# =============================================================================
# MERGE + DEDUPLICATE ALL FINDINGS
# =============================================================================
step "Merging all findings"

> "$OUT_ALL"
> "$OUT_ALL_JSON"

# Collect all .txt findings
find "$NUCLEI_DIR" -name "*.txt" ! -name "all_findings.txt" ! -name "report.md" \
    -exec cat {} + 2>/dev/null | sort -u >> "$OUT_ALL" || true

# Collect all .json findings
find "$NUCLEI_DIR" -name "*.json" ! -name "all_findings.json" \
    -exec cat {} + 2>/dev/null | sort -u >> "$OUT_ALL_JSON" || true

TOTAL_FINDINGS=$(wc -l < "$OUT_ALL" | tr -d ' ')
success "Total unique findings: $TOTAL_FINDINGS"

# =============================================================================
# SEVERITY-BASED SUMMARY
# =============================================================================
step "Severity breakdown"

CRIT_COUNT=$(grep -ic "\[critical\]" "$OUT_ALL" 2>/dev/null || echo 0)
HIGH_COUNT=$(grep -ic "\[high\]" "$OUT_ALL" 2>/dev/null || echo 0)
MED_COUNT=$(grep -ic "\[medium\]" "$OUT_ALL" 2>/dev/null || echo 0)
INFO_COUNT=$(grep -ic "\[info\]" "$OUT_ALL" 2>/dev/null || echo 0)

echo ""
echo -e "  ${RED}[critical]${RESET} $CRIT_COUNT"
echo -e "  ${RED}[high]    ${RESET} $HIGH_COUNT"
echo -e "  ${YELLOW}[medium]  ${RESET} $MED_COUNT"
echo -e "  ${DIM}[info]    ${RESET} $INFO_COUNT"

# Print critical first
if [[ "$CRIT_COUNT" -gt 0 ]]; then
    echo ""
    echo -e "${RED}${BOLD}★ CRITICAL FINDINGS:${RESET}"
    grep -i "\[critical\]" "$OUT_ALL" 2>/dev/null | while IFS= read -r line; do
        echo -e "  ${RED}▶${RESET} $line"
    done
fi

if [[ "$HIGH_COUNT" -gt 0 ]]; then
    echo ""
    echo -e "${RED}${BOLD}★ HIGH FINDINGS:${RESET}"
    grep -i "\[high\]" "$OUT_ALL" 2>/dev/null | while IFS= read -r line; do
        echo -e "  ${RED}▶${RESET} $line"
    done
fi

# =============================================================================
# GENERATE NUCLEI REPORT
# =============================================================================
step "Generating report"

NOW=$(date '+%Y-%m-%d %H:%M')

python3 - "$OUT_ALL_JSON" "$OUT_REPORT" "$DOMAIN" "$NOW" <<'PYEOF'
import sys, json
from collections import defaultdict

json_file = sys.argv[1]
out_file  = sys.argv[2]
domain    = sys.argv[3]
now       = sys.argv[4]

findings = []
try:
    with open(json_file) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
                findings.append(obj)
            except: pass
except FileNotFoundError:
    pass

# Group by severity
by_sev = defaultdict(list)
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
for f in findings:
    sev = (f.get("info", {}).get("severity") or f.get("severity", "info")).lower()
    by_sev[sev].append(f)

SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}

lines = [
    f"# Nuclei Scan Report — {domain}",
    f"**Generated:** {now}",
    "",
    "---",
    "",
    "## Summary",
    "",
    "| Severity | Count |",
    "|----------|-------|",
]

for sev in SEV_ORDER:
    count = len(by_sev.get(sev, []))
    if count > 0:
        lines.append(f"| {SEV_EMOJI.get(sev,'')} {sev.capitalize()} | {count} |")

lines += [
    "",
    "---",
    "",
]

# Findings by severity
for sev in SEV_ORDER:
    items = by_sev.get(sev, [])
    if not items:
        continue

    lines.append(f"## {SEV_EMOJI.get(sev, '')} {sev.capitalize()} ({len(items)})")
    lines.append("")

    for item in items:
        info_block = item.get("info", {})
        name    = info_block.get("name", item.get("template-id", "unknown"))
        matched = item.get("matched-at", item.get("host", ""))
        cve_id  = ""
        classi  = info_block.get("classification", {})
        if classi:
            cve_ids = classi.get("cve-id", [])
            if cve_ids:
                cve_id = f" `{cve_ids[0]}`" if isinstance(cve_ids, list) else f" `{cve_ids}`"

        desc    = info_block.get("description", "").strip()[:200]
        ref     = info_block.get("reference", [])
        ref_str = ref[0] if isinstance(ref, list) and ref else (ref if isinstance(ref, str) else "")

        lines.append(f"### {name}{cve_id}")
        lines.append(f"- **Target:** `{matched}`")
        if desc:
            lines.append(f"- **Description:** {desc}")
        if ref_str:
            lines.append(f"- **Reference:** {ref_str}")
        lines.append("")

with open(out_file, "w") as f:
    f.write("\n".join(lines))

print(f"  Report written: {out_file}")
print(f"  Total findings parsed: {len(findings)}")
PYEOF

# =============================================================================
# FINAL SUMMARY
# =============================================================================
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

summary_box "09 NUCLEI SCAN" \
    "Domain"    "$DOMAIN" \
    "Phase"     "$PHASE" \
    "Severity"  "$SEVERITY" \
    "Critical"  "$CRIT_COUNT" \
    "High"      "$HIGH_COUNT" \
    "Medium"    "$MED_COUNT" \
    "Total"     "$TOTAL_FINDINGS findings" \
    "Elapsed"   "$ELAPSED_FMT" \
    "Report"    "nuclei/report.md"

echo ""
echo -e "  ${BOLD}Output dir :${RESET} ${NUCLEI_DIR}"
echo -e "  ${BOLD}All findings:${RESET} ${OUT_ALL}"
echo -e "  ${BOLD}JSON export :${RESET} ${OUT_ALL_JSON}"
echo -e "  ${BOLD}Report      :${RESET} ${OUT_REPORT}"
