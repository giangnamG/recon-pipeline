#!/usr/bin/env bash
# =============================================================================
# 10_dirfuzz.sh — Directory & Content Fuzzing (ffuf)
#
# Fuzz hidden directories, sensitive files (.env, .git, .bak, .sql), admin panels,
# and API docs using ffuf with smart autocalibration and rate limiting.
#
# INPUT (priority order):
#   1. output/<domain>/triage/tier1.txt      — default high-value targets
#   2. output/<domain>/http/interesting.txt  — interesting targets
#   3. output/<domain>/http/live.txt         — all live HTTP targets (--all-live)
#   4. Direct URL via --url <URL>
#
# OUTPUT:
#   output/<domain>/dirfuzz/
#     raw/                   — per-target ffuf JSON output
#     discovered_paths.txt   — all found paths [STATUS] [SIZE] [WORDS]
#     sensitive_files.txt    — sensitive files (.env, .git, .bak, backup, .sql, config)
#     admin_panels.txt       — admin, login, dashboard, swagger, api-docs
#     all.json               — merged JSON findings
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

show_help() {
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║  10 — Directory & Content Fuzzing (ffuf)                     ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${BOLD}MÔ TẢ:${RESET}"
    echo -e "  Dò tìm đường dẫn ẩn, tệp tin nhạy cảm (.env, .git, .bak, .sql, backup),"
    echo -e "  trang quản trị (admin, login, dashboard) và tài liệu API (swagger, graphql) bằng ffuf."
    echo ""
    echo -e "${BOLD}CÚ PHÁP SỬ DỤNG:${RESET}"
    echo -e "  $0 <domain> [tùy chọn]"
    echo ""
    echo -e "${BOLD}CÁC TÙY CHỌN MỤC TIÊU (Target Selection):${RESET}"
    echo -e "  ${YELLOW}--all-live${RESET}             Quét toàn bộ HTTP targets trong http/live.txt (Mặc định: chỉ quét Tier 1 & Interesting)"
    echo -e "  ${YELLOW}--url <URL>${RESET}            Chỉ quét duy nhất 1 URL cụ thể"
    echo -e "  ${YELLOW}--targets <file>${RESET}       Chỉ định file chứa danh sách URL cần quét"
    echo ""
    echo -e "${BOLD}CÁC TÙY CHỌN TỪ ĐIỂN & EXTENSIONS:${RESET}"
    echo -e "  ${YELLOW}-w, --wordlist <file>${RESET}  Chỉ định wordlist tùy chỉnh (Mặc định: dirsearch.txt hoặc raft-medium)"
    echo -e "  ${YELLOW}-e, --ext <list>${RESET}       Danh sách phần mở rộng file (Mặc định: Server-side + PHP variants + Archives + DB + Configs)"
    echo -e "  ${YELLOW}--no-ext${RESET}               Không thêm extension vào wordlist"
    echo ""
    echo -e "${BOLD}CÁC TÙY CHỌN HIỆU NĂNG & RATE LIMIT:${RESET}"
    echo -e "  ${YELLOW}-t, --threads <N>${RESET}      Số luồng worker cho mỗi target (Mặc định: 40)"
    echo -e "  ${YELLOW}-r, --rate <N>${RESET}         Giới hạn request/giây trên mỗi target (Mặc định: 150)"
    echo -e "  ${YELLOW}--concurrency <N>${RESET}      Số target quét đồng thời (Mặc định: 3)"
    echo -e "  ${YELLOW}--recursion${RESET}            Bật chế độ quét đệ quy thư mục"
    echo -e "  ${YELLOW}--recursion-depth <N>${RESET}  Độ sâu đệ quy tối đa (Mặc định: 1)"
    echo -e "  ${YELLOW}-h, --help${RESET}             Hiển thị hướng dẫn này"
    echo ""
    echo -e "${BOLD}VÍ DỤ:${RESET}"
    echo -e "  $0 mbbank.com.vn                                    # Quét mặc định các mục tiêu Tier 1"
    echo -e "  $0 mbbank.com.vn --all-live                         # Quét tất cả live HTTP targets"
    echo -e "  $0 mbbank.com.vn --url https://api.mbbank.com.vn    # Quét 1 URL cụ thể"
    echo -e "  $0 mbbank.com.vn --rate 50 --threads 20             # Giảm tốc độ để tránh WAF block"
    echo ""
}

[[ $# -eq 0 ]] && { show_help; exit 1; }

for arg in "$@"; do
    case "$arg" in
        -h|--help|help) show_help; exit 0 ;;
    esac
done

DOMAIN="$(normalize_domain "$1")"
shift || true

# ─── Options & Defaults ──────────────────────────────────────────────────────
ALL_LIVE=0
CUSTOM_URL=""
CUSTOM_TARGETS=""
CUSTOM_WORDLIST=""
# Server-side languages (PHP & variants, Java, ASP.NET, Python, Ruby, Perl, CGI, ColdFusion) + Archives & Backups + Configs & DB dumps
EXTENSIONS=".php,.php3,.php4,.php5,.php7,.php8,.phtml,.phar,.pht,.phps,.inc,.jsp,.jspx,.jspf,.action,.do,.class,.jar,.war,.ear,.asp,.aspx,.ashx,.asmx,.axd,.svc,.py,.rb,.pl,.cgi,.cfm,.cfc,.zip,.tar,.tar.gz,.tgz,.rar,.7z,.gz,.bz2,.bak,.backup,.old,.orig,.save,.swp,.tmp,.sql,.dump,.db,.sqlite,.env,.config,.conf,.cfg,.ini,.json,.xml,.yaml,.yml,.properties,.txt,.log"
NO_EXT=0
THREADS=40
RATE_LIMIT=150
MAX_TARGET_CONCURRENCY=3
RECURSION=0
RECURSION_DEPTH=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all-live)        ALL_LIVE=1; shift ;;
        --url)             CUSTOM_URL="${2:-}"; shift 2 ;;
        --targets)         CUSTOM_TARGETS="${2:-}"; shift 2 ;;
        -w|--wordlist)     CUSTOM_WORDLIST="${2:-}"; shift 2 ;;
        -e|--ext)          EXTENSIONS="${2:-}"; shift 2 ;;
        --no-ext)          NO_EXT=1; shift ;;
        -t|--threads)      THREADS="${2:-40}"; shift 2 ;;
        -r|--rate)         RATE_LIMIT="${2:-150}"; shift 2 ;;
        --concurrency)     MAX_TARGET_CONCURRENCY="${2:-3}"; shift 2 ;;
        --recursion)       RECURSION=1; shift ;;
        --recursion-depth) RECURSION_DEPTH="${2:-1}"; shift 2 ;;
        -*)                warn "Unknown option: $1"; shift ;;
        *)                 shift ;;
    esac
done

# Ensure every extension has a leading dot '.' for ffuf
if [[ "$NO_EXT" -eq 0 && -n "$EXTENSIONS" ]]; then
    EXTENSIONS=$(echo "$EXTENSIONS" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | awk 'NF {if ($0 ~ /^\./) print $0; else print "."$0}' | paste -sd, -)
fi

cmd_exists ffuf || { error "ffuf not found — install: apt install ffuf / go install github.com/ffuf/ffuf/v2@latest"; exit 1; }

OUT_DIR="$(output_dir "$DOMAIN")"
FUZZ_DIR="${OUT_DIR}/dirfuzz"
RAW_DIR="${FUZZ_DIR}/raw"
mkdir -p "$FUZZ_DIR" "$RAW_DIR"

IN_TIER1="${OUT_DIR}/triage/tier1.txt"
IN_INTERESTING="${OUT_DIR}/http/interesting.txt"
IN_LIVE="${OUT_DIR}/http/live.txt"

OUT_DISCOVERED="${FUZZ_DIR}/discovered_paths.txt"
OUT_SENSITIVE="${FUZZ_DIR}/sensitive_files.txt"
OUT_ADMIN="${FUZZ_DIR}/admin_panels.txt"
OUT_ALL_JSON="${FUZZ_DIR}/all.json"
LOG_FILE="${OUT_DIR}/logs/10_dirfuzz.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

> "$OUT_DISCOVERED"; > "$OUT_SENSITIVE"; > "$OUT_ADMIN"; > "$OUT_ALL_JSON"

banner "10 — Directory & Content Fuzzing" "$DOMAIN"

ulimit -n 65535 2>/dev/null || true
START_TIME=$(date +%s)

# ──────────────────────────────────────────────
# 1. Resolve Wordlist
# ──────────────────────────────────────────────
WORDLIST=""
if [[ -n "$CUSTOM_WORDLIST" && -f "$CUSTOM_WORDLIST" ]]; then
    WORDLIST="$CUSTOM_WORDLIST"
elif [[ -f "/usr/share/wordlists/dirsearch.txt" ]]; then
    WORDLIST="/usr/share/wordlists/dirsearch.txt"
elif [[ -f "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt" ]]; then
    WORDLIST="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
elif [[ -f "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt" ]]; then
    WORDLIST="/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
elif [[ -f "/usr/share/seclists/Discovery/Web-Content/common.txt" ]]; then
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
else
    # Fallback minimal built-in wordlist
    WORDLIST="${TEMP_DIR}/builtin_wordlist.txt"
    cat << 'EOF' > "$WORDLIST"
admin
api
api/v1
api/v2
api/v3
swagger
swagger-ui.html
swagger.json
openapi.json
graphql
graphiql
actuator
actuator/health
actuator/env
actuator/metrics
console
dashboard
portal
login
logout
auth
oauth
dev
staging
test
demo
internal
backup
backups
db
database
dump
dump.sql
db.sql
config
config.json
config.php
config.yml
configuration
env
.env
.env.prod
.env.production
.env.local
.git
.git/config
.git/HEAD
.svn
.svn/entries
.htaccess
.htpasswd
server-status
web.config
robots.txt
sitemap.xml
crossdomain.xml
clientaccesspolicy.xml
phpinfo.php
info.php
test.php
version
health
healthz
metrics
prometheus
trace
heapdump
manager
manager/html
host-manager
solr
jenkins
kibana
grafana
pma
phpmyadmin
myadmin
EOF
fi

info "Wordlist  : $WORDLIST ($(count_lines "$WORDLIST") entries)"
if [[ "$NO_EXT" -eq 1 ]]; then
    info "Extensions: Disabled"
else
    info "Extensions: $EXTENSIONS"
fi
info "Threads   : $THREADS | Rate: $RATE_LIMIT req/s"

# ──────────────────────────────────────────────
# 2. Build Target List
# ──────────────────────────────────────────────
TARGETS_FILE="${TEMP_DIR}/targets.txt"
> "$TARGETS_FILE"

if [[ -n "$CUSTOM_URL" ]]; then
    echo "$CUSTOM_URL" > "$TARGETS_FILE"
    info "Target mode: Single URL ($CUSTOM_URL)"

elif [[ -n "$CUSTOM_TARGETS" && -f "$CUSTOM_TARGETS" ]]; then
    awk '{print $1}' "$CUSTOM_TARGETS" | grep -E '^https?://' | sort -u > "$TARGETS_FILE"
    info "Target mode: Custom targets file ($CUSTOM_TARGETS)"

elif [[ "$ALL_LIVE" -eq 1 ]]; then
    if [[ -f "$IN_LIVE" && -s "$IN_LIVE" ]]; then
        awk '{print $1}' "$IN_LIVE" | grep -E '^https?://' | sort -u > "$TARGETS_FILE"
        info "Target mode: All live HTTP targets (http/live.txt)"
    fi

else
    # Default: Tier 1 + Interesting
    if [[ -f "$IN_TIER1" && -s "$IN_TIER1" ]]; then
        awk '{print $1}' "$IN_TIER1" | grep -E '^https?://' >> "$TARGETS_FILE" || true
    fi
    if [[ -f "$IN_INTERESTING" && -s "$IN_INTERESTING" ]]; then
        awk '{print $1}' "$IN_INTERESTING" | grep -E '^https?://' >> "$TARGETS_FILE" || true
    fi

    # Deduplicate
    if [[ -s "$TARGETS_FILE" ]]; then
        sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
        info "Target mode: Tier 1 & Interesting ($(count_lines "$TARGETS_FILE") targets)"
    elif [[ -f "$IN_LIVE" && -s "$IN_LIVE" ]]; then
        awk '{print $1}' "$IN_LIVE" | grep -E '^https?://' | sort -u > "$TARGETS_FILE"
        info "Target mode: Fallback to all live targets (http/live.txt)"
    fi
fi

TOTAL_TARGETS=$(count_lines "$TARGETS_FILE")
[[ "$TOTAL_TARGETS" -gt 0 ]] || { warn "No valid targets found to fuzz — exiting"; exit 0; }

info "Total targets to fuzz: $TOTAL_TARGETS"

# ──────────────────────────────────────────────
# 3. Fuzz Execution Function
# ──────────────────────────────────────────────
fuzz_target() {
    local target_url="$1"
    local safe_name
    safe_name=$(echo "$target_url" | sed 's|^https\?://||; s|[/:]|_|g')
    local raw_json="${RAW_DIR}/${safe_name}.json"

    # Base FFUF arguments
    local FFUF_ARGS=(
        -u "${target_url%/}/FUZZ"
        -w "$WORDLIST"
        -mc "200,204,301,302,307,401,403,405,500"
        -ac                     # Autocalibration (filters soft 404s/catch-all)
        -t "$THREADS"
        -rate "$RATE_LIMIT"
        -timeout 10
        -o "$raw_json"
        -of json
        -s                      # Silent
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Recon-Pipeline/1.0"
    )

    if [[ "$NO_EXT" -eq 0 && -n "$EXTENSIONS" ]]; then
        FFUF_ARGS+=(-e "$EXTENSIONS")
    fi

    if [[ "$RECURSION" -eq 1 ]]; then
        FFUF_ARGS+=(-recursion -recursion-depth "$RECURSION_DEPTH")
    fi

    ffuf "${FFUF_ARGS[@]}" 2>/dev/null || true
}

# ──────────────────────────────────────────────
# 4. Run Fuzzing (Parallel / Sequential)
# ──────────────────────────────────────────────
step "Executing directory & content fuzzing with ffuf"

CURRENT=0
while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    (( CURRENT++ )) || true
    echo -e "  ${CYAN}[${CURRENT}/${TOTAL_TARGETS}]${RESET} Fuzzing: ${BOLD}${target}${RESET}"

    fuzz_target "$target" &

    # Limit concurrency
    if (( CURRENT % MAX_TARGET_CONCURRENCY == 0 )); then
        wait
    fi
done < "$TARGETS_FILE"
wait

# ──────────────────────────────────────────────
# 5. Parse, Classify & Consolidate Results
# ──────────────────────────────────────────────
step "Parsing & classifying discovered paths"

RAW_DIR="$RAW_DIR" OUT_DISCOVERED="$OUT_DISCOVERED" OUT_SENSITIVE="$OUT_SENSITIVE" OUT_ADMIN="$OUT_ADMIN" OUT_ALL_JSON="$OUT_ALL_JSON" python3 - << 'PYEOF'
import json
import os
import glob

raw_dir = os.environ.get("RAW_DIR", "")
out_discovered = os.environ.get("OUT_DISCOVERED", "")
out_sensitive = os.environ.get("OUT_SENSITIVE", "")
out_admin = os.environ.get("OUT_ADMIN", "")
out_all_json = os.environ.get("OUT_ALL_JSON", "")

sensitive_keywords = [
    ".env", ".git", ".bak", ".old", ".backup", ".orig", ".save", ".swp", ".tmp",
    ".sql", ".dump", ".db", ".sqlite", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bz2",
    ".war", ".jar", ".ear", "web.config", ".htaccess", ".htpasswd", "database",
    "id_rsa", "credentials", "secret", "private", ".properties", ".conf", ".cfg", ".ini",
    "phpinfo", "config.json", "config.php", "config.yml", "heapdump", "actuator/env", "actuator/metrics"
]

admin_keywords = [
    "admin", "login", "dashboard", "portal", "console", "swagger", "openapi",
    "graphql", "graphiql", "actuator", "manager/html", "pma", "phpmyadmin",
    "kibana", "grafana", "jenkins", "solr"
]

all_results = []
discovered_lines = []
sensitive_lines = []
admin_lines = []

for json_file in glob.glob(os.path.join(raw_dir, "*.json")):
    try:
        with open(json_file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            results = data.get("results", [])
            for res in results:
                url = res.get("url", "")
                status = res.get("status", 0)
                length = res.get("length", 0)
                words = res.get("words", 0)
                lines_count = res.get("lines", 0)
                redirect = res.get("redirectlocation", "")

                info_str = f"[{status}] [size: {length}] [words: {words}] {url}"
                if redirect:
                    info_str += f" -> {redirect}"

                discovered_lines.append(info_str)
                all_results.append(res)

                # Check sensitive
                url_lower = url.lower()
                if any(k in url_lower for k in sensitive_keywords):
                    sensitive_lines.append(info_str)

                # Check admin / api-docs
                if any(k in url_lower for k in admin_keywords):
                    admin_lines.append(info_str)

    except Exception as e:
        continue

# Sort and deduplicate
discovered_lines = sorted(list(set(discovered_lines)))
sensitive_lines = sorted(list(set(sensitive_lines)))
admin_lines = sorted(list(set(admin_lines)))

with open(out_discovered, "w", encoding="utf-8") as f:
    f.write("\n".join(discovered_lines) + ("\n" if discovered_lines else ""))

with open(out_sensitive, "w", encoding="utf-8") as f:
    f.write("\n".join(sensitive_lines) + ("\n" if sensitive_lines else ""))

with open(out_admin, "w", encoding="utf-8") as f:
    f.write("\n".join(admin_lines) + ("\n" if admin_lines else ""))

with open(out_all_json, "w", encoding="utf-8") as f:
    json.dump(all_results, f, indent=2)

PYEOF

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

DISCOVERED_COUNT=$(count_lines "$OUT_DISCOVERED")
SENSITIVE_COUNT=$(count_lines "$OUT_SENSITIVE")
ADMIN_COUNT=$(count_lines "$OUT_ADMIN")

if [[ "$SENSITIVE_COUNT" -gt 0 ]]; then
    warn "Found $SENSITIVE_COUNT sensitive files/paths (→ dirfuzz/sensitive_files.txt)"
fi
if [[ "$ADMIN_COUNT" -gt 0 ]]; then
    info "Found $ADMIN_COUNT admin/API endpoints (→ dirfuzz/admin_panels.txt)"
fi

summary_box "10 DIRECTORY FUZZING" \
    "Domain" "$DOMAIN" \
    "Targets fuzzed" "$TOTAL_TARGETS" \
    "Total paths found" "$DISCOVERED_COUNT" \
    "Sensitive files" "$SENSITIVE_COUNT (→ dirfuzz/sensitive_files.txt)" \
    "Admin/API panels" "$ADMIN_COUNT (→ dirfuzz/admin_panels.txt)" \
    "Elapsed" "$ELAPSED_FMT" \
    "Output dir" "$FUZZ_DIR"
