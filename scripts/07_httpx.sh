#!/usr/bin/env bash
# =============================================================================
# 07_httpx.sh — HTTP Probing (httpx)
#
# Probe live HTTP/HTTPS targets. Collect:
#   - Status code, title, tech stack, server header
#   - Screenshots (nếu có Chromium)
#   - Split: live / dead / interesting (admin/api/dev/staging)
#
# INPUT (priority order):
#   1. output/<domain>/ports/candidate_urls.txt  — candidate URLs for HTTP probing (subdomain:port + ip:port)
#   2. output/<domain>/vhosts/all_vhosts.txt     — verified vhosts (hostname ip proto)
#   3. output/<domain>/ports/open.txt            — fallback: open ports
#   4. output/<domain>/resolved.txt              — fallback: subdomains on :80/:443
# OUTPUT: output/<domain>/http/live.txt          — URL status title tech server
#         output/<domain>/http/dead.txt
#         output/<domain>/http/interesting.txt
#         output/<domain>/http/all.json          — full httpx JSON for parsing later
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

show_help() {
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║  07 — HTTP Probing & Tech Stack Detection                    ║${RESET}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${BOLD}MÔ TẢ:${RESET}"
    echo -e "  Dò quét toàn diện danh sách URL ứng viên (ports/candidate_urls.txt) bằng httpx."
    echo -e "  Thu thập Title, HTTP status code, Server Banner, Tech stack, Favicon hash, TLS info"
    echo -e "  và phân loại thành live.txt, dead.txt, interesting.txt, all.json."
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
HTTP_DIR="${OUT_DIR}/http"
mkdir -p "$HTTP_DIR"

IN_CANDIDATE_URLS="${OUT_DIR}/ports/candidate_urls.txt"
IN_PROBE_URLS="${OUT_DIR}/ports/probe_urls.txt"
IN_VHOST_URLS="${OUT_DIR}/ports/vhost_urls.txt"
IN_OPEN_PORTS="${OUT_DIR}/ports/open.txt"
IN_WEB_PORTS="${OUT_DIR}/ports/web.txt"
IN_ALL_VHOSTS="${OUT_DIR}/vhosts/all_vhosts.txt"
IN_RESOLVED="${OUT_DIR}/resolved.txt"
OUT_LIVE="${HTTP_DIR}/live.txt"
OUT_DEAD="${HTTP_DIR}/dead.txt"
OUT_JSON="${HTTP_DIR}/all.json"
OUT_INTERESTING="${HTTP_DIR}/interesting.txt"
LOG_FILE="${OUT_DIR}/logs/07_httpx.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

> "$OUT_LIVE"; > "$OUT_DEAD"; > "$OUT_JSON"; > "$OUT_INTERESTING"

banner "07 — HTTP Probing" "$DOMAIN"

ulimit -n 65535 2>/dev/null || true

START_TIME=$(date +%s)

# ──────────────────────────────────────────────
# Build probe target list (Merge & Deduplicate All Sources)
# ──────────────────────────────────────────────
PROBE_LIST="${TEMP_DIR}/probe_targets.txt"
RAW_TARGETS="${TEMP_DIR}/raw_targets.txt"
touch "$RAW_TARGETS"

MERGED_SOURCES=0

# 1. Candidate URLs from 05_portscan.sh
if [[ -f "$IN_CANDIDATE_URLS" && -s "$IN_CANDIDATE_URLS" ]]; then
    local_count=$(count_lines "$IN_CANDIDATE_URLS")
    info "Merging candidate URLs (ports/candidate_urls.txt: $local_count URLs)"
    cat "$IN_CANDIDATE_URLS" >> "$RAW_TARGETS"
    ((MERGED_SOURCES++)) || true
fi

# 2. Probe URLs (secondary/fallback from ports)
if [[ -f "$IN_PROBE_URLS" && -s "$IN_PROBE_URLS" ]]; then
    local_count=$(count_lines "$IN_PROBE_URLS")
    info "Merging probe URLs (ports/probe_urls.txt: $local_count URLs)"
    cat "$IN_PROBE_URLS" >> "$RAW_TARGETS"
    ((MERGED_SOURCES++)) || true
fi

# 3. Legacy VHost URLs
if [[ -f "$IN_VHOST_URLS" && -s "$IN_VHOST_URLS" ]]; then
    local_count=$(count_lines "$IN_VHOST_URLS")
    info "Merging legacy vhost URLs (ports/vhost_urls.txt: $local_count URLs)"
    cat "$IN_VHOST_URLS" >> "$RAW_TARGETS"
    ((MERGED_SOURCES++)) || true
fi

# 4. Verified VHosts from 04_vhost.sh
if [[ -f "$IN_ALL_VHOSTS" && -s "$IN_ALL_VHOSTS" ]]; then
    local_count=$(count_lines "$IN_ALL_VHOSTS")
    info "Merging verified vhosts (vhosts/all_vhosts.txt: $local_count hosts)"
    awk -F'\t' '{
        hostname = $1
        proto = $3
        if (hostname != "") {
            if (proto ~ /^http/) {
                print proto "://" hostname
            } else {
                print "https://" hostname
                print "http://" hostname
            }
        }
    }' "$IN_ALL_VHOSTS" >> "$RAW_TARGETS"
    ((MERGED_SOURCES++)) || true
fi

# 5. Open ports & Web ports (Direct IP:Port + Hostname:Port)
COMBINED_PORTS="${TEMP_DIR}/combined_ports.txt"
touch "$COMBINED_PORTS"
[[ -f "$IN_OPEN_PORTS" && -s "$IN_OPEN_PORTS" ]] && cat "$IN_OPEN_PORTS" >> "$COMBINED_PORTS"
[[ -f "$IN_WEB_PORTS" && -s "$IN_WEB_PORTS" ]] && cat "$IN_WEB_PORTS" >> "$COMBINED_PORTS"

if [[ -s "$COMBINED_PORTS" ]]; then
    sort -u "$COMBINED_PORTS" -o "$COMBINED_PORTS"
    local_count=$(count_lines "$COMBINED_PORTS")
    info "Merging open ports (ports/open.txt & web.txt: $local_count ip:port entries)"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        ip="${line%%:*}"
        port="${line##*:}"
        
        case "$port" in
            443|8443|4443|9443)
                echo "https://${ip}:${port}" >> "$RAW_TARGETS" ;;
            80)
                echo "http://${ip}:${port}" >> "$RAW_TARGETS" ;;
            8080|8000|8001|8008|8888|3000|3001|4000|5000|5001|9000|9001|9090)
                echo "http://${ip}:${port}" >> "$RAW_TARGETS"
                echo "https://${ip}:${port}" >> "$RAW_TARGETS" ;;
            *)
                echo "http://${ip}:${port}" >> "$RAW_TARGETS"
                echo "https://${ip}:${port}" >> "$RAW_TARGETS" ;;
        esac

        # Also map subdomains pointing to this IP on this port if resolved.txt exists
        if [[ -f "$IN_RESOLVED" && -s "$IN_RESOLVED" ]]; then
            while IFS= read -r sub; do
                [[ -z "$sub" ]] && continue
                case "$port" in
                    443)  echo "https://${sub}" >> "$RAW_TARGETS" ;;
                    80)   echo "http://${sub}" >> "$RAW_TARGETS" ;;
                    8443|4443|9443) echo "https://${sub}:${port}" >> "$RAW_TARGETS" ;;
                    *)    echo "http://${sub}:${port}" >> "$RAW_TARGETS"
                          echo "https://${sub}:${port}" >> "$RAW_TARGETS" ;;
                esac
            done < <(grep -w "$ip" "$IN_RESOLVED" 2>/dev/null | awk '{print $1}')
        fi
    done < "$COMBINED_PORTS"
    ((MERGED_SOURCES++)) || true
fi

# 6. Resolved subdomains on standard ports (:80 / :443)
if [[ -f "$IN_RESOLVED" && -s "$IN_RESOLVED" ]]; then
    local_count=$(count_lines "$IN_RESOLVED")
    info "Merging resolved subdomains on standard ports (resolved.txt: $local_count domains)"
    awk '{
        subdomain = $1
        if (subdomain != "") {
            print "https://" subdomain
            print "http://" subdomain
        }
    }' "$IN_RESOLVED" >> "$RAW_TARGETS"
    ((MERGED_SOURCES++)) || true
fi

# Check if any targets were gathered
if [[ ! -s "$RAW_TARGETS" ]]; then
    error "No input found from any source (ports, vhosts, or resolved subdomains)"
    error "Please run 02_resolve.sh, 04_vhost.sh, or 05_portscan.sh first"
    exit 1
fi

sort -u "$RAW_TARGETS" | awk 'NF' > "$PROBE_LIST"
TOTAL=$(count_lines "$PROBE_LIST")
success "Merged & Deduplicated from $MERGED_SOURCES sources → Total $TOTAL unique URLs to probe"

# ──────────────────────────────────────────────
# Run httpx
# ──────────────────────────────────────────────
step "Running httpx"

if ! cmd_exists httpx; then
    error "httpx not found"
    error "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    exit 1
fi

HTTPX_RAW="${TEMP_DIR}/httpx_raw.json"

httpx \
    -l "$PROBE_LIST" \
    -title \
    -tech-detect \
    -server \
    -status-code \
    -content-length \
    -follow-redirects \
    -max-redirects 3 \
    -timeout 15 \
    -threads 50 \
    -retries 2 \
    -no-color \
    -json \
    -silent \
    2>/dev/null > "$HTTPX_RAW" || true

# ──────────────────────────────────────────────
# Parse JSON → live.txt, dead.txt, interesting.txt
# ──────────────────────────────────────────────
step "Parsing results"

# Keywords that flag interesting targets
INTERESTING_PATTERNS=(
    "admin" "login" "panel" "portal" "dashboard" "manage" "manager" "management"
    "api" "swagger" "graphql" "rest" "v1" "v2" "v3"
    "dev" "staging" "test" "qa" "beta" "preview" "uat" "sandbox"
    "git" "jenkins" "gitlab" "github" "ci" "cd" "build" "deploy"
    "kibana" "grafana" "prometheus" "sonarqube" "rancher" "k8s"
    "phpmyadmin" "adminer" "dbadmin"
    "jira" "confluence" "bitbucket" "trello"
    "upload" "backup" "console" "shell" "terminal"
    "intranet" "internal" "corp" "vpn"
    "oauth" "sso" "auth" "token" "jwt" "saml"
    "actuator" "metrics" "health" "debug" "trace"
)

python3 - "$HTTPX_RAW" "$OUT_LIVE" "$OUT_DEAD" "$OUT_JSON" "$OUT_INTERESTING" \
    "${INTERESTING_PATTERNS[@]}" <<'PYEOF'
import sys, json, re

raw_file     = sys.argv[1]
live_file    = sys.argv[2]
dead_file    = sys.argv[3]
json_file    = sys.argv[4]
interest_file= sys.argv[5]
keywords     = [k.lower() for k in sys.argv[6:]]

STATUS_COLORS = {
    "2": "✅",  # 2xx green
    "3": "↪️ ",  # 3xx redirect
    "4": "🔒",  # 4xx forbidden/not found
    "5": "💥",  # 5xx server error
}

live_count = dead_count = interest_count = 0

with open(raw_file) as f, \
     open(live_file, "w") as lf, \
     open(dead_file, "w") as df, \
     open(json_file, "w") as jf, \
     open(interest_file, "w") as inf:

    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        jf.write(line + "\n")

        url      = obj.get("url", obj.get("input", ""))
        status   = obj.get("status-code", obj.get("status_code", 0))
        title    = obj.get("title", "").replace("\n", " ").strip()
        server   = obj.get("webserver", obj.get("server", ""))
        length   = obj.get("content-length", obj.get("content_length", 0))
        techs    = obj.get("tech", obj.get("technologies", []))

        # tech list → string
        if isinstance(techs, list):
            tech_str = ", ".join(str(t) for t in techs[:5])
        elif isinstance(techs, dict):
            tech_str = ", ".join(techs.keys())
        else:
            tech_str = str(techs) if techs else ""

        icon   = STATUS_COLORS.get(str(status)[0], "❓") if status else "❌"
        status_str = str(status) if status else "---"

        out_line = f"{icon} [{status_str}] {url}"
        if title:    out_line += f"  | {title[:60]}"
        if server:   out_line += f"  | {server}"
        if tech_str: out_line += f"  | [{tech_str}]"
        if length:   out_line += f"  ({length}b)"

        if status and 100 <= status < 600:
            lf.write(out_line + "\n")
            live_count += 1
            print(f"  {out_line}")
        else:
            df.write(out_line + "\n")
            dead_count += 1

        # Check interesting keywords
        check_str = (url + " " + title + " " + server + " " + tech_str).lower()
        for kw in keywords:
            if kw in check_str:
                inf.write(out_line + f"  [kw:{kw}]\n")
                interest_count += 1
                break

print(f"\n  Live: {live_count}  Dead: {dead_count}  Interesting: {interest_count}")
PYEOF

# Sort by status code
sort -t'[' -k2 "$OUT_LIVE" -o "$OUT_LIVE" 2>/dev/null || true

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

LIVE_COUNT=$(count_lines "$OUT_LIVE")
DEAD_COUNT=$(count_lines "$OUT_DEAD")
INTERESTING_COUNT=$(count_lines "$OUT_INTERESTING")

summary_box "07 HTTP PROBE" \
    "Domain" "$DOMAIN" \
    "Probed" "$TOTAL URLs" \
    "Live" "$LIVE_COUNT" \
    "Dead/timeout" "$DEAD_COUNT" \
    "Interesting" "$INTERESTING_COUNT" \
    "Elapsed" "$ELAPSED_FMT" \
    "Next" "08_triage.sh $DOMAIN"

if [[ "$INTERESTING_COUNT" -gt 0 ]]; then
    step "★ Interesting targets"
    while IFS= read -r line; do
        echo -e "  ${MAGENTA}★${RESET}  $line"
    done < "$OUT_INTERESTING"
fi
