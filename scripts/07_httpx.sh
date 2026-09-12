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

[[ $# -lt 1 ]] && { usage "$0 <domain>"; exit 1; }
DOMAIN="$(normalize_domain "$1")"

OUT_DIR="$(output_dir "$DOMAIN")"
HTTP_DIR="${OUT_DIR}/http"
mkdir -p "$HTTP_DIR"

IN_CANDIDATE_URLS="${OUT_DIR}/ports/candidate_urls.txt"
IN_PROBE_URLS="${OUT_DIR}/ports/probe_urls.txt"  # fallback
IN_VHOST_URLS="${OUT_DIR}/ports/vhost_urls.txt"  # legacy fallback
IN_OPEN_PORTS="${OUT_DIR}/ports/open.txt"
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
# Build probe target list
# ──────────────────────────────────────────────
PROBE_LIST="${TEMP_DIR}/probe_targets.txt"

if [[ -f "$IN_CANDIDATE_URLS" && -s "$IN_CANDIDATE_URLS" ]]; then
    info "Using: candidate URL list (ports/candidate_urls.txt)"
    cp "$IN_CANDIDATE_URLS" "$PROBE_LIST"

elif [[ -f "$IN_PROBE_URLS" && -s "$IN_PROBE_URLS" ]]; then
    info "Using: probe URL list (ports/probe_urls.txt)"
    cp "$IN_PROBE_URLS" "$PROBE_LIST"

elif [[ -f "$IN_VHOST_URLS" && -s "$IN_VHOST_URLS" ]]; then
    info "Using: legacy probe URL list (ports/vhost_urls.txt)"
    cp "$IN_VHOST_URLS" "$PROBE_LIST"

elif [[ -f "$IN_OPEN_PORTS" && -s "$IN_OPEN_PORTS" ]]; then
    info "Using: open ports list (ports/open.txt)"
    cp "$IN_OPEN_PORTS" "$PROBE_LIST"

elif [[ -f "$IN_ALL_VHOSTS" && -s "$IN_ALL_VHOSTS" ]]; then
    info "Using: verified vhosts (vhosts/all_vhosts.txt)"
    # Format: hostname<TAB>ip<TAB>proto[<TAB>source]
    # Build proto://hostname
    awk -F'\t' '{
        proto = $3
        if (proto == "") proto = "https"
        if (proto !~ /^http/) proto = "https"
        print proto "://" $1
    }' "$IN_ALL_VHOSTS" | sort -u > "$PROBE_LIST"

elif [[ -f "$IN_RESOLVED" && -s "$IN_RESOLVED" ]]; then
    info "Using: resolved subdomains (fallback: :80 + :443)"
    awk '{print "http://" $1 "\nhttps://" $1}' "$IN_RESOLVED" \
        | sort -u > "$PROBE_LIST"
else
    error "No input found — run 05_portscan.sh or 04_vhost.sh first"
    exit 1
fi

TOTAL=$(count_lines "$PROBE_LIST")
info "Targets: $TOTAL URLs to probe"

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
