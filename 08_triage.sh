#!/usr/bin/env bash
# =============================================================================
# 08_triage.sh — Target Prioritization + JS Analysis
#
# Tier targets for pentest priority:
#   Tier 1 = admin/api/dev/staging — HIGH value, attack first
#   Tier 2 = old tech / unusual ports / interesting headers
#   Tier 3 = main app, static, CDN-fronted
#
# Also:
#   - Extract API endpoints from JS files (getJS + gau + katana)
#   - Find secrets in JS (secretfinder / trufflehog)
#   - Extract links from live pages
#
# INPUT : output/<domain>/http/live.txt      — httpx live results
#         output/<domain>/http/all.json      — httpx full JSON
#         output/<domain>/services/parsed.txt
# OUTPUT: output/<domain>/triage/tier1.txt
#         output/<domain>/triage/tier2.txt
#         output/<domain>/triage/tier3.txt
#         output/<domain>/triage/js_endpoints.txt
#         output/<domain>/triage/js_secrets.txt
#         output/<domain>/triage/report.md   — pentest summary
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

[[ $# -lt 1 ]] && { usage "$0 <domain>"; exit 1; }
DOMAIN="$(normalize_domain "$1")"

OUT_DIR="$(output_dir "$DOMAIN")"
TRIAGE_DIR="${OUT_DIR}/triage"
mkdir -p "$TRIAGE_DIR"

IN_LIVE="${OUT_DIR}/http/live.txt"
IN_JSON="${OUT_DIR}/http/all.json"
IN_SERVICES="${OUT_DIR}/services/parsed.txt"
IN_SUBDOMAINS="${OUT_DIR}/subdomains.txt"
OUT_TIER1="${TRIAGE_DIR}/tier1.txt"
OUT_TIER2="${TRIAGE_DIR}/tier2.txt"
OUT_TIER3="${TRIAGE_DIR}/tier3.txt"
OUT_JS_EP="${TRIAGE_DIR}/js_endpoints.txt"
OUT_JS_SEC="${TRIAGE_DIR}/js_secrets.txt"
OUT_REPORT="${TRIAGE_DIR}/report.md"
LOG_FILE="${OUT_DIR}/logs/08_triage.log"
TEMP_DIR="$(mktemp -d)"; trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "${OUT_DIR}/logs"
exec > >(tee -a "$LOG_FILE") 2>&1

> "$OUT_TIER1"; > "$OUT_TIER2"; > "$OUT_TIER3"
> "$OUT_JS_EP"; > "$OUT_JS_SEC"; > "$OUT_REPORT"

banner "08 — Triage & Prioritization" "$DOMAIN"

START_TIME=$(date +%s)

# ══════════════════════════════════════════════════════════════════
# STEP 1: Tiering from httpx JSON
# ══════════════════════════════════════════════════════════════════
step "Step 1/4 — Tiering targets"
info "Tier 1: admin/api/dev/staging/ci/db"
info "Tier 2: old tech, unusual ports, error pages"
info "Tier 3: main app, static content"

if [[ -f "$IN_JSON" && -s "$IN_JSON" ]]; then
    python3 - "$IN_JSON" "$OUT_TIER1" "$OUT_TIER2" "$OUT_TIER3" <<'PYEOF'
import sys, json, re
from urllib.parse import urlparse

json_file = sys.argv[1]
t1_file   = sys.argv[2]
t2_file   = sys.argv[3]
t3_file   = sys.argv[4]

T1_KEYWORDS = {
    "admin", "administrator", "panel", "portal", "dashboard",
    "manage", "manager", "management", "control", "console",
    "api", "graphql", "swagger", "openapi", "rest",
    "dev", "development", "developer", "staging", "test", "qa", "uat",
    "beta", "preview", "sandbox", "debug",
    "git", "gitlab", "github", "jenkins", "ci", "build", "deploy", "pipeline",
    "kibana", "grafana", "prometheus", "jaeger", "sonar",
    "phpmyadmin", "adminer", "dbadmin", "redis", "mongo",
    "jira", "confluence", "bitbucket",
    "upload", "backup", "internal", "intranet", "corp",
    "auth", "oauth", "sso", "saml", "identity",
    "actuator", "metrics", "health", "trace", "debug",
}

T2_OLD_TECH = {
    "iis/6", "iis/7", "apache/1", "apache/2.0", "apache/2.2",
    "php/4", "php/5", "php/7.0", "php/7.1",
    "tomcat/5", "tomcat/6", "tomcat/7", "tomcat/8",
    "jboss", "weblogic", "websphere", "struts",
    "openssl/0", "openssl/1.0",
}

T2_INTERESTING_STATUS = {403, 401, 500, 503}

t1, t2, t3 = [], [], []

with open(json_file) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except:
            continue

        url    = obj.get("url", obj.get("input", ""))
        status = obj.get("status-code", obj.get("status_code", 0))
        title  = obj.get("title", "").lower()
        server = (obj.get("webserver", obj.get("server", "")) or "").lower()
        techs  = obj.get("tech", obj.get("technologies", []))
        if isinstance(techs, dict):
            techs = list(techs.keys())

        parsed = urlparse(url)
        host   = parsed.netloc.lower()
        path   = parsed.path.lower()

        # Tier 1 check
        host_parts = re.split(r'[\.\-]', host.split(':')[0])
        is_t1 = any(kw in host_parts or kw in path for kw in T1_KEYWORDS)
        is_t1 = is_t1 or any(kw in title for kw in T1_KEYWORDS)

        # Tier 2 check
        server_old = any(ot in server for ot in T2_OLD_TECH)
        tech_old   = any(ot in (t.lower() for t in techs) for ot in T2_OLD_TECH)
        unusual_port = (
            parsed.port is not None
            and parsed.port not in (80, 443, 8080, 8443)
        )
        interesting_status = status in T2_INTERESTING_STATUS

        is_t2 = not is_t1 and (server_old or tech_old or unusual_port or interesting_status)

        entry = {
            "url": url,
            "status": status,
            "title": obj.get("title", ""),
            "server": obj.get("webserver", ""),
            "tech": ", ".join(str(t) for t in techs[:4]),
        }

        if is_t1:
            t1.append(entry)
        elif is_t2:
            t2.append(entry)
        else:
            t3.append(entry)

def write_tier(lst, path, label):
    with open(path, "w") as f:
        for e in sorted(lst, key=lambda x: x["status"]):
            line = f"[{e['status']}] {e['url']}"
            if e['title']: line += f"  | {e['title'][:60]}"
            if e['server']: line += f"  | {e['server']}"
            if e['tech']: line += f"  | [{e['tech']}]"
            f.write(line + "\n")
            print(f"  {label}  {line}")

print(f"\n  Tier 1 ({len(t1)}):")
write_tier(t1, t1_file, "🔴")
print(f"\n  Tier 2 ({len(t2)}):")
write_tier(t2, t2_file, "🟡")
print(f"\n  Tier 3 ({len(t3)}):")
write_tier(t3, t3_file, "🟢")
PYEOF

else
    warn "No httpx JSON found ($IN_JSON) — cannot tier"
fi

T1_COUNT=$(count_lines "$OUT_TIER1")
T2_COUNT=$(count_lines "$OUT_TIER2")
T3_COUNT=$(count_lines "$OUT_TIER3")
success "Tier 1: $T1_COUNT  |  Tier 2: $T2_COUNT  |  Tier 3: $T3_COUNT"

# ══════════════════════════════════════════════════════════════════
# STEP 2: JS endpoint extraction
# ══════════════════════════════════════════════════════════════════
step "Step 2/4 — JS Endpoint Extraction"

LIVE_URLS="${TEMP_DIR}/live_urls.txt"
[[ -f "$IN_JSON" ]] && python3 -c "
import sys, json
for line in open('$IN_JSON'):
    try:
        obj = json.loads(line)
        print(obj.get('url', obj.get('input','')))
    except: pass
" > "$LIVE_URLS" 2>/dev/null || true

JS_RAW="${TEMP_DIR}/js_files.txt"

if cmd_exists katana; then
    info "Tool: katana (JS crawler)"
    katana \
        -list "$LIVE_URLS" \
        -silent \
        -jc \
        -d 2 \
        -timeout 10 \
        2>/dev/null | grep "\.js" | sort -u > "$JS_RAW" || true

elif cmd_exists getJS; then
    info "Tool: getJS"
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        getJS --url "$url" --complete 2>/dev/null >> "$JS_RAW" || true
    done < "$LIVE_URLS"
    sort -u "$JS_RAW" -o "$JS_RAW" 2>/dev/null || true

else
    warn "Neither katana nor getJS found — skipping JS crawl"
    warn "Install katana: go install github.com/projectdiscovery/katana/cmd/katana@latest"
fi

# Extract endpoints from JS files
if [[ -f "$JS_RAW" && -s "$JS_RAW" ]]; then
    JS_FILE_COUNT=$(count_lines "$JS_RAW")
    info "Found $JS_FILE_COUNT JS files — extracting endpoints..."

    while IFS= read -r js_url; do
        [[ -z "$js_url" ]] && continue
        # Download and grep for API paths
        curl -sk -m 10 "$js_url" 2>/dev/null \
            | grep -oP '["'"'"'][/][a-zA-Z0-9_/\-]{3,100}["'"'"']' \
            | tr -d '"'"'" \
            | grep -E '^/[a-z]' \
            | sort -u
    done < "$JS_RAW" | sort -u > "$OUT_JS_EP" 2>/dev/null || true

    EP_COUNT=$(count_lines "$OUT_JS_EP")
    success "Extracted $EP_COUNT unique API endpoints from JS"
fi

# ══════════════════════════════════════════════════════════════════
# STEP 3: Secret scanning in JS
# ══════════════════════════════════════════════════════════════════
step "Step 3/4 — Secret Scanning (JS files)"

if [[ -f "$JS_RAW" && -s "$JS_RAW" ]]; then
    # Regex patterns for common secrets
    python3 - "$JS_RAW" "$OUT_JS_SEC" <<'PYEOF'
import sys, re, urllib.request, urllib.error

js_list_file = sys.argv[1]
out_file     = sys.argv[2]

SECRET_PATTERNS = {
    "AWS_KEY":       r'AKIA[0-9A-Z]{16}',
    "AWS_SECRET":    r'aws.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
    "GOOGLE_API":    r'AIza[0-9A-Za-z\\-_]{35}',
    "PRIVATE_KEY":   r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "API_KEY":       r'["\']api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
    "SECRET_KEY":    r'["\']secret[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
    "PASSWORD":      r'["\']password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
    "TOKEN":         r'["\']token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-.]{20,}["\']',
    "FIREBASE":      r'[a-zA-Z0-9_-]+\.firebaseio\.com',
    "SLACK_TOKEN":   r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
    "GH_TOKEN":      r'ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}',
    "JWT":           r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    "INTERNAL_IP":   r'(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+',
    "MONGO_URI":     r'mongodb(\+srv)?://[^"\'<> ]{10,}',
    "DB_CONN":       r'(mysql|postgresql|redis)://[^"\'<> ]{10,}',
}

findings = []

with open(js_list_file) as f:
    js_urls = [line.strip() for line in f if line.strip()]

for url in js_urls[:50]:  # limit to first 50 JS files
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        content = resp.read(500_000).decode("utf-8", errors="ignore")
    except Exception:
        continue

    for name, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, content, re.IGNORECASE):
            match_str = m.group(0)
            if len(match_str) > 200:
                match_str = match_str[:200] + "..."
            finding = f"[{name}] {url}\n  Match: {match_str}"
            findings.append(finding)
            print(f"  🔑 {finding}")

with open(out_file, "w") as out:
    for f in sorted(set(findings)):
        out.write(f + "\n\n")

print(f"\n  Secrets found: {len(findings)}")
PYEOF
fi

# ══════════════════════════════════════════════════════════════════
# STEP 4: Generate Pentest Report (Markdown)
# ══════════════════════════════════════════════════════════════════
step "Step 4/4 — Generating Pentest Report"

NOW=$(date '+%Y-%m-%d %H:%M')
SUBDOMAIN_COUNT=$(count_lines "$IN_SUBDOMAINS" 2>/dev/null || echo 0)
RESOLVED_COUNT=$(count_lines "${OUT_DIR}/resolved.txt" 2>/dev/null || echo 0)
ORIGIN_IP_COUNT=$(count_lines "${OUT_DIR}/origin_ips.txt" 2>/dev/null || echo 0)
CDN_IP_COUNT=$(count_lines "${OUT_DIR}/cdn_ips.txt" 2>/dev/null || echo 0)
VHOST_COUNT=$(count_lines "${OUT_DIR}/vhosts/all_vhosts.txt" 2>/dev/null || echo 0)
OPEN_PORTS_COUNT=$(count_lines "${OUT_DIR}/ports/open.txt" 2>/dev/null || echo 0)
SVC_COUNT=$(count_lines "${OUT_DIR}/services/parsed.txt" 2>/dev/null || echo 0)
LIVE_COUNT=$(count_lines "${OUT_DIR}/http/live.txt" 2>/dev/null || echo 0)
JS_EP_COUNT=$(count_lines "$OUT_JS_EP" 2>/dev/null || echo 0)
SECRET_COUNT=$(count_lines "$OUT_JS_SEC" 2>/dev/null || echo 0)

cat > "$OUT_REPORT" <<MDEOF
# Recon Report — ${DOMAIN}
**Generated:** ${NOW}

---

## Summary

| Metric | Count |
|---|---|
| Subdomains found | ${SUBDOMAIN_COUNT} |
| DNS resolved | ${RESOLVED_COUNT} |
| Origin IPs | ${ORIGIN_IP_COUNT} |
| CDN/WAF IPs (skipped) | ${CDN_IP_COUNT} |
| Vhosts discovered | ${VHOST_COUNT} |
| Open ports | ${OPEN_PORTS_COUNT} |
| Services detected | ${SVC_COUNT} |
| Live HTTP targets | ${LIVE_COUNT} |
| Tier 1 (high value) | ${T1_COUNT} |
| Tier 2 (interesting) | ${T2_COUNT} |
| Tier 3 (main app) | ${T3_COUNT} |
| JS API endpoints | ${JS_EP_COUNT} |
| Potential secrets | ${SECRET_COUNT} |

---

## Tier 1 — Attack First (Admin/API/Dev)
MDEOF

if [[ -f "$OUT_TIER1" && -s "$OUT_TIER1" ]]; then
    echo '```' >> "$OUT_REPORT"
    cat "$OUT_TIER1" >> "$OUT_REPORT"
    echo '```' >> "$OUT_REPORT"
else
    echo "_No Tier 1 targets found_" >> "$OUT_REPORT"
fi

cat >> "$OUT_REPORT" <<MDEOF

## Tier 2 — Old Tech / Interesting
MDEOF

if [[ -f "$OUT_TIER2" && -s "$OUT_TIER2" ]]; then
    echo '```' >> "$OUT_REPORT"
    cat "$OUT_TIER2" >> "$OUT_REPORT"
    echo '```' >> "$OUT_REPORT"
else
    echo "_No Tier 2 targets found_" >> "$OUT_REPORT"
fi

cat >> "$OUT_REPORT" <<MDEOF

## Virtual Hosts
MDEOF

if [[ -f "${OUT_DIR}/vhosts/all_vhosts.txt" && -s "${OUT_DIR}/vhosts/all_vhosts.txt" ]]; then
    echo '```' >> "$OUT_REPORT"
    head -50 "${OUT_DIR}/vhosts/all_vhosts.txt" >> "$OUT_REPORT"
    echo '```' >> "$OUT_REPORT"
fi

cat >> "$OUT_REPORT" <<MDEOF

## JS API Endpoints (sample)
MDEOF

if [[ -f "$OUT_JS_EP" && -s "$OUT_JS_EP" ]]; then
    echo '```' >> "$OUT_REPORT"
    head -30 "$OUT_JS_EP" >> "$OUT_REPORT"
    echo '```' >> "$OUT_REPORT"
fi

cat >> "$OUT_REPORT" <<MDEOF

## Potential Secrets
MDEOF

if [[ -f "$OUT_JS_SEC" && -s "$OUT_JS_SEC" ]]; then
    echo '```' >> "$OUT_REPORT"
    cat "$OUT_JS_SEC" >> "$OUT_REPORT"
    echo '```' >> "$OUT_REPORT"
else
    echo "_No secrets found_" >> "$OUT_REPORT"
fi

cat >> "$OUT_REPORT" <<MDEOF

## Services Detected
MDEOF

if [[ -f "$IN_SERVICES" && -s "$IN_SERVICES" ]]; then
    echo '```' >> "$OUT_REPORT"
    cat "$IN_SERVICES" >> "$OUT_REPORT"
    echo '```' >> "$OUT_REPORT"
fi

cat >> "$OUT_REPORT" <<MDEOF

---

## Output Files

| File | Description |
|---|---|
| subdomains.txt | All discovered subdomains |
| resolved.txt | hostname → IP mappings |
| origin_ips.txt | Non-CDN IPs (scan targets) |
| cdn_ips.txt | CDN/WAF IPs |
| vhosts/all_vhosts.txt | Verified virtual hosts |
| ports/open.txt | Open ports (ip:port) |
| services/parsed.txt | Service fingerprints |
| http/live.txt | Live HTTP targets |
| http/all.json | Full httpx JSON data |
| triage/tier1.txt | High-value targets |
| triage/js_endpoints.txt | API endpoints from JS |
| triage/js_secrets.txt | Potential secrets |
MDEOF

END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
ELAPSED_FMT=$(printf '%02d:%02d:%02d' $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))

success "Report: $OUT_REPORT"

summary_box "08 TRIAGE" \
    "Domain" "$DOMAIN" \
    "Tier 1 (attack first)" "$T1_COUNT" \
    "Tier 2 (interesting)" "$T2_COUNT" \
    "Tier 3 (main app)" "$T3_COUNT" \
    "JS endpoints" "$JS_EP_COUNT" \
    "Secrets found" "$SECRET_COUNT" \
    "Elapsed" "$ELAPSED_FMT" \
    "Report" "triage/report.md"

step "★ Tier 1 — Attack First"
if [[ "$T1_COUNT" -gt 0 ]]; then
    while IFS= read -r line; do
        echo -e "  ${RED}▶${RESET}  $line"
    done < "$OUT_TIER1"
else
    info "No Tier 1 targets"
fi
