# 09_nuclei.sh — Tài liệu kỹ thuật

> Tài liệu này mô tả cách sử dụng, input, cơ chế hoạt động và output của `scripts/09_nuclei.sh`.

---

## Sử dụng

```bash
# Chạy qua pipeline (khuyến nghị — đảm bảo có đủ input từ bước 07+08)
./recon.sh example.com --from 07     # chạy 07 → 08 → 09 liên tiếp
./recon.sh example.com --only 09     # chỉ chạy nuclei (07+08 đã có sẵn)

# Chạy độc lập
./scripts/09_nuclei.sh example.com                           # tất cả 3 phase
./scripts/09_nuclei.sh example.com --phase 1                 # chỉ tech-aware scan
./scripts/09_nuclei.sh example.com --phase 2                 # chỉ CVE + exposure sweep
./scripts/09_nuclei.sh example.com --phase 3                 # chỉ network service scan
./scripts/09_nuclei.sh example.com --severity critical,high  # lọc severity (default: critical,high,medium)
./scripts/09_nuclei.sh example.com --rate 20                 # giảm rate (default: 50 req/s)
./scripts/09_nuclei.sh example.com --ai-templates            # bật AI-generated templates (opt-in)
```

**Flags:**

| Flag | Default | Mô tả |
|------|---------|-------|
| `--phase 1\|2\|3\|all` | `all` | Chỉ chạy phase chỉ định |
| `--severity <list>` | `critical,high,medium` | Severity filter cho nuclei |
| `--rate <N>` | `50` | Requests/giây |
| `--ai-templates` | off | Bật AI-generated templates (unverified) |

---

## Input

Script đọc output từ các bước trước trong `recon_output/<domain>/`:

| File | Từ bước | Bắt buộc | Dùng trong |
|------|---------|----------|-----------|
| `http/all.json` | 07 httpx | **Có** | Phase 1: detect tech stack, extract live URLs |
| `http/live.txt` | 07 httpx | Không | Fallback nếu không có `all.json` |
| `triage/tier1.txt` | 08 triage | Không | Phase 1: tier1 extra scan (admin/api/dev) |
| `ports/open.txt` | 05 portscan | Không | Phase 3: network targets dạng `ip:port` |
| `origin_ips.txt` | 03 cdncheck | Không | Phase 3: bare IP sweep |

> **Lưu ý:** Nếu `http/all.json` không tồn tại, script báo lỗi và thoát. Phải chạy bước 07 trước.

**Template sources** (được setup bởi `setup_templates.sh`):

| Biến | Path | Mô tả |
|------|------|-------|
| `OFFICIAL_LOCAL` | `/opt/nuclei-pipeline/nuclei-templates/` | Official templates |
| `COMMUNITY_LOCAL` | `/opt/nuclei-pipeline/community/` | Thư mục gốc community |
| `WORDFENCE_LOCAL` | `community/wordfence-cve/` | WordPress CVE |
| `FINGERPRINT_LOCAL` | `community/fingerprinthub/` | Tech fingerprint |
| `GEEKNIK_LOCAL` | `community/geeknik/` | 1-day CVE |
| `KAYALA_LOCAL` | `community/kayala/` | General community |
| `DAFFAINFO_LOCAL` | `community/daffainfo/` | Personal unique |
| `CUSTOM_LOCAL` | `pipeline/templates/custom/` | Templates tự viết |
| `AI_LOCAL` | `/opt/nuclei-pipeline/ai-generated/` | AI-gen, opt-in |

---

## Cơ chế hoạt động

### Template resolution

Script tự tìm thư mục templates theo thứ tự ưu tiên:
1. `$NUCLEI_TEMPLATES_DIR` — env override
2. `/opt/nuclei-pipeline/` — mặc định
3. `~/nuclei-pipeline/` — fallback
4. `~/nuclei-templates/` — nuclei default location, last resort

### Phase 1 — Tech-aware scan (targeted, ít noise nhất)

Đọc `http/all.json` → Python parse field `tech`/`technologies` → tạo file URL riêng theo tech → chạy nuclei với tags/templates phù hợp:

```
http/all.json
    │ python parse (substring match, lowercase)
    ├── tech_tomcat.txt   → nuclei -tags tomcat,apache   -t cves/ vulnerabilities/ misconfiguration/
    ├── tech_nginx.txt    → nuclei -tags nginx            -t cves/ vulnerabilities/ misconfiguration/
    ├── tech_iis.txt      → nuclei -tags iis,microsoft    -t cves/ ...
    ├── tech_apache.txt   → nuclei -tags apache           -t cves/ ...
    ├── tech_f5.txt       → nuclei -tags f5,bigip         -t cves/ ...
    ├── tech_spring.txt   → nuclei -tags springboot,spring,java
    ├── tech_jboss.txt    → nuclei -tags jboss,java
    ├── tech_weblogic.txt → nuclei -tags weblogic,oracle
    ├── tech_wordpress.txt→ nuclei -tags wordpress,wp
    ├── tech_jira.txt     → nuclei -tags jira,atlassian
    ├── tech_jenkins.txt  → nuclei -tags jenkins
    ├── tech_grafana.txt  → nuclei -tags grafana
    ├── tech_kibana.txt   → nuclei -tags kibana,elasticsearch
    ├── tech_php.txt      → nuclei -tags php
    └── ... (16 tech total)

triage/tier1.txt (admin/api/dev/staging URLs)
    └── nuclei -tags panel,login,admin,api,debug,backup
              -t exposures/configs/ exposures/files/ default-logins/ misconfiguration/

live_urls.txt (tất cả live targets)
    ├── FingerprintHub (18,845 templates) — không filter severity (info OK)
    ├── Wordfence CVE  (82,731 templates) — CHỈ chạy nếu detect WordPress trong http/all.json
    ├── geeknik        (224 templates)    — nếu đã cài
    ├── kayala         (42,469 templates) — nếu đã cài (Tier 2)
    ├── daffainfo      (950 templates)    — nếu đã cài (Tier 2)
    ├── AI-generated   (opt-in)           — chỉ với --ai-templates, in cảnh báo
    └── custom/<domain>/ (4 templates mbbank: tomcat, f5, api, 3ds)
```

### Phase 2 — Broad CVE + Exposure sweep (tất cả live targets)

| Sub-phase | Templates | Tag filter |
|-----------|-----------|-----------|
| 2a CVE | `cves/2020/` → `cves/2025/` + `cves/2021/` | Không (sweep theo năm) |
| 2b Exposure | `exposures/` | `exposure,config,token,log,backup,env,git,aws,cloud` |
| 2c Misconfig | `misconfiguration/` + `default-logins/` | Không |
| 2d Specific | `vulnerabilities/` | `cors,ssrf,redirect,jwt,takeover,xxe,ssti,lfi,xss,sqli` |

### Phase 3 — Network service scan

Input: `ports/open.txt` (dạng `ip:port`) + `origin_ips.txt`

Logic lọc: bỏ web ports (80, 443, 8080, 8443, 8000, 8001, 8888, 3000, 4000, 5000, 9090) → chỉ giữ non-web ports cho network templates.

```
ports/open.txt  ──┐
                  ├─ filter non-web ports ─→ nuclei -t network/
origin_ips.txt  ──┘                                 -t default-logins/ssh/
                                                    -t default-logins/ftp/
                                                    -t default-logins/redis.yaml
```

### Rate control

| Param | Default | Flag |
|-------|---------|------|
| Rate limit | 50 req/s | `--rate N` |
| Concurrency | 10 | hardcoded |
| Timeout | 10s | hardcoded |
| Bulk size | 25 targets/batch | hardcoded |
| Severity | `critical,high,medium` | `--severity` |
| Excluded tags | `dos, fuzz, headless` | hardcoded |

### Merge & Report

Sau khi 3 phase hoàn thành:
1. `find nuclei/ -name "*.txt"` → merge + `sort -u` → `all_findings.txt`
2. `find nuclei/ -name "*.json"` → merge → `all_findings.json`
3. Python parse `all_findings.json` → group by severity → group by template-id → `report.md`
4. In critical/high findings trực tiếp ra terminal

---

## Output

```
recon_output/<domain>/nuclei/
├── phase1_tech/
│   ├── tomcat.{txt,json}              # CVE + misconfig cho Tomcat targets
│   ├── nginx.{txt,json}
│   ├── iis.{txt,json}
│   ├── apache.{txt,json}
│   ├── f5.{txt,json}                  # F5 BigIP: CVE-2020-5902, CVE-2022-1388...
│   ├── spring.{txt,json}
│   ├── tier1_extra.{txt,json}         # Admin/API: default-logins + backup + panel
│   ├── fingerprinthub.{txt,json}      # Tech detection bổ sung (18,845 templates)
│   ├── wordfence_cve.{txt,json}       # WordPress CVE — chỉ có nếu detect WP
│   ├── community_geeknik.{txt,json}
│   ├── community_kayala.{txt,json}
│   ├── community_daffainfo.{txt,json}
│   ├── custom_<domain>.{txt,json}     # Templates tự viết (vd: custom_mbbank.json)
│   └── ai_generated.{txt,json}        # Chỉ có nếu dùng --ai-templates
├── phase2_cve.{txt,json}              # CVE findings (2020–2025)
├── phase2_exposure.{txt,json}         # Config/token/backup/git leak
├── phase2_misconfig.{txt,json}        # Misconfiguration + default credentials
├── phase2_specific.{txt,json}         # CORS, SSRF, JWT, LFI, XSS, SQLi
├── phase3_network.{txt,json}          # Redis/SSH/FTP/MongoDB default-logins + vulns
├── all_findings.txt                   # Tất cả findings, merged + dedup, sort by severity
├── all_findings.json                  # JSON export cho tool integration
└── report.md                          # Triage report: severity breakdown + critical/high list
```

**Format một dòng trong `all_findings.txt`:**
```
[template-id] [severity] [target-url] [matched-at]
```

**Format `report.md`:**
```markdown
# Nuclei Scan Report — <domain> — <timestamp>

## Summary
| Severity | Count |
...

## Critical Findings
### <template-id>
- **Target:** <url>
- **Matched:** <matched-value>
...
```
