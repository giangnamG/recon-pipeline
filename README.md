# recon-pipeline

Pipeline recon tự động cho pentest, gồm 9 bước từ subdomain enumeration đến nuclei vulnerability scan.

---

## Yêu cầu

### Bắt buộc
```bash
# Go tools
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/OJ/gobuster/v3@latest

# System
sudo apt install nmap amass
```

### Tùy chọn (tăng chất lượng kết quả)
```bash
go install github.com/d3mondev/puredns/v2@latest                    # lọc wildcard DNS
go install github.com/projectdiscovery/katana/cmd/katana@latest    # crawl JS
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest        # TLS cert SAN extraction
cargo install ripgen                                                 # permutation vhost
```

### Nuclei (bước 09)
```bash
# Cài nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Lần đầu: tải templates về /opt/nuclei-pipeline/ (Linux ext4, không phải NTFS)
./setup_templates.sh --init          # tạo /opt/nuclei-pipeline + chown
./setup_templates.sh --tier 2        # tải ~158k templates (Tier 1 + Tier 2)
```

### Wordlists (SecLists)
```bash
sudo apt install seclists
# hoặc: git clone https://github.com/danielmiessler/SecLists /usr/share/wordlists/seclists
```

---

## Cài đặt

```bash
git clone https://github.com/giangnamG/recon-pipeline.git
cd recon-pipeline
chmod +x *.sh
chmod +x setup_templates.sh
```

---

## Sử dụng

### Chạy toàn bộ pipeline
```bash
./recon.sh <domain>

# Ví dụ:
./recon.sh example.com
```

### Tiếp tục từ bước N (khi bị gián đoạn)
```bash
./recon.sh <domain> --from <số bước>

# Ví dụ: đã chạy xong bước 1-2, tiếp tục từ bước 3
./recon.sh example.com --from 03
```

### Chạy chỉ 1 bước
```bash
./recon.sh <domain> --only <số bước>

# Ví dụ: chỉ chạy HTTP probing
./recon.sh example.com --only 07
```

---

## Các bước trong pipeline

| Bước | Script | Chức năng |
|------|--------|-----------|
| 01 | `01_subdomain.sh` | Thu thập subdomain (passive + active bruteforce) |
| 02 | `02_resolve.sh` | Resolve DNS, lọc wildcard, lấy danh sách IP |
| 03 | `03_cdncheck.sh` | Phân loại IP: CDN/WAF (bỏ qua) vs origin (giữ lại) |
| 04 | `04_vhost.sh` | Tìm virtual host ẩn qua 5 lớp: PTR / curl / ffuf / TLS-SAN+wildcard / ripgen |
| 05 | `05_portscan.sh` | Scan port với naabu, build danh sách URL có port |
| 06 | `06_service.sh` | Detect service/version với nmap, lọc CDN qua banner |
| 07 | `07_httpx.sh` | Probe HTTP: status code, title, tech stack, server |
| 08 | `08_triage.sh` | Phân tier mục tiêu, extract JS endpoint, tìm secret |
| 09 | `09_nuclei.sh` | Nuclei vuln scan: tech-aware + CVE sweep + network scan |

---

## Kết quả

Tất cả output lưu trong `output/<domain>/`:

```
output/example.com/
├── subdomains.txt          # Toàn bộ subdomain tìm được
├── resolved.txt            # hostname → IP
├── unresolved.txt          # Subdomain không resolve được (vhost candidates)
├── all_ips.txt             # Danh sách IP unique
├── origin_ips.txt          # IP thật (đã loại CDN/WAF)
├── cdn_ips.txt             # IP CDN/WAF (bỏ qua)
├── vhosts/
│   ├── verified.txt        # Vhost xác nhận qua curl baseline-diff (tags: direct, no-dns, ptr-lookup)
│   ├── ffuf.txt            # Vhost tìm qua ffuf Host fuzzing
│   ├── snitched.txt        # Vhost tìm qua TLS-SAN + wildcard scoped fuzz
│   ├── permutations.txt    # Vhost tìm qua ripgen permutation
│   └── all_vhosts.txt      # Tổng hợp: host, ip, proto, source, dns_status
├── ports/
│   ├── open.txt            # ip:port đang mở
│   ├── web.txt             # Chỉ web ports
│   └── vhost_urls.txt      # URL đầy đủ (https://subdomain:port)
├── services/
│   ├── parsed.txt          # ip:port service version
│   ├── interesting.txt     # Service đáng chú ý
│   └── cdn_by_banner.txt   # CDN phát hiện qua banner (bị lọc ra)
├── http/
│   ├── live.txt            # Target HTTP đang sống
│   ├── dead.txt            # Target không phản hồi
│   ├── interesting.txt     # Target có keyword nhạy cảm (admin/api/dev...)
│   └── all.json            # Toàn bộ dữ liệu httpx dạng JSON
├── triage/
│   ├── tier1.txt           # 🔴 Ưu tiên cao: admin/api/dev/staging/ci
│   ├── tier2.txt           # 🟡 Đáng xem: tech cũ, port lạ, lỗi 4xx/5xx
│   ├── tier3.txt           # 🟢 Ứng dụng chính
│   ├── js_endpoints.txt    # API endpoint trích từ file JS
│   ├── js_secrets.txt      # Secret key/token tiềm năng trong JS
│   └── report.md           # Báo cáo tổng hợp
├── nuclei/
│   ├── phase1_tech/        # Tech-aware scan (tomcat, nginx, f5, iis, spring...)
│   │   ├── tomcat.txt
│   │   ├── nginx.txt
│   │   ├── tier1_extra.txt # Admin/API với default-logins + backup scan
│   │   └── *.json          # JSON export từng tech
│   ├── phase2_cve.txt      # CVE findings (2020–2025)
│   ├── phase2_exposure.txt # Exposed configs/files/tokens
│   ├── phase2_misconfig.txt# Misconfiguration findings
│   ├── phase2_specific.txt # CORS, SSRF, JWT, LFI, XSS, SQLi
│   ├── phase3_network.txt  # Network service vulns (Redis, MongoDB, SSH...)
│   ├── all_findings.txt    # Merged, dedup, sorted by severity
│   ├── all_findings.json   # JSON export cho integration
│   └── report.md           # Nuclei triage report
└── logs/                   # Log từng bước
    ├── 01_subdomain.log
    ├── 02_resolve.log
    └── ...
```

---

## Luồng dữ liệu

```
subdomains.txt
      ↓
  [02] resolve → resolved.txt + all_ips.txt
      ↓
  [03] cdncheck → origin_ips.txt (loại CDN)
      ↓
  [04] vhost → vhosts/all_vhosts.txt
      ↓
  [05] portscan → ports/open.txt + vhost_urls.txt
      ↓
  [06] service → services/parsed.txt (+ lọc CDN banner)
      ↓
  [07] httpx → http/live.txt + interesting.txt
      ↓
  [08] triage → tier1/2/3 + js_endpoints + report.md
      ↓
  [09] nuclei →
    Phase 1: http/all.json → tech fingerprint → per-tech CVE templates
    Phase 2: live.txt → CVE (2020-2025) + exposure + misconfig + specific
    Phase 3: ports/open.txt + origin_ips.txt → network service vulns
      ↓
    nuclei/all_findings.txt  (merged, sorted by severity)
    nuclei/report.md
```

---

## setup_templates.sh — Quản lý nuclei templates

### Sử dụng

```bash
# Lần đầu thiết lập
./setup_templates.sh --init          # tạo /opt/nuclei-pipeline + chown (cần sudo)
./setup_templates.sh --tier 2        # tải ~158k templates về disk

# Cập nhật
./setup_templates.sh --tier 2        # update tất cả Tier 2 (recommended)
./setup_templates.sh --source B      # chỉ update một source (vd: Wordfence daily)

# Kiểm tra
./setup_templates.sh                 # help + trạng thái hiện tại
./setup_templates.sh --list          # đếm templates từng source + category breakdown
./setup_templates.sh --status        # health check: disk usage, tuổi, outdated
./setup_templates.sh --check         # xem updates có sẵn mà không pull

# Quản lý
./setup_templates.sh --remove F      # xóa một source (hỏi xác nhận)
./setup_templates.sh --validate      # lint tất cả templates (nuclei -validate)
```

### Input

Không có input file — script tự kết nối GitHub để clone/pull các repo template.

Cần có:
- `git` trong PATH
- Kết nối internet ra `github.com`
- Quyền ghi vào `/opt/` (hoặc dùng `--init` để setup) — nếu không có thì fallback tự động sang `~/nuclei-pipeline/`

### Cơ chế hoạt động

**Storage:** Templates lưu trên Linux filesystem (`/opt/nuclei-pipeline/` hoặc `~/nuclei-pipeline/`), **không** trên NTFS/WSL mount để tránh lỗi `git chmod`. Có thể override bằng `export NUCLEI_TEMPLATES_DIR=/path/to/dir`.

**Clone/Update:** Mỗi source được `git clone --depth=1` lần đầu, sau đó `git pull --ff-only` mỗi lần chạy lại. Có spinner hiển thị progress và kiểm tra disk space trước khi clone (Wordfence yêu cầu ~350MB free).

**Tiering:** Sources được phân 3 tier theo chất lượng và use-case:

| Tier | Sources | Templates | Ghi chú |
|------|---------|-----------|---------|
| 1 | A B C | ~96k | Official + Wordfence + geeknik — luôn cài |
| 2 | + F G H | ~158k | + FingerprintHub + kayala + daffainfo — **recommended** |
| 3 | + I J | ~158k+ | + fuzzing + AI-generated — opt-in, dùng cẩn thận |

**Source registry:**

| ID | Repo | Templates | Mô tả |
|----|------|-----------|-------|
| A | `projectdiscovery/nuclei-templates` | 13,717 | Official, verified, cập nhật hàng ngày |
| B | `topscoder/nuclei-wordfence-cve` | 82,731 | WordPress CVE từ Wordfence intel, cập nhật hàng ngày |
| C | `geeknik/the-nuclei-templates` | 224 | 1-day CVE + bug bounty research |
| F | `0x727/FingerprintHub` | 18,845 | Tech fingerprint detection |
| G | `0xKayala/Custom-Nuclei-Templates` | 42,469 | Community general |
| H | `daffainfo/my-nuclei-templates` | 950 | Personal, unique findings |
| I | `projectdiscovery/fuzzing-templates` | — | Fuzzing only, không chạy mặc định |
| J | `projectdiscovery/nuclei-templates-ai` | — | AI-generated, chưa verified |

**Sau khi clone:** Build flat index `all_templates.txt` (toàn bộ `.yaml` trừ fuzzing/AI), ghi `sources.txt` (lịch sử clone/pull với commit hash + số template).

### Output

```
/opt/nuclei-pipeline/
├── nuclei-templates/          [A] Official templates
│   ├── cves/
│   │   ├── 2020/ … 2025/
│   ├── exposures/
│   ├── misconfiguration/
│   ├── vulnerabilities/
│   ├── network/
│   ├── default-logins/
│   └── technologies/
├── community/
│   ├── wordfence-cve/         [B] ~82,731 WordPress CVE .yaml
│   ├── geeknik/               [C] ~224 templates
│   ├── fingerprinthub/        [F] ~18,845 fingerprint .yaml
│   ├── kayala/                [G] ~42,469 templates
│   └── daffainfo/             [H] ~950 templates
├── fuzzing/                   [I] opt-in only
├── ai-generated/              [J] opt-in only
└── .meta/
    ├── all_templates.txt      # flat index: đường dẫn tuyệt đối từng .yaml
    ├── fuzzing_templates.txt  # index riêng cho fuzzing
    ├── sources.txt            # lịch sử clone/pull: id, timestamp, commit, count
    └── last_update.txt        # timestamp lần setup gần nhất
```

### Update định kỳ

```bash
./setup_templates.sh --source B      # Wordfence: hàng ngày (CVE mới liên tục)
./setup_templates.sh --tier 2        # Toàn bộ Tier 2: hàng tuần
```

---

## 09_nuclei.sh — Nuclei vulnerability scan

### Sử dụng

```bash
# Chạy qua pipeline (khuyến nghị — đảm bảo có đủ input từ bước 07+08)
./recon.sh example.com --from 07     # chạy 07 → 08 → 09 liên tiếp
./recon.sh example.com --only 09     # chỉ chạy nuclei (07+08 đã có)

# Chạy độc lập
./09_nuclei.sh example.com                           # tất cả 3 phase
./09_nuclei.sh example.com --phase 1                 # chỉ tech-aware scan
./09_nuclei.sh example.com --phase 2                 # chỉ CVE + exposure sweep
./09_nuclei.sh example.com --phase 3                 # chỉ network service scan
./09_nuclei.sh example.com --severity critical,high  # lọc severity (default: critical,high,medium)
./09_nuclei.sh example.com --rate 20                 # giảm rate (default: 50 req/s)
./09_nuclei.sh example.com --ai-templates            # bật AI-generated templates (opt-in)
```

### Input

Script đọc output từ các bước trước trong `recon_output/<domain>/`:

| File | Từ bước | Dùng trong |
|------|---------|-----------|
| `http/all.json` | 07 httpx | Phase 1: detect tech stack, extract URL |
| `http/live.txt` | 07 httpx | Fallback nếu không có `all.json` |
| `triage/tier1.txt` | 08 triage | Phase 1: tier1 extra scan (admin/api/dev) |
| `ports/open.txt` | 05 portscan | Phase 3: network targets (`ip:port`) |
| `origin_ips.txt` | 03 cdncheck | Phase 3: bare IP sweep |

> Bắt buộc phải có `http/all.json` (bước 07) trước khi chạy — nếu không có, script báo lỗi và thoát.

### Cơ chế hoạt động

**Template resolution:** Script tự tìm thư mục templates theo thứ tự ưu tiên:
1. `$NUCLEI_TEMPLATES_DIR` (env override)
2. `/opt/nuclei-pipeline/` (mặc định)
3. `~/nuclei-pipeline/` (fallback)
4. `~/nuclei-templates/` (nuclei default, last resort)

**Phase 1 — Tech-aware scan (targeted, ít noise nhất)**

Đọc `http/all.json` → Python parse field `tech`/`technologies` → tạo file URL riêng theo tech → chạy nuclei với tags/templates phù hợp:

```
http/all.json
    │ python parse
    ├── tech_tomcat.txt   → nuclei -tags tomcat,apache  -t cves/ vulnerabilities/ misconfiguration/
    ├── tech_nginx.txt    → nuclei -tags nginx           -t cves/ vulnerabilities/ misconfiguration/
    ├── tech_iis.txt      → nuclei -tags iis,microsoft   -t cves/ ...
    ├── tech_f5.txt       → nuclei -tags f5,bigip         -t cves/ ...
    ├── tech_spring.txt   → nuclei -tags springboot,spring ...
    └── ... (16 tech total)

triage/tier1.txt (admin/api/dev URLs)
    └── nuclei -tags panel,login,admin,api,debug,backup
              -t exposures/configs/ exposures/files/ default-logins/ misconfiguration/

live_urls.txt (tất cả)
    ├── FingerprintHub (18,845 templates) — không filter severity
    ├── Wordfence CVE  (82,731 templates) — chỉ nếu detect WordPress trong tech field
    ├── geeknik        (224 templates)
    ├── kayala         (42,469 templates)
    ├── daffainfo      (950 templates)
    └── custom/<domain>/ (templates tự viết)
```

**Phase 2 — Broad CVE + Exposure sweep (tất cả live targets)**

| Sub-phase | Templates | Filter |
|-----------|-----------|--------|
| 2a CVE | `cves/2020/` → `cves/2025/` | Theo năm |
| 2b Exposure | `exposures/` | tags: config, token, log, backup, env, git, aws |
| 2c Misconfig | `misconfiguration/` + `default-logins/` | Không filter |
| 2d Specific | `vulnerabilities/` | tags: cors, ssrf, jwt, takeover, lfi, xss, sqli |

**Phase 3 — Network service scan (non-web ports)**

Lọc `ports/open.txt` bỏ web ports (80/443/8080/...) → chạy network templates + default-logins cho SSH, FTP, Redis. Thêm bare origin IPs để sweep.

**Rate control:**

| Param | Default | Flag |
|-------|---------|------|
| Rate limit | 50 req/s | `--rate N` |
| Concurrency | 10 | hardcoded |
| Timeout | 10s | hardcoded |
| Severity | critical,high,medium | `--severity` |
| Excluded tags | dos, fuzz, headless | hardcoded |

### Output

```
recon_output/<domain>/nuclei/
├── phase1_tech/
│   ├── tomcat.{txt,json}              # CVE + misconfig cho Tomcat targets
│   ├── nginx.{txt,json}
│   ├── iis.{txt,json}
│   ├── apache.{txt,json}
│   ├── f5.{txt,json}                  # F5 BigIP CVE (CVE-2020-5902, CVE-2022-1388...)
│   ├── spring.{txt,json}
│   ├── tier1_extra.{txt,json}         # Admin/API: default-logins + backup + panel
│   ├── fingerprinthub.{txt,json}      # Tech detection bổ sung
│   ├── wordfence_cve.{txt,json}       # WordPress CVE — chỉ có nếu detect WP
│   ├── community_geeknik.{txt,json}
│   ├── community_kayala.{txt,json}
│   ├── community_daffainfo.{txt,json}
│   ├── custom_<domain>.{txt,json}     # Templates tự viết cho target cụ thể
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

**Format `report.md`:** Groupby severity → groupby template-id → list targets bị ảnh hưởng.

---

## Lưu ý

- Chỉ sử dụng trên domain bạn được phép pentest
- Một số bước có thể mất nhiều thời gian (04_vhost với cross-product lớn, 06_service với nhiều IP)
- Dùng `--from N` để resume khi pipeline bị ngắt giữa chừng
- Log đầy đủ trong `output/<domain>/logs/` để debug khi có lỗi
