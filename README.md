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
│   ├── closed_ips.txt      # IP không mở cổng nào (đóng hoặc bị firewall filter)
│   ├── web.txt             # Danh sách port mở chuyển tiếp
│   └── candidate_urls.txt  # URL ứng viên để probe (http(s)://subdomain:port + ip:port)
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
│   ├── tech/               # Tech-aware scan (tomcat, nginx, f5, iis, spring...)
│   │   ├── tomcat.txt
│   │   ├── nginx.txt
│   │   ├── tier1_extra.txt # Admin/API với default-logins + backup scan
│   │   └── *.json          # JSON export từng tech
│   ├── cve.txt             # CVE findings (2020–2025)
│   ├── exposure.txt        # Exposed configs/files/tokens
│   ├── misconfig.txt       # Misconfiguration findings
│   ├── vulnerabilities.txt # CORS, SSRF, JWT, LFI, XSS, SQLi
│   ├── network.txt         # Network service vulns (Redis, MongoDB, SSH...)
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
  [05] portscan → ports/open.txt + closed_ips.txt + candidate_urls.txt
      ↓
  [06] service → services/parsed.txt (+ lọc CDN banner)
      ↓
  [07] httpx → http/live.txt + interesting.txt
      ↓
  [08] triage → tier1/2/3 + js_endpoints + report.md
      ↓
  [09] nuclei →
    Tech scan: http/all.json → tech fingerprint → per-tech CVE templates
    Phase 2: live.txt → CVE (2020-2025) + exposure + misconfig + specific
    Phase 3: ports/open.txt + origin_ips.txt → network service vulns
      ↓
    nuclei/all_findings.txt  (merged, sorted by severity)
    nuclei/report.md
```

---

## setup_templates.sh — Quản lý nuclei templates

Xem tài liệu đầy đủ: [docs/setup_templates.md](docs/setup_templates.md)

Thiết lập nhanh:
```bash
./setup_templates.sh --init   # tạo /opt/nuclei-pipeline (cần sudo lần đầu)
./setup_templates.sh --tier 2 # tải ~158k templates
```

---

## 09_nuclei.sh — Nuclei vulnerability scan

Xem tài liệu đầy đủ: [docs/09_nuclei.md](docs/09_nuclei.md)

Chạy nhanh:
```bash
./scripts/09_nuclei.sh example.com           # tất cả 3 phase
./scripts/09_nuclei.sh example.com --tech     # chỉ tech-aware scan (Phase 1)
./scripts/09_nuclei.sh example.com --cve      # chỉ broad CVE sweep (Phase 2)
./scripts/09_nuclei.sh example.com --network  # chỉ network service scan (Phase 3)
```

---

## Lưu ý

- Chỉ sử dụng trên domain bạn được phép pentest
- Một số bước có thể mất nhiều thời gian (04_vhost với cross-product lớn, 06_service với nhiều IP)
- Dùng `--from N` để resume khi pipeline bị ngắt giữa chừng
- Log đầy đủ trong `output/<domain>/logs/` để debug khi có lỗi
