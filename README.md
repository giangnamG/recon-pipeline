# recon-pipeline

Pipeline recon tự động cho pentest, gồm 8 bước từ subdomain enumeration đến triage mục tiêu.

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
```

---

## Lưu ý

- Chỉ sử dụng trên domain bạn được phép pentest
- Một số bước có thể mất nhiều thời gian (04_vhost với cross-product lớn, 06_service với nhiều IP)
- Dùng `--from N` để resume khi pipeline bị ngắt giữa chừng
- Log đầy đủ trong `output/<domain>/logs/` để debug khi có lỗi
