# Virtual Host Discovery — Tài liệu kỹ thuật

> Tài liệu này mô tả thiết kế, data flow, output và các quyết định kỹ thuật của `04_vhost.sh`.

---

## 1. Tổng quan

`04_vhost.sh` tìm kiếm virtual host ẩn bằng 5 layer kỹ thuật khác nhau về nguyên lý.
Output chính là `vhosts/all_vhosts.txt` — danh sách hostname đã xác nhận, dedup, kèm phân loại DNS.

```
INPUT
├── resolved.txt      "hostname ip"       — từ bước 02
├── unresolved.txt    "hostname"          — từ bước 02 (CT log findings không resolve được)
└── origin_ips.txt    "ip"               — từ bước 03 (đã loại CDN/WAF/managed-service)

OUTPUT
├── vhosts/verified.txt      — Layer 0+1
├── vhosts/ffuf.txt          — Layer 2
├── vhosts/snitched.txt      — Layer 3
├── vhosts/permutations.txt  — Layer 4
└── vhosts/all_vhosts.txt    — MERGE (output chính)
```

---

## 2. Data flow chi tiết

```
LAYER 0 — Reverse DNS PTR
  host <ip> → grep hostname thuộc domain
  └─→ [TEMP] ptr_candidates.txt

LAYER 1 — Baseline-diff verify (curl --resolve)
  Logic: md5(body(random_host)) ≠ md5(body(candidate)) → confirmed
  ├── 1a: resolved.txt     × own IP        tag: direct
  ├── 1b: unresolved.txt   × origin_ips    tag: no-dns
  └── 1c: ptr_candidates   × origin_ips    tag: ptr-lookup
      (skip nếu hostname đã có trong verified.txt từ 1a)
  └─→ verified.txt  (host\tip\tproto\tsource)

LAYER 2 — ffuf Host header fuzzing
  wordlist (đã lọc bỏ known subdomains) × origin_ips
  -H "Host: FUZZ.<domain>" -ac
  + FP fallback: nếu >150 results → filter common size
  └─→ ffuf.txt  (host\tip\thttps\tffuf-{status})

LAYER 3 — TLS Cert SAN (tlsx)
  ├── 3a: tlsx SAN/CN → non-wildcard → verify_vhost()     tag: tlsx-san
  └── 3b: wildcard SAN → scoped ffuf per namespace         tag: wildcard-expanded-{status}
       *.apps.x.com → ffuf -H "Host: FUZZ.apps.x.com"
  └─→ snitched.txt  (host\tip\thttps\t{tlsx-san|wildcard-expanded-{status}})

LAYER 4 — Ripgen permutation
  feed: verified.txt + ffuf.txt + snitched.txt  → ripgen → verify_vhost()
  └─→ permutations.txt  (host\tip\tproto\tpermutation)

MERGE
  Dedup theo hostname, ưu tiên: verified > ffuf > snitched > permutations
  + dig A → dns_status: dns-resolvable | hidden-vhost
  └─→ all_vhosts.txt  (host\tip\tproto\tsource\tdns_status)
```

---

## 3. Format output files

### `verified.txt` / `ffuf.txt` / `snitched.txt` / `permutations.txt`
```
<hostname>  <ip>  <proto>  <source_tag>
```

Source tags:
| Tag | Layer | Ý nghĩa |
|-----|-------|---------|
| `direct` | 1a | Hostname resolve được, verified trên đúng IP của nó |
| `no-dns` | 1b | Hostname không resolve được (CT log findings), nhưng respond trên origin IP |
| `ptr-lookup` | 1c | Hostname tìm qua reverse DNS từ IP |
| `ffuf-{status}` | 2 | Tìm bằng wordlist fuzzing, status = HTTP status code |
| `tlsx-san` | 3a | Hostname từ TLS cert SAN/CN, verified qua baseline-diff |
| `wildcard-expanded-{status}` | 3b | Tìm bằng scoped ffuf trong namespace của wildcard SAN |
| `permutation` | 4 | Biến thể từ hostname đã biết, verified qua baseline-diff |

### `all_vhosts.txt` — output chính
```
<hostname>  <ip>  <proto>  <source>  <dns_status>
```

`dns_status`:
- `dns-resolvable` — có A record công khai (dig trả về IP)
- `hidden-vhost` — không có DNS public record → internal/staging, attack surface cao hơn

---

## 4. Conflict analysis & quyết định thiết kế

### `snitched.txt` chứa 2 loại (tlsx-san + wildcard-expanded)

**Lý do giữ chung 1 file:** Cả 2 đều có nguồn gốc từ TLS cert (3a từ SAN trực tiếp, 3b từ namespace của wildcard SAN). Bước 08 triage đọc `all_vhosts.txt` với tag đầy đủ — phân biệt được qua `source` column mà không cần tách file.

**Tag phân biệt trong all_vhosts.txt:**
```
api-internal.mbbank.com.vn   103.x.x.x   https   tlsx-san              hidden-vhost
staging.apps.mbbank.com.vn   103.x.x.x   https   wildcard-expanded-200  hidden-vhost
```

### Layer 1c chỉ skip hostname đã có trong `verified.txt`

**Lý do đúng:** Tại thời điểm 1c chạy, `ffuf.txt` và `snitched.txt` chưa có dữ liệu (Layer 2, 3 chưa chạy). Nếu PTR candidate bị verify lại ở Layer 2/3 sau đó → merge dedup theo hostname giữ entry đầu tiên (verified) → output đúng, chỉ tốn thêm vài curl call.

### Layer 4 ripgen feed từ cả 3 files

`verified.txt + ffuf.txt + snitched.txt` → ripgen tạo biến thể từ toàn bộ hostname đã tìm được.
Ví dụ: `api-internal` (từ tlsx-san) → ripgen thử `api-internal-dev`, `api-internal-stg`...

---

## 5. Khoảng trống so với blog research

| Kỹ thuật | Blog nguồn | Trạng thái |
|----------|-----------|------------|
| Reverse DNS PTR | wya.pl, cirosec | ✅ Layer 0 |
| Baseline-diff verify | wya.pl (VhostFinder) | ✅ Layer 1 — `verify_vhost()` |
| CT Log | cirosec, wya.pl | ✅ Bước 01 (`crt.sh` + `certspotter`) → `unresolved.txt` → Layer 1b |
| HTTP Host fuzzing | thehacker.recipes, six2dez | ✅ Layer 2 (`ffuf -ac`) |
| FP fallback `-fs` | six2dez, thehacker.recipes | ✅ Layer 2 — auto khi >150 results |
| TLS SAN extraction | wya.pl, cirosec | ✅ Layer 3a (`tlsx`) |
| Wildcard SAN → namespace fuzz | wya.pl (Ford 384 vhosts) | ✅ Layer 3b |
| TLS SNI fuzzing | cirosec (SNItch) | ⚠️ Covered một phần bởi tlsx probe; SNItch tool riêng có thể bổ sung |
| Permutation | six2dez | ✅ Layer 4 (`ripgen`) |
| `dns-resolvable` vs `hidden-vhost` | wya.pl (VhostFinder -verify) | ✅ Merge step |

---

## 6. Managed service filter (bước 03 + 04)

### `03_cdncheck.sh` — CIDR pre-filter

IP bị loại trước khi vào `origin_ips.txt`:

| CIDR | Service | Verified từ |
|------|---------|-------------|
| `20.190.128.0/18` | Microsoft Entra/MDM | ServiceTags_Public.json — AzureActiveDirectory |
| `40.126.0.0/18` | Microsoft Entra/MDM | ServiceTags_Public.json — AzureActiveDirectory |
| `13.107.0.0/16` | Microsoft AzureFrontDoor | ipinfo.io — AS8068/AS8075 toàn bộ /16 |
| `184.24.0.0/13` | Akamai edge | ipinfo.io — AS16625/AS20940 toàn bộ /13 |
| `13.32.0.0/15` | AWS CloudFront | ip-ranges.amazonaws.com service=CLOUDFRONT |
| `13.35.0.0/16` | AWS CloudFront | ip-ranges.amazonaws.com service=CLOUDFRONT |
| `13.224.0.0/14` | AWS CloudFront | ip-ranges.amazonaws.com service=CLOUDFRONT |

**Đã loại bỏ khỏi danh sách:**
- `52.108.0.0/14` — AzureCloud COMPUTE, target có thể tự host VM
- `23.192.0.0/11` — bao phủ `23.202.x.x` là FPT Telecom (AS18403), không phải Akamai

### `04_vhost.sh` — Hostname pattern filter

Skip cứng trước khi verify (Microsoft-managed service, không thể là infra của target):

| Pattern | Lý do |
|---------|-------|
| `^enterpriseregistration\.` | Microsoft MDM/Intune — CNAME về `windows.net` |
| `^enterpriseenrollment\.` | Microsoft MDM |
| `^msoid\.` | Microsoft Online ID |
| `^lyncdiscover\.` | Microsoft Skype for Business |

`autodiscover`, `sip` **không** bị skip vì target có thể tự host Exchange/SIP server.

---

## 7. Nguồn tham khảo

| Blog | Đóng góp kỹ thuật |
|------|------------------|
| [wya.pl — Virtual Hosting](https://wya.pl/2022/06/16/virtual-hosting-a-well-forgotten-enumeration-technique/) | Baseline-diff, PTR, wildcard SAN namespace, dns-resolvable vs hidden-vhost |
| [cirosec — SNItch](https://cirosec.de/en/news/fuzzing-vhosts-with-snitch/) | PTR per-epoch, CT log iterative, SNI-layer |
| [thehacker.recipes — VHost Fuzzing](https://www.thehacker.recipes/web/recon/virtual-host-fuzzing) | ffuf `-ac`, filter strategies |
| [six2dez — pentest-book](https://github.com/six2dez/pentest-book/blob/master/enumeration/web/vhosts.md) | Tool matrix, `-fs`/`-fc` fallback |
