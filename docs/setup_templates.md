# setup_templates.sh — Tài liệu kỹ thuật

> Tài liệu này mô tả cách sử dụng, input, cơ chế hoạt động và output của `setup_templates.sh`.

---

## Sử dụng

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
./setup_templates.sh --remove F      # xóa một source (hỏi xác nhận trước khi xóa)
./setup_templates.sh --validate      # lint tất cả templates (nuclei -validate)
```

---

## Input

Không có input file — script tự kết nối GitHub để clone/pull các repo template.

**Yêu cầu:**
- `git` trong PATH
- Kết nối internet ra `github.com`
- Quyền ghi vào `/opt/` (hoặc dùng `--init` để setup) — nếu không có thì tự fallback sang `~/nuclei-pipeline/`
- `nuclei` trong PATH (chỉ cần cho `--validate`)

---

## Cơ chế hoạt động

### Storage

Templates lưu trên **Linux filesystem** (`/opt/nuclei-pipeline/` hoặc `~/nuclei-pipeline/`), **không** trên NTFS/WSL mount để tránh lỗi `git chmod on NTFS`.

Thứ tự ưu tiên khi resolve thư mục:
1. `$NUCLEI_TEMPLATES_DIR` — env override
2. `/opt/nuclei-pipeline/` — mặc định (yêu cầu `--init` lần đầu)
3. `~/nuclei-pipeline/` — fallback tự động nếu `/opt` không writable

### Clone / Update

- Lần đầu: `git clone --depth=1 <url> <dir>`
- Lần sau: `git pull --ff-only` trong thư mục đã clone
- Spinner hiển thị progress trong khi git chạy nền
- Kiểm tra disk space trước khi clone (Wordfence yêu cầu ~350MB free)
- Partial clone (thư mục có nhưng không có `.git`) bị xóa tự động trước khi clone lại

### Tiering

Sources được phân 3 tier theo chất lượng và use-case:

| Tier | Sources | Templates | Ghi chú |
|------|---------|-----------|---------|
| 1 | A B C | ~96k | Official + Wordfence + geeknik — luôn cài |
| 2 | + F G H | ~158k | + FingerprintHub + kayala + daffainfo — **recommended** |
| 3 | + I J | ~158k+ | + fuzzing + AI-generated — opt-in, dùng cẩn thận |

### Source registry

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

### Sau khi clone

1. Build flat index `all_templates.txt` — toàn bộ đường dẫn `.yaml` (trừ fuzzing/AI)
2. Build `fuzzing_templates.txt` — index riêng cho fuzzing (opt-in)
3. Ghi `sources.txt` — lịch sử từng lần clone/pull: `[id] timestamp commit=X templates=N url`
4. Ghi `last_update.txt` — timestamp lần chạy gần nhất

### Các mode đặc biệt

| Mode | Mô tả |
|------|-------|
| `--init` | Tạo `/opt/nuclei-pipeline` + `chown $USER`, fallback về `~/nuclei-pipeline` nếu sudo thất bại. In disk space và ước tính dung lượng cần. |
| `--remove <ID>` | Hiện kích thước thư mục, hỏi xác nhận, xóa, rebuild index. |
| `--status` | Per-source: disk size, template count, số ngày kể từ commit cuối. Highlight vàng nếu > 30 ngày. In 5 dòng lịch sử gần nhất từ `sources.txt`. |
| `--check` | `git fetch` từng source, so sánh local HEAD vs remote HEAD, không pull. |
| `--validate` | `nuclei -validate -t <dir>` từng source, in template bị lỗi YAML/syntax. |

---

## Output

```
/opt/nuclei-pipeline/               (hoặc ~/nuclei-pipeline/)
├── nuclei-templates/               [A] Official templates
│   ├── cves/
│   │   ├── 2020/ … 2025/
│   ├── exposures/
│   ├── misconfiguration/
│   ├── vulnerabilities/
│   ├── network/
│   ├── default-logins/
│   └── technologies/
├── community/
│   ├── wordfence-cve/              [B] ~82,731 WordPress CVE .yaml
│   ├── geeknik/                    [C] ~224 templates
│   ├── fingerprinthub/             [F] ~18,845 fingerprint .yaml
│   ├── kayala/                     [G] ~42,469 templates
│   └── daffainfo/                  [H] ~950 templates
├── fuzzing/                        [I] opt-in only
├── ai-generated/                   [J] opt-in only
└── .meta/
    ├── all_templates.txt           flat index: đường dẫn tuyệt đối từng .yaml (trừ fuzzing/AI)
    ├── fuzzing_templates.txt       index riêng cho fuzzing
    ├── sources.txt                 lịch sử clone/pull: id, timestamp, commit, count
    └── last_update.txt             timestamp lần setup gần nhất
```

---

## Update định kỳ

```bash
./setup_templates.sh --source B     # Wordfence: hàng ngày (CVE mới liên tục)
./setup_templates.sh --tier 2       # Toàn bộ Tier 2: hàng tuần
```
