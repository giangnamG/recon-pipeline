# 02_resolve.sh — DNS Resolution & Wildcard Filter

> Tài liệu kỹ thuật mô tả cách sử dụng, input, cơ chế hoạt động và output của script `scripts/02_resolve.sh`.

---

## 1. Cách sử dụng

### 1.1. Chạy trong toàn bộ Recon Pipeline (Khuyến nghị)
```bash
# Chạy từ bước 02 trở đi
./recon.sh example.com --from 02

# Chỉ chạy duy nhất bước 02 (yêu cầu đã có kết quả từ bước 01 subdomain)
./recon.sh example.com --only 02
```

### 1.2. Chạy độc lập script
```bash
# Cú pháp cơ bản
./pipeline/scripts/02_resolve.sh example.com
```

### 1.3. Yêu cầu hệ thống / Công cụ cần thiết
* **`puredns`** (Khuyến nghị): Công cụ lọc Wildcard DNS chuyên sâu (`go install github.com/d3mondev/puredns/v2@latest`).
* **`dnsx`** (Khuyến nghị): Công cụ DNS resolver đa luồng tốc độ cao từ ProjectDiscovery (`go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest`).
* **`dig` / `bind-utils`**: Fallback dự phòng nếu máy chưa cài `dnsx`.
* **`curl`**: Dùng để tự động tải danh sách public DNS resolvers tin cậy nếu máy chưa có sẵn.

---

## 2. Input của Script

Script nhận dữ liệu từ bước `01_subdomain.sh` trong thư mục `output/<domain>/` (hoặc `recon_output/<domain>/`):

| File Input | Nguồn (Bước) | Bắt buộc | Mục đích sử dụng |
| :--- | :--- | :---: | :--- |
| `subdomains.txt` | `01_subdomain.sh` | **BẮT BUỘC** | Toàn bộ danh sách subdomains thu thập được từ bước enum trước đó. |
| `resolvers.txt` | `/usr/share/wordlists/` hoặc tải tự động | Không | Danh sách các Public DNS Resolver chất lượng cao để puredns kiểm tra wildcard. |

> [!IMPORTANT]
> Nếu file `subdomains.txt` không tồn tại hoặc rỗng, script sẽ dừng lại với thông báo lỗi yêu cầu chạy bước `01_subdomain.sh` trước.

---

## 3. Cơ chế hoạt động (Detailed Mechanism)

Quá trình phân giải DNS và lọc dữ liệu của `02_resolve.sh` được thực thi qua 2 giai đoạn nối tiếp:

```mermaid
flowchart TD
    A["Input: subdomains.txt"] --> B["Stage 1: Wildcard DNS Detection (puredns)"]
    B -->|Loại bỏ Wildcard FP| C["wildcard_filtered.txt"]
    B -->|Danh sách subdomain sạch| D["clean.txt"]
    D --> E{"Stage 2: DNS Resolution"}
    E -- "Có dnsx" --> F["dnsx -a -resp -t 100"]
    E -- "Không có dnsx" --> G["Fallback: dig +short A"]
    F --> H["Trích xuất hostname + ip"]
    G --> H
    H --> I["resolved.txt (hostname ip)"]
    H --> J["all_ips.txt (unique IPs)"]
    D -. So sánh với resolved .-> K["unresolved.txt (Ứng viên VHost Fuzzing)"]
```

### Stage 1: Phát hiện và lọc Wildcard DNS (`puredns` + `host` verification)
* **Vấn đề thực tế**: Một số tổ chức cấu hình DNS wildcard (ví dụ: `*.example.com` $\rightarrow$ IP của CDN/WAF hoặc Landing page mặc định). Khi đó, hàng ngàn subdomain rác hoặc ngẫu nhiên đều trả về IP, gây ra hàng loạt False Positive (ảo giác subdomain) và làm nghẽn bước VHost Fuzzing sau này. Tuy nhiên, nếu resolvers công cộng bị timeout hoặc `puredns` phân loại nhầm, một số subdomain hợp lệ có thể bị loại oan.
* **Cơ chế xử lý 2 lớp an toàn**:
  1. **Lớp 1 (`puredns`)**: Tìm file resolvers tại `/usr/share/wordlists/resolvers.txt` (hoặc tự động tải từ Trickest GitHub) và chạy `puredns resolve` để phát hiện wildcard.
  2. **Lớp 2 (Xác thực lại bằng `host <domain>`)**: Trước khi quyết định đưa một subdomain vào `wildcard_filtered.txt`, script chạy lệnh `host` (hoặc `dig`) trực tiếp lên domain đó:
     * Nếu kết quả trả về `not found` (hoặc `NXDOMAIN`), domain mới chính thức bị đưa vào `wildcard_filtered.txt`.
     * Nếu domain **vẫn resolve ra địa chỉ IP / CNAME hợp lệ**, chứng tỏ bước trên resolve bị thiếu/timeout; script sẽ tự động **cứu lại (Rescue)** domain đó vào danh sách sạch (`clean.txt`) để chuyển tiếp sang bước DNS resolution.

### Stage 2: Phân giải địa chỉ IP (`dnsx` / `dig`)
* **Sử dụng `dnsx` (Ưu tiên)**:
  * Thực thi:
    ```bash
    dnsx -l "$CLEAN_LIST" -a -resp -no-color -silent -timeout 10s -retry 3 -t 100
    ```
  * Truy vấn A record với 100 luồng đồng thời, tự động retry 3 lần nếu mạng chập chờn.
  * Phân tích kết quả dạng `hostname [A] [ip]` để ghi vào `resolved.txt` (`<hostname> <ip>`) và `all_ips.txt` (`<ip>`).
* **Fallback `dig`**:
  * Nếu chưa cài `dnsx`, script tự động chuyển sang vòng lặp `dig +short A <host>` để phân giải lần lượt từng tên miền.

### Stage 3: Xác định Unresolved Subdomains (VHost Candidates)
* Sử dụng lệnh `comm -23` so sánh giữa danh sách subdomain sạch (`clean.txt`) và danh sách đã phân giải được (`resolved.txt`).
* Các subdomain không có bản ghi A công cộng sẽ được lưu vào file `unresolved.txt`.
* **Ý nghĩa Pentest**: Các domain trong `unresolved.txt` là ứng viên hàng đầu cho bước `04_vhost.sh` để kiểm tra Virtual Host nội bộ (VHost Fuzzing) trên các IP Origin.

---

## 4. Output của Script

Tất cả kết quả được lưu trực tiếp tại thư mục target `output/<domain>/` (hoặc `recon_output/<domain>/`):

| File Output | Định dạng | Mô tả nội dung |
| :--- | :--- | :--- |
| `resolved.txt` | `<hostname> <ip>` | Danh sách các subdomain đã phân giải thành công kèm địa chỉ IP tương ứng. |
| `all_ips.txt` | `<ip>` | Danh sách tất cả các địa chỉ IPv4 duy nhất (loại bỏ trùng lặp) tìm được. |
| `unresolved.txt` | `<hostname>` | Danh sách các subdomain không thể phân giải ra IP công cộng (input cho `04_vhost.sh`). |
| `wildcard_filtered.txt` | `<hostname>` | Danh sách các subdomain bị loại bỏ do dính wildcard DNS. |

---

## 5. Mẫu kết quả đầu ra

### Mẫu `resolved.txt`
```text
api.mbbank.com.vn 103.12.104.29
online.mbbank.com.vn 103.12.104.78
portal.mbbank.com.vn 103.12.104.29
```

### Mẫu `all_ips.txt`
```text
103.12.104.29
103.12.104.78
125.212.138.88
```

### Mẫu `unresolved.txt`
```text
admin-internal.mbbank.com.vn
dev-api.mbbank.com.vn
staging-portal.mbbank.com.vn
```
