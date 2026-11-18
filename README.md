# Phát hiện hành vi mã độc OurNew.exe bằng Wazuh và Sysmon

> Dự án thực nghiệm giám sát và phát hiện hành vi **tạo tệp thực thi trong thư mục Temp và khởi chạy tệp đó** trên Windows 10, sử dụng **Sysmon** kết hợp **Wazuh SIEM**.

## 1. Giới thiệu dự án

Dự án nghiên cứu mẫu mã độc `OurNew.exe` trên Windows và xây dựng các quy tắc phát hiện dựa trên hành vi trong Wazuh. Kết quả phân tích tĩnh và phân tích động được sử dụng để xác định dấu hiệu cần giám sát; sau đó, một môi trường SIEM cách ly được triển khai để kiểm chứng khả năng thu thập nhật ký và tạo cảnh báo.

**Phạm vi phát hiện đã được kiểm chứng:**

- **Sysmon Event ID 11:** Ghi nhận việc tạo tệp `.exe` có tên gồm **16 ký tự thập lục phân (hex)** trong thư mục Temp.
- **Sysmon Event ID 1:** Ghi nhận việc khởi chạy tệp `.exe` có tên 16 ký tự hex từ thư mục Temp.
- **Wazuh custom rule `100510` và `100511`:** Cả hai quy tắc đã tạo cảnh báo trong lần thực thi mẫu `OurNew.exe` trên máy ảo cách ly.

Hai quy tắc này nhận diện **hành vi đáng ngờ**, không tự chứng minh mọi tệp khớp điều kiện đều là mã độc. Hai cảnh báo hiện **độc lập**; dự án chưa triển khai quy tắc tương quan tự động giữa nhiều sự kiện.

## 2. Kiến trúc hệ thống thực nghiệm

```text
Windows 10 Pro x64 (192.168.100.5)
  └── Sysmon → Microsoft-Windows-Sysmon/Operational
        └── Wazuh Agent (ID 003)
              └── Wazuh Manager 4.14.10 (192.168.100.10)
                    ├── wazuh-archives-* : Nhật ký sự kiện gốc
                    ├── wazuh-alerts-*   : Cảnh báo sau khi áp dụng rule
                    └── Wazuh Dashboard : Trực quan hóa và điều tra

Kali Linux (192.168.100.30): Truy cập Dashboard qua trình duyệt
VMware LAN Segment: Mạng nội bộ cách ly Internet
```

**Lưu ý:** Phân tích động trước đó bằng Procmon và FakeNet-NG sử dụng **một môi trường Host-only khác**. Bằng chứng mạng của môi trường này không được xem là cảnh báo mạng do Wazuh ghi nhận.

## 3. Thông tin mẫu và hành vi quan sát được

| Thuộc tính | Kết quả |
|---|---|
| Tên mẫu | `OurNew.exe` — loader PE64 viết bằng Go |
| SHA-256 của loader | `655d159778124a3e86adaa7fb139de2c107b9936f2d719b54756de98b8135deb` |
| SHA-256 của payload đã trích xuất | `0d96efdf5c9118d395a87a2a8ff2b71c7d4ca94b2f5db4e8c95be6ac3645ae5d` |
| Kết quả phân tích tĩnh | Payload nhúng trong section `.data`, được giải mã bằng RC4 và giải nén bằng zlib |
| Hành vi phân tích động | Loader tạo tệp `%TEMP%\<16 ký tự hex>.exe`, sau đó khởi chạy tệp này |
| Bằng chứng giám sát Wazuh | Sysmon Event ID **11** và **1**; cảnh báo từ rule **100510** và **100511** |

Trong một lượt thực nghiệm, Sysmon ghi nhận:

1. **18:25:48.514 UTC, ngày 16/11/2026 — Event ID 11:** `OurNew.exe` tạo tệp `058e8efac5341811.exe` trong Temp.
2. **18:25:48.519 UTC — Event ID 1:** Tệp vừa tạo được thực thi; trường `ParentImage` cho biết tiến trình cha là `C:\Sample\OurNew.exe`.

Hai sự kiện cách nhau khoảng **5 mili giây**. Tên payload thay đổi giữa các lượt chạy, vì vậy các quy tắc không gắn cứng một tên tệp cụ thể.

Trong **môi trường phân tích động riêng biệt**, Procmon và FakeNet-NG ghi nhận payload thử liên lạc tới `193.111.117.22:80` và phát sinh yêu cầu HTTP POST trong mạng mô phỏng. Tuy nhiên, **môi trường Wazuh không thu được Sysmon Event ID 3 gắn với payload**. Do đó, dự án **không khẳng định Wazuh đã phát hiện kết nối C2 hoặc hành vi đánh cắp dữ liệu**.

## 4. Hai quy tắc phát hiện Wazuh

Mã cấu hình được lưu tại [`rules/ournew_rules.xml`](rules/ournew_rules.xml).

| Rule ID | Mức cảnh báo | Điều kiện phát hiện | Cơ chế kế thừa |
|---|---:|---|---|
| `100510` | 15 | Tạo tệp EXE có tên 16 ký tự hex trong Temp | Kế thừa rule mặc định `92213` |
| `100511` | 13 | Khởi chạy tệp EXE có tên 16 ký tự hex từ Temp | Kế thừa nhóm `sysmon_event1` |

Biểu thức chính quy sử dụng trong hai rule:

```regex
(?i)Temp.*[0-9a-f]{16}\.exe$
```

Trong đó, `(?i)` cho phép không phân biệt chữ hoa/chữ thường, còn `[0-9a-f]{16}` khớp với tên gồm đúng 16 ký tự hex ở cuối đường dẫn trước phần mở rộng `.exe`.

**Nguy cơ cảnh báo nhầm:** Một số bộ cài hoặc chương trình hợp lệ cũng có thể tạo/chạy tệp EXE với cách đặt tên này. Trong thử nghiệm, một bản sao Notepad được đổi tên thành 16 ký tự hex cũng đã kích hoạt cảnh báo. Vì vậy, các mức 13 và 15 là cấu hình phục vụ lab, chưa phải đánh giá độ nguy hiểm tuyệt đối khi triển khai thực tế.

## 5. Triển khai và kiểm chứng

### 5.1. Thu thập Sysmon trên Windows 10

Cài đặt Sysmon trong máy ảo cách ly và cấu hình ghi nhận tối thiểu **Event ID 1** (tạo tiến trình) và **Event ID 11** (tạo tệp).

Trong cấu hình Wazuh Agent (`ossec.conf`), khai báo nguồn nhật ký Sysmon:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 5.2. Cài đặt rule trên Wazuh Manager

Sao chép file `rules/ournew_rules.xml` vào thư mục `/var/ossec/etc/rules/` trên Wazuh Server, sau đó kiểm tra cấu hình và nạp lại dịch vụ:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Chỉ tiếp tục khi kiểm tra cấu hình không có lỗi và trạng thái dịch vụ là `active`.

### 5.3. Quy trình xác minh

1. Kiểm tra Wazuh Agent hoạt động và nhận nhật ký từ kênh Sysmon.
2. Mở **Discover → `wazuh-archives-*`** để kiểm tra Event ID 11 và 1 của mẫu.
3. Kiểm thử logic của rule bằng `wazuh-logtest` và các nhật ký đã thu thập, đồng thời lưu ý kết quả của logtest không thay thế phép thử trên luồng Agent thực tế.
4. Kiểm chứng đường truyền cảnh báo bằng hành vi mô phỏng an toàn, ví dụ bản sao Notepad có tên dạng hex trong Temp.
5. Trong phạm vi phòng lab được phép và cách ly, đối chiếu các cảnh báo mới với tiến trình `OurNew.exe` và payload; không nhầm lẫn với cảnh báo từ Notepad.
6. Mở **Discover → `wazuh-alerts-*`** để xác nhận xuất hiện cả rule `100510` và `100511`.

### 5.4. Truy vấn DQL trên Wazuh Dashboard

**Tìm sự kiện tạo tệp của loader** (index `wazuh-archives-*`):

```text
agent.id: "003" AND data.win.system.eventID: "11" AND data.win.eventdata.image: *OurNew.exe
```

**Tìm sự kiện thực thi payload theo tiến trình cha** (index `wazuh-archives-*`):

```text
agent.id: "003" AND data.win.system.eventID: "1" AND data.win.eventdata.parentImage: *OurNew.exe
```

**Tìm cảnh báo từ hai custom rule** (index `wazuh-alerts-*`):

```text
agent.id: "003" AND (rule.id: "100510" OR rule.id: "100511")
```

**Chỉ tìm cảnh báo liên quan trực tiếp đến `OurNew.exe`** (index `wazuh-alerts-*`):

```text
agent.id: "003" AND ((rule.id: "100510" AND data.win.eventdata.image: *OurNew.exe) OR (rule.id: "100511" AND data.win.eventdata.parentImage: *OurNew.exe))
```

`agent.id = 003` và các địa chỉ IP chỉ đúng với môi trường thực nghiệm này. Khi triển khai trên hệ thống khác, cần thay theo thông tin thực tế và chọn khoảng thời gian tìm kiếm phù hợp.

**Chú ý:** Nhật ký cũ trong `wazuh-archives-*` không tự động được phân tích lại để sinh cảnh báo lịch sử sau khi thêm rule mới.

## 6. Kết quả thực nghiệm

Các kết quả đã xác nhận:

- Sysmon ghi nhận loader tạo tệp EXE trong thư mục Temp và khởi chạy payload.
- Wazuh Agent `003` chuyển các sự kiện Sysmon Event ID 11 và 1 tới Wazuh Server.
- **Rule `100510`:** Tạo cảnh báo khi mẫu tạo tệp thực thi tên hex trong Temp.
- **Rule `100511`:** Tạo cảnh báo khi payload được thực thi từ Temp.
- **Một Dashboard Wazuh:** Hiển thị số lượng cảnh báo theo `rule.id` trong khoảng thời gian được chọn.

**Giới hạn:** Chưa thu được Sysmon Event ID 3 gắn với payload trong phiên Wazuh; chưa triển khai chặn tự động hoặc rule tương quan đa sự kiện; chưa đo precision, recall hay tỷ lệ cảnh báo nhầm trên tập mẫu đủ lớn.

## 7. An toàn thực nghiệm và chia sẻ dự án

Repository này chỉ chia sẻ **quy tắc phát hiện và tài liệu nghiên cứu**. Không đưa lên GitHub tệp mã độc, payload thực thi, khóa xác thực Wazuh Agent, mật khẩu, nhật ký chứa dữ liệu nhạy cảm hoặc snapshot máy ảo.

Việc phân tích mẫu nghi vấn chỉ được thực hiện trong môi trường nghiên cứu cách ly, có khả năng hoàn nguyên và không kết nối Internet công cộng.

## 8. Tài liệu tham khảo

- Nhóm 04, *Phân tích và so sánh hai mẫu StealC V2 trên Windows bằng phương pháp kết hợp*, BTL học phần Phân tích mã độc, Học viện Công nghệ Bưu chính Viễn thông, 2026 — **chỉ sử dụng Mẫu 1 (`OurNew.exe`)**.
- Kết quả thực nghiệm Windows 10 / Sysmon / Wazuh 4.14.10, tháng 11/2026, Wazuh Agent `003`.
- [Tài liệu Wazuh](https://documentation.wazuh.com/)
- [Microsoft Sysmon — Windows Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [MITRE ATT&CK](https://attack.mitre.org/)
