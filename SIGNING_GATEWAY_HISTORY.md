# Lịch Sử Phát Triển & Giải Pháp Ký Số Im Lặng (Silent Signing Gateway)

Tài liệu này ghi lại toàn bộ các giải pháp kỹ thuật đã thử nghiệm, các giải pháp thành công (OK) và các giải pháp thất bại (Không OK) trong quá trình tối ưu hóa Gateway ký số (gỡ bỏ VNPT-CA Plugin cũ, chuyển sang luồng ký trực tiếp native).

---

## 1. Các Giải Pháp Hiện Tại Đang Hoạt Động Tốt (OK)

### 1.1 Tự Động Quét PKCS#11 Trước (Dual-Engine)
* **Giải pháp:** Khi nhận yêu cầu ký, Gateway luôn ưu tiên quét qua các driver PKCS#11 (`.dll`) tương thích trong hệ thống trước (ví dụ: `ncca_csp11_v1.dll`, `vnptca_p11_v8.dll`). Nếu tìm thấy chứng thư trùng khớp Serial, chương trình sẽ ký trực tiếp bằng PKCS#11.
* **Kết quả:** Bypass hoàn toàn 100% hộp thoại PIN của Windows CAPI/CNG, ký ngầm hoàn toàn im lặng.

### 1.2 Mở Session PKCS#11 Ở Chế Độ Read-Only
* **Giải pháp:** Sửa đổi cờ mở kết nối `cOpenSession` trong các hàm quét từ `CKF_SERIAL_SESSION | CKF_RW_SESSION` (Đọc-Ghi) thành chỉ **`CKF_SERIAL_SESSION`** (Chỉ Đọc).
* **Kết quả:** Sửa lỗi không nhận diện được USB Token của VNPT-CA. Driver của VNPT-CA có tính bảo mật cao, từ chối mọi phiên kết nối Đọc-Ghi khi quét chứng thư, chỉ cho phép phiên Chỉ Đọc.

### 1.3 Truyền PIN Khi Quét Chứng Thư PKCS#11
* **Giải pháp:** Truyền mã PIN nhận được từ API vào hàm quét chứng thư `ListCertificatesFromPkcs11` để thực hiện `cLogin` trước khi liệt kê các object.
* **Kết quả:** Tránh lỗi driver VNPT-CA bị treo cứng (deadlock). Với VNPT-CA, việc đọc thông tin chứng thư mà chưa đăng nhập (unauthenticated session) sẽ làm driver cố gắng tìm cách hiển thị hộp thoại PIN ngầm, gây đứng hình tiến trình.

### 1.4 Sử Dụng Bộ Đệm Cố Định Đủ Lớn (Pre-allocated Buffers)
* **Giải pháp:** Khai báo bộ đệm cố định lớn (512 byte cho `CKA_LABEL` và 8192 byte cho `CKA_VALUE` - Certificate data) và truyền trực tiếp con trỏ bộ đệm này vào hàm `cGetAttributeValue`.
* **Kết quả:** Tương thích với các driver không tuân thủ hoàn hảo PKCS#11 spec (như VNPT-CA, NCCA).

### 1.5 Thoát Cương Bức Tiến Trình Bằng Win32 API `TerminateProcess`
* **Giải pháp:** Khi kết thúc ký thành công hoặc thất bại trong `Program.cs`, thay vì dùng `return` hoặc `Environment.Exit`, ta sử dụng P/Invoke để gọi trực tiếp API hệ điều hành Windows:
  `Win32.TerminateProcess(Win32.GetCurrentProcess(), exitCode);`
* **Kết quả:** Khắc phục hoàn toàn lỗi tiến trình bị treo khi thoát (dẫn đến bị Gateway kill sau 15 giây và báo lỗi SCardSvr). Khi tiến trình kết thúc bình thường, .NET CLR cố giải phóng DLL và đợi các luồng chạy ngầm của driver thiết bị đóng lại, gây ra deadlock. `TerminateProcess` sẽ đóng tiến trình ngay lập tức ở tầng OS, bỏ qua mọi bước dọn dẹp lỗi của driver.

### 1.6 Luồng CNG/CAPI Fallback Im Lặng
* **Giải pháp:** Nếu luồng PKCS#11 thất bại, chương trình tự động chuyển sang luồng CAPI CSP cũ. Qua thử nghiệm ma trận chẩn đoán, ta tìm được cấu hình ký im lặng cho VNPT-CA trên CAPI:
  * `UseKeyPassword = False`
  * `Format = asc-raw` (PIN dạng ASCII nguyên bản, không chèn ký tự null `\0` ở cuối).
  * Gọi trực tiếp `CryptSetProvParam` với tham số `PP_SIGNATURE_PIN` / `PP_KEYEXCHANGE_PIN`.
* **Kết quả:** Ký im lặng thành công qua CAPI mà không hiện popup PIN của Windows.

### 1.7 Ẩn Hoàn Toàn Cửa Sổ CMD Khi Khởi Động & Ký Số
* **Giải pháp:** Cấu hình thuộc tính `{ windowsHide: true }` trong tất cả các lệnh gọi `execFile` từ `server.js` đến `pdf-signer.exe`.
* **Kết quả:** Không bao giờ xuất hiện cửa sổ CMD đen trên màn hình (cả lúc máy tính khởi động chạy ngầm lẫn lúc người dùng thực hiện ký số).

### 1.8 Tự Động Reconnect & Self-Heal Cho Cloudflare Tunnel
* **Giải pháp:** Bổ sung cơ chế giám sát log lỗi kết nối (`ERR`, `failed`, `lookup`, `dial tcp`, `lost connection`) của tiến trình `cloudflared.exe`. Nếu phát hiện lỗi liên tục trong 30 giây mà không tự phục hồi, Gateway sẽ kích hoạt bộ đếm giờ tự động restart (kill và khởi động lại tiến trình `cloudflared.exe`).
* **Kết quả:** Đảm bảo Gateway tự động kết nối lại thành công sau khi mạng bị ngắt và có trở lại mà không cần khởi động lại dịch vụ thủ công.

---

## 2. Các Giải Pháp Đã Thử Nghiệm Nhưng Thất Bại (Không OK)

### 2.1 Sử Dụng VNPT-CA Plugin/WebSocket Cũ
* **Vấn đề:** Phức tạp, phụ thuộc vào extension/plugin cài thêm của trình duyệt, dễ mất kết nối và thường xuyên hiện popup hỏi PIN gây phiền hà cho người dùng.

### 2.2 Quét PKCS#11 Không Đăng Nhập PIN (Unauthenticated Session)
* **Vấn đề:** Gây treo vĩnh viễn tiến trình `pdf-signer.exe` trên thiết bị VNPT-CA do driver cố hiển thị popup PIN ngầm ở môi trường dịch vụ không có màn hình tương tác (no UI).

### 2.3 Truy Vấn Kích Thước 2 Bước Chuẩn PKCS#11 Spec
* **Vấn đề:** Giao thức chuẩn PKCS#11 yêu cầu truyền `pValue = NULL` trước để nhận độ dài dữ liệu, sau đó mới cấp phát bộ nhớ. Tuy nhiên, cả driver VNPT-CA và NCCA đều trả về độ dài bằng `0` khi truyền pointer rỗng, dẫn đến chương trình bỏ qua chứng thư.

### 2.4 Thoát Tiến Trình Bằng `return 0` Hoặc `Environment.Exit` Thông Thường
* **Vấn đề:** Cả hai lệnh này đều kích hoạt tiến trình giải phóng tài nguyên của .NET CLR và gọi `DllMain(DLL_PROCESS_DETACH)` của driver. Driver VNPT-CA bị lỗi deadlock trong hàm giải phóng này làm tiến trình bị treo cứng 15 giây cho đến khi bị Gateway kill bằng `SIGKILL`.

### 2.5 Cơ Chế Tự Động Reconnect Mặc Định Của cloudflared
* **Vấn đề:** Khi mất mạng, tiến trình `cloudflared.exe` vẫn chạy ngầm và không tự động thoát. Tuy nhiên, nó thường bị treo vĩnh viễn ở vòng lặp lỗi DNS lookup (`no such host`) hoặc mất phiên Quick Tunnel cũ ở server Cloudflare Edge, khiến đường truyền bị đứt hẳn cho đến khi tiến trình được khởi động lại.

---

## 3. Hướng Dẫn Bảo Trì Sau Này

### 3.1 Biên Dịch Lại `pdf-signer.exe` (C#)
Chạy lệnh sau tại thư mục gốc của dự án:
```powershell
dotnet publish native-signer\pdf-signer.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -o bin
```

### 3.2 Đóng Gói Lại `signing-gateway.exe` (Node.js)
Chạy lệnh sau (sử dụng `.cmd` để tránh lỗi Execution Policy trên PowerShell):
```powershell
npm.cmd run build
```
File thực thi mới sẽ được tạo ra tại `dist\signing-gateway.exe`. Copy đè file này vào thư mục `C:\Program Files (x86)\SigningGateway\signing-gateway.exe` (cần Stop tiến trình cũ trước khi copy đè).
