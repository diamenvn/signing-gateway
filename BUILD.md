# Cách tạo file cài đặt (.exe)

File `.exe` phải build **trên máy Windows** (không build được trên Linux/Mac vì phải nhúng Node runtime cho Windows và chạy Inno Setup).

## Cài trước (máy build, 1 lần)

1. **Node.js 20+** — https://nodejs.org
2. **Inno Setup 6** — https://jrsoftware.org/isdl.php

## Build — 1 lệnh

Mở PowerShell trong thư mục này:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Script tự làm hết:
1. Tải `cloudflared.exe`
2. Cài dependency (`npm ci`)
3. Đóng gói `server.js` → `dist\signing-gateway.exe` (nhúng sẵn Node)
4. Đóng gói tiếp thành `dist\SigningGatewaySetup.exe`

Xong. Copy **`dist\SigningGatewaySetup.exe`** sang máy chủ bệnh viện.

---

## Bộ cài làm gì khi chạy trên máy chủ

1. **Kiểm tra VNPT-CA Plugin** — nếu chưa cài thì cảnh báo (không chặn, nhưng nhắc)
2. **Wizard hỏi cấu hình:**
   - Mã bệnh viện
   - Secret dùng chung với backend HIS4 (64 hex) — kiểm tra độ dài luôn
   - Origin HIS4 (mặc định `https://his4-dev.vnpthis.vn`)
   - Cloudflare Tunnel token (để trống nếu cài tunnel sau)
3. **Ghi `config.json`** vào `C:\ProgramData\SigningGateway\`
4. **Cài Cloudflare Tunnel** dạng Windows Service (nếu có token)
5. **Đặt gateway tự chạy** mỗi khi đăng nhập Windows
6. Màn hình cuối nhắc lại chuyện PIN

Nâng cấp: cài đè lên bản cũ **không ghi đè** `config.json` và audit log.

---

## Bố trí file sau khi cài

```
C:\Program Files\SigningGateway\
    signing-gateway.exe          (chạy, không sửa)
    cloudflared.exe
    README.md

C:\ProgramData\SigningGateway\   (dữ liệu — sao lưu thư mục NÀY)
    config.json
    audit-2026-07.jsonl          (log ký, có hash chain, đừng xoá)
```

Audit log tách khỏi Program Files có chủ đích: Program Files không ghi được nếu thiếu quyền admin, và Windows sẽ "ảo hoá" file ghi vào chỗ khác — log biến mất âm thầm. Đặt ở ProgramData để tránh.

---

## ⚠️ Ký số bộ cài — không làm là bệnh viện không cho cài

`SigningGatewaySetup.exe` chưa ký sẽ bị **Windows SmartScreen** chặn với cảnh báo "Unknown publisher". Nhiều phòng CNTT bệnh viện cấm cài phần mềm dạng này.

Cần mua **code-signing certificate** (Sectigo, DigiCert... khoảng 200–400 USD/năm, hoặc EV cert đắt hơn nhưng qua SmartScreen ngay), rồi ký:

```powershell
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 `
         dist\SigningGatewaySetup.exe
```

Ký cả `signing-gateway.exe` bên trong trước khi đóng gói thì sạch hơn.

---

## Vẫn còn nguyên: chuyện PIN

Bộ cài đặt gateway **tự chạy khi đăng nhập Windows** — không phải Windows Service. Đây là bắt buộc, không phải lười:

VNPT Plugin bật hộp thoại nhập PIN. Windows Service chạy ở session 0, **không có desktop** — hộp thoại sẽ hiện ở nơi không ai bấm được, và mọi request ký treo cho tới khi timeout.

Nên máy chủ phải:
- Bật **auto-logon** vào một tài khoản Windows
- Có người nhập PIN sau mỗi lần khởi động
- **Tắt Windows Update tự động** (reboot lúc 3h sáng = sáng ra cả khoa không ký được)

Đây là giới hạn của plugin. Muốn bỏ hẳn thì phải đi đường PKCS#11 trực tiếp — truyền PIN bằng code — nhưng khi đó phải tự dựng PAdES/CMS.
