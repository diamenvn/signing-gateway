# Tài Liệu Kỹ Thuật — Signing Gateway (HIS4 ⇄ USB Token)

> Phiên bản mã nguồn: `signing-gateway` v0.2.0
> Mục đích: cổng ký số PDF/XML im lặng (silent signing) cho phần mềm bệnh viện HIS4, dùng chứng thư số trên USB Token cắm tại máy chủ.

---

## 1. Tổng quan

Signing Gateway là một dịch vụ chạy ngầm trên **máy chủ ký số của bệnh viện** (Windows). Nó nhận yêu cầu ký tài liệu từ trình duyệt của người dùng HIS4, thực hiện ký số bằng chứng thư trên USB Token cắm ngay tại máy đó, rồi trả tài liệu đã ký về.

Điểm cốt lõi của thiết kế là **ký im lặng (silent signing)**: sau lần nhập PIN đầu tiên, mọi lần ký tiếp theo không bật hộp thoại PIN của Windows. Điều này đạt được bằng cách bỏ hoàn toàn plugin trình duyệt VNPT-CA cũ và thay bằng một bộ ký native viết bằng C# (`pdf-signer.exe`) giao tiếp trực tiếp với token qua **PKCS#11** hoặc **CNG/CAPI**.

### Đặc điểm chính

| Đặc điểm | Mô tả |
|---|---|
| Ký im lặng | Không bật popup PIN sau lần đầu, ưu tiên PKCS#11 → fallback CNG/CAPI |
| Hai loại tài liệu | PDF (PAdES/CMS, chữ ký visible) và XML (XMLDSig Enveloped) |
| Xác thực | Token ngắn hạn do backend HIS4 cấp, ký HMAC-SHA256 với secret dùng chung |
| Đồng bộ | `POST /v2/sign` trả tài liệu đã ký ngay trong response, không cần poll |
| Khóa độc quyền | Cơ chế lock cho phép 1 client ký nhiều file liên tục |
| Kết nối vào | Cloudflare Tunnel (không cần mở port, không cần IP tĩnh) |
| Audit | Log ký append-only có hash-chain chống sửa |
| Giám sát | Gửi cảnh báo lên Telegram (tùy chọn) |

---

## 2. Kiến trúc & luồng dữ liệu

```
   Trình duyệt (his4-dev.vnpthis.vn)
        │  HTTPS
   Cloudflare Tunnel                 (cloudflared.exe — tiến trình con)
        │  HTTP 127.0.0.1:8080
   Signing Gateway  (server.js / signing-gateway.exe)   ← Node.js
        │  execFile (dòng lệnh)
   Native Signer   (pdf-signer.exe)                      ← C# .NET 8
        │  PKCS#11 (.dll)  |  CNG/CAPI
   USB Token (VNPT-CA / NC-CA / I-CA ...)
```

Vì `cloudflared` đã lo phần TLS, Gateway chỉ **bind `127.0.0.1`** và chạy HTTP thường — không cần cài chứng chỉ TLS, không cần IP allowlist. Bảo mật được đảm bảo ở tầng token HMAC.

### Luồng ký một tài liệu

1. Frontend HIS4 xin **token ký ngắn hạn** từ backend HIS4 của mình (`POST /api/signing/token`).
2. Frontend gọi `POST {GATEWAY}/v2/sign` kèm `Authorization: Bearer <token>` và tài liệu (base64).
3. Gateway xác thực token (HMAC + hạn + chống replay), kiểm tra khóa độc quyền nếu có.
4. Gateway ghi file tạm, gọi `pdf-signer.exe` bằng `execFile` với các tham số ký.
5. `pdf-signer.exe` tìm chứng thư theo serial, chọn engine ký (PKCS#11 → CNG/CSP), tạo chữ ký, ghi file đầu ra.
6. Gateway đọc file đã ký, xóa file tạm, ghi audit, trả base64 về frontend.

---

## 3. Các thành phần

### 3.1 `server.js` — Gateway (Node.js)

File chính, ~2.300 dòng, đóng gói thành `signing-gateway.exe` bằng `@yao-pkg/pkg` (nhúng sẵn Node 22 cho Windows x64). Trách nhiệm:

- **HTTP server** thuần (`node:http`), tự parse JSON và multipart, không dùng framework.
- **Xác thực token HMAC** do backend HIS4 cấp.
- **Điều phối ký**: mutex nối tiếp các lệnh ký, khóa độc quyền (TokenLock).
- **Gọi native signer** (`signPdfNative`, `signXmlNative`) qua `execFile`.
- **Quản lý Cloudflare Tunnel** như tiến trình con, tự self-heal.
- **Audit log** hash-chain, **cảnh báo Telegram**.
- **Các chế độ CLI chẩn đoán**: `--probe`, `--diag`, `--license`, `--pintest`, `--install`, `--uninstall`.

Các lớp chính trong `server.js`:

| Lớp / hàm | Vai trò |
|---|---|
| `Plugin` | Trừu tượng hóa token: `listSerials()`, `checkToken()`, `signPdf()`, `signXml()` — thực chất gọi `pdf-signer.exe --list` / ký |
| `Mutex` | Nối tiếp lệnh ký (concurrency = 1), request sau chờ request trước, không ném lỗi |
| `TokenLock` | Khóa độc quyền token cho mô hình "ký cả loạt" |
| `Queue` | Hàng đợi job (dùng cho luồng ký bất đồng bộ, thống kê) |
| `Tunnel` | Bọc `cloudflared.exe`, tự khởi động lại, phát hiện lỗi kết nối |
| `Telegram` | Hàng đợi gửi log, gộp tin, giãn nhịp chống 429 |

### 3.2 `pdf-signer.exe` — Native Signer (C# .NET 8)

Nguồn tại `native-signer/Program.cs` (~2.700 dòng). Đây là "trái tim" của việc ký im lặng. Build self-contained single-file (nhúng .NET runtime), chạy được trên máy chủ không cài .NET.

**Các chế độ dòng lệnh:**

| Cờ | Chức năng |
|---|---|
| `--list` | Liệt kê chứng thư (Windows Store + PKCS#11), in `SERIAL:...\|CN:...\|HAS_KEY:...` |
| `--input --output --serial [--pin ...]` | Ký PDF (mặc định) |
| `--xml --input --output --serial [--pin ...]` | Ký XML (XMLDSig Enveloped) |
| `--test-pkcs11 --serial --pin` | So sánh chữ ký CNG vs PKCS#11 để tìm quy tắc digest của token |

**Tham số ký PDF quan trọng:** `--page`, `--llx/--lly/--urx/--ury` (tọa độ ô chữ ký), `--desc` (lý do), `--image` (ảnh chữ ký), `--color`, `--tsize` (cỡ chữ), `--signmark` (từ khóa để tự dò tọa độ), `--force-cng`, `--pin-format` (định dạng PIN đã cache).

**Ba engine ký (`IExternalSignature`):**

1. **`Pkcs11Signature`** — nạp trực tiếp driver `.dll` (ví dụ `vnptca_p11_v8.dll`, `ncca_csp11_v1.dll`, `ica_csp11_v1.dll`) qua P/Invoke, gọi `C_Initialize → C_OpenSession → C_Login → C_Sign`. Tự dựng `DigestInfo` SHA-256 (prefix ASN.1 + hash) và ký bằng cơ chế `CKM_RSA_PKCS`. Đây là đường ký im lặng 100%.
2. **`CngUserSignature`** — dùng Windows CNG/CAPI. Thử lần lượt nhiều định dạng PIN (`asc-raw`, `uni-raw`, `asc-null`, `uni-null`) và đặt PIN qua thuộc tính `SmartCardPin` (CNG) hoặc `CryptSetProvParam`/`CryptSetKeyParam` với `PP_SIGNATURE_PIN`/`PP_KEYEXCHANGE_PIN` (CSP). Đặt cờ `Silent` + `NoPrompt` để không bật hộp thoại.
3. **`Pkcs11Rsa`** — bọc `Pkcs11Signature` thành đối tượng `RSA` để `SignedXml` (ký XML) dùng được.

**Tạo chữ ký PDF:** dùng thư viện **iTextSharp 5.5.13.3** (`PdfStamper.CreateSignature` + `MakeSignature.SignDetached`, chuẩn CMS/PAdES). Chữ ký visible được vẽ ở layer 2: ảnh bên trái, text "Ký bởi / Ngày ký / Lý do" bên phải, dùng font Unicode (ưu tiên `font.ttf` đi kèm, rồi Arial/Times/Tahoma... trong hệ thống).

**Chọn engine:** nếu tìm được DLL PKCS#11 tương thích và không ép CNG → ưu tiên PKCS#11 (ký im lặng chắc chắn nhất); ngược lại dùng CNG/CAPI. DLL được chọn theo Provider name của khóa, fallback theo Issuer/Subject của chứng thư (ICA → `ica_csp11_v1`, NC-CA → `ncca_csp11_v1`, VNPT → `vnptca_p11_v8`).

### 3.3 `his4-signing-client.js` — Client frontend (ES module)

Module mẫu để tích hợp vào frontend HIS4. Cung cấp:

- `checkGateway()` — gọi `/v2/health` trước khi hiện nút Ký.
- `signPdf(pdf, opts)` — ký 1 file PDF, trả `Blob`.
- `signXml(xmlString, opts)` — ký XML, trả chuỗi XML đã ký.
- `lock(hisToken)` / `unlock(lockToken)` — ký cả loạt.
- `dienGiaiLoi(code)` — ánh xạ mã lỗi sang thông báo tiếng Việt.

### 3.4 Cloudflare Tunnel

`cloudflared.exe` chạy như **tiến trình con** của Gateway (tắt Gateway → tunnel tắt theo). Hai chế độ:

- **Quick tunnel** (`token = ""`): Cloudflare cấp URL `xxx.trycloudflare.com` ngẫu nhiên, **đổi mỗi lần khởi động** — chỉ dùng để test. URL được ghi ra `tunnel_url.txt`.
- **Named tunnel** (`token = "eyJ..."`): hostname cố định, dùng khi triển khai thật. Lấy token ở Cloudflare Zero Trust → Networks → Tunnels.

Cơ chế self-heal: theo dõi log của `cloudflared`, nếu thấy lỗi kết nối (`ERR`, `failed`, `lookup`, `dial tcp`, `lost connection`) kéo dài quá 30s mà không phục hồi → kill và restart. Khi tiến trình thoát, tự khởi động lại với backoff lũy thừa 5s → 10s → 20s → tối đa 60s.

---

## 4. Bảo mật & xác thực

### 4.1 Token HMAC do backend HIS4 cấp

Frontend **không giữ bí mật gì**. Token có dạng:

```
token = base64url(payloadJSON) + "." + base64url(HMAC-SHA256(payload, secret))
payload = { sub, name, exp, jti }
```

- `secret` (`hisSharedSecret`) là chuỗi 64 hex dùng chung giữa **backend HIS4** và **config.json của Gateway**. Sinh bằng:
  ```bash
  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  ```
- Gateway xác minh: chữ ký HMAC (so sánh `timingSafeEqual`), `exp` chưa hết hạn, có `sub`.
- **Chống replay bằng `jti`**: chỉ **lệnh ký** (`POST /v2/sign`) mới tiêu thụ `jti` — token dùng một lần. Các thao tác đọc (poll trạng thái, lock-status...) không tiêu thụ `jti` nên token dùng lại được. `usedJti` được dọn định kỳ theo `exp`.

### 4.2 CORS & Private Network Access

Gateway đặt `Access-Control-Allow-Origin` theo Origin của request, kèm `Access-Control-Allow-Private-Network: true` (cần thiết khi trang HTTPS gọi vào `127.0.0.1`). `allowedOrigins` trong config dùng để định danh origin production.

### 4.3 Audit log hash-chain

Mỗi sự kiện ghi vào `audit-YYYY-MM.jsonl` (append-only, đặt tại ProgramData). Mỗi dòng chứa `prev` = hash của dòng trước; hash mới = `SHA256(prevHash + line)`. Chuỗi bắt đầu từ `GENESIS`. Sửa/xóa một dòng làm gãy chuỗi → phát hiện được can thiệp.

Các loại sự kiện: `gateway.start/stop`, `auth.fail`, `lock.acquire/release/denied`, `sign.start/ok/fail/reject/denied`.

### 4.4 Giải mã PIN (tùy chọn)

`decryptPinAES_GCM()` hỗ trợ nhận PIN đã mã hóa **AES/GCM/NoPadding** (tương thích `SmartCAEncryptionService` phía Java). Payload = `IV(12) + ciphertext + authTag(16)`, khóa lấy từ `hisSharedSecret`. Nếu giải mã thất bại, coi như PIN plaintext.

---

## 5. Cấu hình (`config.json`)

Đặt tại `C:\ProgramData\SigningGateway\config.json` (xem mục 10 về vị trí). Các khóa quan trọng:

| Khóa | Mặc định | Ý nghĩa |
|---|---|---|
| `host` / `port` | `127.0.0.1` / `8080` | Địa chỉ bind |
| `allowedOrigins` | `["https://his4-dev.vnpthis.vn"]` | Origin HIS4 được phép |
| `hisSharedSecret` | `""` | **Bắt buộc** — secret HMAC dùng chung với backend |
| `tenantId` | `""` | Mã bệnh viện (ghi vào audit) |
| `certificateSerial` | `""` | Serial chứng thư mặc định |
| `requireSerial` | `false` | `true` = mỗi request bắt buộc gửi serial |
| `useNativeSigner` | `true` | Dùng `pdf-signer.exe` |
| `nativeSignerExePath` | `""` | Đường dẫn exe (rỗng = tự dò `bin/pdf-signer.exe`) |
| `defaultPin` | `""` | PIN mặc định khi request không gửi |
| `signatureImageBase64` | `""` | Ảnh chữ ký (Adobe yêu cầu có ảnh để "Signature verified") |
| `forceCng` | `true` (ẩn) | Ép dùng CNG thay vì PKCS#11 |
| `signTimeoutMs` | `15000` | Timeout ký (kill exe nếu quá) |
| `maxPdfBytes` | `20 MB` | Giới hạn kích thước PDF |
| `lockTtlMs` / `lockRequired` | `120000` / `false` | Khóa độc quyền |
| `tokenCacheMs` | `10000` | Cache kết quả kiểm tra token (tránh nghẽn driver) |
| `monitorToken` | `false` | Hỏi token định kỳ (mặc định tắt vì gây nghẽn) |
| `devMode` | `false` | **Bỏ qua xác thực token** — chỉ để test, phải tắt khi lên production |
| `tunnel.{enabled,token,exePath}` | — | Cấu hình Cloudflare Tunnel |
| `telegram.{enabled,botToken,chatId,...}` | — | Cảnh báo Telegram |
| `tsaUrl/tsaUsername/tsaPassword` | `""` | Timestamp Authority (nếu dùng) |

Lưu ý xử lý config: tự tạo file mẫu nếu chưa có; bỏ BOM UTF-8 trước khi `JSON.parse`; báo lỗi rõ ràng và giữ cửa sổ CMD mở nếu JSON hỏng.

---

## 6. API Reference

Tất cả endpoint (trừ `/` và `/v2/health`) yêu cầu header `Authorization: Bearer <hisToken>`.

Response được bọc theo định dạng thống nhất:
```json
{ "data": <payload|null>, "message": "Thành công", "error_code": 0, "status": 200 }
```
Khi lỗi (`status >= 400`), `error_code` là số hoặc chuỗi (`WRONG_PIN`, `KHONG_CO_USB_TOKEN`, `TOKEN_BUSY`, `THIEU_SERIAL`, `CERTIFICATE_NOT_FOUND`, `SIGNMARK_NOT_FOUND`...).

| Method | Path | Auth | Mô tả |
|---|---|---|---|
| GET | `/` | Không | Trang trạng thái HTML cho người vận hành (tự refresh 5s) |
| GET | `/v2/health` | Không | Kiểm tra token/plugin/tunnel trước khi hiện nút Ký |
| POST | `/v2/sign` | Có (tiêu thụ jti) | **Ký hợp nhất** PDF/XML, phân biệt bằng `docType` |
| POST | `/v2/sign-file` | Có (chỉ `devMode`) | Nhận multipart, ký đồng bộ, trả PDF trực tiếp (cho Postman) |
| POST | `/v2/lock` | Có | Chiếm khóa độc quyền token |
| POST | `/v2/unlock` | Có | Nhả khóa |
| GET | `/v2/lock-status` | Có | Trạng thái khóa (ai giữ, còn bao lâu) |
| POST | `/v2/reload-token` | Có | Buộc đọc lại USB token |
| GET | `/v2/certificates` | Có | Thông tin chứng thư (JSON) |
| GET | `/v2/serials` | Có | Danh sách serial trong token |

### `POST /v2/sign` — body

```jsonc
{
  "docType": "pdf",                 // "pdf" (mặc định) | "xml"
  "document": "<base64 PDF | XML>",
  "docId": "HS-001",                // tùy chọn, ghi audit
  "lockToken": "lk_...",            // chỉ khi đang trong phiên lock
  "pin": "<PIN | PIN mã hóa>",      // tùy chọn
  "signature": {
    "certificateSerial": "5401...", // ưu tiên hơn config
    "page": 1,
    "llx": 380, "lly": 40, "urx": 560, "ury": 110,
    "description": "Lý do ký",
    "imageBase64": "<base64>",
    "color": "0,70,150",
    "sigTextSize": 8,
    "signmark": "Người lập phiếu",  // tự dò tọa độ theo từ khóa
    "signingType": "Enveloped",     // (XML)
    "digestMethod": "SHA256"        // (XML)
  }
}
```

Response PDF: `{ docType, document: "<base64 đã ký>", sha256 }`.
Response XML: `{ docType, document: "<XML>", documentBase64, sha256 }`.

---

## 7. Cơ chế ký im lặng (điểm mấu chốt)

Rút ra từ `SIGNING_GATEWAY_HISTORY.md` và mã nguồn — các quyết định thiết kế quan trọng:

**Đã hoạt động tốt (OK):**

1. **Quét PKCS#11 trước (dual-engine)** — ưu tiên ký qua `.dll` driver, bypass 100% hộp thoại PIN của Windows CAPI/CNG.
2. **Mở session PKCS#11 chỉ đọc** — chỉ dùng `CKF_SERIAL_SESSION`, không dùng `CKF_RW_SESSION`; driver VNPT-CA từ chối session đọc-ghi khi quét.
3. **Truyền PIN khi quét chứng thư** — `C_Login` trước khi liệt kê object, tránh driver deadlock khi cố hiện popup PIN ngầm.
4. **Buffer cố định đủ lớn** — 256B cho `CKA_LABEL`, 4096B cho `CKA_VALUE`; không dùng cơ chế query kích thước 2 bước vì driver VNPT-CA/NCCA trả 0 khi truyền pointer NULL.
5. **`TerminateProcess` khi thoát** — thoát cưỡng bức ở tầng OS, bỏ qua bước dọn dẹp `DllMain(DLL_PROCESS_DETACH)` của driver (nơi driver VNPT-CA hay deadlock 15s). *(Lưu ý: trong bản mã hiện tại các đường ký đều `return` mã lỗi; kỹ thuật này được ghi lại như bài học từ lịch sử.)*
6. **CNG/CAPI fallback im lặng** — cấu hình `NoPrompt` + PIN dạng `asc-raw` + `CryptSetProvParam(PP_SIGNATURE_PIN)`.
7. **Ẩn cửa sổ CMD** — mọi `execFile` đặt `windowsHide: true`.
8. **Self-heal Cloudflare Tunnel** — tự restart khi mất kết nối.

**Đã thất bại (không dùng):**

- Plugin/WebSocket VNPT-CA cũ (phức tạp, hay mất kết nối, hay hỏi PIN).
- Quét PKCS#11 không đăng nhập PIN (treo tiến trình).
- Query kích thước 2 bước chuẩn PKCS#11 (driver trả về 0).
- Thoát bằng `return 0`/`Environment.Exit` (deadlock trong driver).
- Reconnect mặc định của `cloudflared` (kẹt vòng lặp DNS lookup).

### PIN format cache

Sau lần ký thành công, `pdf-signer.exe` in `[SUCCESS_FORMAT] <fmt>`; Gateway ghi nhớ `<fmt>` theo serial (`pinFormatCache`) và truyền lại `--pin-format` cho lần sau để thử đúng định dạng trước, giảm thời gian ký.

### Self-heal SmartCard

Nếu ký bị timeout/kill hoặc gặp lỗi driver (`NTE_*`, `CryptographicException`), Gateway tự `net stop/start SCardSvr` để phục hồi dịch vụ Smart Card.

---

## 8. Đồng bộ hóa: Mutex & TokenLock

- **`Mutex`**: nối tiếp tuyệt đối các lệnh ký (một token chỉ ký được một file tại một thời điểm). Request sau *chờ* request trước xong (giữ thứ tự), không ném lỗi.
- **`TokenLock`** (mô hình "A2"): một client gọi `/v2/lock` để chiếm token, ký nhiều file rồi `/v2/unlock`. Trong lúc bị khóa, client khác nhận **423 Locked** kèm `Retry-After`. Nếu client chết không unlock, khóa tự hết hạn sau `lockTtlMs`; mỗi lần ký thành công **gia hạn** khóa. Chủ khóa re-acquire được (idempotent).

---

## 9. Ký XML

- Dùng `System.Security.Cryptography.Xml.SignedXml`, chuẩn **Enveloped Signature**.
- `Reference.Uri = ""` (ký toàn bộ document), DigestMethod SHA-256, SignatureMethod `rsa-sha256`.
- `KeyInfo` nhúng `X509Data` của chứng thư.
- Khóa ký lấy từ `Pkcs11Rsa` (nếu có DLL PKCS#11) hoặc `CngUserSignature.GetSilentRsaKey` (CNG/CSP silent).
- Chữ ký được `AppendChild` vào `DocumentElement`.

---

## 10. Triển khai & vận hành

### Vị trí file sau khi cài

```
C:\Program Files\SigningGateway\        (chỉ đọc)
    signing-gateway.exe
    cloudflared.exe
    vnpt.ico, DIEU_KHOAN.txt

C:\ProgramData\SigningGateway\          (dữ liệu — SAO LƯU THƯ MỤC NÀY)
    config.json
    audit-YYYY-MM.jsonl                 (log ký, hash-chain, đừng xóa)
    bin\pdf-signer.exe, bin\font.ttf    (tự giải nén khi chạy)
    temp\                               (file tạm khi ký)
    tunnel_url.txt                      (URL quick tunnel hiện tại)
    pdf-signer-debug.log                (log lần ký gần nhất)
```

`pickDataDir()` chọn thư mục ghi được đầu tiên trong: `SIGNING_GATEWAY_DATA` (env) → `%ProgramData%\SigningGateway` → `%LOCALAPPDATA%\SigningGateway` → cạnh file exe. Đặt dữ liệu ngoài Program Files là **có chủ đích**: Program Files không ghi được nếu thiếu quyền admin và Windows sẽ "ảo hóa" file ghi sang nơi khác → audit log biến mất âm thầm.

### Chạy ngầm — KHÔNG dùng Windows Service

`signing-gateway.exe --install` tạo **Scheduled Task** `SigningGateway` chạy **onlogon** (qua `run-hidden.vbs` với `wscript.exe`, cửa sổ ẩn). Lý do không dùng Windows Service: service chạy ở **session 0 không có desktop**, nên hộp thoại nhập PIN của driver sẽ hiện ở nơi không ai bấm được → mọi request ký treo tới timeout.

Hệ quả vận hành, máy chủ phải:
- Bật **auto-logon** vào một tài khoản Windows.
- Có người **nhập PIN** sau mỗi lần khởi động (lần ký đầu tiên).
- **Tắt Windows Update tự động** (reboot lúc 3h sáng = sáng ra cả khoa không ký được).

### Build

**Gateway (Node → exe):**
```powershell
npm ci
npm run build      # pkg . --targets node22-win-x64 --output dist/signing-gateway.exe
```

**Native signer (C# → exe):** — build được cả trên macOS/Linux (cross-compile):
```bash
cd native-signer
dotnet publish -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:PublishReadyToRun=true -o ../bin
```

**Bộ cài (.exe):** dùng Inco Setup (`installer/signing-gateway.iss`, `build.ps1` tự tải cloudflared + đóng gói). Wizard hỏi: mã bệnh viện, secret HMAC (kiểm tra 64 hex), origin HIS4, token Cloudflare; ghi `config.json`; cài tunnel; đặt tự chạy khi đăng nhập. Nâng cấp cài đè **không ghi đè** config.json và audit log.

> ⚠️ Nên **ký số bộ cài** (code-signing cert) để tránh Windows SmartScreen chặn "Unknown publisher" — nhiều phòng CNTT bệnh viện cấm cài phần mềm chưa ký.

---

## 11. Công cụ chẩn đoán (CLI)

```
signing-gateway.exe                 chạy gateway
signing-gateway.exe --install       tạo scheduled task chạy ngầm onlogon
signing-gateway.exe --uninstall     gỡ scheduled task
signing-gateway.exe --probe         dò plugin, liệt kê certificate
signing-gateway.exe --diag <pdf>    chẩn đoán SignPDF, xem plugin trả về gì
signing-gateway.exe --license       dò license: thử nhiều domain, in response thô
signing-gateway.exe --pintest <pdf> đo thời gian PIN cache sống
signing-gateway.exe --telegram-test gửi tin thử lên Telegram
```

*(Các lệnh `--probe`, `--diag`, `--license` giao tiếp với plugin VNPT-CA WebSocket cũ — di sản từ kiến trúc trước; đường ký chính hiện tại là native signer.)*

---

## 12. Xử lý lỗi & mã lỗi chính

| Mã | Ý nghĩa | Xử lý phía client |
|---|---|---|
| `KHONG_CO_USB_TOKEN` | Chưa cắm USB Token | Nhắc cắm token |
| `THIEU_SERIAL` | `requireSerial=true` mà không gửi serial | Gửi `certificateSerial` |
| `SERIAL_KHONG_KHOP` | Serial không có trong token đang cắm | Kiểm tra token/serial |
| `CERTIFICATE_NOT_FOUND` | Không tìm thấy chứng thư (Store & PKCS#11) | Kiểm tra cài đặt token |
| `WRONG_PIN` | PIN sai hoặc thiếu | Nhập lại PIN |
| `SIGN_CANCELLED` | Ký bị hủy / thiếu PIN (NTE_SILENT_CONTEXT) | Nhập PIN trên máy chủ |
| `SIGNMARK_NOT_FOUND` | Không tìm thấy từ khóa signmark trong PDF | Kiểm tra `signmark` |
| `TOKEN_DANG_BAN`/`TOKEN_BUSY` (423) | Token đang bị khóa/đang ký | Thử lại sau `retryAfterMs` |
| `TOKEN_HET_HAN`/`TOKEN_DA_DUNG`/`TOKEN_SAI_CHU_KY` | Token HMAC không hợp lệ | Xin token mới |

Trước khi ký, `resolveSerial()` **luôn làm mới** danh sách serial (`force=true`, không dùng cache) để chắc chắn token vẫn cắm và đúng serial tại thời điểm ký.

---

## 13. Hạn chế đã biết

- **Lần ký đầu sau mỗi lần khởi động máy vẫn bật hộp thoại PIN** — phải có người nhập tại máy chủ. Đây là giới hạn của driver/token; muốn bỏ hẳn phải đi PKCS#11 truyền PIN bằng code (đã làm cho phần lớn token, nhưng phụ thuộc driver).
- **`devMode: true` bỏ qua toàn bộ xác thực** — chỉ để test, tuyệt đối tắt trên production.
- **Quick tunnel đổi URL mỗi lần khởi động** — chỉ dùng test; production phải dùng named tunnel.
- **`NODE_TLS_REJECT_UNAUTHORIZED=0`** được đặt toàn cục (do plugin cũ dùng self-signed cert) — ảnh hưởng mọi kết nối TLS outbound của tiến trình.
- **Concurrency = 1**: một token chỉ ký tuần tự; throughput bị giới hạn bởi tốc độ token phần cứng.
- **Phụ thuộc Windows**: native signer dùng CNG/CAPI/WinSCard, chỉ chạy trên Windows x64.

---

*Tài liệu này được tổng hợp từ mã nguồn: `server.js`, `native-signer/Program.cs`, `his4-signing-client.js`, `config.example.json`, `BUILD.md`, `native-signer/README.md`, `signing-gateway/SIGNING_GATEWAY_HISTORY.md`, `installer/signing-gateway.iss`.*
