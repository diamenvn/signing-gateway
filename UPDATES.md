# Cập nhật Signing Gateway từ tray Windows

> Nguồn phát hành hiện tại: upload `SignerGateway.exe` vào Assets của GitHub Release (bộ cài vượt giới hạn Git 100 MiB). Script sinh manifest mặc định dùng `https://github.com/diamenvn/signing-gateway/releases/download/v<version>/SignerGateway.exe`. Không dùng `/releases/tag/`: đó là trang release, không phải link tải. Upload asset trước rồi push `releases/latest.json` lên nhánh `HMIS-20756`. Các hướng dẫn lưu EXE trực tiếp trong `dist` trên Git dưới đây chỉ áp dụng nếu file nằm trong giới hạn GitHub.

Ứng dụng `SigningGateway.Tray.exe` chạy trong phiên người dùng, tự mở cùng Windows qua shortcut Startup. Gateway tiếp tục chạy nền theo task hiện có.

## Hành vi

- Kiểm tra khi tray mở và mỗi 3 giờ. Lỗi mạng/manifest: thử lại sau 30 phút, không ảnh hưởng ký.
- Khi version mới hơn version tray đã cài: hiện balloon cạnh đồng hồ và hộp thoại **Có phiên bản x.y.z**, với **Tải cập nhật** / **Để sau**.
- **Để sau** hoặc đóng hộp thoại: không tải/chạy bộ cài; lưu hoãn 24 giờ tại `%LOCALAPPDATA%\SigningGateway\Updates\deferred.json` cho các lần kiểm tra định kỳ trong phiên tray hiện tại. Khi tray khởi động lại (đăng nhập Windows hoặc mở lại thủ công), lần kiểm tra thành công đầu tiên bỏ qua hoãn cũ và thông báo nếu có bản mới. Nếu lúc khởi động chưa có mạng, lần thử lại thành công vẫn áp dụng quy tắc này. Bản mới khác vẫn được thông báo. Có thể mở lại qua menu tray.
- **Tải cập nhật**: tải vào thư mục Updates của người dùng; kiểm tra SHA-256, định dạng PE, ProductName=Signing Gateway, ProductVersion khớp manifest và FileDescription=Signing Gateway Setup (AutoUpdate v1). Sau đó mở bộ cài với `/UPDATE=1 /SILENT /NORESTART`. Windows vẫn có thể yêu cầu quyền admin; hủy quyền thì không cập nhật.
- Bộ cài chế độ update giữ nguyên toàn bộ config.json, không cài lại VNPT plugin. Trước khi thay file, bộ cài hỏi xác nhận dừng gateway (kể cả chế độ /SILENT). Chọn Không thì không dừng ứng dụng; chọn Có thì dừng gateway và tray để cài bản mới. Tác vụ ký đang chạy có thể bị gián đoạn. Bộ cài không gọi --prepare-update và không bị chặn bởi HTTP 403/404/409 hoặc hisSharedSecret trống.
- Bộ cài khởi động lại gateway và tray. Nếu lỗi sau bước dừng, thử khởi động lại task/tray hiện có; không đảm bảo rollback file trong mọi lỗi ổ đĩa/hệ điều hành.
- Không tải trước khi người dùng bấm nút, không tự reboot. File tải cũ hơn 7 ngày được dọn khi mở tray.

## Nguồn phát hành

Tray đọc manifest tại:

`https://raw.githubusercontent.com/diamenvn/signing-gateway/HMIS-20756/releases/latest.json`

Link tải mặc định trỏ trực tiếp đến bộ cài mới do build.ps1 tạo ra:

`https://raw.githubusercontent.com/diamenvn/signing-gateway/HMIS-20756/dist/SignerGateway.exe`

Phát hành trực tiếp `dist/SignerGateway.exe`; không cần sao chép hoặc đổi tên sang file VNPT-CA Plugin. Version lấy từ metadata bộ cài, phải khớp manifest. `dist/signing-gateway.exe` là chương trình gateway, không phải bộ cài để phân phối qua updater.

Repository/nhánh/file cần truy cập được mà không đăng nhập. Không nhúng GitHub token vào app. Nếu repository private, cần endpoint phân phối khác được bảo vệ phù hợp. Các request của tray dùng HttpClient riêng với kiểm tra TLS mặc định, không chịu ảnh hưởng NODE_TLS_REJECT_UNAUTHORIZED của gateway.

Manifest mẫu là `releases/latest.example.json`, không phải manifest đang phát hành. SHA-256 phải được sinh từ file thật. Cơ chế tin cậy dựa vào HTTPS và quyền quản lý repository; checksum/metadata không thay thế chữ ký số nhà phát hành. Nên ký Authenticode trước khi sinh manifest.

## Phát hành một phiên bản

1. Cập nhật `version` trong package.json (ví dụ 0.3.0). Chạy `npm install --package-lock-only` để đồng bộ lockfile nếu cần.
2. Chạy `powershell -ExecutionPolicy Bypass -File build.ps1`. Script dùng cùng version cho gateway, tray và Inno Setup. Máy build cần Node, .NET SDK 8 và Inno Setup 6.
3. Nếu ký Authenticode, ký **dist\SignerGateway.exe** trước bước tiếp theo.
4. Sinh manifest trực tiếp từ bộ cài vừa build:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\write-update-manifest.ps1 `
  -InstallerPath 'dist\SignerGateway.exe' `
  -ReleaseNotes 'Bổ sung tính năng cập nhật từ tray Windows.'
```

5. Upload/commit `dist/SignerGateway.exe` lên nhánh HMIS-20756 trước, sau đó xuất bản `releases/latest.json` trên cùng nhánh. Chưa publish manifest thì máy khách chưa biết release mới. Có thể dùng GitHub Releases với URL asset riêng cho mỗi version; truyền `-DownloadUrl` vào script.
6. Cài thủ công một lần bản có tray/updater trên máy đang dùng bản cũ. Những lần sau mới tự phát hiện và nâng cấp được. Giữ nguyên AppId Inno Setup.

Không tự đổi version/release hoặc upload lên GitHub trong quá trình sửa code.

## Kiểm thử không cài app

```powershell
node --test test/update-lifecycle.test.js
dotnet build tray-updater/SigningGateway.Tray.csproj
dotnet build test/update-fixture/Fixture.csproj
dotnet run --project test/update-client/UpdateClientTests.csproj -- test/update-fixture/bin/Debug/net8.0/Fixture.dll
```

Để thử tray bằng tay: `dotnet run --project tray-updater/SigningGateway.Tray.csproj`. Chức năng kiểm tra bản mới chỉ hoạt động sau khi manifest thật đã được publish. Muốn kiểm thử nâng cấp end-to-end, dùng VM với hai bản (ví dụ 0.2.0 có updater và 0.3.0), kiểm tra Để sau, hủy UAC, tải lỗi, checksum sai, đang ký, bảo toàn config và version `/v2/health` sau cài.

Endpoint nội bộ `/internal/update/prepare` vẫn dành cho CLI `signing-gateway.exe --prepare-update`, cần loopback, Host loopback và HMAC từ hisSharedSecret, không dùng cho frontend. Bộ cài không còn phụ thuộc endpoint này. Chức năng ký vẫn cần hisSharedSecret hợp lệ.
