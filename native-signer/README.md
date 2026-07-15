# Hướng Dẫn Biên Dịch Bộ Tự Ký PDF (C# Native Signer)

Bộ ký số này được viết bằng C# .NET 8.0, sử dụng Windows Certificate Store (CNG/CAPI) để tự động giao tiếp với USB Token cắm trên máy chủ và tự ký file PDF.

## 1. Yêu cầu môi trường biên dịch
Bạn cần cài đặt **.NET 8.0 SDK** trên máy dùng để biên dịch (có thể biên dịch ngay trên macOS hoặc Windows).
* Tải SDK tại: [https://dotnet.microsoft.com/download/dotnet/8.0](https://dotnet.microsoft.com/download/dotnet/8.0)
* Hoặc trên macOS dùng Homebrew:
  ```bash
  brew install --cask dotnet-sdk
  ```

---

## 2. Lệnh biên dịch nhanh

### Từ macOS/Linux (Biên dịch chéo ra file chạy Windows):
Mở Terminal tại thư mục `native-signer/` và chạy lệnh sau (hoặc chạy trực tiếp file `./build.sh`):
```bash
chmod +x build.sh
./build.sh
```

### Từ Windows:
Mở CMD tại thư mục `native-signer\` và chạy lệnh sau (hoặc chạy trực tiếp file `build.bat`):
```cmd
build.bat
```

Lệnh biên dịch đầy đủ:
```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -o ../bin
```

Sau khi chạy xong, file thực thi độc lập **`pdf-signer.exe`** sẽ được tạo ra tại thư mục **`bin/`** ở thư mục gốc của dự án. File này chứa sẵn cả môi trường chạy .NET nên bạn không cần cài thêm bất kỳ .NET Framework nào trên máy chủ của bệnh viện.

---

## 3. Cách cấu hình chạy thử nghiệm trên Gateway
1. Mở file `config.json` trên máy chủ ký số.
2. Bật chế độ tự ký bằng cách thêm/sửa các cấu hình sau:
   ```json
   {
     "useNativeSigner": true,
     "defaultPin": "12345678",
     "nativeSignerExePath": "./bin/pdf-signer.exe"
   }
   ```
   *(Thay đổi `"defaultPin"` thành mã PIN USB Token của bạn).*
3. Chạy lại Gateway và gọi ký thử bằng file `test-sign.js`.
