@echo off
echo ====================================================
echo  Dang bien dich pdf-signer.exe (Self-Contained)
echo ====================================================
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -o ../bin
if %ERRORLEVEL% GEQ 1 (
    echo [ERROR] Bien dich that bai! Vui long kiem tra lai xem da cai .NET 8.0 SDK chua.
    pause
    exit /b %ERRORLEVEL%
)
echo [SUCCESS] Da bien dich thanh cong! File binary nam tai: bin/pdf-signer.exe
pause
