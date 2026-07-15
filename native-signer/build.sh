#!/bin/bash
echo "===================================================="
echo " Dang bien dich pdf-signer.exe (Self-Contained) cho Windows"
echo "===================================================="
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -o ../bin
if [ $? -ne 0 ]; then
    echo "[ERROR] Bien dich that bai! Vui long kiem tra .NET 8.0 SDK."
    exit 1
fi
echo "[SUCCESS] Da bien dich thanh cong! File binary nam tai: bin/pdf-signer.exe"
