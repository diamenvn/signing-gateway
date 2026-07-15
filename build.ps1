# =============================================================================
#  build.ps1 - Chay tren may Windows, ra file SignerGateway.exe
#
#  Yeu cau cai truoc:
#    1. Node.js 20+     https://nodejs.org
#    2. Inno Setup 6    https://jrsoftware.org/isdl.php
#
#  Chay:  powershell -ExecutionPolicy Bypass -File build.ps1
# =============================================================================

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$Root      = $PSScriptRoot
$DistDir   = Join-Path $Root 'dist'
$InstDir   = Join-Path $Root 'installer'
$IssFile   = Join-Path $InstDir 'signing-gateway.iss'
$GatewayEx = Join-Path $DistDir 'signing-gateway.exe'
$CfExe     = Join-Path $InstDir 'cloudflared.exe'

Write-Host ''
Write-Host '  Signing Gateway - build' -ForegroundColor Cyan
Write-Host '  -----------------------'
Write-Host ("  Thu muc: {0}" -f $Root)
Write-Host ''

# --- 0. Kiem tra cau truc thu muc --------------------------------------------
if (-not (Test-Path (Join-Path $Root 'server.js'))) {
    throw "Khong thay server.js. Hay chay build.ps1 TRONG thu muc da giai nen."
}
if (-not (Test-Path $IssFile)) {
    throw "Khong thay installer\signing-gateway.iss. Giai nen thieu file."
}
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# --- 1. Kiem tra cong cu ------------------------------------------------------
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Chua cai Node.js. Tai tai https://nodejs.org'
}
Write-Host ("  Node.js: {0}" -f (node -v)) -ForegroundColor Green

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) {
    throw 'Khong thay ISCC.exe. Cai Inno Setup 6 tai https://jrsoftware.org/isdl.php'
}
Write-Host ("  Inno Setup: {0}" -f $iscc) -ForegroundColor Green

# --- 2. Tai cloudflared (khong bat buoc) -------------------------------------
if (-not (Test-Path $CfExe)) {
    Write-Host '  Dang tai cloudflared...' -ForegroundColor Yellow
    $url = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe'
    try {
        # curl.exe co san tu Windows 10 1803, xu ly redirect + TLS tot hon Invoke-WebRequest
        & curl.exe -L --fail --silent --show-error -o "$CfExe" $url
        if ($LASTEXITCODE -ne 0) { throw 'curl that bai' }
        Write-Host '  cloudflared: OK' -ForegroundColor Green
    } catch {
        Write-Host ''
        Write-Host '  ==========================================================' -ForegroundColor Red
        Write-Host '   KHONG TAI DUOC CLOUDFLARED' -ForegroundColor Red
        Write-Host '' -ForegroundColor Red
        Write-Host '   Neu build tiep, bo cai se THIEU cloudflared va tunnel' -ForegroundColor Red
        Write-Host '   se KHONG chay duoc tren may chu.' -ForegroundColor Red
        Write-Host '' -ForegroundColor Red
        Write-Host '   Tai thu cong tai:' -ForegroundColor Yellow
        Write-Host "     $url" -ForegroundColor Yellow
        Write-Host "   Doi ten thanh cloudflared.exe va dat vao:" -ForegroundColor Yellow
        Write-Host "     $InstDir" -ForegroundColor Yellow
        Write-Host '  ==========================================================' -ForegroundColor Red
        Write-Host ''
        $ans = Read-Host '  Van build tiep (khong co tunnel)? [y/N]'
        if ($ans -ne 'y') { throw 'Da dung. Tai cloudflared roi chay lai.' }
    }
} else {
    Write-Host '  cloudflared: da co' -ForegroundColor Green
}

# --- 3. Dependency -----------------------------------------------------------
Write-Host '  Dang cai dependency...' -ForegroundColor Yellow
& npm install --silent
if ($LASTEXITCODE -ne 0) { throw 'npm install that bai' }


# --- 3b. Bien dich native-signer (C#) ----------------------------------------
Write-Host '  Dang kiem tra .NET SDK...' -ForegroundColor Yellow
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'Chua cai .NET SDK 8.0. Tai tai https://dotnet.microsoft.com/download/dotnet/8.0'
}
Write-Host '  Dang bien dich pdf-signer.exe (C#)...' -ForegroundColor Yellow
$NativeSignerProj = Join-Path $Root 'native-signer\pdf-signer.csproj'
if (-not (Test-Path $NativeSignerProj)) {
    throw "Khong tim thay $NativeSignerProj"
}
& dotnet publish "$NativeSignerProj" -c Release -r win-x86 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -o (Join-Path $Root 'bin')
if ($LASTEXITCODE -ne 0) { throw 'Bien dich C# native-signer that bai' }
Write-Host '  pdf-signer.exe: OK' -ForegroundColor Green

# --- 4. Dong goi thanh signing-gateway.exe -----------------------------------
Write-Host '  Dang dong goi exe...' -ForegroundColor Yellow
& npx pkg . --targets node22-win-x64 --output "$GatewayEx"
if ($LASTEXITCODE -ne 0) { throw 'pkg that bai' }
if (-not (Test-Path $GatewayEx)) { throw "pkg khong tao ra $GatewayEx" }

$mb = [math]::Round((Get-Item $GatewayEx).Length / 1MB, 1)
Write-Host ("  dist\signing-gateway.exe  ({0} MB)" -f $mb) -ForegroundColor Green

# --- 4b. Nhung icon VNPT vao exe (tuy chon) ---------------------------------
# pkg khong tu dat icon cho exe. Dung rcedit neu co.
$IcoFile = Join-Path $PSScriptRoot 'installer\vnpt.ico'
if (Test-Path $IcoFile) {
    $rcedit = Get-Command rcedit -ErrorAction SilentlyContinue
    if (-not $rcedit) {
        # thu tai rcedit tu npm neu chua co
        try {
            & npx --yes rcedit "$GatewayEx" --set-icon "$IcoFile"
            if ($LASTEXITCODE -eq 0) { Write-Host '  Da nhung icon VNPT vao exe.' -ForegroundColor Green }
        } catch {
            Write-Host '  (Bo qua icon exe: khong co rcedit. Shortcut van co icon.)' -ForegroundColor DarkGray
        }
    } else {
        & rcedit "$GatewayEx" --set-icon "$IcoFile"
        Write-Host '  Da nhung icon VNPT vao exe.' -ForegroundColor Green
    }
}

# --- 5. Tao bo cai -----------------------------------------------------------
Write-Host '  Dang tao bo cai...' -ForegroundColor Yellow
Write-Host ''

# Duong dan TUYET DOI + khong dung /Q, de thay loi that neu ISCC bao loi.
& $iscc "/O$DistDir" "$IssFile"
$isccCode = $LASTEXITCODE

if ($isccCode -ne 0) {
    Write-Host ''
    Write-Host "  ISCC tra ve ma loi $isccCode. Doc thong bao ngay tren dong nay." -ForegroundColor Red
    throw 'Inno Setup that bai'
}

$setup = Join-Path $DistDir 'SignerGateway.exe'
if (-not (Test-Path $setup)) { throw "Khong thay $setup" }
$mb = [math]::Round((Get-Item $setup).Length / 1MB, 1)

Write-Host ''
Write-Host ("  XONG:  dist\SignerGateway.exe  ({0} MB)" -f $mb) -ForegroundColor Green
Write-Host ''
Write-Host '  Copy file nay sang may chu benh vien va double-click.' -ForegroundColor Cyan
Write-Host ''

# --- 6. Ky so bo cai (nen lam truoc khi giao cho benh vien) -------------------
# Khong ky -> Windows SmartScreen canh bao "Unknown publisher",
# nhieu phong CNTT benh vien se khong cho cai. Can code-signing certificate.
#
#   signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 `
#            dist\SignerGateway.exe
