param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [string]$DownloadUrl,
    [string]$ReleaseNotes = 'Cập nhật Signing Gateway.',
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot '..\releases\latest.json'
}
$metadata = Get-Content (Join-Path $PSScriptRoot '..\package.json') -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($DownloadUrl)) {
    $DownloadUrl = "https://github.com/trongdqtgg/signing-gateway/releases/download/v$($metadata.version)/SignerGateway.exe"
}
$downloadUri = $null
if (-not [Uri]::TryCreate($DownloadUrl, [UriKind]::Absolute, [ref]$downloadUri)) {
    throw 'DownloadUrl khong phai URL hop le.'
}
if ($downloadUri.AbsolutePath.StartsWith('/trongdqtgg/signing-gateway/releases/tag/')) {
    throw 'Sai link trang release: thay /releases/tag/ bang /releases/download/ va chon dung ten file EXE trong Assets.'
}
$allowed = ($downloadUri.Host -eq 'github.com' -and $downloadUri.AbsolutePath.StartsWith('/trongdqtgg/signing-gateway/releases/download/', [StringComparison]::Ordinal)) -or
    ($downloadUri.Host -eq 'raw.githubusercontent.com' -and $downloadUri.AbsolutePath.StartsWith('/diamenvn/signing-gateway/', [StringComparison]::Ordinal))
if (-not $allowed -or $downloadUri.Scheme -ne 'https' -or -not $downloadUri.IsDefaultPort -or $downloadUri.UserInfo -ne '' -or $downloadUri.Fragment -ne '' -or -not $downloadUri.AbsolutePath.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'DownloadUrl phai la link EXE HTTPS tu Releases trongdqtgg/signing-gateway hoac raw diamenvn/signing-gateway.'
}
$installer = Get-Item -LiteralPath $InstallerPath
$info = $installer.VersionInfo
if ($info.ProductName.Trim() -ne 'Signing Gateway' -or $info.ProductVersion.Trim() -ne $metadata.version) {
    throw 'Tên hoặc version bộ cài không khớp package.json. Không xuất manifest.'
}
if ($info.FileDescription.Trim() -ne 'Signing Gateway Setup (AutoUpdate v1)') {
    throw 'Bo cai chua ho tro giao thuc AutoUpdate v1. Hay build lai bang source moi.'
}
$manifest = [ordered]@{
    appId = 'signing-gateway'
    version = $metadata.version
    downloadUrl = $DownloadUrl
    sha256 = (Get-FileHash -LiteralPath $installer.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    releaseNotes = $ReleaseNotes
}
$target = [IO.Path]::GetFullPath($OutputPath)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
[IO.File]::WriteAllText($target, ($manifest | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
Write-Host "Manifest: $target"
