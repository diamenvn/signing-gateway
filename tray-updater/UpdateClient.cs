using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SigningGateway.Updates;

public sealed record Release(string AppId, string Version, string DownloadUrl, string Sha256, string? ReleaseNotes);

public sealed class UpdateClient
{
    public const string ManifestUrl = "https://raw.githubusercontent.com/diamenvn/signing-gateway/HMIS-20756/releases/latest.json";
    public const string AppId = "signing-gateway";
    public static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly HttpClient client;
    public UpdateClient(HttpClient client) { this.client = client; }

    public static Version ParseVersion(string value)
    {
        if (!Regex.IsMatch(value, @"^\d+\.\d+\.\d+$")) throw new InvalidDataException("Phiên bản phải có dạng major.minor.patch.");
        return Version.Parse(value);
    }

    public static Uri DownloadUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
            throw new InvalidDataException("downloadUrl trong releases/latest.json không phải URL hợp lệ.");
        if (uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo != "" || uri.Fragment != "")
            throw new InvalidDataException("Đường dẫn tải không hợp lệ.");
        if (uri.Host == "github.com" && uri.AbsolutePath.StartsWith("/diamenvn/signing-gateway/releases/tag/", StringComparison.Ordinal))
            throw new InvalidDataException("downloadUrl trong releases/latest.json đang dùng link trang release (/releases/tag/). Hãy dùng link tải bộ cài: https://github.com/diamenvn/signing-gateway/releases/download/<tag>/SignerGateway.exe");
        if (uri.Host == "github.com" && uri.AbsolutePath.StartsWith("/diamenvn/signing-gateway/blob/", StringComparison.Ordinal))
            uri = new Uri("https://raw.githubusercontent.com" + uri.AbsolutePath.Replace("/blob/", "/"));
        bool allowed = (uri.Host == "raw.githubusercontent.com" && uri.AbsolutePath.StartsWith("/diamenvn/signing-gateway/", StringComparison.Ordinal)) ||
            (uri.Host == "github.com" && uri.AbsolutePath.StartsWith("/diamenvn/signing-gateway/releases/download/", StringComparison.Ordinal));
        if (!allowed || !uri.AbsolutePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Bộ cài phải thuộc repository diamenvn/signing-gateway.");
        return uri;
    }

    public static Release Validate(Release release)
    {
        if (release.AppId != AppId) throw new InvalidDataException("Bản cập nhật không dành cho Signing Gateway.");
        ParseVersion(release.Version);
        DownloadUri(release.DownloadUrl);
        if (!Regex.IsMatch(release.Sha256 ?? "", "^[a-fA-F0-9]{64}$")) throw new InvalidDataException("Thiếu SHA-256 hợp lệ.");
        return release;
    }

    public async Task<Release> Check(CancellationToken ct)
    {
        using var response = await client.GetAsync(ManifestUrl, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var memory = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (memory.Length + count > 65536) throw new InvalidDataException("Manifest quá lớn.");
            memory.Write(buffer, 0, count);
        }
        return Validate(JsonSerializer.Deserialize<Release>(memory.ToArray(), JsonOptions) ?? throw new InvalidDataException("Manifest rỗng."));
    }

    public async Task<string> Download(Release release, string directory, IProgress<int> progress, CancellationToken ct)
    {
        Validate(release);
        Directory.CreateDirectory(directory);
        string output = Path.Combine(directory, Guid.NewGuid() + ".exe");
        try
        {
            using var response = await client.GetAsync(DownloadUri(release.DownloadUrl), HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();
            long total = response.Content.Headers.ContentLength ?? 0;
            const long max = 1024L * 1024 * 1024;
            if (total > max) throw new InvalidDataException("Bộ cài quá lớn.");
            await using (var input = await response.Content.ReadAsStreamAsync(ct))
            await using (var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true))
            {
                var buffer = new byte[81920];
                long size = 0;
                int count;
                while ((count = await input.ReadAsync(buffer, ct)) > 0)
                {
                    size += count;
                    if (size > max) throw new InvalidDataException("Bộ cài quá lớn.");
                    await file.WriteAsync(buffer.AsMemory(0, count), ct);
                    if (total > 0) progress.Report((int)Math.Min(100, size * 100 / total));
                }
            }
            await using (var file = File.OpenRead(output))
            {
                if (file.ReadByte() != 'M' || file.ReadByte() != 'Z') throw new InvalidDataException("File tải về không phải bộ cài Windows (có thể là trang HTML hoặc Git LFS pointer).");
                file.Position = 0;
                string hash = Convert.ToHexString(await SHA256.HashDataAsync(file, ct));
                if (!hash.Equals(release.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("SHA-256 không khớp. Không chạy bộ cài.");
            }
            var info = FileVersionInfo.GetVersionInfo(output);
            if (info.ProductName?.Trim() != "Signing Gateway" || info.ProductVersion?.Trim() != release.Version ||
                info.FileDescription?.Trim() != "Signing Gateway Setup (AutoUpdate v1)")
                throw new InvalidDataException("Tên hoặc phiên bản bộ cài không khớp bản phát hành Signing Gateway.");
            return output;
        }
        catch { if (File.Exists(output)) File.Delete(output); throw; }
    }
}
