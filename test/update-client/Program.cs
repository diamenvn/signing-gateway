using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SigningGateway.Updates;

int passed = 0;
void Check(bool condition) { if (!condition) throw new Exception("Assertion failed"); passed++; }
void Reject(Action action) { bool rejected = false; try { action(); } catch { rejected = true; } Check(rejected); }
var baseline = new Release("signing-gateway", "0.3.0", "https://github.com/diamenvn/signing-gateway/blob/HMIS-20756/dist/setup.exe", new string('a', 64), "Test");
Check(UpdateClient.ParseVersion("0.10.0") > UpdateClient.ParseVersion("0.9.0"));
Check(UpdateClient.DownloadUri(baseline.DownloadUrl).AbsoluteUri == "https://raw.githubusercontent.com/diamenvn/signing-gateway/HMIS-20756/dist/setup.exe");
const string assetUrl = "https://github.com/trongdqtgg/signing-gateway/releases/download/v0.3.0/SignerGateway.exe";
Check(UpdateClient.DownloadUri(assetUrl).AbsoluteUri == assetUrl);
Check(UpdateClient.DownloadUri("https://github.com/trongdqtgg/signing-gateway/releases/download/v1.0.2/SignerGateway.exe").Host == "github.com");
Reject(() => UpdateClient.DownloadUri("https://github.com/trongdqtgg/signing-gateway-other/releases/download/v1.0.2/SignerGateway.exe"));
try
{
    UpdateClient.DownloadUri(assetUrl.Replace("/download/", "/tag/"));
    throw new Exception("Accepted release page as installer");
}
catch (InvalidDataException e) { Check(e.Message.Contains("/releases/download/")); }
Reject(() => UpdateClient.DownloadUri("not a URL"));
Reject(() => UpdateClient.Validate(baseline with { AppId = "plugin" }));
Reject(() => UpdateClient.Validate(baseline with { Version = "0.3.0-beta" }));
Reject(() => UpdateClient.Validate(baseline with { Sha256 = "bad" }));
foreach (string url in new[] { "http://github.com/trongdqtgg/signing-gateway/releases/download/0.3/setup.exe", "https://evil.example/setup.exe", "https://github.com/other/repo/releases/download/0.3/setup.exe", "https://raw.githubusercontent.com/diamenvn/signing-gateway/main/file.html" })
    Reject(() => UpdateClient.DownloadUri(url));
var handler = new FakeHandler();
using var http = new HttpClient(handler);
var client = new UpdateClient(http);
handler.Data = JsonSerializer.SerializeToUtf8Bytes(baseline);
Check((await client.Check(CancellationToken.None)).Version == "0.3.0");
handler.Data = new byte[65537];
try { await client.Check(CancellationToken.None); throw new Exception("Accepted oversized manifest"); }
catch (InvalidDataException) { passed++; }
string temp = Path.Combine(Path.GetTempPath(), "gateway-update-test-" + Guid.NewGuid());
try
{
    foreach (byte[] bytes in new[] { Encoding.UTF8.GetBytes("<html>not an installer</html>"), Encoding.UTF8.GetBytes("MZwrong-hash") })
    {
        handler.Data = bytes;
        try { await client.Download(baseline, temp, new Progress<int>(), CancellationToken.None); throw new Exception("Accepted invalid download"); }
        catch (InvalidDataException) { passed++; }
        Check(Directory.GetFiles(temp).Length == 0);
    }
    // Optional real local installer fixture: verify metadata, hash and complete download.
    if (args.Length > 0)
    {
        handler.Data = File.ReadAllBytes(args[0]);
        string hash = Convert.ToHexString(SHA256.HashData(handler.Data));
        var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(args[0]);
        var release = baseline with { Version = info.ProductVersion!.Trim(), Sha256 = hash };
        if (info.FileDescription?.Trim() == "Signing Gateway Setup (AutoUpdate v1)")
        {
            string output = await client.Download(release, temp, new Progress<int>(), CancellationToken.None);
            Check(File.Exists(output)); File.Delete(output);
        }
        else
        {
            try { await client.Download(release, temp, new Progress<int>(), CancellationToken.None); throw new Exception("Accepted legacy installer"); }
            catch (InvalidDataException) { passed++; }
        }
        try { await client.Download(release with {Version = "99.0.0"}, temp, new Progress<int>(), CancellationToken.None); throw new Exception("Accepted wrong product version"); }
        catch (InvalidDataException) { passed++; }
    }
}
finally { if (Directory.Exists(temp)) Directory.Delete(temp, true); }
Console.WriteLine($"PASS: {passed} update client checks");

sealed class FakeHandler : HttpMessageHandler
{
    public byte[] Data = Array.Empty<byte>();
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {Content = new ByteArrayContent(Data)});
}
