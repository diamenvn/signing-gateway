using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Reflection;

class Program
{
    static int Main(string[] args)
    {
        string input = null;
        string output = null;
        string serial = null;
        string pin = null;
        int page = 1;
        float llx = 0;
        float lly = 0;
        float urx = 0;
        float ury = 0;
        string desc = null;
        string image = null;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--input" && i + 1 < args.Length) input = args[++i];
            else if (args[i] == "--output" && i + 1 < args.Length) output = args[++i];
            else if (args[i] == "--serial" && i + 1 < args.Length) serial = args[++i];
            else if (args[i] == "--pin" && i + 1 < args.Length) pin = args[++i];
            else if (args[i] == "--page" && i + 1 < args.Length) int.TryParse(args[++i], out page);
            else if (args[i] == "--llx" && i + 1 < args.Length) float.TryParse(args[++i], out llx);
            else if (args[i] == "--lly" && i + 1 < args.Length) float.TryParse(args[++i], out lly);
            else if (args[i] == "--urx" && i + 1 < args.Length) float.TryParse(args[++i], out urx);
            else if (args[i] == "--ury" && i + 1 < args.Length) float.TryParse(args[++i], out ury);
            else if (args[i] == "--desc" && i + 1 < args.Length) desc = args[++i];
            else if (args[i] == "--image" && i + 1 < args.Length) image = args[++i];
        }

        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(output) || string.IsNullOrEmpty(serial))
        {
            Console.Error.WriteLine("Loi: Thieu tham so bat buoc (--input, --output, --serial)");
            Console.Error.WriteLine("Cach dung: pdf-signer.exe --input <file.pdf> --output <output.pdf> --serial <serial> [--pin <pin>] [--page <page>] [--llx <x>] [--lly <y>] [--urx <x>] [--ury <y>] [--desc <desc>] [--image <img.png>]");
            return 1;
        }

        try
        {
            Console.WriteLine($"[INFO] Dang tim chung thu voi Serial: {serial} trong Windows Store (CurrentUser/My)...");
            X509Certificate2 cert = FindCertificate(serial);
            if (cert == null)
            {
                Console.Error.WriteLine($"CERTIFICATE_NOT_FOUND: Khong tim thay chung thu nao voi Serial: '{serial}' trong Windows Store.");
                return 1;
            }

            Console.WriteLine($"[INFO] Da tim thay chung thu: {cert.Subject}");
            Console.WriteLine($"[INFO] Dang tien hanh ky file PDF: {input} -> {output}...");
            SignPdf(input, output, cert, pin, page, llx, lly, urx, ury, desc, image);
            Console.WriteLine("[INFO] Ky so thanh cong!");
            return 0;
        }
        catch (Exception ex)
        {
            string msg = ex.Message;
            Console.Error.WriteLine($"[DEBUG_RAW_ERR] {ex.ToString()}");
            if (msg.Contains("wrong PIN") || msg.Contains("incorrect PIN") || msg.Contains("PIN was presented") || msg.Contains("0x8009001A") || msg.Contains("context was acquired as silent"))
            {
                Console.Error.WriteLine("WRONG_PIN: Ma PIN cua USB Token khong chinh xac hoac thieu ma PIN.");
            }
            else if (msg.Contains("NTE_SILENT_CONTEXT") || msg.Contains("cancelled") || msg.Contains("cancelled by the user") || msg.Contains("0x80090022"))
            {
                Console.Error.WriteLine("SIGN_CANCELLED: Thao tac ky bi huy hoac thieu ma PIN.");
            }
            else
            {
                Console.Error.WriteLine($"UNKNOWN_ERROR: Loi khi ky so: {msg}");
            }
            return 1;
        }
    }

    static X509Certificate2 FindCertificate(string serialNumber)
    {
        string cleanSerial = serialNumber.Replace(" ", "").Replace(":", "").ToUpper();
        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        try
        {
            foreach (var cert in store.Certificates)
            {
                string certSerial = cert.SerialNumber.Replace(" ", "").Replace(":", "").ToUpper();
                if (certSerial == cleanSerial)
                {
                    return cert;
                }
            }
        }
        finally
        {
            store.Close();
        }
        return null;
    }

    static void SignPdf(
        string inputPath, 
        string outputPath, 
        X509Certificate2 cert, 
        string pin,
        int page, 
        float llx, 
        float lly, 
        float urx, 
        float ury, 
        string description, 
        string imagePath)
    {
        Console.WriteLine("[DEBUG] Bat dau SignPdf...");
        // 1. Dung chuoi chung thu (cert chain)
        X509Chain chainObj = new X509Chain();
        chainObj.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Tat kiem tra truc tuyen de tranh treo/timeout
        chainObj.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags; // Bo qua xac thuc de chay nhanh offline
        chainObj.Build(cert);
        Console.WriteLine("[DEBUG] Dung x509 chain xong. So luong cert: " + chainObj.ChainElements.Count);

        var chain = new Org.BouncyCastle.X509.X509Certificate[chainObj.ChainElements.Count];
        for (int i = 0; i < chainObj.ChainElements.Count; i++)
        {
            var c = chainObj.ChainElements[i].Certificate;
            chain[i] = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(c.RawData);
        }

        // 2. Khoi tao doi tuong ky ngoai (IExternalSignature) ho tro CNG va CSP
        var externalSignature = new CngUserSignature(cert, pin, "SHA256");

        // 3. Mo va tao chu ky PDF
        using (PdfReader reader = new PdfReader(inputPath))
        using (FileStream os = new FileStream(outputPath, FileMode.Create))
        using (PdfStamper stamper = PdfStamper.CreateSignature(reader, os, '\0'))
        {
            Console.WriteLine("[DEBUG] Da mo PdfReader, FileStream, PdfStamper...");
            PdfSignatureAppearance appearance = stamper.SignatureAppearance;
            
            // Thiet lap vi tri chu ky visible
            appearance.SetVisibleSignature(new iTextSharp.text.Rectangle(llx, lly, urx, ury), page, null);
            
            // Build text thong tin nguoi ky
            string subjectCN = GetCertCN(cert);
            string signingTimeStr = DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss");
            string text = $"Ký bởi: {subjectCN}\nNgày ký: {signingTimeStr}";
            if (!string.IsNullOrEmpty(description))
            {
                text += $"\nLý do: {description}";
            }
            appearance.Layer2Text = text;

            // Chen hinh anh ben trai va text ben phai neu co anh
            if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
            {
                iTextSharp.text.Image img = iTextSharp.text.Image.GetInstance(imagePath);
                appearance.SignatureGraphic = img;
                appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION;
            }
            else
            {
                appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
            }

            // Thuc hien ky so detached CMS
            Console.WriteLine("[DEBUG] Dang goi MakeSignature.SignDetached...");
            MakeSignature.SignDetached(appearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
            Console.WriteLine("[DEBUG] Da goi xong MakeSignature.SignDetached...");
        }
        Console.WriteLine("[DEBUG] Da dong va hoan tat PdfStamper.");
    }

    static string GetCertCN(X509Certificate2 cert)
    {
        string subject = cert.Subject;
        foreach (string part in subject.Split(','))
        {
            string clean = part.Trim();
            if (clean.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return clean.Substring(3);
            }
        }
        return cert.FriendlyName ?? subject;
    }
}

public class CngUserSignature : IExternalSignature
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPT_KEY_PROV_INFO
    {
        public string pwszContainerName;
        public string pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateContextProperty(
        IntPtr pCertContext,
        int dwPropId,
        IntPtr pvData,
        ref int pcbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptSetProvParam(
        IntPtr hProv,
        uint dwParam,
        [In] byte[] pbData,
        uint dwFlags);

    private const int CERT_KEY_PROV_INFO_PROP_ID = 2;
    private const uint PP_KEYEXCHANGE_PIN = 32;
    private const uint PP_SIGNATURE_PIN = 33;

    private X509Certificate2 _cert;
    private string _pin;
    private string _hashAlgorithm;

    public CngUserSignature(X509Certificate2 cert, string pin, string hashAlgorithm)
    {
        _cert = cert;
        _pin = pin;
        _hashAlgorithm = hashAlgorithm.ToUpper().Replace("-", "");
    }

    public string GetHashAlgorithm()
    {
        return _hashAlgorithm;
    }

    public string GetEncryptionAlgorithm()
    {
        return "RSA";
    }

    private CRYPT_KEY_PROV_INFO? GetKeyProvInfo()
    {
        int pcbData = 0;
        if (!CertGetCertificateContextProperty(_cert.Handle, CERT_KEY_PROV_INFO_PROP_ID, IntPtr.Zero, ref pcbData))
        {
            return null;
        }

        IntPtr pData = Marshal.AllocHGlobal(pcbData);
        try
        {
            if (CertGetCertificateContextProperty(_cert.Handle, CERT_KEY_PROV_INFO_PROP_ID, pData, ref pcbData))
            {
                return Marshal.PtrToStructure<CRYPT_KEY_PROV_INFO>(pData);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pData);
        }
        return null;
    }

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    private static extern int SCardEstablishContext(uint dwScope, IntPtr pvReserved1, IntPtr pvReserved2, out IntPtr phContext);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    private static extern int SCardReleaseContext(IntPtr hContext);

    [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
    private static extern int SCardListReaders(IntPtr hContext, string mszGroups, byte[] mszReaders, ref uint pcchReaders);

    private List<string> GetReaderNames()
    {
        List<string> readers = new List<string>();
        IntPtr hContext = IntPtr.Zero;
        try
        {
            int ret = SCardEstablishContext(0, IntPtr.Zero, IntPtr.Zero, out hContext);
            if (ret == 0)
            {
                uint pcchReaders = 0;
                ret = SCardListReaders(hContext, null, null, ref pcchReaders);
                if (ret == 0 && pcchReaders > 0)
                {
                    byte[] mszReaders = new byte[pcchReaders * 2]; // unicode
                    ret = SCardListReaders(hContext, null, mszReaders, ref pcchReaders);
                    if (ret == 0)
                      {
                        string allReaders = Encoding.Unicode.GetString(mszReaders);
                        string[] split = allReaders.Split('\0');
                        foreach (string r in split)
                        {
                            if (!string.IsNullOrEmpty(r))
                                readers.Add(r);
                        }
                    }
                }
            }
        }
        catch {}
        finally
        {
            if (hContext != IntPtr.Zero) SCardReleaseContext(hContext);
        }
        return readers;
    }

    public byte[] Sign(byte[] message)
    {
        Console.WriteLine("[DEBUG] Bat dau phuong thuc Sign...");
        Console.WriteLine($"[DEBUG] Sign: pin length = {(_pin != null ? _pin.Length : 0)}");

        CRYPT_KEY_PROV_INFO? provInfoOpt = GetKeyProvInfo();
        if (provInfoOpt == null)
        {
            Console.WriteLine("[DEBUG] Khong doc duoc CRYPT_KEY_PROV_INFO. Fallback sang GetRSAPrivateKey...");
            using (RSA rsa = _cert.GetRSAPrivateKey())
            {
                if (rsa == null)
                    throw new Exception("Chung thu khong chua khoa bi mat RSA hop le.");
                return rsa.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
            }
        }

        var provInfo = provInfoOpt.Value;
        Console.WriteLine($"[DEBUG] KeyProvInfo: Container={provInfo.pwszContainerName}, Provider={provInfo.pwszProvName}, Type={provInfo.dwProvType}");

        // 1. NEU LA CSP TRUYEN THONG (dwProvType > 0) -> Bat buoc dung luong CSP de tuong thich driver tot nhat
        if (provInfo.dwProvType > 0)
        {
            Console.WriteLine("[DEBUG] Uu tien luong CSP cho khoa Type > 0...");
            CspParameters cspParams = new CspParameters
            {
                ProviderName = provInfo.pwszProvName,
                ProviderType = (int)provInfo.dwProvType,
                KeyContainerName = provInfo.pwszContainerName,
                Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.NoPrompt
            };

            using (var rsaCsp = new RSACryptoServiceProvider(cspParams))
            {
                if (!string.IsNullOrEmpty(_pin))
                {
                    Console.WriteLine("[DEBUG] Thiet lap PIN qua CryptSetProvParam...");
                    try
                    {
                        var field = typeof(RSACryptoServiceProvider).GetField("_safeProvHandle", BindingFlags.NonPublic | BindingFlags.Instance);
                        if (field != null)
                        {
                            var safeHandle = field.GetValue(rsaCsp) as SafeHandle;
                            if (safeHandle != null)
                            {
                                IntPtr hProv = safeHandle.DangerousGetHandle();
                                byte[] pinBytes = Encoding.ASCII.GetBytes(_pin + '\0');
                                bool retSig = CryptSetProvParam(hProv, PP_SIGNATURE_PIN, pinBytes, 0);
                                bool retKey = CryptSetProvParam(hProv, PP_KEYEXCHANGE_PIN, pinBytes, 0);
                                Console.WriteLine($"[DEBUG] CryptSetProvParam PP_SIGNATURE_PIN: {retSig}, PP_KEYEXCHANGE_PIN: {retKey}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[DEBUG] Loi thiet lap PIN: {ex.Message}");
                    }
                }

                Console.WriteLine("[DEBUG] Dang ky bang RSACryptoServiceProvider...");
                byte[] sig = rsaCsp.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
                Console.WriteLine("[DEBUG] Ky bang RSACryptoServiceProvider thanh cong.");
                return sig;
            }
        }
        // 2. NEU LA CNG KSP (dwProvType == 0) -> Dung luong CNG
        else
        {
            Console.WriteLine("[DEBUG] Uu tien luong CNG cho khoa Type == 0...");
            CngProvider cngProvider = new CngProvider(provInfo.pwszProvName);
            using (CngKey cngKey = CngKey.Open(provInfo.pwszContainerName, cngProvider, CngKeyOpenOptions.Silent))
            {
                if (!string.IsNullOrEmpty(_pin))
                {
                    Console.WriteLine("[DEBUG] Dang set PIN cho CngKey...");
                    byte[] pinBytes = Encoding.Unicode.GetBytes(_pin + '\0');
                    CngProperty pinProperty = new CngProperty("SmartCardPin", pinBytes, CngPropertyOptions.None);
                    cngKey.SetProperty(pinProperty);
                }

                using (var rsaCng = new RSACng(cngKey))
                {
                    Console.WriteLine("[DEBUG] Dang ky bang RSACng...");
                    byte[] sig = rsaCng.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
                    Console.WriteLine("[DEBUG] Ky bang RSACng thanh cong.");
                    return sig;
                }
            }
        }
    }
}
