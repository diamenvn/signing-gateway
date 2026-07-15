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

        bool listOnly = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--list") listOnly = true;
            else if (args[i] == "--input" && i + 1 < args.Length) input = args[++i];
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

        if (listOnly)
        {
            try
            {
                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly);
                try
                {
                    foreach (var cert in store.Certificates)
                    {
                        string serialNumber = cert.SerialNumber.Replace(" ", "").Replace(":", "").ToUpper();
                        string cn = GetCertCN(cert);
                        Console.WriteLine($"SERIAL:{serialNumber}|CN:{cn}|HAS_KEY:{cert.HasPrivateKey}");
                    }
                }
                finally
                {
                    store.Close();
                }

                // Quet tat ca cac file PKCS#11 DLL trong thu muc he thong
                Console.WriteLine("=== DANH SACH THU VIEN PKCS#11 ===");
                string[] searchDirs = { 
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
                };
                foreach (var dir in searchDirs)
                {
                    if (Directory.Exists(dir))
                    {
                        try
                        {
                            var files = Directory.GetFiles(dir, "*csp11*.dll");
                            foreach (var f in files)
                            {
                                Console.WriteLine($"PKCS11_DLL:{Path.GetFileName(f)}|PATH:{f}");
                            }
                            var pkcsFiles = Directory.GetFiles(dir, "*pkcs11*.dll");
                            foreach (var f in pkcsFiles)
                            {
                                Console.WriteLine($"PKCS11_DLL:{Path.GetFileName(f)}|PATH:{f}");
                            }
                        }
                        catch {}
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 1;
            }
            return 0;
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

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptGetUserKey(
        IntPtr hProv,
        uint dwKeySpec,
        out IntPtr phUserKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptSetKeyParam(
        IntPtr hKey,
        uint dwParam,
        byte[] pbData,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptDestroyKey(
        IntPtr hKey);

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

    private void SetCspPin(RSACryptoServiceProvider rsaCsp, string pin, bool isUnicode)
    {
        var field = typeof(RSACryptoServiceProvider).GetField("_safeProvHandle", BindingFlags.NonPublic | BindingFlags.Instance);
        if (field != null)
        {
            var safeHandle = field.GetValue(rsaCsp) as SafeHandle;
            if (safeHandle != null)
            {
                IntPtr hProv = safeHandle.DangerousGetHandle();
                byte[] pinBytes = isUnicode ? Encoding.Unicode.GetBytes(pin + '\0') : Encoding.ASCII.GetBytes(pin + '\0');
                
                // 1. Thiet lap tren Provider
                bool retSigProv = CryptSetProvParam(hProv, PP_SIGNATURE_PIN, pinBytes, 0);
                bool retKeyProv = CryptSetProvParam(hProv, PP_KEYEXCHANGE_PIN, pinBytes, 0);
                Console.WriteLine($"[DEBUG] CryptSetProvParam isUnicode={isUnicode}: PP_SIGNATURE_PIN: {retSigProv}, PP_KEYEXCHANGE_PIN: {retKeyProv}");

                // 2. Thiet lap tren Key (KP_SIGNATURE_PIN/KP_KEYEXCHANGE_PIN)
                // Thu ca 2 loai khoa AT_SIGNATURE (2) va AT_KEYEXCHANGE (1)
                uint[] keySpecs = { 2, 1 };
                foreach (uint spec in keySpecs)
                {
                    IntPtr hKey = IntPtr.Zero;
                    if (CryptGetUserKey(hProv, spec, out hKey))
                    {
                        try
                        {
                            bool retSigKey = CryptSetKeyParam(hKey, 33, pinBytes, 0); // KP_SIGNATURE_PIN = 33
                            bool retKeyKey = CryptSetKeyParam(hKey, 32, pinBytes, 0); // KP_KEYEXCHANGE_PIN = 32
                            Console.WriteLine($"[DEBUG] CryptSetKeyParam spec={spec} isUnicode={isUnicode}: KP_SIGNATURE_PIN: {retSigKey}, KP_KEYEXCHANGE_PIN: {retKeyKey}");
                        }
                        finally
                        {
                            CryptDestroyKey(hKey);
                        }
                    }
                }
            }
        }
    }

    private void SetCngPin(CngKey cngKey, string pin, bool isUnicode)
    {
        byte[] pinBytes = isUnicode ? Encoding.Unicode.GetBytes(pin + '\0') : Encoding.ASCII.GetBytes(pin + '\0');
        CngProperty pinProperty = new CngProperty("SmartCardPin", pinBytes, CngPropertyOptions.None);
        cngKey.SetProperty(pinProperty);
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
            
            // A. Thu voi NoPrompt (Silent) + KeyPassword + CryptSetProvParam truoc
            try
            {
                Console.WriteLine("[DEBUG] Thu CSP voi NoPrompt + KeyPassword + CryptSetProvParam (ASCII)...");
                CspParameters cspParamsSilent = new CspParameters
                {
                    ProviderName = provInfo.pwszProvName,
                    ProviderType = (int)provInfo.dwProvType,
                    KeyContainerName = provInfo.pwszContainerName,
                    Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.NoPrompt
                };

                if (!string.IsNullOrEmpty(_pin))
                {
                    SecureString securePin = new SecureString();
                    foreach (char c in _pin)
                    {
                        securePin.AppendChar(c);
                    }
                    cspParamsSilent.KeyPassword = securePin;
                }

                using (var rsaCsp = new RSACryptoServiceProvider(cspParamsSilent))
                {
                    if (!string.IsNullOrEmpty(_pin))
                    {
                        SetCspPin(rsaCsp, _pin, false);
                    }
                    byte[] sig = rsaCsp.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
                    Console.WriteLine("[DEBUG] Ky CSP NoPrompt (ASCII) thanh cong.");
                    return sig;
                }
            }
            catch (CryptographicException ex) when (ex.Message.Contains("silent") || ex.Message.Contains("0x80090022") || ex.Message.Contains("0x8009001A"))
            {
                Console.WriteLine("[DEBUG] Ky CSP NoPrompt that bai (silent). Thu lai voi luong CSP tuong tac (khong NoPrompt) + KeyPassword + CryptSetProvParam...");
                
                // B. Thu voi tuong tac (khong NoPrompt) + KeyPassword + CryptSetProvParam
                // Neu PIN dung, driver se tu dong dung PIN va ky ngam ma khong hien bat ky UI nao
                try
                {
                    CspParameters cspParamsInteractive = new CspParameters
                    {
                        ProviderName = provInfo.pwszProvName,
                        ProviderType = (int)provInfo.dwProvType,
                        KeyContainerName = provInfo.pwszContainerName,
                        Flags = CspProviderFlags.UseExistingKey // KHONG dung NoPrompt
                    };

                    if (!string.IsNullOrEmpty(_pin))
                    {
                        SecureString securePin = new SecureString();
                        foreach (char c in _pin)
                        {
                            securePin.AppendChar(c);
                        }
                        cspParamsInteractive.KeyPassword = securePin;
                    }

                    using (var rsaCsp = new RSACryptoServiceProvider(cspParamsInteractive))
                    {
                        if (!string.IsNullOrEmpty(_pin))
                        {
                            SetCspPin(rsaCsp, _pin, false);
                        }
                        byte[] sig = rsaCsp.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
                        Console.WriteLine("[DEBUG] Ky CSP Interactive + KeyPassword + CryptSetProvParam (ASCII) thanh cong.");
                        return sig;
                    }
                }
                catch (Exception innerEx)
                {
                    Console.WriteLine($"[DEBUG] Thu CSP Interactive loi: {innerEx.Message}");
                    throw;
                }
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
                    // A. Thu ky voi PIN dang Unicode truoc (CNG mac dinh la Unicode)
                    try
                    {
                        Console.WriteLine("[DEBUG] Dang set PIN cho CngKey (Unicode)...");
                        SetCngPin(cngKey, _pin, true);
                        using (var rsaCng = new RSACng(cngKey))
                        {
                            Console.WriteLine("[DEBUG] Dang ky bang RSACng (Unicode)...");
                            byte[] sig = rsaCng.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
                            Console.WriteLine("[DEBUG] Ky bang RSACng (Unicode) thanh cong.");
                            return sig;
                        }
                    }
                    catch (CryptographicException ex) when (ex.Message.Contains("silent") || ex.Message.Contains("0x80090022") || ex.Message.Contains("0x8009001A"))
                    {
                        Console.WriteLine("[DEBUG] Ky CNG voi PIN Unicode that bai. Thu lai voi PIN dang ASCII...");
                        try
                        {
                            SetCngPin(cngKey, _pin, false);
                            using (var rsaCng = new RSACng(cngKey))
                            {
                                Console.WriteLine("[DEBUG] Dang ky bang RSACng (ASCII)...");
                                byte[] sig = rsaCng.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
                                Console.WriteLine("[DEBUG] Ky bang RSACng (ASCII) thanh cong.");
                                return sig;
                            }
                        }
                        catch (Exception innerEx)
                        {
                            Console.WriteLine($"[DEBUG] Thu CNG PIN ASCII loi: {innerEx.Message}");
                            throw;
                        }
                    }
                }
                else
                {
                    using (var rsaCng = new RSACng(cngKey))
                    {
                        Console.WriteLine("[DEBUG] Dang ky bang RSACng (Khong PIN)...");
                        byte[] sig = rsaCng.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
                        Console.WriteLine("[DEBUG] Ky bang RSACng thanh cong.");
                        return sig;
                    }
                }
            }
        }
    }
}
