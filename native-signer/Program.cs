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
        bool testPkcs11 = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--list") listOnly = true;
            else if (args[i] == "--test-pkcs11") testPkcs11 = true;
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
                                DumpDllExports(f);
                            }
                            var pkcsFiles = Directory.GetFiles(dir, "*pkcs11*.dll");
                            foreach (var f in pkcsFiles)
                            {
                                Console.WriteLine($"PKCS11_DLL:{Path.GetFileName(f)}|PATH:{f}");
                                DumpDllExports(f);
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

        if (testPkcs11)
        {
            if (string.IsNullOrEmpty(serial) || string.IsNullOrEmpty(pin))
            {
                Console.Error.WriteLine("Loi: Thieu tham so cho --test-pkcs11 (--serial, --pin)");
                return 1;
            }

            try
            {
                Console.WriteLine("[TEST] Khoi dong so sanh chu ky CNG va PKCS#11...");
                X509Certificate2 cert = FindCertificate(serial);
                if (cert == null)
                {
                    Console.Error.WriteLine($"Khong tim thay chung thu voi serial {serial}");
                    return 1;
                }

                var signatureObj = new CngUserSignature(cert, pin, "SHA256");
                var provInfo = signatureObj.GetKeyProvInfo();
                if (provInfo == null || string.IsNullOrEmpty(provInfo.Value.pwszProvName))
                {
                    Console.Error.WriteLine("Khong doc duoc KeyProvInfo tu chung thu.");
                    return 1;
                }

                string pkcs11DllPath = FindPkcs11Dll(provInfo.Value.pwszProvName);
                if (pkcs11DllPath == null)
                {
                    Console.Error.WriteLine($"Khong tim thay DLL PKCS#11 phu hop cho Provider: {provInfo.Value.pwszProvName}");
                    return 1;
                }

                Console.WriteLine($"[TEST] DLL PKCS#11 duoc su dung: {pkcs11DllPath}");

                // Tao 32 bytes hash gia lap
                byte[] testHash = new byte[32];
                for (int idx = 0; idx < 32; idx++) testHash[idx] = (byte)idx;

                // 1. Ky bang CNG (Gold Standard)
                byte[] cngSig = null;
                CngProvider cngProvider = new CngProvider(provInfo.Value.pwszProvName);
                using (CngKey cngKey = CngKey.Open(provInfo.Value.pwszContainerName, cngProvider, CngKeyOpenOptions.None))
                {
                    byte[] pinBytes = Encoding.Unicode.GetBytes(pin + '\0');
                    CngProperty pinProperty = new CngProperty("SmartCardPin", pinBytes, CngPropertyOptions.None);
                    cngKey.SetProperty(pinProperty);
                    using (var rsaCng = new RSACng(cngKey))
                    {
                        cngSig = rsaCng.SignHash(testHash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                }
                string cngSigHex = BitConverter.ToString(cngSig).Replace("-", "");
                Console.WriteLine($"[TEST] CNG SignHash (GOC): {cngSigHex.Substring(0, 30)}... ({cngSig.Length} bytes)");

                // 2. Chay test PKCS#11 voi 2 truong hop
                var pkcs = new Pkcs11Signature(pkcs11DllPath, pin, "SHA256");
                
                // Truong hop A: Truyen Prefix + Hash
                byte[] sigA = pkcs.SignTest(testHash, true); 
                string hexA = BitConverter.ToString(sigA).Replace("-", "");
                bool matchA = hexA == cngSigHex;
                Console.WriteLine($"[TEST] PKCS11 (Prefix + Hash): {hexA.Substring(0, 30)}... Khop: {matchA}");

                // Truong hop B: Truyen raw Hash
                byte[] sigB = pkcs.SignTest(testHash, false);
                string hexB = BitConverter.ToString(sigB).Replace("-", "");
                bool matchB = hexB == cngSigHex;
                Console.WriteLine($"[TEST] PKCS11 (Raw Hash): {hexB.Substring(0, 30)}... Khop: {matchB}");

                if (matchA) Console.WriteLine("[TEST_RESULT] KET LUAN: Token yeu cau truyen day du Prefix + Hash (Case A).");
                else if (matchB) Console.WriteLine("[TEST_RESULT] KET LUAN: Token tu dong them Prefix, chi can truyen Raw Hash (Case B).");
                else Console.WriteLine("[TEST_RESULT] KET LUAN: Ca hai deu khong khop! Can kiem tra lai.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[TEST] Loi test: {ex}");
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

        // 2. Khoi tao doi tuong ky ngoai (IExternalSignature) ho tro PKCS#11, CNG va CSP
        IExternalSignature externalSignature;
        string pkcs11DllPath = null;
        var signatureObj = new CngUserSignature(cert, pin, "SHA256");
        var provInfo = signatureObj.GetKeyProvInfo();
        if (provInfo != null && !string.IsNullOrEmpty(provInfo.Value.pwszProvName))
        {
            pkcs11DllPath = FindPkcs11Dll(provInfo.Value.pwszProvName);
        }

        if (pkcs11DllPath != null)
        {
            Console.WriteLine($"[INFO] Phat hien driver PKCS#11 tuong thich: {pkcs11DllPath}. Chuyen sang luong ky PKCS#11 de ky an 100%...");
            externalSignature = new Pkcs11Signature(pkcs11DllPath, pin, "SHA256");
        }
        else
        {
            Console.WriteLine("[INFO] Su dung luong ky mac dinh CAPI/CNG...");
            externalSignature = signatureObj;
        }

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

    static string FindPkcs11Dll(string providerName)
    {
        string pattern = null;
        if (providerName.Contains("ICA")) pattern = "ica_csp11_v1";
        else if (providerName.Contains("NC-CA")) pattern = "ncca_csp11_v1";
        else return null;

        string[] searchDirs = { 
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
        };

        foreach (var dir in searchDirs)
        {
            if (Directory.Exists(dir))
            {
                // Chỉ load bản DLL thường vì kết quả quét PE xuất khẩu cho thấy
                // chỉ bản thường mới hỗ trợ chuẩn PKCS#11 (chứa các hàm C_...),
                // còn bản _s.dll chỉ là driver CSP thuần.
                string normalPath = Path.Combine(dir, pattern + ".dll");
                if (File.Exists(normalPath)) return normalPath;
            }
        }
        return null;
    }

    static void DumpDllExports(string dllPath)
    {
        try
        {
            Console.WriteLine($"=== EXPORTS FOR {Path.GetFileName(dllPath)} ===");
            byte[] fileBytes = File.ReadAllBytes(dllPath);
            int dosHeaderActive = BitConverter.ToInt32(fileBytes, 0x3C);
            int peHeaderSign = BitConverter.ToInt32(fileBytes, dosHeaderActive);
            if (peHeaderSign != 0x00004550)
            {
                Console.WriteLine("Not a valid PE file.");
                return;
            }

            int numSections = BitConverter.ToInt16(fileBytes, dosHeaderActive + 6);
            int optHeaderSize = BitConverter.ToInt16(fileBytes, dosHeaderActive + 20);
            int optHeaderOffset = dosHeaderActive + 24;

            ushort magic = BitConverter.ToUInt16(fileBytes, optHeaderOffset);
            bool is64 = magic == 0x20b;

            int exportDirRvaOffset = is64 ? (optHeaderOffset + 112) : (optHeaderOffset + 96);
            int exportDirRva = BitConverter.ToInt32(fileBytes, exportDirRvaOffset);

            if (exportDirRva == 0)
            {
                Console.WriteLine("No exports found.");
                return;
            }

            int sectionHeaderOffset = optHeaderOffset + optHeaderSize;
            int rawOffset = 0;
            for (int i = 0; i < numSections; i++)
            {
                int secOffset = sectionHeaderOffset + i * 40;
                int secVirtualAddress = BitConverter.ToInt32(fileBytes, secOffset + 12);
                int secSizeOfRawData = BitConverter.ToInt32(fileBytes, secOffset + 16);
                int secPointerToRawData = BitConverter.ToInt32(fileBytes, secOffset + 20);

                if (exportDirRva >= secVirtualAddress && exportDirRva < secVirtualAddress + secSizeOfRawData)
                {
                    rawOffset = secPointerToRawData - secVirtualAddress;
                    break;
                }
            }

            if (rawOffset == 0)
            {
                Console.WriteLine("Export directory section not found.");
                return;
            }

            int exportDirFileOffset = exportDirRva + rawOffset;
            int numNames = BitConverter.ToInt32(fileBytes, exportDirFileOffset + 24);
            int addressOfNamesRva = BitConverter.ToInt32(fileBytes, exportDirFileOffset + 32);
            int addressOfNamesFileOffset = addressOfNamesRva + rawOffset;

            for (int i = 0; i < numNames && i < 100; i++)
            {
                int nameRva = BitConverter.ToInt32(fileBytes, addressOfNamesFileOffset + i * 4);
                int nameFileOffset = nameRva + rawOffset;
                
                StringBuilder sb = new StringBuilder();
                int idx = nameFileOffset;
                while (fileBytes[idx] != 0)
                {
                    sb.Append((char)fileBytes[idx]);
                    idx++;
                }
                Console.WriteLine($"EXPORT_FUNC:{sb.ToString()}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing exports: {ex.Message}");
        }
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

    public CRYPT_KEY_PROV_INFO? GetKeyProvInfo()
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

public class Pkcs11Signature : IExternalSignature
{
    private string _dllPath;
    private string _pin;
    private string _hashAlgorithm;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hModule);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_Initialize(IntPtr pReserved);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_Finalize(IntPtr pReserved);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_GetSlotList(byte tokenPresent, IntPtr pSlotList, ref uint pulCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_OpenSession(uint slotID, uint flags, IntPtr pApplication, IntPtr Notify, out IntPtr phSession);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_CloseSession(IntPtr hSession);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_Login(IntPtr hSession, uint userType, byte[] pPin, uint ulPinLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_Logout(IntPtr hSession);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_FindObjectsInit(IntPtr hSession, CK_ATTRIBUTE[] pTemplate, uint ulCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_FindObjects(IntPtr hSession, IntPtr phObject, uint ulMaxObjectCount, out uint pulObjectCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_FindObjectsFinal(IntPtr hSession);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_GetAttributeValue(IntPtr hSession, IntPtr hObject, CK_ATTRIBUTE[] pTemplate, uint ulCount);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_SignInit(IntPtr hSession, ref CK_MECHANISM pMechanism, IntPtr hKey);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint C_Sign(IntPtr hSession, byte[] pData, uint ulDataLen, byte[] pSignature, ref uint pulSignatureLen);

    [StructLayout(LayoutKind.Sequential)]
    struct CK_ATTRIBUTE
    {
        public uint type;
        public IntPtr pValue;
        public uint ulValueLen;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CK_MECHANISM
    {
        public uint mechanism;
        public IntPtr pParameter;
        public uint ulParameterLen;
    }

    private const uint CKA_CLASS = 0x00000000;
    private const uint CKO_PRIVATE_KEY = 0x00000003;
    private const uint CKM_RSA_PKCS = 0x00000001;
    private const uint CKU_USER = 1;
    private const uint CKF_SERIAL_SESSION = 0x00000004;

    public Pkcs11Signature(string dllPath, string pin, string hashAlgorithm)
    {
        _dllPath = dllPath;
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

    private int GetParamSize(string name)
    {
        switch (name)
        {
            case "C_Initialize": return 4;
            case "C_Finalize": return 4;
            case "C_CloseSession": return 4;
            case "C_Logout": return 4;
            case "C_FindObjectsFinal": return 4;
            case "C_GetSlotList": return 12;
            case "C_FindObjectsInit": return 12;
            case "C_SignInit": return 12;
            case "C_Login": return 16;
            case "C_FindObjects": return 16;
            case "C_GetAttributeValue": return 16;
            case "C_OpenSession": return 20;
            case "C_Sign": return 20;
            default: return 0;
        }
    }

    private T GetFunc<T>(IntPtr hModule, string name) where T : Delegate
    {
        IntPtr proc = GetProcAddress(hModule, name);
        if (proc == IntPtr.Zero)
        {
            // Fallback ho tro ten bi decorated tren 32-bit (x86) Windows
            int size = GetParamSize(name);
            if (size > 0)
            {
                // Thu dang _Name@size
                string dec1 = $"_{name}@{size}";
                proc = GetProcAddress(hModule, dec1);
                
                // Thu dang Name@size
                if (proc == IntPtr.Zero)
                {
                    string dec2 = $"{name}@{size}";
                    proc = GetProcAddress(hModule, dec2);
                }
            }
        }

        if (proc == IntPtr.Zero)
            throw new Exception($"Failed to find PKCS#11 function {name} in {_dllPath}");
            
        return Marshal.GetDelegateForFunctionPointer<T>(proc);
    }

    public byte[] Sign(byte[] message)
    {
        Console.WriteLine($"[DEBUG] Pkcs11: Loading library {_dllPath}...");
        IntPtr hModule = LoadLibrary(_dllPath);
        if (hModule == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            throw new Exception($"Failed to load PKCS#11 DLL: {_dllPath} (Error: {err})");
        }

        try
        {
            var cInitialize = GetFunc<C_Initialize>(hModule, "C_Initialize");
            var cFinalize = GetFunc<C_Finalize>(hModule, "C_Finalize");
            var cGetSlotList = GetFunc<C_GetSlotList>(hModule, "C_GetSlotList");
            var cOpenSession = GetFunc<C_OpenSession>(hModule, "C_OpenSession");
            var cCloseSession = GetFunc<C_CloseSession>(hModule, "C_CloseSession");
            var cLogin = GetFunc<C_Login>(hModule, "C_Login");
            var cLogout = GetFunc<C_Logout>(hModule, "C_Logout");
            var cFindObjectsInit = GetFunc<C_FindObjectsInit>(hModule, "C_FindObjectsInit");
            var cFindObjects = GetFunc<C_FindObjects>(hModule, "C_FindObjects");
            var cFindObjectsFinal = GetFunc<C_FindObjectsFinal>(hModule, "C_FindObjectsFinal");
            var cSignInit = GetFunc<C_SignInit>(hModule, "C_SignInit");
            var cSign = GetFunc<C_Sign>(hModule, "C_Sign");

            Console.WriteLine("[DEBUG] Pkcs11: Calling C_Initialize...");
            uint rv = cInitialize(IntPtr.Zero);
            if (rv != 0 && rv != 0x00000191) // CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
                throw new Exception($"C_Initialize failed: 0x{rv:X8}");

            try
            {
                Console.WriteLine("[DEBUG] Pkcs11: Getting slot list...");
                uint count = 0;
                rv = cGetSlotList(1, IntPtr.Zero, ref count);
                if (rv != 0 || count == 0)
                    throw new Exception("No active smart card slots found.");

                IntPtr pSlots = Marshal.AllocHGlobal((int)count * 4);
                try
                {
                    rv = cGetSlotList(1, pSlots, ref count);
                    if (rv != 0)
                        throw new Exception("C_GetSlotList failed.");

                    int[] slots = new int[count];
                    Marshal.Copy(pSlots, slots, 0, (int)count);
                    uint slotId = (uint)slots[0];
                    Console.WriteLine($"[DEBUG] Pkcs11: Using slotId={slotId}");

                    Console.WriteLine("[DEBUG] Pkcs11: Opening session...");
                    IntPtr hSession;
                    rv = cOpenSession(slotId, CKF_SERIAL_SESSION, IntPtr.Zero, IntPtr.Zero, out hSession);
                    if (rv != 0)
                        throw new Exception($"C_OpenSession failed: 0x{rv:X8}");

                    try
                    {
                        Console.WriteLine("[DEBUG] Pkcs11: Logging in...");
                        byte[] pinBytes = Encoding.ASCII.GetBytes(_pin);
                        rv = cLogin(hSession, CKU_USER, pinBytes, (uint)pinBytes.Length);
                        if (rv != 0 && rv != 0x00000100) // CKR_USER_ALREADY_LOGGED_IN = 0x00000100
                            throw new Exception($"C_Login failed (wrong PIN?): 0x{rv:X8}");

                        try
                        {
                            Console.WriteLine("[DEBUG] Pkcs11: Listing all objects on the token...");
                            CK_ATTRIBUTE[] emptyTemplate = new CK_ATTRIBUTE[0];
                            rv = cFindObjectsInit(hSession, emptyTemplate, 0);
                            if (rv != 0)
                                throw new Exception($"C_FindObjectsInit failed: 0x{rv:X8}");

                            IntPtr hKey = IntPtr.Zero;
                            try
                            {
                                IntPtr phObject = Marshal.AllocHGlobal(400); // cho cho 100 handles
                                try
                                {
                                    uint objCount;
                                    rv = cFindObjects(hSession, phObject, 100, out objCount);
                                    if (rv != 0)
                                        throw new Exception($"C_FindObjects failed: 0x{rv:X8}");

                                    Console.WriteLine($"[DEBUG] Pkcs11: Found {objCount} objects on the token.");
                                    int[] handles = new int[objCount];
                                    Marshal.Copy(phObject, handles, 0, (int)objCount);

                                    var cGetAttributeValue = GetFunc<C_GetAttributeValue>(hModule, "C_GetAttributeValue");

                                    for (int i = 0; i < objCount; i++)
                                    {
                                        IntPtr hObj = (IntPtr)handles[i];
                                        
                                        // Truy van CKA_CLASS
                                        IntPtr pClassVal = Marshal.AllocHGlobal(4);
                                        try
                                        {
                                            CK_ATTRIBUTE[] attrClass = new CK_ATTRIBUTE[1];
                                            attrClass[0].type = 0; // CKA_CLASS = 0
                                            attrClass[0].pValue = pClassVal;
                                            attrClass[0].ulValueLen = 4;

                                            uint rvAttr = cGetAttributeValue(hSession, hObj, attrClass, 1);
                                            if (rvAttr == 0)
                                            {
                                                uint classVal = (uint)Marshal.ReadInt32(pClassVal);
                                                Console.WriteLine($"[DEBUG] Pkcs11: Object handle={hObj.ToInt32()}, class={classVal}");
                                                
                                                if (classVal == CKO_PRIVATE_KEY) // CKO_PRIVATE_KEY = 3
                                                {
                                                    hKey = hObj;
                                                    Console.WriteLine($"[DEBUG] Pkcs11: Selected private key handle={hKey.ToInt32()}");
                                                }
                                            }
                                            else
                                            {
                                                Console.WriteLine($"[DEBUG] Pkcs11: Object handle={hObj.ToInt32()} CKA_CLASS query failed: 0x{rvAttr:X8}");
                                            }
                                        }
                                        finally
                                        {
                                            Marshal.FreeHGlobal(pClassVal);
                                        }
                                    }
                                }
                                finally
                                {
                                    Marshal.FreeHGlobal(phObject);
                                }
                            }
                            finally
                            {
                                cFindObjectsFinal(hSession);
                            }

                            if (hKey == IntPtr.Zero)
                                throw new Exception("No private key object found on the token.");

                            Console.WriteLine("[DEBUG] Pkcs11: Hashing message using SHA-256...");
                            byte[] hashVal;
                            using (var sha = SHA256.Create())
                            {
                                hashVal = sha.ComputeHash(message);
                            }

                            Console.WriteLine("[DEBUG] Pkcs11: Formatting digest...");
                            // Formatted DigestInfo for SHA-256
                            byte[] prefix = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
                            byte[] digestInfo = new byte[prefix.Length + hashVal.Length];
                            Buffer.BlockCopy(prefix, 0, digestInfo, 0, prefix.Length);
                            Buffer.BlockCopy(hashVal, 0, digestInfo, prefix.Length, hashVal.Length);

                            Console.WriteLine("[DEBUG] Pkcs11: Initializing sign mechanism...");
                            CK_MECHANISM mech = new CK_MECHANISM();
                            mech.mechanism = CKM_RSA_PKCS;
                            mech.pParameter = IntPtr.Zero;
                            mech.ulParameterLen = 0;

                            rv = cSignInit(hSession, ref mech, hKey);
                            if (rv != 0)
                                throw new Exception($"C_SignInit failed: 0x{rv:X8}");

                            Console.WriteLine("[DEBUG] Pkcs11: Calling C_Sign (query length)...");
                            uint sigLen = 0;
                            rv = cSign(hSession, digestInfo, (uint)digestInfo.Length, null, ref sigLen);
                            if (rv != 0 || sigLen == 0)
                                throw new Exception($"C_Sign failed to query length: 0x{rv:X8}");

                            Console.WriteLine($"[DEBUG] Pkcs11: Calling C_Sign (executing signature, length={sigLen})...");
                            byte[] signature = new byte[sigLen];
                            rv = cSign(hSession, digestInfo, (uint)digestInfo.Length, signature, ref sigLen);
                            if (rv != 0)
                                throw new Exception($"C_Sign signature failed: 0x{rv:X8}");

                            Console.WriteLine("[DEBUG] Pkcs11: Signature succeeded!");
                            return signature;
                        }
                        finally
                        {
                            Console.WriteLine("[DEBUG] Pkcs11: Logging out...");
                            cLogout(hSession);
                        }
                    }
                    finally
                    {
                        Console.WriteLine("[DEBUG] Pkcs11: Closing session...");
                        cCloseSession(hSession);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pSlots);
                }
            }
            finally
            {
                cFinalize(IntPtr.Zero);
            }
        }
        finally
        {
            FreeLibrary(hModule);
        }
    }

    public byte[] SignTest(byte[] hashVal, bool prependPrefix)
    {
        IntPtr hModule = LoadLibrary(_dllPath);
        if (hModule == IntPtr.Zero)
            throw new Exception($"Failed to load PKCS#11 DLL: {_dllPath}");

        try
        {
            var cInitialize = GetFunc<C_Initialize>(hModule, "C_Initialize");
            var cFinalize = GetFunc<C_Finalize>(hModule, "C_Finalize");
            var cGetSlotList = GetFunc<C_GetSlotList>(hModule, "C_GetSlotList");
            var cOpenSession = GetFunc<C_OpenSession>(hModule, "C_OpenSession");
            var cCloseSession = GetFunc<C_CloseSession>(hModule, "C_CloseSession");
            var cLogin = GetFunc<C_Login>(hModule, "C_Login");
            var cLogout = GetFunc<C_Logout>(hModule, "C_Logout");
            var cFindObjectsInit = GetFunc<C_FindObjectsInit>(hModule, "C_FindObjectsInit");
            var cFindObjects = GetFunc<C_FindObjects>(hModule, "C_FindObjects");
            var cFindObjectsFinal = GetFunc<C_FindObjectsFinal>(hModule, "C_FindObjectsFinal");
            var cSignInit = GetFunc<C_SignInit>(hModule, "C_SignInit");
            var cSign = GetFunc<C_Sign>(hModule, "C_Sign");

            uint rv = cInitialize(IntPtr.Zero);
            if (rv != 0 && rv != 0x00000191)
                throw new Exception($"C_Initialize failed: 0x{rv:X8}");

            try
            {
                uint count = 0;
                rv = cGetSlotList(1, IntPtr.Zero, ref count);
                if (rv != 0 || count == 0)
                    throw new Exception("No active smart card slots found.");

                IntPtr pSlots = Marshal.AllocHGlobal((int)count * 4);
                try
                {
                    rv = cGetSlotList(1, pSlots, ref count);
                    if (rv != 0)
                        throw new Exception("C_GetSlotList failed.");

                    int[] slots = new int[count];
                    Marshal.Copy(pSlots, slots, 0, (int)count);
                    uint slotId = (uint)slots[0];

                    IntPtr hSession;
                    rv = cOpenSession(slotId, CKF_SERIAL_SESSION, IntPtr.Zero, IntPtr.Zero, out hSession);
                    if (rv != 0)
                        throw new Exception($"C_OpenSession failed: 0x{rv:X8}");

                    try
                    {
                        byte[] pinBytes = Encoding.ASCII.GetBytes(_pin);
                        rv = cLogin(hSession, CKU_USER, pinBytes, (uint)pinBytes.Length);
                        if (rv != 0 && rv != 0x00000100) // CKR_USER_ALREADY_LOGGED_IN = 0x00000100
                            throw new Exception($"C_Login failed: 0x{rv:X8}");

                        try
                        {
                            CK_ATTRIBUTE[] emptyTemplate = new CK_ATTRIBUTE[0];
                            rv = cFindObjectsInit(hSession, emptyTemplate, 0);
                            if (rv != 0)
                                throw new Exception($"C_FindObjectsInit failed: 0x{rv:X8}");

                            IntPtr hKey = IntPtr.Zero;
                            try
                            {
                                IntPtr phObject = Marshal.AllocHGlobal(400);
                                try
                                {
                                    uint objCount;
                                    rv = cFindObjects(hSession, phObject, 100, out objCount);
                                    if (rv != 0)
                                        throw new Exception($"C_FindObjects failed: 0x{rv:X8}");

                                    int[] handles = new int[objCount];
                                    Marshal.Copy(phObject, handles, 0, (int)objCount);

                                    var cGetAttributeValue = GetFunc<C_GetAttributeValue>(hModule, "C_GetAttributeValue");

                                    for (int i = 0; i < objCount; i++)
                                    {
                                        IntPtr hObj = (IntPtr)handles[i];
                                        IntPtr pClassVal = Marshal.AllocHGlobal(4);
                                        try
                                        {
                                            CK_ATTRIBUTE[] attrClass = new CK_ATTRIBUTE[1];
                                            attrClass[0].type = 0;
                                            attrClass[0].pValue = pClassVal;
                                            attrClass[0].ulValueLen = 4;

                                            uint rvAttr = cGetAttributeValue(hSession, hObj, attrClass, 1);
                                            if (rvAttr == 0)
                                            {
                                                uint classVal = (uint)Marshal.ReadInt32(pClassVal);
                                                if (classVal == CKO_PRIVATE_KEY)
                                                {
                                                    hKey = hObj;
                                                }
                                            }
                                        }
                                        finally
                                        {
                                            Marshal.FreeHGlobal(pClassVal);
                                        }
                                    }
                                }
                                finally
                                {
                                    Marshal.FreeHGlobal(phObject);
                                }
                            }
                            finally
                            {
                                cFindObjectsFinal(hSession);
                            }

                            if (hKey == IntPtr.Zero)
                                throw new Exception("No private key object found on the token.");

                            byte[] dataToSign;
                            if (prependPrefix)
                            {
                                byte[] prefix = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
                                dataToSign = new byte[prefix.Length + hashVal.Length];
                                Buffer.BlockCopy(prefix, 0, dataToSign, 0, prefix.Length);
                                Buffer.BlockCopy(hashVal, 0, dataToSign, prefix.Length, hashVal.Length);
                            }
                            else
                            {
                                dataToSign = hashVal;
                            }

                            CK_MECHANISM mech = new CK_MECHANISM();
                            mech.mechanism = CKM_RSA_PKCS;
                            mech.pParameter = IntPtr.Zero;
                            mech.ulParameterLen = 0;

                            rv = cSignInit(hSession, ref mech, hKey);
                            if (rv != 0)
                                throw new Exception($"C_SignInit failed: 0x{rv:X8}");

                            uint sigLen = 0;
                            rv = cSign(hSession, dataToSign, (uint)dataToSign.Length, null, ref sigLen);
                            if (rv != 0 || sigLen == 0)
                                throw new Exception($"C_Sign query length failed: 0x{rv:X8}");

                            byte[] signature = new byte[sigLen];
                            rv = cSign(hSession, dataToSign, (uint)dataToSign.Length, signature, ref sigLen);
                            if (rv != 0)
                                throw new Exception($"C_Sign failed: 0x{rv:X8}");

                            return signature;
                        }
                        finally
                        {
                            cLogout(hSession);
                        }
                    }
                    finally
                    {
                        cCloseSession(hSession);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pSlots);
                }
            }
            finally
            {
                cFinalize(IntPtr.Zero);
            }
        }
        finally
        {
            FreeLibrary(hModule);
        }
    }
}
