using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using System.Text;

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
                Console.Error.WriteLine($"Loi: Khong tim thay chung thu nao voi Serial: '{serial}' trong Windows Store.");
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
            Console.Error.WriteLine($"Loi khi ky so: {ex.Message}");
            Console.Error.WriteLine(ex.StackTrace);
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
        // 1. Dung chuoi chung thu (cert chain)
        X509Chain chainObj = new X509Chain();
        chainObj.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Tat kiem tra truc tuyen de tranh treo/timeout
        chainObj.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags; // Bo qua xac thuc de chay nhanh offline
        chainObj.Build(cert);
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
            MakeSignature.SignDetached(appearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
        }
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

    public byte[] Sign(byte[] message)
    {
        using (RSA rsa = _cert.GetRSAPrivateKey())
        {
            if (rsa == null)
                throw new Exception("Chung thu khong chua khoa bi mat RSA hop le.");

            // 1. Thiet lap PIN cho khoa dang CNG (Key Storage Provider)
            if (rsa is RSACng rsaCng && !string.IsNullOrEmpty(_pin))
            {
                byte[] pinBytes = Encoding.Unicode.GetBytes(_pin + '\0');
                CngProperty pinProperty = new CngProperty("SmartCardPin", pinBytes, CngPropertyOptions.None);
                rsaCng.Key.SetProperty(pinProperty);
            }
            // 2. Thiet lap PIN cho khoa dang CSP cu (Cryptographic Service Provider)
            else if (rsa is RSACryptoServiceProvider rsaCsp && !string.IsNullOrEmpty(_pin))
            {
                var container = rsaCsp.CspKeyContainerInfo;
                CspParameters cspParams = new CspParameters
                {
                    ProviderName = container.ProviderName,
                    ProviderType = container.ProviderType,
                    KeyContainerName = container.KeyContainerName,
                    Flags = CspProviderFlags.UseExistingKey
                };
                if (container.MachineKeyStore)
                    cspParams.Flags |= CspProviderFlags.UseMachineKeyStore;
                
                SecureString securePin = new SecureString();
                foreach (char c in _pin) securePin.AppendChar(c);
                cspParams.KeyPassword = securePin;
                
                using (var rsaCspWithPin = new RSACryptoServiceProvider(cspParams))
                {
                    return rsaCspWithPin.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
                }
            }

            return rsa.SignData(message, new HashAlgorithmName(_hashAlgorithm), RSASignaturePadding.Pkcs1);
        }
    }
}
