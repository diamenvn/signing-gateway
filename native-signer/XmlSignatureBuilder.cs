using System;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

public static class XmlSignatureBuilder
{
    // Accept an exact qualified name, or a unique local name (namespace independent).
    static XmlElement FindElement(XmlDocument doc, string name)
    {
        XmlElement found = null;
        foreach (XmlElement element in doc.GetElementsByTagName("*"))
        {
            if ((name.Contains(":") ? element.Name : element.LocalName) != name) continue;
            if (found != null) throw new ArgumentException("XML_SIGN_OPTIONS: Nhieu the trung ten: " + name);
            found = element;
        }
        return found ?? throw new ArgumentException("XML_SIGN_OPTIONS: Khong tim thay the: " + name);
    }

    public static void Sign(XmlDocument doc, RSA key, X509Certificate2 cert,
                            string tagSigning = null, string tagReference = null)
    {
        XmlElement container = string.IsNullOrEmpty(tagSigning) ? doc.DocumentElement : FindElement(doc, tagSigning);
        string uri = "";
        if (!string.IsNullOrEmpty(tagReference))
        {
            XmlElement target = FindElement(doc, tagReference);
            string id = null;
            foreach (string attribute in new[] { "Id", "id", "ID" })
            {
                if (!target.HasAttribute(attribute)) continue;
                string value = target.GetAttribute(attribute);
                if (string.IsNullOrEmpty(value) || (id != null && id != value))
                    throw new ArgumentException("XML_SIGN_OPTIONS: Id cua the reference rong hoac khong nhat quan");
                id = value;
            }
            if (id == null)
            {
                id = "Id-" + Guid.NewGuid().ToString();
                target.SetAttribute("Id", id);
            }
            try { XmlConvert.VerifyNCName(id); }
            catch (XmlException) { throw new ArgumentException("XML_SIGN_OPTIONS: Id cua the reference khong hop le"); }
            foreach (XmlElement element in doc.GetElementsByTagName("*"))
                foreach (string attribute in new[] { "Id", "id", "ID" })
                    if (element != target && element.GetAttribute(attribute) == id)
                        throw new ArgumentException("XML_SIGN_OPTIONS: Id reference bi trung: " + id);
            uri = "#" + id;
        }

        // Use the destination context so inherited namespaces are canonicalized correctly.
        var signedXml = new SignedXml(container) { SigningKey = key };
        var reference = new Reference(uri) { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(cert));
        signedXml.KeyInfo = keyInfo;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.ComputeSignature();
        container.AppendChild(doc.ImportNode(signedXml.GetXml(), true));
    }
}
