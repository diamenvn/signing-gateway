using System;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

using var key = RSA.Create(2048);
using var cert = new CertificateRequest("CN=XML Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
    .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
int passed = 0;
void Check(bool condition) { if (!condition) throw new Exception("Assertion failed"); }
XmlDocument Load(string xml) { var doc = new XmlDocument { PreserveWhitespace = true }; doc.LoadXml(xml); return doc; }
bool Verify(XmlDocument doc) {
    var verifier = new SignedXml(doc);
    verifier.LoadXml((XmlElement)doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0]);
    return verifier.CheckSignature(cert, true);
}
foreach (string ns in new[] { "", " xmlns='urn:his' xmlns:x='urn:extra'" })
foreach (string id in new[] { "", " Id='sample-id'", " ID='sample-id'", " id='sample-id'" })
{
    var doc = Load($"<HSTH01BH{ns}><DS_CHITIET{id}><VALUE>original</VALUE></DS_CHITIET><CHUKYDONVI /></HSTH01BH>");
    XmlSignatureBuilder.Sign(doc, key, cert, "CHUKYDONVI", "DS_CHITIET");
    doc = Load(doc.OuterXml);
    Check(Verify(doc));
    var signature = (XmlElement)doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0];
    Check(signature.ParentNode.LocalName == "CHUKYDONVI");
    Check(((XmlElement)doc.GetElementsByTagName("Reference", SignedXml.XmlDsigNamespaceUrl)[0]).GetAttribute("URI").StartsWith("#"));
    doc.GetElementsByTagName("VALUE")[0].InnerText = "tampered";
    Check(!Verify(doc));
    passed++;
}
foreach (string container in new[] { null, "CHUKYDONVI", "DS_CHITIET" })
{
    var doc = Load("<ROOT><DS_CHITIET>data</DS_CHITIET><CHUKYDONVI /></ROOT>");
    XmlSignatureBuilder.Sign(doc, key, cert, container);
    Check(Verify(Load(doc.OuterXml)));
    passed++;
}
foreach (string xml in new[] {
    "<ROOT><CHUKYDONVI /></ROOT>",
    "<ROOT><DS_CHITIET/><DS_CHITIET/><CHUKYDONVI/></ROOT>",
    "<ROOT><DS_CHITIET Id='dup'/><OTHER ID='dup'/><CHUKYDONVI/></ROOT>",
    "<ROOT><DS_CHITIET Id=''/><CHUKYDONVI/></ROOT>"
}) {
    bool rejected = false;
    try { XmlSignatureBuilder.Sign(Load(xml), key, cert, "CHUKYDONVI", "DS_CHITIET"); }
    catch (ArgumentException e) when (e.Message.StartsWith("XML_SIGN_OPTIONS:")) { rejected = true; }
    Check(rejected); passed++;
}
Console.WriteLine($"PASS: {passed} XML signing scenarios (including verification and tampering)");
