# Ký XML qua POST /v2/sign

```json
{
  "docType": "xml",
  "base64": false,
  "document": "<HSTH01BH><DS_CHITIET Id=\"Id-123\"><CHITIET_HS01BH /></DS_CHITIET><CHUKYDONVI /></HSTH01BH>",
  "signature": {
    "certificateSerial": "SERIAL_CHUNG_THU",
    "pin": "PIN",
    "tagSigning": "CHUKYDONVI",
    "tagReference": "DS_CHITIET"
  }
}
```

- `signature.tagSigning`: tên thẻ có sẵn để chứa phần tử XMLDSig `Signature`. Bỏ qua thì chèn vào root.
- `signature.tagReference`: tên thẻ có sẵn chứa dữ liệu cần ký. Reference dùng `#<Id>` của thẻ đó; hỗ trợ thuộc tính `Id`, `id`, `ID`. Nếu chưa có thì tự thêm `Id="Id-<UUID>"`. Bỏ qua thì ký toàn bộ tài liệu với `URI=""`.
- Hai tham số độc lập, phân biệt hoa thường. Tên không có prefix được so khớp theo local name; tên có prefix được so khớp chính xác. Không hỗ trợ XPath. Mỗi tên phải xác định đúng một thẻ, kể cả khi XML có namespace.
- Không tự tạo thẻ chứa chữ ký, không xóa chữ ký cũ. Thẻ thiếu/trùng, ID rỗng/không hợp lệ/trùng bị từ chối với HTTP 400 (`XML_SIGN_OPTIONS`).
- Khi reference chỉ một thẻ, dữ liệu ngoài thẻ đó không thuộc phạm vi bảo vệ của chữ ký.
- XML Base64 phải gửi `base64: true` ở cấp ngoài. Header `Authorization: Bearer <his_token>` bắt buộc trừ devMode; truyền `lockToken` nếu gateway yêu cầu khóa.
- Thuật toán vẫn là RSA-SHA256, digest SHA256, enveloped transform. Các tham số hiển thị PDF không áp dụng cho XML.

Kết quả của ví dụ có dạng:

```xml
<HSTH01BH>
  <DS_CHITIET Id="Id-123"><CHITIET_HS01BH /></DS_CHITIET>
  <CHUKYDONVI>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <!-- SignedInfo chứa Reference URI="#Id-123", cùng SignatureValue và KeyInfo -->
    </Signature>
  </CHUKYDONVI>
</HSTH01BH>
```

Đây chỉ là minh họa cấu trúc, không phải chữ ký hợp lệ. Không định dạng lại XML sau khi ký.

## Kiểm thử và triển khai

`dotnet run --project tests/xml-signature/XmlSignatureTests.csproj` kiểm tra bằng chứng thư tạm, không cần USB token.

Cần build/publish lại native signer và gateway theo BUILD.md rồi triển khai cùng nhau. Native signer cũ chưa xử lý hai tham số mới.
