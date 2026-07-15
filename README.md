# Signing Gateway — tích hợp HIS4

```
Trình duyệt (his4-dev.vnpthis.vn)
        │  HTTPS
Cloudflare Tunnel
        │  HTTP localhost
Gateway (server.js)              127.0.0.1:8080
        │  WSS localhost
VNPT-CA Plugin
        │
USB Token
```

`cloudflared` lo TLS → gateway chỉ bind `127.0.0.1`, chạy HTTP thường.
**Không cert, không IP allowlist, không mở port router.**

---

## 1. Backend HIS4 — cấp token ký

Mảnh ghép quan trọng nhất. **Frontend không được giữ secret** — mở DevTools là thấy.

```js
// POST /api/signing/token  — backend HIS4, user đã đăng nhập
const crypto = require('crypto');
const SIGN_SECRET = process.env.SIGN_SHARED_SECRET;  // giống config.json của gateway

app.post('/api/signing/token', requireLogin, (req, res) => {
  if (!req.user.permissions.includes('KY_SO')) {
    return res.status(403).json({ error: 'khong co quyen ky so' });
  }

  const payload = {
    sub:  req.user.id,                                 // ai ký — cả audit dựa vào dòng này
    name: req.user.fullName,
    exp:  Math.floor(Date.now() / 1000) + 300,         // sống 5 phút
    jti:  crypto.randomUUID(),                         // dùng 1 lần, chống replay
  };

  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SIGN_SECRET).update(body).digest('base64url');

  res.json({ token: `${body}.${sig}` });
});
```

Sinh secret (1 lần, dùng chung cho backend HIS4 và `config.json` của gateway):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## 2. Frontend HIS4

Dùng `his4-signing-client.js`:

```js
import { checkGateway, signPdf } from './his4-signing-client';

// Trước khi hiện nút "Ký số"
const g = await checkGateway();
if (!g.ok) return toast.warn(g.reason);   // vd: "Chưa cắm USB Token"

// Khi bấm ký
const signed = await signPdf(pdfBlob, {
  docId: phieu.id,
  page: 1,
  description: `Ký bởi ${user.fullName}`,
  onProgress: (s, i) => {
    if (s === 'queued')  setMsg(`Đang chờ, vị trí ${i.position}`);
    if (s === 'signing') setMsg('Đang ký...');
  },
});

await uploadToHis(signed);
```

## 3. Máy chủ ký — cài 4 thứ

| # | Cài gì | Nguồn |
|---|---|---|
| 1 | Driver USB Token | VNPT |
| 2 | VNPT-CA Plugin | VNPT |
| 3 | `signing-gateway.exe` + `config.json` | build từ repo này |
| 4 | `cloudflared` | cloudflare.com |

## 4. Cloudflare Tunnel

```bash
cloudflared tunnel login
cloudflared tunnel create bvxyz-sign
cloudflared tunnel route dns bvxyz-sign bvxyz.sign.abc.vn
cloudflared service install          # tự khởi động cùng Windows
```

## 5. Build

```bash
npm install
npm run build          # -> dist/signing-gateway.exe
```

---

## Kiểm thử — theo đúng thứ tự này

- [ ] Gateway kết nối được plugin (xem log khởi động)
- [ ] `GET /v2/health` trả `token: "present"`
- [ ] Preflight `OPTIONS` trả 204 (DevTools → Network)
- [ ] Chrome không chặn Private Network Access
- [ ] Ký file thứ nhất → **có hiện hộp thoại PIN không?**
- [ ] Ký file thứ hai → **có hỏi PIN lại không?** ← câu quan trọng nhất
- [ ] Ký 20 file liên tiếp → đo thời gian trung bình

---

## Ba thứ sẽ cắn anh

**1. PIN.** Plugin không có API truyền PIN. Lần ký đầu sau mỗi lần khởi động máy sẽ bật hộp thoại — phải có người ở phòng máy chủ nhập. Windows Update tự reboot lúc 3h sáng → sáng ra cả khoa không ký được. **Tắt auto-update trên máy đó.**

**2. Hàng đợi.** Token ký tuần tự, 0.3–2 giây/file. 30 y tá bấm cùng lúc → người cuối chờ hơn một phút. Frontend phải hiện vị trí hàng đợi, đừng để họ tưởng treo rồi bấm lại.

**3. Chứng thư là của bệnh viện, không phải của người ký.** Chữ ký số không biết ai bấm nút. **Audit log của gateway là bằng chứng duy nhất** — ghi `user`, `docId`, `sha256`, thời gian, có hash chain chống sửa. Đừng xoá `audit-*.jsonl`.

---

## Bốn câu cần hỏi VNPT

Chưa có đáp án, và chúng có thể chặn cả dự án:

1. Plugin có license theo domain không? Trường `domain` được validate thế nào? Nhiều bệnh viện thì tính phí ra sao?
2. Có được nhúng plugin vào sản phẩm triển khai cho nhiều khách hàng không?
3. `signHash` (functionID 9) nhận format gì — hex hay base64? Thuật toán nào? Có tự thêm DigestInfo prefix không?
4. `ClearPinCache(times)` — `times` là số lần ký hay số phút? PIN cache mặc định sống bao lâu?

Câu 4 quyết định hệ thống này vận hành được hay không.
