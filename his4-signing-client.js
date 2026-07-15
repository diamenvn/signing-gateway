/**
 * his4-signing-client.js — Module frontend goi gateway ky so.
 *
 * API DONG BO: POST /v2/sign tra ve PDF da ky NGAY trong response.
 * Khong jobId, khong poll. Ky 1 file rat nhanh.
 *
 * KHOA (optional):
 *   - Ky 1 file  -> goi signPdf() truc tiep, KHONG can lock.
 *   - Ky ca loat -> lock() -> signPdf() nhieu lan -> unlock().
 *     Trong luc lock, client khac bi tu choi (423). Khong unlock thi
 *     khoa tu het han sau lockTtlMs (cau hinh o server).
 */

const GATEWAY = 'https://bvxyz.sign.abc.vn'; // doi thanh URL that
const HIS_API = '/api';

async function getSignToken() {
  const r = await fetch(`${HIS_API}/signing/token`, { method: 'POST', credentials: 'include' });
  if (!r.ok) throw new Error('Khong lay duoc token ky. Dang nhap lai.');
  return (await r.json()).token;
}

export async function checkGateway() {
  try {
    const r = await fetch(`${GATEWAY}/v2/health`, { mode: 'cors' });
    if (!r.ok) return { ok: false, reason: 'Gateway khong phan hoi' };
    const resObj = await r.json();
    const h = resObj.data;
    if (h.plugin !== 'connected') return { ok: false, reason: 'May chu chua chay VNPT Plugin' };
    if (h.token === 'absent')     return { ok: false, reason: 'Chua cam USB Token' };
    if (h.token !== 'present')    return { ok: false, reason: 'Khong kiem tra duoc USB Token' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: 'Khong ket noi duoc may chu ky so' };
  }
}

const toBase64 = (buf) => {
  const b = new Uint8Array(buf); let s = '';
  const C = 0x8000;
  for (let i = 0; i < b.length; i += C) s += String.fromCharCode.apply(null, b.subarray(i, i + C));
  return btoa(s);
};
const fromBase64 = (b64) => {
  const bin = atob(b64); const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
};

/* ===================== KY 1 FILE (khong can lock) ===================== */

/**
 * Ky mot file. Neu dang trong phien lock, truyen lockToken vao opts.
 * @returns {Promise<Blob>} PDF da ky
 */
export async function signPdf(pdf, opts = {}) {
  const buf = pdf instanceof Blob ? await pdf.arrayBuffer() : pdf;
  const token = opts.hisToken || await getSignToken();

  const r = await fetch(`${GATEWAY}/v2/sign`, {
    method: 'POST', mode: 'cors',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({
      docType: 'pdf',
      document: toBase64(buf),
      docId: opts.docId ?? null,
      lockToken: opts.lockToken ?? undefined,  // chi khi dang trong phien lock
      signature: {
        certificateSerial: opts.certificateSerial ?? undefined,
        page: opts.page ?? 1,
        llx: opts.llx, lly: opts.lly, urx: opts.urx, ury: opts.ury,
        description: opts.description ?? null,
        imageBase64: opts.imageBase64 ?? undefined,
        setImageBackground: opts.setImageBackground ?? undefined,
        pin: opts.pin ?? undefined,
      },
    }),
  });

  const resObj = await r.json();
  if (r.status === 423) {
    const retryAfterMs = (resObj.data && resObj.data.retryAfterMs) || 0;
    throw new Error(`Token dang ban (nguoi khac ky). Thu lai sau ${Math.ceil(retryAfterMs / 1000)}s.`);
  }
  if (!r.ok) throw new Error(dienGiaiLoi(resObj.error_code));

  return new Blob([fromBase64(resObj.data.document)], { type: 'application/pdf' });
}

/* ===================== KY CA LOAT (dung lock) ===================== */

/**
 * Chiem token de ky nhieu file.
 * @returns {Promise<{lockToken, expiresInMs}>}
 */
export async function lock(hisToken) {
  const token = hisToken || await getSignToken();
  const r = await fetch(`${GATEWAY}/v2/lock`, {
    method: 'POST', mode: 'cors',
    headers: { authorization: `Bearer ${token}` },
  });
  const resObj = await r.json();
  if (r.status === 423) {
    const lockedBy = (resObj.data && resObj.data.lockedBy) || '';
    const retryAfterMs = (resObj.data && resObj.data.retryAfterMs) || 0;
    throw new Error(`Token dang ban (${lockedBy}). Thu lai sau ${Math.ceil(retryAfterMs / 1000)}s.`);
  }
  if (!r.ok) throw new Error(resObj.error_code);
  return resObj.data; // { lockToken, expiresInMs, signCount }
}

export async function unlock(lockToken, hisToken) {
  const token = hisToken || await getSignToken();
  const r = await fetch(`${GATEWAY}/v2/unlock`, {
    method: 'POST', mode: 'cors',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ lockToken }),
  });
  return r.ok ? (await r.json()).data : null;
}

/**
 * Vi du ky ca loat:
 *   const t = await getSignToken();
 *   const { lockToken } = await lock(t);
 *   try {
 *     for (const f of files) await signPdf(f.blob, { lockToken, hisToken: t, docId: f.id });
 *   } finally {
 *     await unlock(lockToken, t);   // luon unlock du co loi
 *   }
 */

function dienGiaiLoi(code) {
  const map = {
    KHONG_CO_USB_TOKEN: 'Chua cam USB Token vao may chu ky so.',
    TOKEN_DANG_BAN: 'Token dang duoc nguoi khac su dung.',
    SERIAL_KHONG_KHOP: 'Serial chung thu khong khop token dang cam.',
    PLUGIN_THIEU_LICENSE: 'May chu chua nap license VNPT-CA Plugin.',
    PLUGIN_KHONG_KET_NOI: 'May chu chua chay VNPT Plugin.',
    PLUGIN_TREO_CHECK_TOKEN: 'Loi ket noi thiet bi. Dang tu dong khoi dong lai plugin. Vui long cam USB Token va thu lai sau.',
    PLUGIN_TREO_CONG_CU: 'Plugin he thong bi treo. Dang tu dong khoi dong lai. Vui long doi vai giay va thu lai.',
    PLUGIN_QUA_HAN: 'Qua han. Co the dang cho nhap PIN tren may chu.',
  };
  return map[code] || `Ky that bai: ${code}`;
}

/* ===================== KY XML ===================== */

/**
 * Ky XML qua endpoint /v2/sign hop nhat (docType: "xml").
 * @param xmlString  noi dung XML
 * @param opts       { signingType, digestMethod, certificateSerial, lockToken, hisToken, docId }
 * @returns {Promise<string>} XML da ky
 */
export async function signXml(xmlString, opts = {}) {
  const token = opts.hisToken || await getSignToken();
  const r = await fetch(`${GATEWAY}/v2/sign`, {
    method: 'POST', mode: 'cors',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({
      docType: 'xml',
      document: xmlString,
      docId: opts.docId ?? null,
      lockToken: opts.lockToken ?? undefined,
      signature: {
        signingType: opts.signingType ?? 'Enveloped',
        digestMethod: opts.digestMethod ?? 'SHA256',
        certificateSerial: opts.certificateSerial ?? undefined,
        tagSigning: opts.tagSigning ?? undefined,
      },
    }),
  });
  const resObj = await r.json();
  if (r.status === 423) {
    const retryAfterMs = (resObj.data && resObj.data.retryAfterMs) || 0;
    throw new Error(`Token dang ban. Thu lai sau ${Math.ceil(retryAfterMs / 1000)}s.`);
  }
  if (!r.ok) throw new Error(dienGiaiLoi(resObj.error_code));
  return resObj.data.document; // XML da ky
}
