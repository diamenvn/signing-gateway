/**
 * test-sign.js — Ky thu qua API /v2/sign (dong bo).
 *
 * Cach dung:
 *   node test-sign.js <base-url> <secret> <file.pdf> [soLan]
 * Vi du:
 *   node test-sign.js http://127.0.0.1:8080 <secret> file.pdf 3
 *
 * Ky lien tiep [soLan] de do PIN cache: lan dau hoi PIN, cac lan sau
 * neu nhanh (khong hoi PIN) = con cache.
 */
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');

const [, , BASE, SECRET, PDF, N] = process.argv;
if (!BASE || !SECRET || !PDF) {
  console.log('Dung: node test-sign.js <base-url> <secret> <file.pdf> [soLan]');
  process.exit(1);
}
const times = Number(N) || 1;

function makeToken() {
  const p = { sub: 'test', name: 'Test', exp: Math.floor(Date.now()/1000)+300, jti: crypto.randomUUID() };
  const b = Buffer.from(JSON.stringify(p)).toString('base64url');
  const s = crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
  return b + '.' + s;
}

(async () => {
  // health
  const h = await (await fetch(`${BASE}/v2/health`)).json();
  console.log('health:', h);
  if (h.token !== 'present') { console.log('CHUA CAM USB TOKEN.'); process.exit(1); }

  const pdfB64 = fs.readFileSync(PDF).toString('base64');

  for (let i = 1; i <= times; i++) {
    const t0 = Date.now();
    const r = await fetch(`${BASE}/v2/sign`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${makeToken()}` },
      body: JSON.stringify({
        docType: 'pdf',
        document: pdfB64,
        docId: `test-${i}`,
        signature: { page: 1, llx: 380, lly: 40, urx: 560, ury: 110, description: `Lan ${i}` },
      }),
    });
    const ms = Date.now() - t0;
    const data = await r.json();
    if (r.ok) {
      const out = `signed-${i}.pdf`;
      fs.writeFileSync(out, Buffer.from(data.document, 'base64'));
      console.log(`Lan ${i}: ${ms}ms -> ${out}  ${i > 1 && ms < 4000 ? '(nhanh - con PIN cache)' : ''}`);
    } else {
      console.log(`Lan ${i}: LOI ${r.status} - ${data.error}`);
    }
  }
})();
