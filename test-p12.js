/**
 * test-p12.js — Ky PDF bang file .p12, KHONG can plugin / USB / license.
 *
 * Cach dung:
 *   npm install @signpdf/signpdf @signpdf/signer-p12 @signpdf/placeholder-plain
 *   node test-p12.js <file.pdf> <chung-thu.p12> <mat-khau>
 *
 * Vi du:
 *   node test-p12.js file.pdf "vu anh kiet.p12" matkhau123
 *
 * Ket qua: <file>-signed-p12.pdf
 *
 * LUU Y BAO MAT: file .p12 chua khoa bi mat. Ai co file + mat khau la ky duoc
 * nhan danh chu the. Khac han USB token (khoa khong ra khoi thiet bi).
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const [, , PDF_PATH, P12_PATH, PASSWORD] = process.argv;

if (!PDF_PATH || !P12_PATH) {
  console.log('Cach dung: node test-p12.js <file.pdf> <chung-thu.p12> <mat-khau>');
  process.exit(1);
}

let SignPdf, P12Signer, plainAddPlaceholder;
try {
  const signpdfMod = require('@signpdf/signpdf');
  // Ban moi export { SignPdf } (class); ban cu la default.
  SignPdf = signpdfMod.SignPdf || signpdfMod.default;
  P12Signer = require('@signpdf/signer-p12').P12Signer;
  plainAddPlaceholder = require('@signpdf/placeholder-plain').plainAddPlaceholder;
} catch (e) {
  console.log('\n  Thieu thu vien. Cai bang lenh:');
  console.log('  npm install @signpdf/signpdf @signpdf/signer-p12 @signpdf/placeholder-plain\n');
  process.exit(1);
}

(async () => {
  if (!fs.existsSync(PDF_PATH)) { console.log(`Khong thay PDF: ${PDF_PATH}`); process.exit(1); }
  if (!fs.existsSync(P12_PATH)) { console.log(`Khong thay .p12: ${P12_PATH}`); process.exit(1); }

  const pdfBuffer = fs.readFileSync(PDF_PATH);
  const p12Buffer = fs.readFileSync(P12_PATH);

  console.log(`\n  PDF  : ${PDF_PATH} (${pdfBuffer.length} byte)`);
  console.log(`  .p12 : ${P12_PATH} (${p12Buffer.length} byte)`);

  if (pdfBuffer.subarray(0, 4).toString() !== '%PDF') {
    console.log('  File dau vao khong phai PDF hop le.');
    process.exit(1);
  }

  try {
    // 1. Chen placeholder chu ky vao PDF (ByteRange + vung trong cho CMS)
    const withPlaceholder = plainAddPlaceholder({
      pdfBuffer,
      reason: 'Ky thu bang .p12',
      contactInfo: '',
      name: 'Test P12',
      location: 'Vietnam',
    });

    // 2. Ky. P12Signer tu doc khoa + chung thu tu file .p12
    const signer = new P12Signer(p12Buffer, { passphrase: PASSWORD || '' });
    const signedPdf = await new SignPdf().sign(withPlaceholder, signer);

    // 3. Ghi ra
    const out = PDF_PATH.replace(/\.pdf$/i, '') + '-signed-p12.pdf';
    fs.writeFileSync(out, signedPdf);

    console.log(`\n  >>> KY THANH CONG: ${out}`);
    console.log('      Mo bang Adobe Reader de kiem tra chu ky.\n');
  } catch (e) {
    console.log(`\n  LOI: ${e.message}`);
    if (/pass|mac|integrity/i.test(e.message)) {
      console.log('  -> Nhieu kha nang SAI MAT KHAU file .p12.\n');
    } else if (/asn|forge|parse/i.test(e.message)) {
      console.log('  -> File .p12 co the hong hoac khong dung dinh dang.\n');
    } else {
      console.log('');
    }
    process.exit(1);
  }
})();
