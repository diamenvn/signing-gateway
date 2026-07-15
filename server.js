/**
 * Signing Gateway — tich hop HIS4
 *
 *   Trinh duyet (his4-dev.vnpthis.vn)
 *        |  HTTPS
 *   Cloudflare Tunnel
 *        |  HTTP localhost
 *   Gateway (file nay)          <- 127.0.0.1:8080
 *        |  WSS localhost
 *   VNPT-CA Plugin
 *        |
 *   USB Token
 *
 * Vi cloudflared da lo TLS, gateway chi bind 127.0.0.1 va chay HTTP thuong.
 * Khong can cert, khong can IP allowlist.
 *
 * Xac thuc: token ngan han do BACKEND HIS4 cap, ky bang HMAC-SHA256
 * voi secret dung chung. Frontend KHONG giu bi mat gi.
 */

'use strict';

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const WebSocket = require('ws');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // plugin dung self-signed cert

/**
 * APP_DIR  = noi dat file .exe (Program Files). Chi doc.
 * BASE_DIR = noi dat config + audit log (ProgramData). Ghi duoc.
 */
const APP_DIR = process.pkg ? path.dirname(process.execPath) : __dirname;

/**
 * Thu muc du lieu (config + audit log).
 * KHONG dat canh file .exe: bo cai dat exe vao Program Files, thu muc do
 * khong ghi duoc neu khong co quyen admin, va Windows se "ao hoa" file ghi vao
 * mot noi khac -> audit log bien mat mot cach am tham.
 *
 * Thu lan luot, lay noi dau tien GHI DUOC:
 *   1. Bien moi truong SIGNING_GATEWAY_DATA
 *   2. C:\ProgramData\SigningGateway         (may chuan, co quyen admin)
 *   3. %LOCALAPPDATA%\SigningGateway         (may siet quyen)
 *   4. Thu muc canh file .exe                (cuoi cung)
 */
function pickDataDir() {
  const candidates = [];
  if (process.env.SIGNING_GATEWAY_DATA) candidates.push(process.env.SIGNING_GATEWAY_DATA);
  if (process.platform === 'win32') {
    if (process.env.ProgramData) candidates.push(path.join(process.env.ProgramData, 'SigningGateway'));
    if (process.env.LOCALAPPDATA) candidates.push(path.join(process.env.LOCALAPPDATA, 'SigningGateway'));
  }
  candidates.push(process.pkg ? path.dirname(process.execPath) : __dirname);

  const errors = [];
  for (const dir of candidates) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      const probe = path.join(dir, '.write-test');
      fs.writeFileSync(probe, 'x');
      fs.unlinkSync(probe);
      return dir;
    } catch (e) {
      errors.push(`  ${dir}\n    -> ${e.message}`);
    }
  }

  console.error('\n  LOI: khong ghi duoc vao bat ky thu muc du lieu nao.\n');
  console.error(errors.join('\n'));
  console.error('\n  Thu chay signing-gateway.exe bang quyen Administrator,');
  console.error('  hoac dat bien moi truong SIGNING_GATEWAY_DATA tro toi thu muc ghi duoc.\n');
  pauseThenExit(1);
}

/** Giu cua so CMD mo de nguoi dung doc duoc loi khi ho double-click file exe. */
function pauseThenExit(code) {
  if (process.platform === 'win32' && process.stdin.isTTY) {
    console.error('  Nhan Enter de dong cua so...');
    try {
      process.stdin.setRawMode(true);
      require('node:fs').readSync(0, Buffer.alloc(1), 0, 1, null);
    } catch (_) { /* khong doc duoc thi thoi */ }
  }
  process.exit(code);
}

const BASE_DIR = pickDataDir();
const CONFIG_PATH = path.join(BASE_DIR, 'config.json');

/* ================================================================== */
/* Config                                                             */
/* ================================================================== */

const DEFAULTS = {
  host: '127.0.0.1',
  port: 8080,

  // Origin duoc phep goi. Them domain production khi trien khai that.
  allowedOrigins: ['https://his4-dev.vnpthis.vn'],

  // Secret dung chung voi BACKEND HIS4 de ky token.
  // Sinh bang: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  hisSharedSecret: '',

  // Thong tin dinh danh cua benh vien (ghi vao audit)
  tenantId: '',

  pluginPorts: [4433, 4434, 4435, 9201, 9202],
  pluginDomain: 'his4-dev.vnpthis.vn',

  certificateSerial: '',

  // Theo doi token nen (hoi CheckToken dinh ky).
  // MAC DINH TAT: hoi token lien tuc lam nghen driver PKCS#11 -> co the
  // treo phan mem quan ly token va ca plugin. Chi bat neu that su can
  // tu phat hien rut/cam USB, va chap nhan rui ro.
  monitorToken: false,
  monitorIntervalMs: 15000,   // neu bat, hoi thua thot thoi (15s)

  // Cache ket qua CheckToken. Hoi driver USB lien tuc lam nghen thiet bi.
  // 10s: du de khong nghen, van phat hien rut USB kip thoi.
  tokenCacheMs: 10000,

  // Gui log quan trong len Telegram thay vi chi in CMD.
  // Tao bot: nhan @BotFather tren Telegram -> /newbot -> lay botToken.
  // chatId: nhan tin cho bot roi mo
  //   https://api.telegram.org/bot<botToken>/getUpdates  -> lay "chat":{"id":...}
  telegram: {
    enabled: false,
    botToken: '',
    chatId: '',
    minLevel: 'warn',   // chi gui tu muc nay tro len: info < ok < warn < error
    sendLevels: ['warn', 'error'], // mang chua cac level can gui (vi du: ['info', 'ok', 'warn', 'error'])
    silent: false,      // true = gui khong keu thong bao
  },

  // Anh hien thi canh chu ky (base64 PNG/JPG, khong co tien to data:).
  // QUAN TRONG: chu ky TEXT-ONLY bi Adobe bao "Signature Not Verified".
  // Ky KEM ANH thi Adobe chap nhan. Dat logo don vi vao day.
  signatureImageBase64: '',
  // Bat = moi request BAT BUOC phai gui certificateSerial, khong nhan mac dinh.
  // Dung khi client luon biet serial thiet bi va muon ep dung dung cai do.
  requireSerial: false,
  tsaUrl: '',
  tsaUsername: '',
  tsaPassword: '',

  signTimeoutMs: 15000,
  jobTtlMinutes: 30,
  maxPdfBytes: 20 * 1024 * 1024,

  // KHOA DOC QUYEN (mo hinh A2): mot client giu token, ky nhieu file, roi unlock.
  // Client khac goi trong luc bi khoa -> 423 Locked.
  // Khong unlock (client chet) -> khoa tu het han sau lockTtlMs.
  // Moi lan ky thanh cong se GIA HAN khoa them lockTtlMs.
  lockTtlMs: 120000,          // 2 phut. Anh chinh sau.
  lockRequired: false,        // true = BAT BUOC lock truoc khi ky (khong cho ky le)

  // CHE DO DEV — CHI DUNG DE TEST, PHAI TAT TRUOC KHI LEN PRODUCTION.
  // Bat = cho goi API khong can token HMAC (de test bang Postman/curl).
  // De bat: dat "devMode": true trong config.json.
  devMode: false,

  // Cloudflare Tunnel chay nhu tien trinh con cua gateway.
  // Tat may / dong gateway -> tunnel tat theo. Khong co service ngam nao con lai.
  //
  //   token = ""     -> QUICK TUNNEL: khong can domain, khong can tai khoan.
  //                     Cloudflare cap URL ngau nhien xxx.trycloudflare.com.
  //                     URL DOI MOI LAN KHOI DONG LAI -> chi dung de test.
  //
  //   token = "eyJ.." -> NAMED TUNNEL: hostname co dinh, dung khi trien khai that.
  //                     Lay o Cloudflare Zero Trust > Networks > Tunnels.
  tunnel: {
    enabled: false,
    token: '',
    exePath: '',      // de trong = tim cloudflared.exe canh signing-gateway.exe
  },
  pluginProcessName: 'VNPT-CA Plugin.exe',
  pluginExePath: '',
  useNativeSigner: true,
  nativeSignerExePath: '',
  defaultPin: '',
};

function loadConfig() {
  if (!fs.existsSync(CONFIG_PATH)) {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULTS, null, 2));
    console.log(`  Chua co config.json. Da tao mau tai:\n    ${CONFIG_PATH}\n`);
  }

  let file;
  try {
    // Bo BOM: Notepad va Inno Setup deu co the ghi UTF-8 kem BOM (EF BB BF),
    // va JSON.parse khong chap nhan BOM.
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8').replace(/^\uFEFF/, '');
    file = JSON.parse(raw);
  } catch (e) {
    console.error(`\n  LOI: config.json sai dinh dang JSON.`);
    console.error(`  File : ${CONFIG_PATH}`);
    console.error(`  Chi tiet: ${e.message}`);
    console.error(`\n  Sua lai file, hoac xoa di de gateway tao lai file mau.\n`);
    pauseThenExit(1);
  }

  const cfg = {
    ...DEFAULTS,
    ...file,
    pluginDomain: normalizeDomain(file.pluginDomain || DEFAULTS.pluginDomain),
    tunnel: { ...DEFAULTS.tunnel, ...(file.tunnel || {}) }, // config cu khong co tunnel
  };

  // Origin cho WebSocket handshake. Mac dinh lay origin dau tien cua HIS4.
  if (!cfg.pluginOrigin) {
    cfg.pluginOrigin = (cfg.allowedOrigins && cfg.allowedOrigins[0])
      || `https://${cfg.pluginDomain}`;
  }
  return cfg;
}

/** "https://his4-dev.vnpthis.vn/abc" -> "his4-dev.vnpthis.vn" */
function normalizeDomain(d) {
  return String(d || '')
    .trim()
    .replace(/^[a-z]+:\/\//i, '')   // bo scheme
    .replace(/[/?#].*$/, '')        // bo path/query
    .replace(/:\d+$/, '')           // bo port
    .toLowerCase();
}

const TAG = { info: 'INFO', warn: 'WARN', error: 'ERR ', ok: ' OK ' };
/* ================================================================== */
/* Telegram — gui log QUAN TRONG len Telegram (loc + chong spam)       */
/* ================================================================== */

const Telegram = {
  cfg: null,
  queue: [],
  sending: false,
  lastSentAt: 0,

  init(cfg) {
    this.cfg = cfg.telegram || {};
    this.tenantId = cfg.tenantId || '';
    if (this.enabled) {
      log('info', `Telegram: BAT (chat ${this.cfg.chatId}). Muc log gui: ${this.cfg.minLevel || 'warn'}+`);
    }
  },

  get enabled() {
    return !!(this.cfg && this.cfg.enabled && this.cfg.botToken && this.cfg.chatId);
  },

  // Chi gui log tu muc nay tro len. Mac dinh: warn (bo qua ok/info).
  shouldSend(level) {
    if (!this.enabled) return false;
    if (Array.isArray(this.cfg.sendLevels)) {
      return this.cfg.sendLevels.includes(level);
    }
    const rank = { info: 0, ok: 1, warn: 2, error: 3 };
    const min = this.cfg.minLevel || 'warn';
    return (rank[level] ?? 0) >= (rank[min] ?? 2);
  },

  // Day tin vao hang doi (khong gui ngay -> gom + gian nhip tranh 429)
  push(text) {
    if (!this.enabled) return;
    const prefix = this.tenantId ? `[${this.tenantId}] ` : '';
    this.queue.push(prefix + text);
    if (this.queue.length > 100) this.queue.shift(); // chong tran bo nho
    this._drain();
  },

  async _drain() {
    if (this.sending || !this.queue.length) return;
    this.sending = true;
    try {
      while (this.queue.length) {
        // Telegram: ~1 tin/giay cho moi chat. Gian toi thieu 1.2s giua cac tin.
        const wait = 1200 - (Date.now() - this.lastSentAt);
        if (wait > 0) await new Promise((r) => setTimeout(r, wait));

        // Gom nhieu dong thanh 1 tin (toi da ~3500 ky tu, duoi gioi han 4096)
        let batch = '';
        while (this.queue.length && (batch.length + this.queue[0].length) < 3500) {
          batch += (batch ? '\n' : '') + this.queue.shift();
        }
        await this._send(batch);
        this.lastSentAt = Date.now();
      }
    } catch (_) { /* loi mang -> bo qua, khong lam sap gateway */ }
    finally { this.sending = false; }
  },

  _send(text) {
    return new Promise((resolve) => {
      const data = JSON.stringify({
        chat_id: this.cfg.chatId,
        text: text.slice(0, 4096),
        disable_notification: this.cfg.silent === true,
      });
      const req = https.request({
        hostname: 'api.telegram.org',
        path: `/bot${this.cfg.botToken}/sendMessage`,
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) },
        timeout: 8000,
      }, (res) => { res.on('data', () => {}); res.on('end', resolve); });
      req.on('error', resolve);   // loi mang khong duoc lam sap gateway
      req.on('timeout', () => { req.destroy(); resolve(); });
      req.write(data);
      req.end();
    });
  },

  // Gui tin chu dong (khong qua bo loc level) — dung cho su kien lon
  notify(text) {
    if (this.enabled) this.push(text);
  },
};

function log(lv, m) {
  const t = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`[${t}] [${TAG[lv]}] ${m}`);
  // Day log quan trong len Telegram (co loc theo muc)
  if (Telegram.shouldSend(lv)) {
    const icon = { error: '\u{1F534}', warn: '\u{1F7E1}', ok: '\u{1F7E2}', info: '\u{2139}\u{FE0F}' }[lv] || '';
    Telegram.push(`${icon} [${TAG[lv]}] ${m}`);
  }
}

/* ================================================================== */
/* Audit — append-only, hash chain de phat hien sua log               */
/* ================================================================== */

let prevHash = 'GENESIS';

function audit(cfg, ev) {
  const d = new Date();
  const f = path.join(BASE_DIR,
    `audit-${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}.jsonl`);
  const line = JSON.stringify({ ts: d.toISOString(), tenant: cfg.tenantId, prev: prevHash, ...ev });
  prevHash = crypto.createHash('sha256').update(prevHash + line).digest('hex');
  try { fs.appendFileSync(f, line + '\n'); }
  catch (e) { log('error', `audit: ${e.message}`); }
}

/* ================================================================== */
/* Token do backend HIS4 cap                                          */
/*                                                                    */
/*   token = base64url(payloadJSON) + "." + base64url(HMAC-SHA256)    */
/*   payload = { sub, name, exp, jti }                                */
/*                                                                    */
/* Frontend chi cam token, khong cam secret.                          */
/* ================================================================== */

const usedJti = new Map(); // chong replay

/**
 * @param consumeJti  true  = lenh ky   -> tieu thu jti, token khong dung lai duoc
 *                    false = doc du lieu -> chi kiem tra chu ky + han, cho dung lai
 *
 * Neu tieu thu jti o CA hai loai, client se bi 401 ngay khi poll trang thai job,
 * vi no dung lai token cua lenh ky. Chi chan replay o hanh dong co tac dung phu.
 */
function verifyHisToken(cfg, token, consumeJti) {
  if (!cfg.hisSharedSecret) throw new Error('SECRET_CHUA_CAU_HINH');
  const [body, sig] = String(token).split('.');
  if (!body || !sig) throw new Error('TOKEN_SAI_DINH_DANG');

  const want = crypto.createHmac('sha256', cfg.hisSharedSecret)
    .update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error('TOKEN_SAI_CHU_KY');
  }

  const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (!p.exp || p.exp * 1000 < Date.now()) throw new Error('TOKEN_HET_HAN');
  if (!p.sub) throw new Error('TOKEN_THIEU_SUB');

  if (consumeJti && p.jti) {
    if (usedJti.has(p.jti)) throw new Error('TOKEN_DA_DUNG');
    usedJti.set(p.jti, p.exp * 1000);
  }
  return p; // { sub, name, exp, jti }
}

setInterval(() => {
  const now = Date.now();
  for (const [k, exp] of usedJti) if (exp < now) usedJti.delete(k);
}, 60e3).unref();

/* ================================================================== */
/* VNPT Plugin client                                                 */
/* ================================================================== */

const FN = {
  GetCertInfo: 0, SignXML: 1, SignPDF: 2, setLicenseKey: 6, checkPlugin: 7, getVersion: 11,
  CheckToken: 34, SetGetCertFromUsbToken: 35, SetGetCertByPkcs11: 36,
  SetShowCertListDialog: 37, GetAllCertificates: 45,
};

/**
 * Plugin tra ve: "<payload>*<funcCallback>"
 *
 * <payload> co HAI dang, tuy ham:
 *   1. JSON:  {"code":0, "data":"<base64>", "error":"", "type":null, "serial":null}
 *   2. Chuoi tho: "0" / "1" / "1.0.2.2"   (vd CheckToken, checkPlugin, getVersion)
 *
 * MA TRANG THAI KHONG NHAT QUAN GIUA CAC HAM (do bang --diag va --probe):
 *   setLicenseKey       -> code  1  = thanh cong
 *   SetGetCertByPkcs11  -> code  1  = thanh cong
 *   SignPDF             -> code  0  = thanh cong   <-- KHAC!
 *   moi ham             -> code -1  = loi
 *
 * Vi vay quy tac DUY NHAT dung duoc: code AM = loi, con lai = thanh cong.
 * KHONG duoc kiem tra `code === 0` hay `code === 1`.
 *
 * Truong `error` chua ca thong bao THANH CONG ("Set license success"),
 * nen KHONG duoc dung no de phan doan thanh/bai.
 */
function parsePluginResponse(text) {
  const i = text.lastIndexOf('*');
  const payload = (i === -1 ? text : text.slice(0, i)).trim();

  if (payload.startsWith('{')) {
    let o;
    try { o = JSON.parse(payload); }
    catch (e) { throw new Error(`PLUGIN_JSON_HONG: ${payload.slice(0, 120)}`); }

    if (o.code !== undefined && Number(o.code) < 0) {
      const err = String(o.error || '').trim();
      if (/license/i.test(err)) throw new Error(`PLUGIN_THIEU_LICENSE: ${err}`);
      throw new Error(`PLUGIN_LOI(${o.code}): ${err || 'khong ro'}`);
    }
    return o.data !== undefined ? o.data : payload;
  }

  // Chuoi tho. Chi "-1" va chuoi rong moi la loi.
  if (payload === '-1' || payload === '') throw new Error('PLUGIN_LOI');
  return payload;
}

class Plugin {
  constructor(cfg) {
    this.cfg = cfg; this.ws = null; this.port = null;
    this.busy = false; this.version = null;
    this._mutex = new Mutex();   // moi lenh goi plugin noi duoi nhau qua day
    this.licensed = false;       // da nap license cho ket noi hien tai chua
    this._reconnecting = false;
    this._monitorOn = false;
    this._lastTokenState = null;  // theo doi rut/cam USB
  }
  get connected() { return this.ws && this.ws.readyState === WebSocket.OPEN; }

  _open(port) {
    return new Promise((res, rej) => {
      const ws = new WebSocket(`wss://localhost:${port}/plugin`, {
        rejectUnauthorized: false,
        origin: this.cfg.pluginOrigin,
        headers: { Origin: this.cfg.pluginOrigin },
      });
      const t = setTimeout(() => { ws.terminate(); rej(new Error('timeout')); }, 3000);
      ws.on('open', () => { clearTimeout(t); res(ws); });
      ws.on('error', (e) => { clearTimeout(t); rej(e); });
    });
  }

  async connect() {
    for (const p of this.cfg.pluginPorts) {
      try {
        this.ws = await this._open(p);
        this.port = p;
        this.licensed = false;
        this.ws.on('close', () => {
          this.ws = null; this.licensed = false;
          log('warn', 'Mat ket noi plugin. Se tu ket noi lai...');
          this._scheduleReconnect();
        });
        this.ws.on('error', () => {});
        log('ok', `Ket noi plugin tai port ${p}`);
        return true;
      } catch (_) { /* thu port ke tiep */ }
    }
    return false;
  }

  /**
   * Tu khoi dong VNPT-CA Plugin native neu no chua chay.
   * Tim file thuc thi o cac vi tri cai dat thuong gap.
   * Tra ve true neu da goi lenh khoi dong (khong dam bao chay ngay).
   */
  tryStartNativePlugin() {
    if (process.platform !== 'win32') return false;

    // 1. Dung duong dan cau hinh neu co
    if (this.cfg.pluginExePath && fs.existsSync(this.cfg.pluginExePath)) {
      log('info', `Khoi dong Plugin tu cau hinh: ${this.cfg.pluginExePath}`);
      spawn(this.cfg.pluginExePath, [], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      return true;
    }

    // 2. Tim theo danh sach candidates tu dong (ho tro ca VNPT va ICA)
    const candidates = [
      // VNPT candidates
      'C\\:\\Program Files (x86)\\VNPT-CA Plugin\\VNPT-CA Plugin.exe',
      'C\\:\\Program Files\\VNPT-CA Plugin\\VNPT-CA Plugin.exe',
      path.join(process.env.LOCALAPPDATA || '', 'VNPT-CA Plugin', 'VNPT-CA Plugin.exe'),
      path.join(process.env.PROGRAMFILES || '', 'VNPT-CA Plugin', 'VNPT-CA Plugin.exe'),
      path.join(process.env['PROGRAMFILES(X86)'] || '', 'VNPT-CA Plugin', 'VNPT-CA Plugin.exe'),
      // ICA candidates
      'C\\:\\Program Files (x86)\\i-CA Plugin\\ica_csp11_v1_certd.exe',
      'C\\:\\Program Files\\i-CA Plugin\\ica_csp11_v1_certd.exe',
      'C\\:\\Program Files (x86)\\ICA\\ica_csp11_v1_certd.exe',
      'C\\:\\Program Files\\ICA\\ica_csp11_v1_certd.exe',
      path.join(process.env.LOCALAPPDATA || '', 'i-CA Plugin', 'ica_csp11_v1_certd.exe'),
      path.join(process.env.PROGRAMFILES || '', 'i-CA Plugin', 'ica_csp11_v1_certd.exe'),
      path.join(process.env['PROGRAMFILES(X86)'] || '', 'i-CA Plugin', 'ica_csp11_v1_certd.exe'),
    ].map((s) => s.replace('C\\:', 'C:'));

    // Neu cau hinh pluginProcessName thi uu tien tim file exe co ten do truoc
    const sortedCandidates = [...candidates];
    if (this.cfg.pluginProcessName) {
      const matchName = this.cfg.pluginProcessName.toLowerCase();
      sortedCandidates.sort((a, b) => {
        const aMatch = path.basename(a).toLowerCase() === matchName;
        const bMatch = path.basename(b).toLowerCase() === matchName;
        if (aMatch && !bMatch) return -1;
        if (!aMatch && bMatch) return 1;
        return 0;
      });
    }

    for (const exe of sortedCandidates) {
      try {
        if (fs.existsSync(exe)) {
          log('info', `Khoi dong Plugin tu dong: ${exe}`);
          spawn(exe, [], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
          return true;
        }
      } catch (_) { /* thu tiep */ }
    }

    log('warn', 'Khong tim thay Plugin ky so trong he thong de tu khoi dong.');
    return false;
  }

  _scheduleReconnect() {
    if (this._reconnecting) return;
    this._reconnecting = true;
    let tried = 0;
    const attempt = async () => {
      if (this.connected) { this._reconnecting = false; return; }
      tried++;
      // Sau vai lan that bai, thu tu KHOI DONG plugin native (co the no da tat)
      if (tried === 3) this.tryStartNativePlugin();

      if (await this.connect()) {
        this._reconnecting = false;
        log('ok', 'Da ket noi lai plugin.');
        try { await this.warmup(); } catch (_) {}
        return;
      }
      const wait = Math.min(2000 * tried, 10000);
      setTimeout(attempt, wait).unref();
    };
    setTimeout(attempt, 1500).unref();
  }

  /** Dam bao dang ket noi + da nap license. Goi truoc moi thao tac quan trong. */
  async ensureReady() {
    if (!this.connected) {
      if (!(await this.connect())) {
        this.tryStartNativePlugin();
        // cho plugin khoi dong roi thu lai 1 lan
        await new Promise((r) => setTimeout(r, 3000));
        if (!(await this.connect())) throw new Error('PLUGIN_KHONG_KET_NOI');
      }
    }
    if (!this.licensed && this.cfg.licenseKey) {
      try {
        await this.call(FN.setLicenseKey, [this.cfg.licenseKey]);
        this.licensed = true;
      } catch (_) { /* warmup se thu lai */ }
    }
  }

  /**
   * Protocol VNPT Plugin:
   *   gui : {functionID, funcCallback, args, domain}
   *   nhan: "<payload>*<funcCallback>"
   * Khong co request id -> phai serialize hoan toan.
   *
   * MOI lenh goi plugin (ky, checkToken, license, monitor...) deu di qua
   * mot mutex CHUNG. Truoc day chi cac lenh ky duoc serialize, con monitor
   * chay nen thi goi thang -> no chen ngang lenh ky -> "PLUGIN_DANG_BAN".
   * Gio tat ca noi duoi nhau, khong ai bi tu choi.
   */
  async call(fnId, args, timeoutMs = 30000) {
    return this._mutex.run(() => this._callNow(fnId, args, timeoutMs));
  }

  async _callNow(fnId, args, timeoutMs) {
    if (!this.connected) throw new Error('PLUGIN_KHONG_KET_NOI');
    this.busy = true;
    try {
      return await new Promise((res, rej) => {
        const cb = 'cb_' + crypto.randomBytes(4).toString('hex');
        const t = setTimeout(() => {
          this.ws.off('message', on);
          const fnName = Object.keys(FN).find(k => FN[k] === fnId) || fnId;
          log('error', `Goi plugin qua han (timeout ${timeoutMs}ms) o ham: ${fnName}`);
          
          if (fnId !== FN.SignPDF && fnId !== FN.SignXML) {
            this.forceRestartNativePlugin().catch(() => {});
            if (fnId === FN.CheckToken) {
              rej(new Error('PLUGIN_TREO_CHECK_TOKEN'));
            } else {
              rej(new Error('PLUGIN_TREO_CONG_CU'));
            }
          } else {
            rej(new Error('PLUGIN_QUA_HAN'));
          }
        }, timeoutMs);
        const on = (raw) => {
          clearTimeout(t);
          this.ws.off('message', on);
          try { res(parsePluginResponse(raw.toString())); }
          catch (e) { rej(e); }
        };
        this.ws.on('message', on);
        this.ws.send(JSON.stringify({
          functionID: fnId, funcCallback: cb, args, domain: this.cfg.pluginDomain,
        }));
      });
    } finally { this.busy = false; }
  }

  async warmup() {
    // BAT BUOC goi truoc tien. Khong co license, plugin tra ve:
    //   {"code":-1, "data":"", "error":"License not set for: <domain>"}
    // License gan voi DOMAIN gui trong truong `domain` cua moi request.
    if (this.cfg.licenseKey) {
      const lic = this.cfg.licenseKey;
      if (/\s/.test(lic)) {
        log('warn', `License co ${(lic.match(/\s/g) || []).length} ky tu trang/xuong dong -> nhieu kha nang bi cat khi dan.`);
      }
      try {
        await this.call(FN.setLicenseKey, [lic]);
        this.licensed = true;
        log('ok', `Da nap license (${lic.length} ky tu) cho domain: ${this.cfg.pluginDomain}`);
      } catch (e) {
        this.licensed = false;
        log('error', `Nap license that bai: ${e.message}`);
        log('error', `License dai ${lic.length} ky tu, domain gui: ${this.cfg.pluginDomain}`);
        log('error', 'Chay:  signing-gateway.exe --license   de do nguyen nhan.');
      }
    } else {
      log('warn', 'CHUA CO licenseKey trong config.json.');
      log('warn', 'Neu plugin chua duoc cap license san cho domain nay, moi lenh ky se bi tu choi.');
    }

    this.version = await this.call(FN.getVersion, ['']).catch(() => null);
    await this.call(FN.SetGetCertFromUsbToken, ['1']).catch(() => {});
    await this.call(FN.SetGetCertByPkcs11, ['1']).catch(() => {});
    await this.call(FN.SetShowCertListDialog, ['0']).catch(() => {});
    log('ok', `Plugin version: ${this.version || '?'}`);
  }

  /**
   * Theo doi lien tuc: plugin con song khong, USB con cam khong.
   * Tu log khi rut/cam USB. Tu ket noi lai neu plugin tat.
   * KHONG can tat/bat lai tool khi thay doi phan cung.
   */
  /**
   * Buoc plugin doc lai token tu dau: refresh cert, va neu can thi mo lai
   * ket noi WebSocket (mot so plugin chi doc lai USB khi co ket noi moi).
   * Dung khi cam USB vao ma plugin van bao "khong co token".
   */
  async reloadToken() {
    if (!this.connected) {
      await this.connect().catch(() => {});
      if (this.connected) await this.warmup().catch(() => {});
    }
    // Thu refresh nhe truoc
    await this.call(FN.SetGetCertFromUsbToken, ['1']).catch(() => {});
    await this.call(FN.SetGetCertByPkcs11, ['1']).catch(() => {});
    let t = await this.checkToken().catch(() => null);
    if (t && t.present) return { present: true, method: 'refresh' };

    // Van khong thay -> mo lai ket noi (dut cache cua plugin)
    try { if (this.ws) this.ws.close(); } catch (_) {}
    this.ws = null; this.licensed = false;
    await new Promise((r) => setTimeout(r, 500));
    await this.connect().catch(() => {});
    if (this.connected) {
      await this.warmup().catch(() => {});
      t = await this.checkToken().catch(() => null);
    }
    return { present: !!(t && t.present), method: 'reconnect' };
  }

  startMonitor(intervalMs) {
    if (this._monitorOn) return;
    if (!this.cfg.monitorToken) {
      log('info', 'Theo doi token nen: TAT (tranh nghen driver USB).');
      return;
    }
    this._monitorOn = true;
    intervalMs = intervalMs || this.cfg.monitorIntervalMs || 15000;
    log('info', `Theo doi token nen: BAT (moi ${intervalMs / 1000}s).`);
    const tick = async () => {
      try {
        // Monitor phai NHE: chi hoi trang thai, KHONG refresh/reconnect o day.
        // Truoc day monitor goi SetGetCertFromUsbToken + reconnect -> chiem mutex
        // -> lenh ky phai cho ca chuoi nay -> ky cham ca phut. Da bo.
        if (this.connected && !this.busy) {
          const t = await this.checkToken().catch(() => null);
          const present = t ? t.present : null;
          if (present !== null && present !== this._lastTokenState) {
            if (this._lastTokenState === null) {
              log('info', present ? 'USB Token: da phat hien.' : 'USB Token: chua cam.');
            } else if (present) {
              log('ok', 'USB Token vua duoc CAM vao. San sang ky.');
            } else {
              log('warn', 'USB Token vua bi RUT ra.');
            }
            this._lastTokenState = present;
          }
        }
      } catch (_) { /* bo qua */ }
      setTimeout(tick, intervalMs).unref();
    };
    setTimeout(tick, intervalMs).unref();
  }

  /**
   * CheckToken tra ve CHUOI THO, khong phai JSON.
   * Do thuc te: "0" = KHONG co token cam vao may.
   * (Phat hien khi rut token ra ma he thong van bao "da phat hien".)
   * Gia tri khac 0 = co token. Chua ro no la so luong hay ma trang thai.
   */
  /**
   * CheckToken tra ve CHUOI THO. "0" = KHONG co token.
   *
   * Co CACHE NGAN (mac dinh 10s): hoi driver PKCS#11 lien tuc lam nghen
   * thiet bi USB — da tung lam treo ca phan mem quan ly token va plugin.
   * Cache giup: khong hoi qua day, nhung van phat hien duoc rut USB
   * trong vong ~10s.
   */
  async checkToken(force = false) {
    const now = Date.now();
    const ttl = this.cfg.tokenCacheMs ?? 10000;
    if (!force && this._tokenCache && now - this._tokenCacheAt < ttl) {
      return this._tokenCache;
    }
    const raw = await this.call(FN.CheckToken, [''], 5000);
    const r = { raw: String(raw).trim(), present: String(raw).trim() !== '0' };
    this._tokenCache = r;
    this._tokenCacheAt = now;
    return r;
  }
  async getCertInfo() {
    if (this.cfg.useNativeSigner) {
      try {
        const { execFile } = require('node:child_process');
        const exePath = path.join(BASE_DIR, 'bin', 'pdf-signer.exe');
        const raw = await new Promise((resolve, reject) => {
          execFile(exePath, ['--list'], { windowsHide: true }, (err, stdout, stderr) => {
            if (err) reject(err);
            else resolve(stdout);
          });
        });
        
        const certs = [];
        const lines = raw.split('\n');
        for (const line of lines) {
          if (line.includes('SERIAL:')) {
            const parts = line.split('|');
            const serial = (parts.find(p => p.startsWith('SERIAL:')) || '').replace('SERIAL:', '').trim();
            const cn = (parts.find(p => p.startsWith('CN:')) || '').replace('CN:', '').trim();
            const hasKey = (parts.find(p => p.startsWith('HAS_KEY:')) || '').replace('HAS_KEY:', '').trim();
            certs.push({ serial, cn, hasKey: hasKey === 'True' });
          }
        }
        return JSON.stringify(certs);
      } catch (e) {
        log('error', `Loi khi getCertInfo tu native-signer: ${e.message}`);
        return '[]';
      }
    }
    return this.call(FN.GetCertInfo, ['1', this.cfg.certificateSerial || ''], 15000);
  }

  /**
   * Liet ke serial cua cac cert dang co trong token (chuan hoa chu HOA).
   * Cache NGAN (mac dinh 3s) va co the ep lam moi (force=true).
   */
  async listSerials(force = false) {
    const now = Date.now();
    const ttl = this.cfg.serialCacheMs ?? 3000;
    if (!force && this._serialCache && now - this._serialCacheAt < ttl) {
      return this._serialCache;
    }
    
    let serials = [];
    if (this.cfg.useNativeSigner) {
      try {
        const { execFile } = require('node:child_process');
        const exePath = path.join(BASE_DIR, 'bin', 'pdf-signer.exe');
        const raw = await new Promise((resolve, reject) => {
          execFile(exePath, ['--list'], { windowsHide: true }, (err, stdout, stderr) => {
            if (err) reject(err);
            else resolve(stdout);
          });
        });
        
        const lines = raw.split('\n');
        for (const line of lines) {
          if (line.includes('SERIAL:')) {
            const parts = line.split('|');
            const serialPart = parts.find(p => p.startsWith('SERIAL:'));
            if (serialPart) {
              const s = serialPart.replace('SERIAL:', '').trim().toUpperCase().replace(/\s+/g, '');
              if (s) serials.push(s);
            }
          }
        }
      } catch (e) {
        log('error', `Loi khi listSerials tu native-signer: ${e.message}`);
      }
    } else {
      const raw = await this.call(FN.GetAllCertificates, [''], 15000);
      try {
        const arr = JSON.parse(raw);
        serials = arr.map((item) => {
          const o = typeof item === 'string' ? JSON.parse(item) : item;
          return String(o.serial || '').toUpperCase().replace(/\s+/g, '');
        }).filter(Boolean);
      } catch (_) {}
    }

    this._serialCache = serials;
    this._serialCacheAt = now;
    return serials;
  }

  /** Xoa moi cache token — goi khi nghi ngo USB da thay doi. */
  invalidateTokenCache() {
    this._serialCache = null;
    this._tokenCache = null;
    this._lastTokenState = null;
  }

  /**
   * Ky PDF NGUYEN TU: gom kiem token + doc serial + ky vao MOT lan giu mutex.
   * Khong lenh nao chen giua duoc. Tranh truong hop:
   *   - Kiem token thay "co", nhung truoc khi ky thi USB bi rut
   *   - Hai request ky chen lenh cua nhau tren driver -> treo
   *
   * Xac minh serial NGAY TRONG mutex, bang du lieu token THAT (khong cache),
   * nen serial cua USB da rut se bi tu choi.
   */
  async signPdfAtomic(pdfB64, o, requiredSerial) {
    return this._mutex.run(async () => {
      // 1. Token con cam khong? (hoi that, dang trong mutex)
      const raw = await this._callNow(FN.CheckToken, [''], 5000);
      if (String(raw).trim() === '0') throw new Error('KHONG_CO_USB_TOKEN');

      // 2. Doc serial that trong token dang cam (khong cache)
      if (requiredSerial) {
        const certRaw = await this._callNow(FN.GetAllCertificates, [''], 15000);
        let serials = [];
        try {
          const arr = JSON.parse(certRaw);
          serials = arr.map((it) => {
            const x = typeof it === 'string' ? JSON.parse(it) : it;
            return String(x.serial || '').toUpperCase().replace(/\s+/g, '');
          }).filter(Boolean);
        } catch (_) {}
        const want = String(requiredSerial).toUpperCase().replace(/[\s:]+/g, '');
        if (!serials.includes(want)) {
          throw new Error(`SERIAL_KHONG_KHOP: token dang cam khong co cert ${want}`);
        }
      }

      // 3. Ky — van trong cung mutex, khong ai chen
      const signer = this._buildPdfSigner(o);
      return this._callNow(FN.SignPDF, [pdfB64, JSON.stringify(signer)], this.cfg.signTimeoutMs);
    });
  }

  /** Tach phan dung PdfSigner object de signPdf va signPdfAtomic dung chung. */
  _buildPdfSigner(o = {}) {
    const c = this.cfg;
    const rawImage = o.imageBase64 || c.signatureImageBase64 || null;
    const cleanImage = typeof rawImage === 'string'
      ? rawImage.replace(/^data:image\/[a-z]+;base64,/i, '')
      : null;

    return {
      page: o.page ?? 1,
      llx: o.llx ?? 380, lly: o.lly ?? 40, urx: o.urx ?? 560, ury: o.ury ?? 110,
      SigTextSize: o.sigTextSize ?? 8,
      Signer: o.signer ?? null,
      SignerPosition: o.signerPosition ?? null,
      SigningTime: null,
      Description: o.description ?? null,
      ImageBase64: cleanImage,
      OnlyDescription: o.onlyDescription === true,
      ValidationOption: true, SigColorRGB: null,
      SetImageBackground: o.setImageBackground === true,
      PagesArray: null,
      CertificateSerial: o.certificateSerial || c.certificateSerial || null,
      TsaUrl: c.tsaUrl || null,
      TsaUsername: c.tsaUsername || null,
      TsaPassword: c.tsaPassword || null,
      AdvancedCustom: false,
      SigType: o.sigType ?? 2,
      IsEncyptFile: false, EncryptPassword: null,
      SigVisible: o.visible !== false, SigSignerVisible: true,
      SigEmailVisible: false, SigPositionVisible: false, SigSigningTimeVisible: true,
    };
  }

  signPdf(pdfB64, o = {}) {
    return this.call(FN.SignPDF, [pdfB64, JSON.stringify(this._buildPdfSigner(o))], this.cfg.signTimeoutMs);
  }

  // (_signPdfOld da xoa — dung _buildPdfSigner + signPdf/signPdfAtomic)

  /**
   * Ky XML. Plugin ho tro chu ky XMLDSig (Enveloped/Enveloping/Detached).
   *
   * @param xml   noi dung XML dang chuoi (KHONG phai base64)
   * @param o     tuy chon:
   *   signingType   "Enveloped" (mac dinh) | "Enveloping" | "Detached"
   *   digestMethod  "SHA256" (mac dinh) | "SHA1"
   *   tagSigning        ten the muon ky (null = ca tai lieu)
   *   nodeToSign        XPath node can ky
   *   tagSaveResult     the de luu chu ky
   *   parentTagSigning  the cha
   *   certificateSerial serial cert
   * @returns chuoi XML da ky (giai ma tu base64 trong .data)
   */
  signXml(xml, o = {}) {
    const c = this.cfg;
    const signer = {
      TagSigning: o.tagSigning ?? null,
      NodeToSign: o.nodeToSign ?? null,
      TagSaveResult: o.tagSaveResult ?? null,
      ParrentTagSigning: o.parentTagSigning ?? null,   // giu nguyen chinh ta cua SDK
      NameXPathFilter: o.nameXPathFilter ?? null,
      NameIDTimeSignature: o.nameIdTimeSignature ?? null,
      DsSignature: o.dsSignature ?? false,
      SigningType: o.signingType ?? 'Enveloped',
      SigningTime: o.signingTime ?? null,              // "HH:mm:ss dd/MM/yyyy"
      CertificateSerial: o.certificateSerial || c.certificateSerial || null,
      ValidateBefore: o.validateBefore ?? false,
      // Mac dinh SHA256 (SDK mac dinh SHA1 — cu nhung SHA256 an toan hon)
      DigestMethod: o.digestMethod ?? 'SHA256',
      SignatureMethod: o.signatureMethod ?? 'RSAwithSHA256',
    };
    return this.call(FN.SignXML, [xml, JSON.stringify(signer)], c.signTimeoutMs);
  }

  async forceRestartNativePlugin() {
    if (process.platform !== 'win32') return;
    log('warn', 'Phat hien VNPT-CA Plugin bi treo. Dang tien hanh khoi dong lai plugin...');
    
    // 1. Dong WS hien tai de giai phong ket noi
    try { if (this.ws) this.ws.close(); } catch (_) {}
    this.ws = null;
    this.licensed = false;

    // 2. Kill tien trinh cu
    const procName = this.cfg.pluginProcessName || 'VNPT-CA Plugin.exe';
    log('warn', `Dang tat tien trinh plugin bi treo: ${procName}...`);
    await new Promise((resolve) => {
      const k = spawn('taskkill', ['/F', '/IM', procName], { windowsHide: true });
      k.on('exit', () => resolve());
    });

    // 3. Cho 1 giay de OS giai phong port
    await new Promise((r) => setTimeout(r, 1000));
    
    // 4. Khoi dong lai plugin
    this.tryStartNativePlugin();
  }
}

/* ================================================================== */
/* Hang doi — concurrency = 1 (token ky tuan tu)                      */
/* ================================================================== */

/* ================================================================== */
/* Khoa doc quyen token (A2)                                          */
/* ================================================================== */

/* ================================================================== */
/* Mutex — noi tiep cac lenh ky, KHONG can queue/jobId phuc tap        */
/*                                                                    */
/* Ly do van can serialize du la ky dong bo: protocol plugin khong co */
/* request id, hai lenh dong thoi tren cung WebSocket se lan response.*/
/* Mutex cho request sau CHO request truoc xong, thay vi nem loi.      */
/* ================================================================== */

class Mutex {
  constructor() { this._chain = Promise.resolve(); }
  /** Chay fn sao cho khong bao gio 2 fn chay dong thoi. Giu thu tu goi. */
  run(fn) {
    const result = this._chain.then(() => fn());
    // giu chain tiep tuc du fn loi
    this._chain = result.then(() => {}, () => {});
    return result;
  }
}

class TokenLock {
  constructor(cfg) {
    this.cfg = cfg;
    this.holder = null;      // { lockToken, owner, ownerName, expiresAt, signCount }
    setInterval(() => this._sweep(), 5000).unref();
  }

  /** Khoa con hieu luc khong? */
  get active() {
    return this.holder && this.holder.expiresAt > Date.now();
  }

  _sweep() {
    if (this.holder && this.holder.expiresAt <= Date.now()) {
      log('info', `Khoa cua ${this.holder.owner} tu het han (khong unlock).`);
      this.holder = null;
    }
  }

  /** Chiem khoa. Tra ve {ok, lock} hoac {ok:false, ...} neu dang bi giu. */
  acquire(owner, ownerName) {
    if (this.active) {
      // Cho phep chinh chu re-acquire (idempotent) — coi nhu gia han
      if (this.holder.owner === owner) {
        this.holder.expiresAt = Date.now() + this.cfg.lockTtlMs;
        return { ok: true, lock: this._public() };
      }
      return {
        ok: false,
        lockedBy: this.holder.owner,
        retryAfterMs: this.holder.expiresAt - Date.now(),
      };
    }
    this.holder = {
      lockToken: 'lk_' + crypto.randomBytes(12).toString('hex'),
      owner, ownerName,
      expiresAt: Date.now() + this.cfg.lockTtlMs,
      signCount: 0,
    };
    log('info', `Khoa token: ${owner} (het han sau ${this.cfg.lockTtlMs / 1000}s)`);
    return { ok: true, lock: this._public() };
  }

  /** Kiem tra lockToken hop le va con han. Dung truoc moi lenh ky. */
  verify(lockToken) {
    if (!this.active) return { ok: false, error: 'KHONG_CO_KHOA' };
    if (this.holder.lockToken !== lockToken) return { ok: false, error: 'SAI_LOCK_TOKEN' };
    return { ok: true };
  }

  /** Gia han + dem so lan ky. Goi sau moi lan ky thanh cong. */
  renew() {
    if (this.holder) {
      this.holder.expiresAt = Date.now() + this.cfg.lockTtlMs;
      this.holder.signCount++;
    }
  }

  /** Nha khoa. Chi chu khoa moi nha duoc. */
  release(lockToken) {
    if (!this.holder) return { ok: true, alreadyFree: true };
    if (this.holder.lockToken !== lockToken) return { ok: false, error: 'SAI_LOCK_TOKEN' };
    const count = this.holder.signCount;
    log('info', `Nha khoa: ${this.holder.owner} (da ky ${count} file)`);
    this.holder = null;
    return { ok: true, signCount: count };
  }

  _public() {
    return {
      lockToken: this.holder.lockToken,
      expiresInMs: this.holder.expiresAt - Date.now(),
      signCount: this.holder.signCount,
    };
  }

  status() {
    if (!this.active) return { locked: false };
    return {
      locked: true,
      owner: this.holder.owner,
      ownerName: this.holder.ownerName,
      expiresInMs: this.holder.expiresAt - Date.now(),
      signCount: this.holder.signCount,
    };
  }
}

class Queue {
  constructor(plugin, cfg) {
    this.plugin = plugin; this.cfg = cfg;
    this.jobs = new Map(); this.pending = []; this.running = false;
    this.stats = { done: 0, failed: 0, lastSignAt: null, lastMs: null };
    setInterval(() => this._gc(), 60e3).unref();
  }
  get depth() { return this.pending.length; }
  get(id) { return this.jobs.get(id); }

  submit(job) {
    this.jobs.set(job.id, job);
    this.pending.push(job.id);
    this._drain();
    return job;
  }

  async _drain() {
    if (this.running) return;
    this.running = true;
    while (this.pending.length) {
      const job = this.jobs.get(this.pending.shift());
      if (!job) continue;
      job.status = 'signing';
      const t0 = Date.now();
      try {
        job.result = await this.plugin.signPdf(job.input, job.opts);
        job.status = 'done';
        job.durationMs = Date.now() - t0;
        this.stats.done++;
        this.stats.lastSignAt = Date.now();
        this.stats.lastMs = job.durationMs;
        log('ok', `${job.id} ky xong ${job.durationMs}ms  (user: ${job.user})`);
        audit(this.cfg, { type: 'sign.ok', jobId: job.id, user: job.user, userName: job.userName,
                          docId: job.docId, sha256: job.sha256, ms: job.durationMs });
      } catch (e) {
        job.status = 'failed';
        job.error = e.message;
        this.stats.failed++;
        log('error', `${job.id} that bai: ${e.message}`);
        audit(this.cfg, { type: 'sign.fail', jobId: job.id, user: job.user, userName: job.userName,
                          docId: job.docId, sha256: job.sha256, error: e.message });
      }
      job.input = null;                  // giai phong bo nho ngay
      job.finishedAt = Date.now();
    }
    this.running = false;
  }

  _gc() {
    const cut = Date.now() - this.cfg.jobTtlMinutes * 60e3;
    for (const [id, j] of this.jobs) if (j.finishedAt && j.finishedAt < cut) this.jobs.delete(id);
  }
}

/* ================================================================== */
/* Cloudflare Tunnel — chay nhu tien trinh con                        */
/* ================================================================== */

class Tunnel {
  constructor(cfg) {
    this.cfg = cfg.tunnel || {};
    this.port = cfg.port;
    this.proc = null;
    this.state = 'off';          // off | starting | up | retrying | error
    this.hostname = null;
    this.retries = 0;
    this.stopping = false;
    this.mode = this.cfg.token ? 'named' : 'quick';
  }

  /** Tim cloudflared.exe: config -> canh file exe -> PATH he thong */
  resolveExe() {
    const name = process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared';
    if (this.cfg.exePath && fs.existsSync(this.cfg.exePath)) return this.cfg.exePath;
    const beside = path.join(APP_DIR, name);
    if (fs.existsSync(beside)) return beside;
    return name; // thu tim trong PATH
  }

  start() {
    if (!this.cfg.enabled) { this.state = 'off'; return; }

    const exe = this.resolveExe();
    const besideExpected = path.join(APP_DIR, process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared');

    if (!fs.existsSync(exe) && exe === besideExpected) {
      this.state = 'error';
      log('error', 'KHONG TIM THAY cloudflared.');
      log('error', `Can dat file cloudflared.exe vao: ${APP_DIR}`);
      log('error', 'Tai tai: https://github.com/cloudflare/cloudflared/releases/latest');
      return;
    }

    // Named tunnel: hostname co dinh, can token.
    // Quick tunnel: URL ngau nhien, khong can gi ca. Dung de test.
    const args = this.cfg.token
      ? ['tunnel', '--no-autoupdate', 'run', '--token', this.cfg.token]
      : ['tunnel', '--no-autoupdate', '--url', `http://127.0.0.1:${this.port}`];

    this.state = 'starting';
    log('info', `Khoi dong Cloudflare Tunnel (che do: ${this.mode})...`);

    this.proc = spawn(exe, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });

    this.proc.on('error', (e) => {
      this.state = 'error';
      log('error', `Khong chay duoc cloudflared: ${e.message}`);
      log('error', `Duong dan da thu: ${exe}`);
      this.proc = null;
    });

    const onLine = (line) => {
      if (!line.trim()) return;

      // Quick tunnel: cloudflared in ra URL ngau nhien trong log
      const quick = line.match(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)/i);
      if (quick && this.hostname !== quick[1]) {
        this.hostname = quick[1];
        this.state = 'up';
        this.retries = 0;
        console.log('');
        log('ok', `Tunnel san sang: https://${this.hostname}`);
        
        // Ghi URL ra file de tien tra cuu khi chay ngam
        try {
          fs.writeFileSync(path.join(BASE_DIR, 'tunnel_url.txt'), `https://${this.hostname}`);
        } catch (_) {}

        log('warn', 'URL nay DOI moi lan khoi dong lai. Chi dung de test.');
        console.log('');
        return;
      }

      if (/Registered tunnel connection/i.test(line)) {
        if (this.state !== 'up') {
          this.state = 'up';
          this.retries = 0;
          log('ok', 'Cloudflare Tunnel: da ket noi');
        }
        return;
      }

      if (/ERR |error=|failed/i.test(line)) {
        log('warn', `cloudflared: ${line.trim().slice(0, 160)}`);
      }
    };

    let buf = '';
    const feed = (chunk) => {
      buf += chunk.toString();
      const parts = buf.split('\n');
      buf = parts.pop();
      parts.forEach(onLine);
    };
    this.proc.stdout.on('data', feed);
    this.proc.stderr.on('data', feed);  // cloudflared ghi log ra stderr

    this.proc.on('exit', (code) => {
      this.proc = null;
      try {
        fs.unlinkSync(path.join(BASE_DIR, 'tunnel_url.txt'));
      } catch (_) {}
      if (this.stopping) { this.state = 'off'; return; }

      // Tunnel chet -> khoi dong lai, gian dan 5s, 10s, 20s... toi da 60s
      this.retries++;
      const wait = Math.min(5000 * 2 ** (this.retries - 1), 60000);
      this.state = 'retrying';
      this.hostname = null;
      log('warn', `cloudflared thoat (ma ${code}). Thu lai sau ${wait / 1000}s.`);
      setTimeout(() => this.start(), wait).unref();
    });
  }

  stop() {
    this.stopping = true;
    if (this.proc) {
      log('info', 'Dang tat Cloudflare Tunnel...');
      this.proc.kill();
      this.proc = null;
    }
    try {
      fs.unlinkSync(path.join(BASE_DIR, 'tunnel_url.txt'));
    } catch (_) {}
    this.state = 'off';
  }
}

/* ================================================================== */
/* HTTP                                                               */
/* ================================================================== */

function json(res, code, obj) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function readBody(req, limit) {
  return new Promise((res, rej) => {
    const cs = []; let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) { rej(new Error('FILE_QUA_LON')); req.destroy(); return; }
      cs.push(c);
    });
    req.on('end', () => res(Buffer.concat(cs)));
    req.on('error', rej);
  });
}

/**
 * Parse multipart/form-data (thuan JS, khong thu vien).
 * Tra ve { fields: {ten: giatri}, files: {ten: Buffer} }.
 * Du dung cho form-data cua Postman: cac field text + 1 file.
 */
function parseMultipart(buf, boundary) {
  const fields = {};
  const files = {};
  const delim = Buffer.from('--' + boundary);
  const parts = [];

  let start = buf.indexOf(delim);
  while (start !== -1) {
    const next = buf.indexOf(delim, start + delim.length);
    if (next === -1) break;
    // bo qua CRLF sau boundary
    parts.push(buf.subarray(start + delim.length, next));
    start = next;
  }

  for (let part of parts) {
    // moi part: <CRLF>headers<CRLF><CRLF>body<CRLF>
    if (part.length < 4) continue;
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd === -1) continue;

    const header = part.subarray(0, headerEnd).toString('utf8');
    let body = part.subarray(headerEnd + 4);
    // bo CRLF cuoi
    if (body.length >= 2 && body[body.length - 2] === 0x0d && body[body.length - 1] === 0x0a) {
      body = body.subarray(0, body.length - 2);
    }

    const nameM = header.match(/name="([^"]*)"/i);
    if (!nameM) continue;
    const name = nameM[1];
    const isFile = /filename="/i.test(header);

    if (isFile) files[name] = body;
    else fields[name] = body.toString('utf8').trim();
  }

  return { fields, files };
}

const TUNNEL_LABEL = {
  off: 'tat', starting: 'dang khoi dong', up: 'da ket noi',
  retrying: 'dang thu lai', error: 'LOI',
};

/**
 * Chuan hoa serial: bo khoang trang, viet HOA.
 * "54 01 01 ..." va "5401 01..." va "5401...abc" deu ve mot dang.
 */
function normalizeSerial(s) {
  return String(s || '').toUpperCase().replace(/[\s:]+/g, '');
}

/**
 * Quyet dinh serial dung de ky, va kiem tra no CO THAT trong token.
 *
 * Thu tu uu tien:
 *   1. serial client gui trong request  (theo yeu cau: client truyen thiet bi)
 *   2. certificateSerial trong config    (mac dinh cua may chu)
 *
 * Neu cau hinh requireSerial = true va client khong gui -> tu choi.
 * Neu serial khong khop cert nao trong token -> tu choi (khong de plugin hoi lai).
 *
 * Tra ve { ok, serial, error }.
 */
async function signPdfNative(cfg, pdfBase64, opts) {
  let exePath = cfg.nativeSignerExePath;
  if (!exePath) {
    const packagedPath = path.join(BASE_DIR, 'bin', 'pdf-signer.exe');
    const devPath = path.join(__dirname, 'bin', 'pdf-signer.exe');
    exePath = fs.existsSync(packagedPath) ? packagedPath : devPath;
  }
  if (!fs.existsSync(exePath)) {
    throw new Error(`File executable ky so khong ton tai: ${exePath}`);
  }

  const tempDir = path.join(BASE_DIR, 'temp');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }

  const uniqueId = crypto.randomBytes(8).toString('hex');
  const inputPdfPath = path.join(tempDir, `in_${uniqueId}.pdf`);
  const outputPdfPath = path.join(tempDir, `out_${uniqueId}.pdf`);
  let imagePath = '';

  try {
    // 1. Ghi file PDF tam
    fs.writeFileSync(inputPdfPath, Buffer.from(pdfBase64, 'base64'));

    // 2. Lay image va ghi file anh tam
    const rawImage = opts.imageBase64 || cfg.signatureImageBase64 || null;
    if (rawImage) {
      const cleanImage = typeof rawImage === 'string'
        ? rawImage.replace(/^data:image\/[a-z]+;base64,/i, '')
        : null;
      if (cleanImage) {
        imagePath = path.join(tempDir, `img_${uniqueId}.png`);
        fs.writeFileSync(imagePath, Buffer.from(cleanImage, 'base64'));
      }
    }

    // 3. Lay cert serial va PIN
    const serial = opts.certificateSerial || cfg.certificateSerial || '';
    if (!serial) {
      throw new Error('THIEU_SERIAL: request phai gui certificateSerial hoac cau hinh mac dinh');
    }

    // Lay PIN tu request, neu khong co thi dung defaultPin trong config
    const pin = opts.pin || cfg.defaultPin || '';

    // 4. Chuan bi tham so cho executable
    const args = [
      '--input', inputPdfPath,
      '--output', outputPdfPath,
      '--serial', serial,
    ];

    if (pin) {
      args.push('--pin', pin);
    }

    args.push('--page', String(opts.page ?? 1));
    args.push('--llx', String(opts.llx ?? 380));
    args.push('--lly', String(opts.lly ?? 40));
    args.push('--urx', String(opts.urx ?? 560));
    args.push('--ury', String(opts.ury ?? 110));

    if (opts.description) {
      args.push('--desc', opts.description);
    }

    if (imagePath) {
      args.push('--image', imagePath);
    }

    // 5. Thuc thi file .exe
    log('info', `Goi pdf-signer.exe de ky file. Serial: ${serial}, Pin: ${pin ? '***' : '(trong)'}`);
    
    const { execFile } = require('node:child_process');
    try {
      await new Promise((resolve, reject) => {
        execFile(exePath, args, { windowsHide: true, timeout: cfg.signTimeoutMs, killSignal: 'SIGKILL' }, (err, stdout, stderr) => {
          if (err) {
            log('error', `Loi khi thuc thi pdf-signer.exe:\nStdout: ${stdout}\nStderr: ${stderr}`);
            const errorMsg = stderr.trim() || stdout.trim() || err.message;
            
            // Neu bi kill do timeout, hoac gap loi driver cua thiet bi
            if (err.killed || err.signal === 'SIGKILL' || errorMsg.includes('NTE_') || errorMsg.includes('CryptographicException')) {
              log('warn', 'Phat hien loi ket noi thiet bi hoac bi treo (timeout). Tu dong kich hoat self-heal cho SCardSvr...');
              forceRestartSmartCardService();
            }
            
            reject(new Error(errorMsg));
          } else {
            resolve();
          }
        });
      });
    } catch (e) {
      throw e;
    }

    // 6. Doc file da ky va convert lai base64
    if (!fs.existsSync(outputPdfPath)) {
      throw new Error('Loi: pdf-signer.exe bao thanh cong nhung khong tim thay file dau ra.');
    }

    const signedBuf = fs.readFileSync(outputPdfPath);
    return signedBuf.toString('base64');

  } finally {
    // 7. Don dep file tam
    try { if (fs.existsSync(inputPdfPath)) fs.unlinkSync(inputPdfPath); } catch (_) {}
    try { if (fs.existsSync(outputPdfPath)) fs.unlinkSync(outputPdfPath); } catch (_) {}
    try { if (imagePath && fs.existsSync(imagePath)) fs.unlinkSync(imagePath); } catch (_) {}
  }
}

function extractEmbeddedSigner() {
  if (!process.pkg) return;

  const embeddedExePath = path.join(__dirname, 'bin', 'pdf-signer.exe');
  const targetBinDir = path.join(BASE_DIR, 'bin');
  const targetExePath = path.join(targetBinDir, 'pdf-signer.exe');

  try {
    if (!fs.existsSync(embeddedExePath)) {
      return;
    }

    if (!fs.existsSync(targetBinDir)) {
      fs.mkdirSync(targetBinDir, { recursive: true });
    }

    let needsExtract = true;
    if (fs.existsSync(targetExePath)) {
      const embeddedStat = fs.statSync(embeddedExePath);
      const targetStat = fs.statSync(targetExePath);
      // Neu target exe tren dia co thoi gian ghi moi hon hoac bang thoi gian compile cua file nhung, va size giong nhau -> bo qua
      if (targetStat.mtimeMs >= embeddedStat.mtimeMs && targetStat.size === embeddedStat.size) {
        needsExtract = false;
      }
    }

    if (needsExtract) {
      log('info', `Dang tu dong giai nen pdf-signer.exe sang: ${targetExePath}`);
      const data = fs.readFileSync(embeddedExePath);
      fs.writeFileSync(targetExePath, data);
    }
  } catch (e) {
    log('error', `Loi khi tu dong giai nen pdf-signer.exe: ${e.message}`);
  }
}

function checkCertPresent(serial) {
  if (process.platform !== 'win32') return false;
  if (!serial) return false;
  const { execSync } = require('node:child_process');
  try {
    const clean = serial.replace(/[\s:]/g, '');
    execSync(`certutil -silent -store -user MY "${clean}"`, { stdio: 'ignore', windowsHide: true });
    return true;
  } catch (_) {
    return false;
  }
}

function forceRestartSmartCardService() {
  if (process.platform !== 'win32') return false;
  const { execSync } = require('node:child_process');
  try {
    log('info', 'Dang tu dong khoi dong lai dich vu Smart Card (SCardSvr)...');
    try {
      execSync('net stop SCardSvr', { stdio: 'ignore', windowsHide: true });
    } catch (e) {
      log('warn', `Khong the stop SCardSvr: ${e.message}`);
    }
    execSync('net start SCardSvr', { stdio: 'ignore', windowsHide: true });
    log('info', 'Khoi dong lai dich vu SCardSvr thanh cong.');
    return true;
  } catch (e) {
    log('error', `Loi khi khoi dong lai SCardSvr: ${e.message}`);
    return false;
  }
}

async function resolveSerial(cfg, plugin, requestedSerial) {
  const req = normalizeSerial(requestedSerial);
  const def = normalizeSerial(cfg.certificateSerial);

  if (cfg.requireSerial && !req) {
    return { ok: false, error: 'THIEU_SERIAL: request phai gui certificateSerial' };
  }

  const chosen = req || def;
  if (!chosen) {
    // Khong ai chi dinh -> de plugin tu quyet (co the hien hop thoai).
    return { ok: true, serial: null };
  }

  // BAT BUOC lam moi danh sach serial (force=true) — KHONG dung cache.
  // Ly do: neu USB da bi rut/thay, cache cu se cho ky bang serial khong con
  // trong may. Phai hoi token THAT tai thoi diem ky.
  let serials;
  try {
    serials = await plugin.listSerials(true);
  } catch (e) {
    return { ok: false, error: `KHONG_DOC_DUOC_CERT: ${e.message}` };
  }

  // Token khong co cert nao (rut roi, hoac chua cam) -> tu choi
  if (!serials.length) {
    return { ok: false, error: 'KHONG_CO_CERT: token chua cam hoac khong doc duoc cert' };
  }

  if (!serials.includes(chosen)) {
    return {
      ok: false,
      error: `SERIAL_KHONG_KHOP: token hien tai khong co cert ${chosen}. ` +
             `Serial co trong token dang cam: ${serials.join(', ')}`,
    };
  }

  return { ok: true, serial: chosen };
}

function makeHandler(cfg, plugin, queue, tunnel, lock, mutex) {
  return async (req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    const origin = req.headers.origin;

    /* ---- CORS + Private Network Access ---- */
    if (origin && cfg.allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Private-Network', 'true');
    }
    if (req.method === 'OPTIONS') {
      if (!origin || !cfg.allowedOrigins.includes(origin)) {
        return json(res, 403, { error: 'origin khong duoc phep' });
      }
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'content-type,authorization');
      res.setHeader('Access-Control-Max-Age', '86400');
      res.writeHead(204);
      return res.end();
    }

    try {
      /* ---- Trang trang thai cho nguoi van hanh may chu ---- */
      if (req.method === 'GET' && p === '/') {
        const s = queue.stats;
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(`<!doctype html><meta charset="utf-8"><title>Signing Gateway</title>
<style>body{font:15px/1.8 system-ui;margin:40px;max-width:560px;color:#1e1e1c}
h2{font-weight:500}table{border-collapse:collapse;width:100%}
td{padding:7px 4px;border-bottom:1px solid #eee}td:first-child{color:#777;width:45%}</style>
<h2>Signing Gateway</h2><table>
<tr><td>Plugin</td><td><b>${plugin.connected ? `da ket noi (port ${plugin.port})` : 'MAT KET NOI'}</b></td></tr>
<tr><td>Phien ban plugin</td><td><b>${plugin.version || '—'}</b></td></tr>
<tr><td>Cloudflare Tunnel</td><td><b>${TUNNEL_LABEL[tunnel.state]}${tunnel.hostname ? ' — ' + tunnel.hostname : ''}</b></td></tr>
<tr><td>Hang doi</td><td><b>${queue.depth}</b></td></tr>
<tr><td>Da ky</td><td><b>${s.done}</b></td></tr>
<tr><td>That bai</td><td><b>${s.failed}</b></td></tr>
<tr><td>Lan ky gan nhat</td><td><b>${s.lastSignAt ? new Date(s.lastSignAt).toLocaleString('vi-VN') + ` (${s.lastMs}ms)` : 'chua co'}</b></td></tr>
</table><script>setTimeout(()=>location.reload(),5000)</script>`);
      }

      /* ---- Health: khong can token, de HIS kiem tra truoc khi hien nut Ky ---- */
      if (req.method === 'GET' && p === '/v2/health') {
        let token = 'unknown';
        if (cfg.useNativeSigner) {
          const serial = cfg.certificateSerial;
          const present = checkCertPresent(serial);
          token = present ? 'present' : 'absent';
        } else {
          try {
            const t = await plugin.checkToken();
            token = t.present ? 'present' : 'absent';   // "0" = khong co token
          } catch (_) { token = 'unknown'; }
        }
        return json(res, 200, {
          ok: cfg.useNativeSigner ? (token === 'present') : (plugin.connected && token === 'present'),
          plugin: cfg.useNativeSigner ? 'connected' : (plugin.connected ? 'connected' : 'disconnected'),
          token,
          tunnel: tunnel.state,
          queueDepth: queue.depth,
        });
      }

      /* ---- Tu day tro di: bat buoc co token do backend HIS4 cap ---- */
      const auth = req.headers.authorization || '';

      let claim;
      if (cfg.devMode) {
        // CHE DO DEV: bo qua xac thuc token de test bang Postman/curl.
        claim = { sub: 'dev-user', name: 'Dev Mode' };
      } else {
        if (!auth.startsWith('Bearer ')) return json(res, 401, { error: 'thieu token' });
        // Chi lenh ky moi tieu thu jti. Doc trang thai/ket qua dung lai token duoc.
        const isSignAction = (req.method === 'POST' && p === '/v2/sign');
        try {
          claim = verifyHisToken(cfg, auth.slice(7), isSignAction);
        } catch (e) {
          audit(cfg, { type: 'auth.fail', reason: e.message, path: p });
          return json(res, 401, { error: e.message });
        }
      }

      // ===== KHOA DOC QUYEN =====

      // Chiem token de ky nhieu file. Client khac se bi 423 cho toi khi unlock/het han.
      if (req.method === 'POST' && p === '/v2/lock') {
        const r = lock.acquire(claim.sub, claim.name);
        if (!r.ok) {
          audit(cfg, { type: 'lock.denied', user: claim.sub, lockedBy: r.lockedBy });
          res.setHeader('Retry-After', Math.ceil(r.retryAfterMs / 1000));
          return json(res, 423, {
            error: 'TOKEN_DANG_BAN',
            lockedBy: r.lockedBy,
            retryAfterMs: r.retryAfterMs,
          });
        }
        audit(cfg, { type: 'lock.acquire', user: claim.sub });
        return json(res, 200, r.lock);
      }

      // Nha khoa som (khi da ky xong het file).
      if (req.method === 'POST' && p === '/v2/unlock') {
        const body = JSON.parse((await readBody(req, 4096)).toString() || '{}');
        const r = lock.release(body.lockToken);
        if (!r.ok) return json(res, 400, { error: r.error });
        audit(cfg, { type: 'lock.release', user: claim.sub, signCount: r.signCount });
        return json(res, 200, { ok: true, signCount: r.signCount ?? 0 });
      }

      // Xem token co dang bi khoa khong, ai giu, con bao lau.
      if (req.method === 'GET' && p === '/v2/lock-status') {
        return json(res, 200, lock.status());
      }

      // Buoc plugin doc lai USB token (khi cam vao ma khong tu nhan).
      if (req.method === 'POST' && p === '/v2/reload-token') {
        const r = await plugin.reloadToken();
        return json(res, 200, { tokenPresent: r.present, method: r.method });
      }

      if (req.method === 'GET' && p === '/v2/certificates') {
        return json(res, 200, { raw: await plugin.getCertInfo() });
      }

      // Liet ke serial cac cert trong token — de client biet nen gui serial nao.
      if (req.method === 'GET' && p === '/v2/serials') {
        try {
          return json(res, 200, { serials: await plugin.listSerials() });
        } catch (e) {
          return json(res, 503, { error: e.message });
        }
      }

      // ENDPOINT TIEN LOI CHO POSTMAN/curl: nhan file truc tiep (multipart),
      // ky DONG BO, tra ve PDF luon (khong phai base64, khong phai poll).
      //   Postman: Body -> form-data -> key "file" (type File), chon PDF.
      //   Tuy chon them cac field text: page, llx, lly, urx, ury, description
      // Chi bat khi devMode = true (vi no dong bo, giu ket noi lau).
      if (req.method === 'POST' && p === '/v2/sign-file') {
        if (!cfg.devMode) return json(res, 403, { error: 'chi dung khi devMode=true' });

        try {
          const t = await plugin.checkToken();
          if (!t.present) return json(res, 503, { error: 'KHONG_CO_USB_TOKEN' });
        } catch (e) {
          return json(res, 503, { error: `KHONG_KIEM_TRA_DUOC_TOKEN: ${e.message}` });
        }

        const ct = req.headers['content-type'] || '';
        const m2 = ct.match(/boundary=(.+)$/);
        if (!m2) return json(res, 400, { error: 'can multipart/form-data' });

        const raw = await readBody(req, cfg.maxPdfBytes * 2);
        const parsed = parseMultipart(raw, m2[1]);
        const filePart = parsed.files.file;
        if (!filePart) return json(res, 400, { error: 'thieu file (key phai la "file")' });
        if (filePart.subarray(0, 4).toString() !== '%PDF') return json(res, 400, { error: 'khong phai PDF' });

        const f = parsed.fields;
        const sr = await resolveSerial(cfg, plugin, f.certificateSerial || f.serial);
        if (!sr.ok) return json(res, 400, { error: sr.error });

        const opts = {
          page: Number(f.page) || 1,
          llx: f.llx !== undefined ? Number(f.llx) : undefined,
          lly: f.lly !== undefined ? Number(f.lly) : undefined,
          urx: f.urx !== undefined ? Number(f.urx) : undefined,
          ury: f.ury !== undefined ? Number(f.ury) : undefined,
          description: f.description || null,
        };
        if (sr.serial) opts.certificateSerial = sr.serial;

        log('info', `sign-file: ${filePart.length} byte, trang ${opts.page}`);
        let signedB64;
        try {
          if (cfg.useNativeSigner) {
            signedB64 = await mutex.run(() => signPdfNative(cfg, filePart.toString('base64'), opts));
          } else {
            signedB64 = await mutex.run(() => plugin.signPdf(filePart.toString('base64'), opts));
          }
        } catch (e) {
          return json(res, 500, { error: e.message });
        }

        const signed = Buffer.from(signedB64, 'base64');
        audit(cfg, { type: 'sign.ok', via: 'sign-file', bytes: filePart.length,
                     sha256: crypto.createHash('sha256').update(filePart).digest('hex') });

        // Tra PDF THANG. Postman bam "Save Response" la co file da ky.
        res.writeHead(200, {
          'content-type': 'application/pdf',
          'content-disposition': 'attachment; filename="signed.pdf"',
        });
        return res.end(signed);
      }

      // ===== KY HOP NHAT: PDF hoac XML, phan biet bang docType =====
      if (req.method === 'POST' && p === '/v2/sign') {
        try {
          if (!cfg.useNativeSigner && !plugin.connected) {
            await plugin.ensureReady();
          }
        } catch (e) {
          return json(res, 503, { error: `PLUGIN_KHONG_SAN_SANG: ${e.message}` });
        }

        const body = JSON.parse((await readBody(req, cfg.maxPdfBytes * 2)).toString());

        // docType: "pdf" (mac dinh) | "xml"
        const docType = String(body.docType || 'pdf').toLowerCase();
        if (docType !== 'pdf' && docType !== 'xml') {
          return json(res, 400, { error: 'docType phai la "pdf" hoac "xml"' });
        }

        // Khoa doc quyen (neu dang khoa hoac cau hinh bat buoc)
        if (lock.active || cfg.lockRequired) {
          const v = lock.verify(body.lockToken);
          if (!v.ok) {
            const st = lock.status();
            audit(cfg, { type: 'sign.denied', user: claim.sub, reason: v.error });
            return json(res, 423, { error: 'TOKEN_DANG_BAN', detail: v.error,
                                    lockedBy: st.owner || null, retryAfterMs: st.expiresInMs || 0 });
          }
        }

        // Tham so ky trong "signature" (dung chung PDF/XML). Nhan ca "options" (cu).
        const sig = body.signature || body.options || {};
        const reqSerial = normalizeSerial(sig.certificateSerial || body.certificateSerial)
                          || normalizeSerial(cfg.certificateSerial);

        if (cfg.requireSerial && !reqSerial) {
          return json(res, 400, { error: 'THIEU_SERIAL: request phai gui certificateSerial' });
        }

        // ---- Nhanh PDF ----
        if (docType === 'pdf') {
          if (!body.document) return json(res, 400, { error: 'thieu truong document (PDF base64)' });
          const pdf = Buffer.from(body.document, 'base64');
          if (pdf.length > cfg.maxPdfBytes) return json(res, 413, { error: 'PDF qua lon' });
          if (pdf.subarray(0, 4).toString() !== '%PDF') return json(res, 400, { error: 'khong phai PDF hop le' });

          const opts = { ...sig };
          if (reqSerial) opts.certificateSerial = reqSerial;

          const sha = crypto.createHash('sha256').update(pdf).digest('hex');
          lock.renew();
          audit(cfg, { type: 'sign.start', docType: 'pdf', user: claim.sub,
                       docId: String(body.docId || '').slice(0, 120), serial: reqSerial || null,
                       sha256: sha, bytes: pdf.length });

          let signedB64;
          try {
            if (cfg.useNativeSigner) {
              signedB64 = await mutex.run(() => signPdfNative(cfg, body.document, opts));
            } else {
              // NGUYEN TU: kiem token + verify serial (khong cache) + ky, trong 1 mutex.
              // Serial cua USB da rut se bi tu choi ngay tai buoc verify.
              signedB64 = await plugin.signPdfAtomic(body.document, opts, reqSerial || null);
            }
          } catch (e) {
            if (!cfg.useNativeSigner) plugin.invalidateTokenCache();  // co the token da bi rut -> xoa cache
            audit(cfg, { type: 'sign.fail', docType: 'pdf', user: claim.sub, sha256: sha, error: e.message });
            return json(res, /TOKEN/.test(e.message) ? 503 : 500, { error: e.message });
          }
          audit(cfg, { type: 'sign.ok', docType: 'pdf', user: claim.sub, sha256: sha });
          return json(res, 200, { docType: 'pdf', document: signedB64, sha256: sha });
        }

        // ---- Nhanh XML ----
        let xml = body.document || body.xml;
        if (!xml) return json(res, 400, { error: 'thieu truong document (noi dung XML)' });
        if (body.base64) xml = Buffer.from(xml, 'base64').toString('utf8');
        if (!xml.includes('<')) return json(res, 400, { error: 'khong phai XML hop le' });

        // Verify serial voi token THAT (force refresh) truoc khi ky
        const srXml = await resolveSerial(cfg, plugin, reqSerial);
        if (!srXml.ok) {
          audit(cfg, { type: 'sign.reject', docType: 'xml', reason: srXml.error, user: claim.sub });
          return json(res, 400, { error: srXml.error });
        }

        const opts = { ...sig };
        if (srXml.serial) opts.certificateSerial = srXml.serial;

        const sha = crypto.createHash('sha256').update(xml, 'utf8').digest('hex');
        lock.renew();
        audit(cfg, { type: 'sign.start', docType: 'xml', user: claim.sub,
                     docId: String(body.docId || '').slice(0, 120), serial: srXml.serial || null, sha256: sha });

        let signedB64;
        try {
          signedB64 = await plugin.signXml(xml, opts);
        } catch (e) {
          plugin.invalidateTokenCache();
          audit(cfg, { type: 'sign.fail', docType: 'xml', user: claim.sub, error: e.message });
          return json(res, /TOKEN/.test(e.message) ? 503 : 500, { error: e.message });
        }
        const signedXml = Buffer.from(signedB64, 'base64').toString('utf8');
        audit(cfg, { type: 'sign.ok', docType: 'xml', user: claim.sub, sha256: sha });
        return json(res, 200, { docType: 'xml', document: signedXml, documentBase64: signedB64, sha256: sha });
      }

      return json(res, 404, { error: 'khong tim thay' });

    } catch (e) {
      log('error', `${req.method} ${p} -> ${e.message}`);
      return json(res, e.message === 'FILE_QUA_LON' ? 413 : 500, { error: e.message });
    }
  };
}

/* ================================================================== */
/* Che do chan doan — chay trong chinh exe, khong can cai Node        */
/*                                                                    */
/*   signing-gateway.exe --probe                                      */
/*   signing-gateway.exe --diag <file.pdf>                            */
/* ================================================================== */

function rawConnect(ports, origin) {
  const tryOne = (port) => new Promise((res, rej) => {
    const opt = { rejectUnauthorized: false };
    if (origin) { opt.origin = origin; opt.headers = { Origin: origin }; }
    const ws = new WebSocket(`wss://localhost:${port}/plugin`, opt);
    const t = setTimeout(() => { ws.terminate(); rej(new Error('timeout')); }, 3000);
    ws.on('open', () => { clearTimeout(t); res({ ws, port }); });
    ws.on('error', (e) => { clearTimeout(t); rej(e); });
  });
  return (async () => {
    for (const p of ports) {
      try { return await tryOne(p); } catch (_) { /* thu port tiep */ }
    }
    return null;
  })();
}

function rawSend(ws, functionID, args, domain) {
  ws.send(JSON.stringify({
    functionID,
    funcCallback: 'cb_' + crypto.randomBytes(3).toString('hex'),
    args,
    domain: domain || 'localhost',
  }));
}

const sleep = (ms) => new Promise((s) => setTimeout(s, ms));

/**
 * signing-gateway.exe --license
 *
 * Do tim ly do license bi tu choi. Thu lan luot nhieu bien the domain,
 * in RESPONSE THO cua plugin cho tung cai. Khong doan, khong parse.
 */
/**
 * signing-gateway.exe --pintest <file.pdf>
 *
 * Do PIN cache song bao lau. Ky file lien tuc, cach nhau tang dan:
 *   ngay lap tuc, 30s, 1p, 2p, 5p, 10p, 15p, 30p...
 * Lan nao thoi gian ky VOT LEN (vi hien hop thoai PIN) = cache da het.
 *
 * NHIN MAN HINH: moi lan ky, ghi lai co hop thoai PIN bat len khong.
 */
async function runPinTest(pdfPath) {
  const cfg = loadConfig();
  if (!pdfPath || !fs.existsSync(pdfPath)) {
    console.log('\n  Cach dung: signing-gateway.exe --pintest <file.pdf>\n');
    process.exit(1);
  }

  const pdfB64 = fs.readFileSync(pdfPath).toString('base64');
  const plugin = new Plugin(cfg);

  console.log('\n  Do thoi gian PIN cache\n  ----------------------\n');
  if (!(await plugin.connect())) { console.log('  Khong ket noi plugin.\n'); process.exit(1); }
  await plugin.warmup();

  // Khoang cach giua cac lan ky (giay). Tang dan de tim nguong cache het han.
  const gaps = [0, 30, 60, 120, 300, 600, 900, 1800];

  const opts = { page: 1, description: 'Pin cache test' };
  if (cfg.certificateSerial) opts.certificateSerial = cfg.certificateSerial;

  const signOnce = async () => {
    const t0 = Date.now();
    await plugin.signPdf(pdfB64, opts);
    return Date.now() - t0;
  };

  let baseline = null;
  console.log('  Lan 1: dang ky (se hien hop thoai PIN)...');
  try {
    const ms = await signOnce();
    console.log(`         xong ${ms}ms  <- lan dau, co nhap PIN\n`);
  } catch (e) {
    console.log(`         LOI: ${e.message}\n`);
    process.exit(1);
  }

  for (let i = 0; i < gaps.length; i++) {
    const wait = gaps[i];
    if (wait > 0) {
      console.log(`  ... cho ${wait >= 60 ? wait/60 + ' phut' : wait + ' giay'} ...`);
      await new Promise((s) => setTimeout(s, wait * 1000));
    }

    process.stdout.write(`  Lan ${i + 2} (sau ${wait}s): `);
    let ms;
    try { ms = await signOnce(); }
    catch (e) { console.log(`LOI ${e.message}`); continue; }

    if (baseline === null) baseline = ms;

    // Neu lan nay lau hon gap 3 lan lan truoc on dinh -> co hop thoai PIN -> cache het
    const pinDialog = ms > baseline * 3 && ms > 4000;
    console.log(`${ms}ms  ${pinDialog ? '<<< CO HOP THOAI PIN? Cache co le da het sau ~' + wait + 's' : '(khong hoi PIN)'}`);

    if (pinDialog) {
      console.log(`\n  >>> PIN CACHE SONG KHOANG: ${gaps[i-1] || 0}s den ${wait}s`);
      console.log('      Nhap PIN de tiep tuc test, hoac Ctrl+C de dung.\n');
      baseline = null; // reset sau khi nhap lai PIN
    }
  }

  console.log('\n  ' + '='.repeat(66));
  console.log('  Xong. Khoang cach lon nhat ma KHONG hoi PIN = thoi gian cache toi thieu.');
  console.log('  NHO: con phai NHIN MAN HINH xac nhan lan nao thuc su hien hop thoai PIN.');
  console.log('  ' + '='.repeat(66) + '\n');
  process.exit(0);
}

async function runLicense() {
  const cfg = loadConfig();
  const lic = cfg.licenseKey || '';

  console.log('\n  Do license VNPT-CA Plugin\n  -------------------------\n');

  if (!lic) { console.log('  licenseKey trong config.json dang TRONG.\n'); process.exit(1); }

  console.log(`  Do dai license : ${lic.length} ky tu`);
  console.log(`  Co xuong dong  : ${/[\r\n]/.test(lic) ? 'CO - LOI' : 'khong'}`);
  try {
    const xml = Buffer.from(lic.slice(0, 400), 'base64').toString('utf8');
    const m = xml.match(/<DonViDuocCap>([^<]*)<\/DonViDuocCap>/);
    if (m) console.log(`  Cap cho domain : ${m[1]}`);
  } catch (_) {}

  // Plugin doc domain tu HEADER Origin cua WebSocket handshake,
  // KHONG doc truong `domain` trong JSON. Moi Origin can mot ket noi rieng.
  const host = cfg.pluginDomain;
  const parts = host.split('.');
  const parent = parts.length > 2 ? parts.slice(1).join('.') : null;

  const origins = [`https://${host}`];
  if (parent) origins.push(`https://${parent}`);
  origins.push(`http://${host}`, null);   // null = khong gui Origin header (nhu truoc)

  console.log('\n  Thu tung Origin header (moi cai la mot ket noi moi):\n');

  let winner;

  for (const org of origins) {
    const label = org === null ? '(khong gui Origin)' : org;
    console.log(`  --- Origin: ${label}`);

    const c = await rawConnect(cfg.pluginPorts, org);
    if (!c) { console.log('      khong ket noi duoc\n'); continue; }

    const raw = (fnId, args) => new Promise((res) => {
      const t = setTimeout(() => { c.ws.off('message', on); res('(qua han)'); }, 15000);
      const on = (m) => { clearTimeout(t); c.ws.off('message', on); res(m.toString()); };
      c.ws.on('message', on);
      rawSend(c.ws, fnId, args, cfg.pluginDomain);
    });

    const r1 = await raw(FN.setLicenseKey, [lic]);
    console.log(`      setLicenseKey -> ${r1.slice(0, 150)}`);

    const r2 = await raw(FN.CheckToken, ['']);
    console.log(`      CheckToken    -> ${r2.slice(0, 150)}`);
    console.log('');

    // code 1 = thanh cong (KHONG phai 0). CheckToken co the tra chuoi tho "0".
    const licOk = /"code"\s*:\s*1\b/.test(r1);
    if (winner === undefined && licOk) winner = org;
    c.ws.close();
  }

  console.log('  ' + '='.repeat(68));
  if (winner !== undefined) {
    console.log(`  >>> ORIGIN DUNG: ${winner === null ? '(khong gui)' : winner}`);
    if (winner) console.log(`      Dat trong config.json:  "pluginOrigin": "${winner}"`);
    console.log('');
    console.log('  Luu y: plugin NHO license trong bo nho tien trinh. Sau khi nap thanh');
    console.log('  cong mot lan, cac ket noi sau deu chay - ke ca khi khong gui Origin.');
    console.log('  Nhung khi plugin khoi dong lai thi phai nap lai, va luc do Origin');
    console.log('  header LA BAT BUOC.\n');
  } else {
    console.log('  >>> KHONG ORIGIN NAO DUOC CHAP NHAN.');
    console.log('      License khong hop le voi plugin ban 1.0.2.4, hoac plugin');
    console.log('      can license khac. Gui output nay de xu ly.\n');
  }
  process.exit(0);
}

async function runProbe() {
  const cfg = loadConfig();
  console.log('\n  Do tim VNPT-CA Plugin\n  ---------------------\n');

  const c = await rawConnect(cfg.pluginPorts, cfg.pluginOrigin);
  if (!c) {
    console.log('  Khong ket noi duoc plugin tren cac port: ' + cfg.pluginPorts.join(', '));
    console.log('  Plugin da chay chua? (xem icon o khay he thong)\n');
    process.exit(1);
  }
  console.log(`  [OK] Ket noi tai port ${c.port}\n`);

  console.log(`  Domain gui cho plugin: ${cfg.pluginDomain}`);
  console.log(`  License key         : ${cfg.licenseKey ? '(da co)' : '(TRONG)'}\n`);

  const steps = [
    ['setLicenseKey',                6,  [cfg.licenseKey || '']],
    ['checkPlugin',                  7,  ['']],
    ['getVersion',                  11,  ['']],
    ['GetComputerInfo',             39,  ['']],
    ['CheckToken  (0 = KHONG co token)', 34, ['']],
    ['SetGetCertFromUsbToken(1)',   35,  ['1']],
    ['SetGetCertByPkcs11(1)',       36,  ['1']],
    ['SetShowCertListDialog(0)',    37,  ['0']],
    ['GetCertInfo',                  0,  ['1', '']],
    ['GetAllCertificates',          45,  ['']],
  ];

  for (const [name, id, args] of steps) {
    const got = await new Promise((res) => {
      const t = setTimeout(() => { c.ws.off('message', on); res('(qua han)'); }, 15000);
      const on = (raw) => {
        clearTimeout(t);
        c.ws.off('message', on);
        const s = raw.toString();
        const i = s.lastIndexOf('*');
        res(i === -1 ? s : s.slice(0, i));
      };
      c.ws.on('message', on);
      rawSend(c.ws, id, args, cfg.pluginDomain);
    });
    const shown = got.length > 200 ? got.slice(0, 200) + ` ... [${got.length} ky tu]` : got;
    console.log(`  ${name} (fn=${id})\n    ${shown}\n`);
  }

  console.log('  Quan sat MAN HINH: co hop thoai nao bat len khong?\n');
  c.ws.close();
  process.exit(0);
}

async function runDiag(pdfPath) {
  const cfg = loadConfig();

  if (!pdfPath || !fs.existsSync(pdfPath)) {
    console.log('\n  Cach dung: signing-gateway.exe --diag <duong-dan-file.pdf>\n');
    process.exit(1);
  }

  const pdf = fs.readFileSync(pdfPath);
  const pdfB64 = pdf.toString('base64');

  console.log('\n  Chan doan SignPDF\n  -----------------');
  console.log(`  File goc  : ${pdfPath}`);
  console.log(`  Kich thuoc: ${pdf.length} byte -> base64: ${pdfB64.length} ky tu\n`);

  const c = await rawConnect(cfg.pluginPorts, cfg.pluginOrigin);
  if (!c) { console.log('  Khong ket noi duoc plugin.\n'); process.exit(1); }
  console.log(`  [OK] Ket noi tai port ${c.port}\n`);

  console.log(`  Domain gui cho plugin: ${cfg.pluginDomain}`);
  console.log(`  License key         : ${cfg.licenseKey ? '(da co)' : '(TRONG)'}\n`);

  const D = cfg.pluginDomain;
  rawSend(c.ws, 6,  [cfg.licenseKey || ''], D); await sleep(600);  // setLicenseKey
  rawSend(c.ws, 35, ['1'], D); await sleep(400);
  rawSend(c.ws, 36, ['1'], D); await sleep(400);
  rawSend(c.ws, 37, ['0'], D); await sleep(600);

  const signer = {
    page: 1, llx: 380, lly: 40, urx: 560, ury: 110, SigTextSize: 8,
    Signer: null, SignerPosition: null, SigningTime: null,
    Description: 'Test chan doan', ImageBase64: null,
    OnlyDescription: false, ValidationOption: true, SigColorRGB: null,
    SetImageBackground: false, PagesArray: null,
    CertificateSerial: cfg.certificateSerial || null,
    TsaUrl: null, TsaUsername: null, TsaPassword: null,
    AdvancedCustom: false, SigType: 2,
    IsEncyptFile: false, EncryptPassword: null,
    SigVisible: true, SigSignerVisible: true,
    SigEmailVisible: false, SigPositionVisible: false, SigSigningTimeVisible: true,
  };

  const msgs = [];
  const t0 = Date.now();

  c.ws.on('message', (raw) => {
    const s = raw.toString();
    msgs.push(s);
    console.log(`  --- MESSAGE #${msgs.length}  (+${Date.now() - t0}ms)  do dai: ${s.length}`);
    console.log(`      100 ky tu DAU : ${JSON.stringify(s.slice(0, 100))}`);
    console.log(`      60 ky tu CUOI : ${JSON.stringify(s.slice(-60))}\n`);
  });

  console.log('  Dang goi SignPDF (fn=2). Nhap PIN neu co hop thoai...\n');
  msgs.length = 0;   // bo qua cac response cua buoc chuan bi o tren
  rawSend(c.ws, 2, [pdfB64, JSON.stringify(signer)], D);

  await sleep(90000);

  console.log('  ' + '='.repeat(68));
  console.log(`  Nhan duoc ${msgs.length} message.\n`);

  if (msgs.length === 0) {
    console.log('  Plugin khong tra ve gi. Co the dang cho PIN, hoac loi.\n');
    process.exit(1);
  }
  if (msgs.length > 1) {
    console.log('  >>> PLUGIN GUI NHIEU MESSAGE.');
    console.log('      server.js dang lay message DAU TIEN roi ngung nghe -> PDF bi cat.\n');
  }

  const main = msgs.reduce((a, b) => (b.length > a.length ? b : a));
  const star = main.lastIndexOf('*');
  const payload = star === -1 ? main : main.slice(0, star);
  const trimmed = payload.trim();

  console.log(`  Message dai nhat: ${main.length} ky tu`);
  console.log(`  Payload         : ${payload.length} ky tu`);
  console.log(`  So dau '*'      : ${(main.match(/\*/g) || []).length}\n`);

  let b64 = payload;

  if (trimmed.startsWith('{')) {
    let o;
    try { o = JSON.parse(trimmed); }
    catch (e) { console.log(`  Khong parse duoc JSON: ${e.message}\n`); process.exit(1); }

    console.log(`  code  : ${o.code}`);
    console.log(`  error : ${JSON.stringify(o.error || '')}`);
    console.log(`  data  : ${o.data ? o.data.length + ' ky tu' : '(trong)'}\n`);

    if (Number(o.code) !== 0) {
      if (/license/i.test(String(o.error))) {
        console.log('  >>> PLUGIN TU CHOI: CHUA CO LICENSE cho domain nay.');
        console.log(`      Domain da gui: ${cfg.pluginDomain}`);
        console.log('      Dat licenseKey trong config.json, hoac xin license tu VNPT.\n');
      } else {
        console.log(`  >>> PLUGIN BAO LOI: ${o.error}\n`);
      }
      process.exit(1);
    }
    b64 = o.data;
  }

  const buf = Buffer.from(b64, 'base64');
  const head = buf.subarray(0, 5).toString('latin1');
  const tail = buf.subarray(-20).toString('latin1');
  console.log(`  Giai ma base64 -> ${buf.length} byte`);
  console.log(`  5 byte dau     : ${JSON.stringify(head)}`);
  console.log(`  20 byte cuoi   : ${JSON.stringify(tail)}\n`);

  if (head.startsWith('%PDF')) {
    const out = path.join(BASE_DIR, 'diag-signed.pdf');
    fs.writeFileSync(out, buf);
    console.log(`  >>> DUNG LA PDF. Da ghi ra: ${out}`);
    if (!tail.includes('%%EOF')) {
      console.log('  >>> NHUNG THIEU %%EOF -> FILE BI CAT. Plugin gui nhieu message.');
    } else {
      console.log('  >>> File hoan chinh. Mo bang Adobe Reader de kiem tra chu ky.');
    }
  } else {
    console.log('  >>> KHONG PHAI PDF. Gui toan bo output nay de xu ly tiep.');
  }
  console.log('');
  process.exit(0);
}

/* ================================================================== */
/* Main                                                               */
/* ================================================================== */

async function main() {
  const arg = process.argv[2];
  if (arg === '--probe')   return runProbe();
  if (arg === '--license') return runLicense();
  if (arg === '--telegram-test') {
    const cfg = loadConfig();
    Telegram.init(cfg);
    if (!Telegram.enabled) {
      console.log('\n  Telegram CHUA bat hoac thieu botToken/chatId trong config.json\n');
      process.exit(1);
    }
    console.log('\n  Dang gui tin thu len Telegram...');
    const prefix = Telegram.tenantId ? `[${Telegram.tenantId}] ` : '';
    await Telegram._send(`${prefix}\u{2705} Signer Gateway: ket noi Telegram thanh cong.`);
    console.log('  Da gui. Kiem tra Telegram cua ban.\n');
    process.exit(0);
  }
  if (arg === '--install') {
    const { execSync } = require('node:child_process');
    const fs = require('node:fs');
    try {
      const exePath = process.execPath;
      const exeDir = path.dirname(exePath);
      const vbsPath = path.join(exeDir, 'run-hidden.vbs');
      
      const vbsContent = [
        'Set s = CreateObject("WScript.Shell")',
        `s.CurrentDirectory = "${BASE_DIR}"`,
        `s.Run """${exePath}""", 0, False`
      ].join('\r\n');
      
      fs.writeFileSync(vbsPath, vbsContent, 'utf8');
      
      execSync(`schtasks /create /tn "SigningGateway" /tr "wscript.exe \\"${vbsPath}\\"" /sc onlogon /rl highest /f`, { stdio: 'ignore', windowsHide: true });
      execSync(`schtasks /run /tn "SigningGateway"`, { stdio: 'ignore', windowsHide: true });
      process.exit(0);
    } catch (e) {
      process.exit(1);
    }
  }
  if (arg === '--uninstall') {
    const { execSync } = require('node:child_process');
    const fs = require('node:fs');
    try {
      try { execSync(`schtasks /end /tn "SigningGateway"`, { stdio: 'ignore', windowsHide: true }); } catch (_) {}
      try { execSync(`schtasks /delete /tn "SigningGateway" /f`, { stdio: 'ignore', windowsHide: true }); } catch (_) {}
      
      const exePath = process.execPath;
      const vbsPath = path.join(path.dirname(exePath), 'run-hidden.vbs');
      if (fs.existsSync(vbsPath)) {
        try { fs.unlinkSync(vbsPath); } catch (_) {}
      }
      process.exit(0);
    } catch (e) {
      process.exit(1);
    }
  }
  if (arg === '--diag')    return runDiag(process.argv[3]);
  if (arg === '--pintest') return runPinTest(process.argv[3]);
  if (arg === '--help' || arg === '-h') {
    console.log(`
  signing-gateway.exe                  chay gateway
  signing-gateway.exe --install        cai dat gateway chay ngam he thong (Windows Service)
  signing-gateway.exe --uninstall      go cai dat gateway chay ngam
  signing-gateway.exe --license        do license: thu nhieu domain, in response tho
  signing-gateway.exe --probe          do tim plugin, liet ke certificate
  signing-gateway.exe --diag <pdf>     chan doan SignPDF, xem plugin tra ve gi
`);
    process.exit(0);
  }

  console.log('\n  Signing Gateway — HIS4\n  ----------------------\n');
  log('info', `Thu muc du lieu: ${BASE_DIR}`);
  const cfg = loadConfig();
  extractEmbeddedSigner();

  if (!cfg.hisSharedSecret) {
    log('warn', 'CHUA CAU HINH hisSharedSecret. Moi request ky se bi tu choi.');
    log('warn', 'Sinh secret: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    log('warn', 'Dat CUNG MOT chuoi do vao config.json va vao backend HIS4.');
  }

  Telegram.init(cfg);

  const plugin = new Plugin(cfg);
  const queue = new Queue(plugin, cfg);
  const lock = new TokenLock(cfg);
  const mutex = new Mutex();
  const tunnel = new Tunnel(cfg);

  if (cfg.devMode) {
    console.log('  ============================================');
    console.log('   CHE DO DEV DANG BAT (devMode = true)');
    console.log('   API KHONG can token - ai goi cung ky duoc.');
    console.log('   PHAI TAT truoc khi len production.');
    console.log('  ============================================\n');
  }

  if (await plugin.connect()) {
    await plugin.warmup();
    try {
      const t = await plugin.checkToken();
      if (t.present) log('ok', `USB token: da phat hien (CheckToken = ${t.raw})`);
      else {
        log('warn', 'Chua co USB Token. Cam vao la ky duoc ngay, khong can khoi dong lai.');
      }
    } catch (e) {
      log('warn', `Khong goi duoc CheckToken: ${e.message}`);
    }
  } else {
    log('warn', 'Chua ket noi duoc VNPT-CA Plugin. Dang thu tu khoi dong plugin...');
    plugin.tryStartNativePlugin();
    // cho plugin khoi dong roi thu lai
    setTimeout(async () => {
      if (await plugin.connect()) {
        await plugin.warmup();
        log('ok', 'Da tu khoi dong va ket noi VNPT-CA Plugin.');
      } else {
        log('error', 'Van chua ket noi duoc plugin. Kiem tra plugin da cai chua.');
        log('error', `Da thu cac port: ${cfg.pluginPorts.join(', ')}`);
      }
    }, 4000);
  }

  // Theo doi lien tuc: tu ket noi lai plugin, tu bao khi rut/cam USB.
  // Khong can tat/bat lai tool khi thay doi phan cung.
  plugin.startMonitor(4000);
  setInterval(() => {
    if (!plugin.connected && !plugin.busy && !plugin._reconnecting) {
      plugin.connect().then((ok) => ok && plugin.warmup()).catch(() => {});
    }
  }, 15e3).unref();

  const server = http.createServer(makeHandler(cfg, plugin, queue, tunnel, lock, mutex));
  server.listen(cfg.port, cfg.host, () => {
    console.log('');
    log('ok', `Gateway chay tai http://${cfg.host}:${cfg.port}`);
    log('info', `Trang trang thai: http://127.0.0.1:${cfg.port}/`);
    console.log('');
    console.log('  Origin duoc phep: ' + cfg.allowedOrigins.join(', '));
    console.log('');
    tunnel.start();
    if (!cfg.tunnel.enabled) {
      log('info', 'Tunnel dang TAT. Bat trong config.json: tunnel.enabled = true');
    }
    console.log('  LUU Y: lan ky dau tien sau moi lan khoi dong may se bat');
    console.log('  hop thoai PIN. Phai co nguoi nhap PIN ngay tren may chu nay.');
    console.log('');
    audit(cfg, { type: 'gateway.start', port: cfg.port });
  });

  const stop = () => {
    audit(cfg, { type: 'gateway.stop' });
    tunnel.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

/* Bat MOI loi chua xu ly. Khong cho process chet im lang khi double-click. */
process.on('uncaughtException', (e) => {
  console.error('\n  LOI KHONG XU LY DUOC:\n');
  console.error('  ' + (e.stack || e.message).split('\n').join('\n  '));
  console.error('');
  pauseThenExit(1);
});

process.on('unhandledRejection', (e) => {
  console.error('\n  LOI KHONG XU LY DUOC (promise):\n');
  console.error('  ' + String(e && e.stack || e));
  console.error('');
  pauseThenExit(1);
});

main().catch((e) => {
  console.error('\n  LOI KHI KHOI DONG:\n');
  console.error('  ' + (e.stack || e.message).split('\n').join('\n  '));
  console.error('');
  pauseThenExit(1);
});
