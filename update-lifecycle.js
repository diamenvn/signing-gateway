'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

function isLoopbackAddress(addr) {
  if (!addr) return false;
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

function isLoopbackHost(host) {
  if (!host) return false;
  const hostname = host.split(':')[0].toLowerCase();
  return hostname === '127.0.0.1' || hostname === 'localhost';
}

function createUpdateLifecycle(cfg) {
  let isUpdating = false;
  let activeSigning = 0;

  return {
    enter() {
      if (isUpdating) return false;
      activeSigning++;
      return true;
    },

    leave() {
      if (activeSigning > 0) activeSigning--;
    },

    async prepare(req) {
      // Must be loopback remote address
      const remote = req.socket && req.socket.remoteAddress;
      if (!isLoopbackAddress(remote)) {
        return { status: 403, body: { error: 'Chi cho phep truy cap tu loopback' } };
      }

      // Must be loopback Host
      const host = req.headers.host;
      if (!isLoopbackHost(host)) {
        return { status: 403, body: { error: 'Host phai la loopback' } };
      }

      // Verify HMAC from hisSharedSecret
      const auth = req.headers.authorization || '';
      if (!auth.startsWith('Bearer ')) {
        return { status: 401, body: { error: 'Thieu token authorization' } };
      }

      const token = auth.slice(7);
      if (!cfg.hisSharedSecret) {
        return { status: 500, body: { error: 'hisSharedSecret chua duoc cau hinh' } };
      }

      try {
        const [body, sig] = token.split('.');
        if (!body || !sig) throw new Error('Token sai dinh dang');
        const want = crypto.createHmac('sha256', cfg.hisSharedSecret)
          .update(body).digest('base64url');
        const a = Buffer.from(sig);
        const b = Buffer.from(want);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
          throw new Error('Token sai chu ky');
        }
      } catch (err) {
        return { status: 401, body: { error: err.message } };
      }

      // Start update mode
      isUpdating = true;

      // Wait for any active signing jobs to complete (up to 10s)
      const start = Date.now();
      while (activeSigning > 0 && Date.now() - start < 10000) {
        await new Promise(r => setTimeout(r, 100));
      }

      if (activeSigning > 0) {
        return { status: 409, body: { error: 'Dang co tien trinh ky chua hoan tat' } };
      }

      return { status: 200, body: { ok: true, message: 'San sang cap nhat' } };
    }
  };
}

async function prepareUpdate(cfg) {
  if (!cfg.hisSharedSecret) {
    throw new Error('hisSharedSecret chua duoc cau hinh');
  }

  const payload = {
    sub: 'update-cli',
    exp: Math.floor(Date.now() / 1000) + 60,
    jti: crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'),
  };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', cfg.hisSharedSecret).update(body).digest('base64url');
  const token = `${body}.${sig}`;

  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: cfg.port || 6688,
      path: '/internal/update/prepare',
      method: 'POST',
      headers: {
        'Host': `127.0.0.1:${cfg.port || 6688}`,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      timeout: 15000,
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(data);
        } else {
          reject(new Error(`prepare failed with status ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    req.end();
  });
}

module.exports = {
  createUpdateLifecycle,
  prepareUpdate,
};
