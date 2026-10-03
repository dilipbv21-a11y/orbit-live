// Orbit live relay + media store, on Cloudflare's free plan.
// - /live  : WebSocket that pushes new messages to everyone online
// - /hook  : Supabase calls this when data changes
// - /media : upload (POST) and view (GET) photos, videos, voice notes and files
const MAX_MEDIA = 10 * 1024 * 1024;           // 10 MB per file
const KEEP_MS = 30 * 24 * 60 * 60 * 1000;     // media auto-deletes after 30 days, like messages

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Name, X-Keep',
  'Access-Control-Max-Age': '86400',
};

// ---------- Web Push (RFC 8291 encryption + VAPID), built on WebCrypto ----------
const enc = new TextEncoder();
const b64u = (buf) => { let s = ''; for (const c of new Uint8Array(buf)) s += String.fromCharCode(c); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const ub64u = (str) => { let s = String(str).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function encryptPush(p256dh, authB64, text) {
  const uaPub = ub64u(p256dh), authSecret = ub64u(authB64);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, concat(enc.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(enc.encode(text), new Uint8Array([2]))));
  return concat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([asPub.length]), asPub, ct);
}
async function vapidHeader(endpoint, privKey, pubB64) {
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const p = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'mailto:login@orbitcampus.in' })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, enc.encode(h + '.' + p));
  return `vapid t=${h}.${p}.${b64u(sig)}, k=${pubB64}`;
}

async function verifyUser(env, token) {
  if (!token) return null;
  const r = await fetch(env.SUPABASE_URL + '/auth/v1/user', {
    headers: { Authorization: 'Bearer ' + token, apikey: env.SUPABASE_KEY },
  });
  if (!r.ok) return null;
  let user;
  try { user = await r.json(); } catch { return null; }
  const email = String((user && user.email) || '').toLowerCase();
  if (!user || !user.id || !email.endsWith('@ssb.scaler.com')) return null;
  return { id: user.id, email };
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const hub = env.HUB.get(env.HUB.idFromName('orbit'));
    const store = env.HUB.get(env.HUB.idFromName('media'));
    const pusher = env.HUB.get(env.HUB.idFromName('push'));

    if (url.pathname === '/hook' && req.method === 'POST') {
      if (!env.HOOK_SECRET || req.headers.get('x-orbit-secret') !== env.HOOK_SECRET) {
        return new Response('unauthorized', { status: 401 });
      }
      const text = await req.text();
      let ev = null;
      try { ev = JSON.parse(text); } catch {}
      if (ev && ev.push) ctx.waitUntil(pusher.fetch('https://hub/push-enqueue', { method: 'POST', body: JSON.stringify(ev.push) }));
      return hub.fetch('https://hub/broadcast', { method: 'POST', body: text });
    }

    // ---- notifications ----
    if (url.pathname === '/push/key' && req.method === 'GET') {
      const r = await pusher.fetch('https://hub/push-key');
      return new Response(await r.text(), { headers: { ...CORS, 'content-type': 'application/json' } });
    }
    if ((url.pathname === '/push/subscribe' || url.pathname === '/push/unsubscribe') && req.method === 'POST') {
      const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
      const user = await verifyUser(env, token);
      if (!user) return new Response('unauthorized', { status: 401, headers: CORS });
      const r = await pusher.fetch('https://hub/' + (url.pathname.endsWith('unsubscribe') ? 'push-unsub' : 'push-sub'), {
        method: 'POST', body: await req.text(), headers: { 'x-uid': user.id },
      });
      return new Response(await r.text(), { status: r.status, headers: CORS });
    }

    if (url.pathname === '/live') {
      if (req.headers.get('Upgrade') !== 'websocket') return new Response('expected websocket', { status: 426 });
      const user = await verifyUser(env, url.searchParams.get('token') || '');
      if (!user) return new Response('unauthorized', { status: 401 });
      const headers = new Headers(req.headers);
      headers.set('x-uid', user.id);
      headers.set('x-email', user.email);
      return hub.fetch(new Request('https://hub/connect', { headers }));
    }

    if (url.pathname === '/media' && req.method === 'POST') {
      const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
      const user = await verifyUser(env, token);
      if (!user) return new Response('unauthorized', { status: 401, headers: CORS });
      const len = Number(req.headers.get('Content-Length') || 0);
      if (len > MAX_MEDIA) return new Response('too big', { status: 413, headers: CORS });
      const r = await store.fetch('https://hub/media-put', {
        method: 'POST',
        body: req.body,
        headers: {
          'content-type': req.headers.get('Content-Type') || 'application/octet-stream',
          'x-name': req.headers.get('X-Name') || 'file',
          'x-uid': user.id,
          'x-keep': req.headers.get('X-Keep') === '1' ? '1' : '0',
        },
      });
      const out = new Response(r.body, r);
      Object.entries(CORS).forEach(([k, v]) => out.headers.set(k, v));
      if (r.ok) {
        const { id } = await out.clone().json();
        return new Response(JSON.stringify({ id, url: url.origin + '/media/' + id }), {
          headers: { ...CORS, 'content-type': 'application/json' },
        });
      }
      return out;
    }

    const m = url.pathname.match(/^\/media\/([a-f0-9]{32})$/);
    if (m && req.method === 'DELETE') {   // "delete for everyone" also removes the uploader's file
      const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
      const user = await verifyUser(env, token);
      if (!user) return new Response('unauthorized', { status: 401, headers: CORS });
      const r = await store.fetch('https://hub/media-del/' + m[1], { method: 'POST', headers: { 'x-uid': user.id } });
      return new Response(await r.text(), { status: r.status, headers: CORS });
    }
    if (m && req.method === 'GET') {
      const r = await store.fetch('https://hub/media-get/' + m[1], { headers: { range: req.headers.get('range') || '' } });
      const out = new Response(r.body, r);
      out.headers.set('Access-Control-Allow-Origin', '*');
      return out;
    }

    return new Response('Orbit live relay is running');
  },
};

export class Hub {
  constructor(ctx) {
    this.ctx = ctx;
    this.sql = ctx.storage.sql;
    this.sql.exec(`create table if not exists media (
      id text, part integer, parts integer, mime text, name text, size integer, created integer, data blob,
      primary key (id, part))`);
    // columns added later: who uploaded it, and whether to keep it (stickers) past 30 days
    for (const col of ['uid text', 'keep integer default 0']) {
      try { this.sql.exec('alter table media add column ' + col); } catch {}
    }
    this.sql.exec('create table if not exists kv (k text primary key, v text)');
    this.sql.exec('create table if not exists subs (endpoint text primary key, uid text, p256dh text, auth text, prefs text, created integer)');
    this.sql.exec('create table if not exists pushq (id integer primary key autoincrement, endpoint text, payload text)');
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === '/connect') {
      const [client, server] = Object.values(new WebSocketPair());
      this.ctx.acceptWebSocket(server, ['u:' + req.headers.get('x-uid'), 'e:' + req.headers.get('x-email')]);
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === '/broadcast') {
      let ev;
      try { ev = await req.json(); } catch { return new Response('bad json', { status: 400 }); }
      this.route(ev);
      return new Response('ok');
    }
    if (url.pathname === '/media-put') return this.mediaPut(req);
    if (url.pathname === '/push-key') return new Response(JSON.stringify({ key: (await this.vapid()).pub }));
    if (url.pathname === '/push-sub') {
      let b; try { b = await req.json(); } catch { return new Response('bad json', { status: 400 }); }
      const s = b && b.sub, k = s && s.keys;
      if (!s || typeof s.endpoint !== 'string' || !/^https:\/\//.test(s.endpoint) || !k || !k.p256dh || !k.auth) return new Response('bad subscription', { status: 400 });
      const prefs = JSON.stringify({ dm: b.prefs?.dm !== false, group: b.prefs?.group !== false, bigbang: b.prefs?.bigbang === true });
      this.sql.exec('insert or replace into subs (endpoint, uid, p256dh, auth, prefs, created) values (?, ?, ?, ?, ?, ?)',
        s.endpoint, req.headers.get('x-uid'), k.p256dh, k.auth, prefs, Date.now());
      return new Response('ok');
    }
    if (url.pathname === '/push-unsub') {
      let b; try { b = await req.json(); } catch { b = {}; }
      this.sql.exec('delete from subs where endpoint = ? and uid = ?', String(b.endpoint || ''), req.headers.get('x-uid'));
      return new Response('ok');
    }
    if (url.pathname === '/push-enqueue') {
      let p; try { p = await req.json(); } catch { return new Response('bad json', { status: 400 }); }
      const rows = this.sql.exec('select endpoint, uid, prefs from subs').toArray();
      const to = Array.isArray(p.to) ? new Set(p.to) : null;
      const payload = JSON.stringify({ title: p.title, body: p.body, cid: p.cid });
      let n = 0;
      for (const r of rows) {
        if (r.uid === p.sender) continue;
        if (to && !to.has(r.uid)) continue;
        let pr = {}; try { pr = JSON.parse(r.prefs || '{}'); } catch {}
        if (p.scope === 'bigbang' ? pr.bigbang !== true : p.scope === 'dm' ? pr.dm === false : pr.group === false) continue;
        this.sql.exec('insert into pushq (endpoint, payload) values (?, ?)', r.endpoint, payload);
        n++;
      }
      if (n) await this.ctx.storage.setAlarm(Date.now() + 50);
      return new Response('queued ' + n);
    }
    if (url.pathname.startsWith('/media-del/')) {
      const id = url.pathname.slice(11), uid = req.headers.get('x-uid') || '-';
      const n = this.sql.exec('select count(*) as n from media where id = ? and uid = ?', id, uid).one().n;
      if (!n) return new Response('not yours', { status: 403 });
      this.sql.exec('delete from media where id = ? and uid = ?', id, uid);
      return new Response('deleted');
    }
    if (url.pathname.startsWith('/media-get/')) return this.mediaGet(url.pathname.slice(11), req.headers.get('range'));
    return new Response('not found', { status: 404 });
  }

  // ---------- media (stored in this object's free SQLite storage, split into 1.5 MB parts) ----------
  async mediaPut(req) {
    const buf = new Uint8Array(await req.arrayBuffer());
    if (!buf.length) return new Response('empty', { status: 400 });
    if (buf.length > MAX_MEDIA) return new Response('too big', { status: 413 });
    const id = crypto.randomUUID().replace(/-/g, '');
    const CH = 1536 * 1024, parts = Math.ceil(buf.length / CH), now = Date.now();
    let mime = (req.headers.get('content-type') || 'application/octet-stream').split(';')[0].trim().toLowerCase();
    if (!/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(mime)) mime = 'application/octet-stream';
    const uid = req.headers.get('x-uid') || null, keep = req.headers.get('x-keep') === '1' ? 1 : 0;
    let name = 'file';
    try { name = decodeURIComponent(req.headers.get('x-name') || 'file').slice(0, 120); } catch {}
    for (let i = 0; i < parts; i++) {
      this.sql.exec('insert into media (id, part, parts, mime, name, size, created, data, uid, keep) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        id, i, parts, mime, name, buf.length, now, buf.subarray(i * CH, (i + 1) * CH), uid, keep);
    }
    if (!(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(now + 24 * 3600 * 1000);
    return new Response(JSON.stringify({ id }), { headers: { 'content-type': 'application/json' } });
  }

  mediaGet(id, range) {
    const rows = this.sql.exec('select part, mime, name, size, data from media where id = ? order by part', id).toArray();
    if (!rows.length) return new Response('not found', { status: 404 });
    const { mime, name, size } = rows[0];
    const all = new Uint8Array(size);
    let off = 0;
    for (const r of rows) { const d = new Uint8Array(r.data); all.set(d, off); off += d.length; }
    // only images, video and audio are shown inline; everything else downloads (safer)
    const inline = /^(image\/(jpeg|png|gif|webp)|video\/|audio\/)/.test(mime);
    const headers = {
      'content-type': inline ? mime : 'application/octet-stream',
      'content-disposition': (inline ? 'inline' : 'attachment') + "; filename*=UTF-8''" + encodeURIComponent(name),
      'cache-control': 'public, max-age=31536000, immutable',
      'x-content-type-options': 'nosniff',
      'accept-ranges': 'bytes',
    };
    const m = /^bytes=(\d*)-(\d*)$/.exec(range || '');
    if (m && (m[1] || m[2])) {           // video/audio players on iPhone need byte ranges
      let start = m[1] ? Number(m[1]) : size - Number(m[2]);
      let end = m[1] && m[2] ? Number(m[2]) : size - 1;
      start = Math.max(0, start); end = Math.min(size - 1, end);
      if (start > end) return new Response(null, { status: 416, headers: { 'content-range': 'bytes */' + size } });
      return new Response(all.subarray(start, end + 1), {
        status: 206, headers: { ...headers, 'content-range': `bytes ${start}-${end}/${size}` },
      });
    }
    return new Response(all, { headers });
  }

  async vapid() {
    if (this._vapid) return this._vapid;
    const row = this.sql.exec("select v from kv where k = 'vapid'").toArray()[0];
    let data;
    if (row) data = JSON.parse(row.v);
    else {
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      data = { jwk: await crypto.subtle.exportKey('jwk', kp.privateKey), pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)) };
      this.sql.exec("insert into kv (k, v) values ('vapid', ?)", JSON.stringify(data));
    }
    const priv = await crypto.subtle.importKey('jwk', data.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    return (this._vapid = { priv, pub: data.pub });
  }

  async sendPushBatch() {
    const batch = this.sql.exec('select q.id, q.endpoint, q.payload, s.p256dh, s.auth from pushq q left join subs s on s.endpoint = q.endpoint order by q.id limit 40').toArray();
    if (!batch.length) return false;
    const keys = await this.vapid();
    await Promise.all(batch.map(async (r) => {
      this.sql.exec('delete from pushq where id = ?', r.id);
      if (!r.p256dh) return;
      try {
        const body = await encryptPush(r.p256dh, r.auth, r.payload);
        const res = await fetch(r.endpoint, {
          method: 'POST', body,
          headers: { Authorization: await vapidHeader(r.endpoint, keys.priv, keys.pub), 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high' },
        });
        if (res.status === 404 || res.status === 410) this.sql.exec('delete from subs where endpoint = ?', r.endpoint);
      } catch {}
    }));
    return this.sql.exec('select count(*) as n from pushq').one().n > 0;
  }

  async alarm() {
    const more = await this.sendPushBatch();
    this.sql.exec('delete from media where created < ? and coalesce(keep, 0) = 0', Date.now() - KEEP_MS);
    if (more) await this.ctx.storage.setAlarm(Date.now() + 200);
    else if (this.sql.exec('select count(*) as n from media').one().n) await this.ctx.storage.setAlarm(Date.now() + 24 * 3600 * 1000);
  }

  // ---------- live updates ----------
  send(sockets, payload) {
    const data = JSON.stringify(payload);
    for (const ws of sockets) { try { ws.send(data); } catch {} }
  }
  all() { return this.ctx.getWebSockets(); }
  to(tag) { return this.ctx.getWebSockets(tag); }

  // private chats (DMs) list exactly who may receive the event; everything else goes to everyone online
  targets(ev) {
    if (!Array.isArray(ev.to)) return this.all();
    const seen = new Set(), out = [];
    for (const id of ev.to) for (const ws of this.to('u:' + id)) if (!seen.has(ws)) { seen.add(ws); out.push(ws); }
    return out;
  }

  route(ev) {
    const { type, table } = ev;
    const row = ev.record || null, old = ev.old_record || null;
    const who = this.targets(ev);
    if (table === 'aegir_messages') {
      if (type === 'INSERT') this.send(this.all(), { t: 'aegir', row });
      else if (type === 'UPDATE' && row.kind === 'deleted') this.send(this.all(), { t: 'aegir_tomb', id: row.id });
      return;
    }
    if (table === 'messages') {
      if (type === 'INSERT') {
        if (row.group_id === null) this.send(who, { t: 'msg', row });
        else this.send(who, { t: 'gmsg', id: row.id, g: row.group_id });
      } else if (type === 'DELETE') this.send(who, { t: 'del', id: old.id });
      else if (type === 'UPDATE' && row.kind === 'deleted') this.send(who, { t: 'tomb', id: row.id, by: row.deleted_by });
      return;
    }
    if (table === 'groups' || table === 'group_members' || table === 'profiles') {
      this.send(who, { t: 'row', table, op: type, row, old });
      return;
    }
    if (table === 'pins') { this.send(who, { t: 'refetch', k: 'pins' }); return; }
    if (table === 'message_reactions') { this.send(who, { t: 'react', op: type, row, old }); return; }
    if (table === 'group_invites') {
      const r = row || old;
      this.send(this.to('e:' + String(r.email).toLowerCase()), { t: 'refetch', k: 'invites', mine: true });
      this.send(who, { t: 'refetch', k: 'invites', g: r.group_id });
      return;
    }
    if (table === 'join_requests') {
      const r = row || old;
      this.send(this.to('u:' + r.user_id), { t: 'refetch', k: 'requests', mine: true });
      this.send(who, { t: 'refetch', k: 'requests', g: r.group_id });
    }
  }

  webSocketMessage() {}
  webSocketClose(ws, code) { try { ws.close(code, 'closed'); } catch {} }
  webSocketError(ws) { try { ws.close(1011, 'error'); } catch {} }
}
