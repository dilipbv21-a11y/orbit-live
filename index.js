// Orbit live relay + media store, on Cloudflare's free plan.
// - /live  : WebSocket that pushes new messages to everyone online
// - /hook  : Supabase calls this when data changes
// - /media : upload (POST) and view (GET) photos, videos, voice notes and files
const MAX_MEDIA = 10 * 1024 * 1024;           // 10 MB per file
const KEEP_MS = 30 * 24 * 60 * 60 * 1000;     // media auto-deletes after 30 days, like messages

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Name',
  'Access-Control-Max-Age': '86400',
};

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
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const hub = env.HUB.get(env.HUB.idFromName('orbit'));
    const store = env.HUB.get(env.HUB.idFromName('media'));

    if (url.pathname === '/hook' && req.method === 'POST') {
      if (!env.HOOK_SECRET || req.headers.get('x-orbit-secret') !== env.HOOK_SECRET) {
        return new Response('unauthorized', { status: 401 });
      }
      return hub.fetch('https://hub/broadcast', { method: 'POST', body: await req.text() });
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
    let name = 'file';
    try { name = decodeURIComponent(req.headers.get('x-name') || 'file').slice(0, 120); } catch {}
    for (let i = 0; i < parts; i++) {
      this.sql.exec('insert into media (id, part, parts, mime, name, size, created, data) values (?, ?, ?, ?, ?, ?, ?, ?)',
        id, i, parts, mime, name, buf.length, now, buf.subarray(i * CH, (i + 1) * CH));
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

  async alarm() {
    this.sql.exec('delete from media where created < ?', Date.now() - KEEP_MS);
    await this.ctx.storage.setAlarm(Date.now() + 24 * 3600 * 1000);
  }

  // ---------- live updates ----------
  send(sockets, payload) {
    const data = JSON.stringify(payload);
    for (const ws of sockets) { try { ws.send(data); } catch {} }
  }
  all() { return this.ctx.getWebSockets(); }
  to(tag) { return this.ctx.getWebSockets(tag); }

  route(ev) {
    const { type, table } = ev;
    const row = ev.record || null, old = ev.old_record || null;
    if (table === 'messages') {
      if (type === 'INSERT') {
        if (row.group_id === null) this.send(this.all(), { t: 'msg', row });
        else this.send(this.all(), { t: 'gmsg', id: row.id, g: row.group_id });
      } else if (type === 'DELETE') this.send(this.all(), { t: 'del', id: old.id });
      return;
    }
    if (table === 'groups' || table === 'group_members' || table === 'profiles') {
      this.send(this.all(), { t: 'row', table, op: type, row, old });
      return;
    }
    if (table === 'pins') { this.send(this.all(), { t: 'refetch', k: 'pins' }); return; }
    if (table === 'group_invites') {
      const r = row || old;
      this.send(this.to('e:' + String(r.email).toLowerCase()), { t: 'refetch', k: 'invites', mine: true });
      this.send(this.all(), { t: 'refetch', k: 'invites', g: r.group_id });
      return;
    }
    if (table === 'join_requests') {
      const r = row || old;
      this.send(this.to('u:' + r.user_id), { t: 'refetch', k: 'requests', mine: true });
      this.send(this.all(), { t: 'refetch', k: 'requests', g: r.group_id });
    }
  }

  webSocketMessage() {}
  webSocketClose(ws, code) { try { ws.close(code, 'closed'); } catch {} }
  webSocketError(ws) { try { ws.close(1011, 'error'); } catch {} }
}
