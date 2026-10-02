// Orbit live relay: one Cloudflare Durable Object holds every open connection and
// pushes new messages to all of them. Runs on Cloudflare's free plan.
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const hub = env.HUB.get(env.HUB.idFromName('orbit'));

    // Supabase calls this whenever a row changes (see the SQL triggers)
    if (url.pathname === '/hook' && req.method === 'POST') {
      if (!env.HOOK_SECRET || req.headers.get('x-orbit-secret') !== env.HOOK_SECRET) {
        return new Response('unauthorized', { status: 401 });
      }
      return hub.fetch('https://hub/broadcast', { method: 'POST', body: await req.text() });
    }

    // The app opens a WebSocket here, proving who it is with its Supabase login token
    if (url.pathname === '/live') {
      if (req.headers.get('Upgrade') !== 'websocket') return new Response('expected websocket', { status: 426 });
      const token = url.searchParams.get('token') || '';
      const r = await fetch(env.SUPABASE_URL + '/auth/v1/user', {
        headers: { Authorization: 'Bearer ' + token, apikey: env.SUPABASE_KEY },
      });
      if (!r.ok) return new Response('unauthorized', { status: 401 });
      let user;
      try { user = await r.json(); } catch { return new Response('auth check failed, retry', { status: 503 }); }
      if (!user || !user.id) return new Response('unauthorized', { status: 401 });
      const email = String(user.email || '').toLowerCase();
      if (!email.endsWith('@ssb.scaler.com')) return new Response('forbidden', { status: 403 });
      const headers = new Headers(req.headers);
      headers.set('x-uid', user.id);
      headers.set('x-email', email);
      return hub.fetch(new Request('https://hub/connect', { headers }));
    }

    return new Response('Orbit live relay is running');
  },
};

export class Hub {
  constructor(ctx) {
    this.ctx = ctx;
    // answer keep-alive pings without waking up (free)
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
    return new Response('not found', { status: 404 });
  }

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
        // Big Bang messages go to everyone; group messages only as a "new message" ping,
        // and members fetch the text themselves (the database checks they're allowed)
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
