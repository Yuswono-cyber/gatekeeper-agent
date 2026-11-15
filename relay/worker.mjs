// zkVerify Agent Games — Proof Gatekeeper relay.
// The platform POSTs signed task envelopes to this Worker's public URL.
// A Durable Object holds one WebSocket out to the agent running on the
// operator's machine and forwards each request through it, returning the
// agent's signed response verbatim (status, headers, body).
// The relay never sees the HMAC game secret; it only moves bytes.

export class Relay {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.agent = null;
    this.pending = new Map();
    this.seq = 0;
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === '/agent-connect') {
      if (request.headers.get('Upgrade') !== 'websocket') {
        return new Response('expected websocket upgrade', { status: 426 });
      }
      if (!this.env.RELAY_TOKEN || request.headers.get('x-relay-token') !== this.env.RELAY_TOKEN) {
        return new Response('unauthorized', { status: 401 });
      }
      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      server.accept();
      if (this.agent) {
        try { this.agent.close(1000, 'replaced by newer agent connection'); } catch {}
      }
      this.agent = server;
      server.addEventListener('message', (ev) => this.onAgentMessage(ev.data));
      const drop = () => { if (this.agent === server) this.agent = null; };
      server.addEventListener('close', drop);
      server.addEventListener('error', drop);
      return new Response(null, { status: 101, webSocket: client });
    }

    if (url.pathname === '/relay-health') {
      return new Response(JSON.stringify({ relay: 'up', agentConnected: this.agent !== null }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }

    if (!this.agent) {
      return new Response(JSON.stringify({ error: 'agent offline' }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    }

    const id = `${Date.now()}-${++this.seq}`;
    const body = request.method === 'GET' || request.method === 'HEAD' ? '' : await request.text();
    const headers = {};
    for (const [k, v] of request.headers) headers[k] = v;

    const reply = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('agent timeout'));
      }, 55000);
      this.pending.set(id, { resolve, timer });
    });

    try {
      this.agent.send(JSON.stringify({
        type: 'task', id,
        method: request.method,
        path: url.pathname + url.search,
        headers, body,
      }));
    } catch {
      const p = this.pending.get(id);
      if (p) { clearTimeout(p.timer); this.pending.delete(id); }
      return new Response(JSON.stringify({ error: 'agent send failed' }), {
        status: 502,
        headers: { 'content-type': 'application/json' },
      });
    }

    try {
      const res = await reply;
      return new Response(res.body ?? '', {
        status: res.status || 200,
        headers: res.headers || { 'content-type': 'application/json' },
      });
    } catch {
      return new Response(JSON.stringify({ error: 'agent timeout' }), {
        status: 504,
        headers: { 'content-type': 'application/json' },
      });
    }
  }

  onAgentMessage(data) {
    let m;
    try { m = JSON.parse(data); } catch { return; }
    if (m.type === 'result' && this.pending.has(m.id)) {
      const p = this.pending.get(m.id);
      this.pending.delete(m.id);
      clearTimeout(p.timer);
      p.resolve(m);
    }
  }
}

export default {
  async fetch(request, env) {
    const stub = env.RELAY.get(env.RELAY.idFromName('gatekeeper'));
    return stub.fetch(request);
  },
};
