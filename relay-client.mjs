// Relay client: keeps one outbound WebSocket to the Cloudflare relay and
// dispatches each forwarded task to the local Gatekeeper agent over HTTP.
// Env: RELAY_URL (wss://.../agent-connect), RELAY_TOKEN, AGENT_BASE (default http://127.0.0.1:8931)
import WebSocket from 'ws';
import { HttpsProxyAgent } from 'https-proxy-agent';

const RELAY_URL = process.env.RELAY_URL;
const RELAY_TOKEN = process.env.RELAY_TOKEN || '';
const AGENT_BASE = process.env.AGENT_BASE || 'http://127.0.0.1:8931';
if (!RELAY_URL) { console.error('RELAY_URL wajib diisi'); process.exit(1); }

const DROP_HEADERS = new Set(['host', 'content-length', 'connection', 'keep-alive', 'transfer-encoding']);
let backoff = 1000;
let ws = null;
let pingTimer = null;

function log(...a) { console.log(new Date().toISOString(), ...a); }

async function dispatch(task) {
  const headers = {};
  for (const [k, v] of Object.entries(task.headers || {})) {
    const lk = k.toLowerCase();
    if (DROP_HEADERS.has(lk) || lk.startsWith('cf-')) continue;
    headers[k] = v;
  }
  const init = { method: task.method, headers };
  if (task.method !== 'GET' && task.method !== 'HEAD') init.body = task.body || '';
  const res = await fetch(AGENT_BASE + (task.path || '/'), init);
  const body = await res.text();
  const outHeaders = {};
  res.headers.forEach((v, k) => { if (!DROP_HEADERS.has(k.toLowerCase())) outHeaders[k] = v; });
  return { type: 'result', id: task.id, status: res.status, headers: outHeaders, body };
}

function connect() {
  const opts = { headers: { 'x-relay-token': RELAY_TOKEN } };
  const proxy = process.env.https_proxy || process.env.HTTPS_PROXY;
  if (proxy && RELAY_URL.startsWith('wss:')) opts.agent = new HttpsProxyAgent(proxy);
  ws = new WebSocket(RELAY_URL, opts);
  ws.on('open', () => {
    log('relay: terhubung');
    backoff = 1000;
    pingTimer = setInterval(() => { try { ws.ping(); } catch {} }, 25000);
  });
  ws.on('message', async (data) => {
    let m;
    try { m = JSON.parse(data.toString()); } catch { return; }
    if (m.type !== 'task') return;
    try {
      const result = await dispatch(m);
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(result));
    } catch (e) {
      log('relay: dispatch gagal', e.message);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'result', id: m.id, status: 502, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'local agent unreachable' }) }));
      }
    }
  });
  const retry = () => {
    if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
    log(`relay: koneksi putus, coba lagi dalam ${Math.round(backoff / 1000)}s`);
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 30000);
  };
  ws.on('close', retry);
  ws.on('error', (e) => { log('relay: error', e.message); try { ws.close(); } catch {} });
}

connect();
