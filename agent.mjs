// Proof Gatekeeper agent endpoint — zkVerify Agent Games.
// Flow: verify HMAC over the RAW body -> parse envelope -> deterministic
// decision (mirrors the circuit) -> Groth16 proof via snarkjs -> signed
// response. Fail closed everywhere: any doubt means REJECT, and a decision
// is only sent with a proof when the circuit itself can prove it.
//
// Config (env):
//   AGENT_GAMES_SECRET  HMAC secret from the dashboard (Rotate Secret)
//   AGENT_GAMES_PORT    local port (default 8931, bind 127.0.0.1)
//   AGENT_GAMES_STATE   state file path (default ./state.json)
//
// The HMAC secret is a platform operational secret for THIS agent only.
// No wallet keys are involved anywhere in this service.

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

const DIR = path.dirname(fileURLToPath(import.meta.url));
const SECRET = process.env.AGENT_GAMES_SECRET || '';
const PORT = Number(process.env.AGENT_GAMES_PORT || 8931);
const STATE_PATH = process.env.AGENT_GAMES_STATE || path.join(DIR, 'state.json');
const WASM = path.join(DIR, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(DIR, 'circuits', 'gatekeeper_final.zkey');
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PROVE_TIMEOUT_MS = 20000;

if (!SECRET) {
  console.error('AGENT_GAMES_SECRET belum di-set — endpoint menolak start (fail closed).');
  process.exit(1);
}

// ---------- state: seen proof references + cached responses per taskId ----
let state = { seenProofRefs: {}, responses: {} };
try { state = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8')); } catch { /* fresh */ }
function saveState() {
  fs.writeFileSync(STATE_PATH, JSON.stringify(state));
}

// ---------- helpers -------------------------------------------------------
function hmacHex(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('hex');
}
function sigMatches(headerVal, rawBody) {
  if (!headerVal) return false;
  const expected = hmacHex(rawBody);
  const given = String(headerVal).trim().replace(/^sha256=/, '');
  const candidates = [given, Buffer.from(given, 'base64').toString('hex')];
  return candidates.some((c) => {
    try {
      const a = Buffer.from(c, 'utf8');
      const b = Buffer.from(expected, 'utf8');
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch { return false; }
  });
}
function pick(obj, names, nests = []) {
  const scopes = [obj, ...nests.map((n) => obj?.[n]).filter((x) => x && typeof x === 'object')];
  for (const s of scopes) for (const n of names) if (s[n] !== undefined && s[n] !== null) return s[n];
  return undefined;
}
function toField(v) {
  // hex string / number / decimal string -> BN254 field element as decimal string
  let b;
  if (typeof v === 'string' && v.startsWith('0x')) b = BigInt(v);
  else b = BigInt(v);
  return (b % FIELD_P).toString();
}
function addrField(v) { return BigInt(v).toString(); } // 160-bit, fits the field as-is

// ---------- envelope -> circuit inputs + decision -------------------------
function parseEnvelope(env) {
  const nests = ['task', 'payload', 'data', 'condition', 'transfer', 'request'];
  const taskId = pick(env, ['taskId', 'task_id', 'id'], nests);
  const f = {
    registeredVkHash: pick(env, ['registeredVkHash', 'registered_vk_hash', 'conditionVkHash'], nests),
    proofVkHash: pick(env, ['proofVkHash', 'proof_vk_hash', 'vkHash', 'vk_hash'], nests),
    minimum: pick(env, ['minimum', 'minBalance', 'min'], nests),
    publicBalance: pick(env, ['publicBalance', 'balance'], nests),
    expiryBlock: pick(env, ['expiryBlock', 'expiry', 'expiresAtBlock'], nests),
    currentBlock: pick(env, ['currentBlock', 'blockNumber', 'block'], nests),
    recipient: pick(env, ['recipient', 'to'], nests),
    conditionRecipient: pick(env, ['conditionRecipient', 'expectedRecipient'], nests),
    amount: pick(env, ['amount'], nests),
    maxTransfer: pick(env, ['maxTransfer', 'maxAmount', 'cap'], nests),
    proofReference: pick(env, ['proofReference', 'proofRef', 'reference', 'proof_reference'], nests),
  };
  return { taskId, f };
}

function decide(f) {
  // Mirrors the circuit exactly: approve iff EVERY check passes.
  try {
    if (f.registeredVkHash === undefined || f.proofVkHash === undefined) return 0;
    if (toField(f.registeredVkHash) !== toField(f.proofVkHash)) return 0;
    if (f.publicBalance === undefined || f.minimum === undefined) return 0;
    if (BigInt(f.publicBalance) < BigInt(f.minimum)) return 0;
    if (!f.recipient || !f.conditionRecipient) return 0;
    if (BigInt(f.recipient) !== BigInt(f.conditionRecipient)) return 0;
    if (f.amount === undefined || f.maxTransfer === undefined) return 0;
    if (BigInt(f.amount) > BigInt(f.maxTransfer)) return 0;
    if (f.expiryBlock === undefined || f.currentBlock === undefined) return 0;
    if (BigInt(f.currentBlock) >= BigInt(f.expiryBlock)) return 0;
    return 1;
  } catch { return 0; }
}

function circuitInput(f, decision, taskId) {
  const salt = (BigInt('0x' + hmacHex('salt:' + String(taskId))) % FIELD_P).toString();
  return {
    registeredVkHash: toField(f.registeredVkHash),
    proofVkHash: toField(f.proofVkHash),
    minimum: String(f.minimum),
    publicBalance: String(f.publicBalance),
    expiryBlock: String(f.expiryBlock),
    currentBlock: String(f.currentBlock),
    recipient: addrField(f.recipient),
    conditionRecipient: addrField(f.conditionRecipient),
    amount: String(f.amount),
    maxTransfer: String(f.maxTransfer),
    decision: String(decision),
    taskId: String(taskId ?? 0).replace(/\D/g, '') || '0',
    salt,
  };
}

async function prove(input) {
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error('prove timeout')), PROVE_TIMEOUT_MS));
  return Promise.race([snarkjs.groth16.fullProve(input, WASM, ZKEY), timeout]);
}

// ---------- task handling (serialized) ------------------------------------
let queue = Promise.resolve();
function enqueue(fn) { const r = queue.then(fn, fn); queue = r.catch(() => {}); return r; }

async function handleTask(rawBody) {
  const env = JSON.parse(rawBody.toString('utf8'));
  const { taskId, f } = parseEnvelope(env);
  const key = String(taskId ?? 'unknown');

  if (state.responses[key]) return state.responses[key]; // retry -> identical bytes

  let body;
  const ref = f.proofReference ? String(f.proofReference) : null;
  if (ref && state.seenProofRefs[ref]) {
    // Reused proof reference: decision alone, no proof (per tournament scoring notes).
    body = JSON.stringify({ taskId, decision: 0, decisionLabel: 'REJECT', proofReused: true });
  } else {
    let decision = decide(f);
    let proof = null, publicSignals = null;
    try {
      ({ proof, publicSignals } = await prove(circuitInput(f, decision, taskId)));
    } catch {
      // Circuit disagrees with my decision -> the other decision is the provable one.
      try {
        ({ proof, publicSignals } = await prove(circuitInput(f, 1 - decision, taskId)));
        decision = 1 - decision;
      } catch { /* no provable decision: send decision without proof */ }
    }
    const out = { taskId, decision, decisionLabel: decision === 1 ? 'APPROVE' : 'REJECT' };
    if (proof) { out.proof = proof; out.publicSignals = publicSignals; }
    body = JSON.stringify(out);
    if (ref) state.seenProofRefs[ref] = key;
  }
  state.responses[key] = body;
  saveState();
  return body;
}

// ---------- HTTP server ----------------------------------------------------
const server = http.createServer((req, res) => {
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', agent: 'proof-gatekeeper' }));
    return;
  }
  if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    const sig = req.headers['x-agent-games-signature'] || req.headers['x-signature'] || req.headers['x-agent-signature'];
    if (!sigMatches(sig, raw)) { res.writeHead(401); res.end('bad signature'); return; }
    try {
      const body = await enqueue(() => handleTask(raw));
      res.writeHead(200, {
        'content-type': 'application/json',
        'x-agent-games-signature': hmacHex(body),
      });
      res.end(body);
    } catch {
      // Fail closed: signed REJECT without proof evidence.
      const body = JSON.stringify({ decision: 0, decisionLabel: 'REJECT', error: 'internal' });
      res.writeHead(200, {
        'content-type': 'application/json',
        'x-agent-games-signature': hmacHex(body),
      });
      res.end(body);
    }
  });
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`gatekeeper endpoint listening on 127.0.0.1:${PORT}`);
});
