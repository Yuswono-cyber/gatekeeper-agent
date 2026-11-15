# Gatekeeper Agent — zkVerify Agent Games, Proof Gatekeeper

An autonomous agent for the **Proof Gatekeeper** track of
[Agent Games by zkVerify](https://agentgames.zkverify.io) (Season 01).
For every signed task envelope it receives, the agent verifies the request
against the registered policy (VK hash, threshold, recipient, transfer cap,
expiry), decides APPROVE or REJECT deterministically, and answers with a
Groth16 (BN254) proof of the decision generated locally with snarkjs from the
official gatekeeper circuit. Responses are HMAC-signed; bad request
signatures are rejected with 401; replayed task IDs return the cached
byte-identical response; a reused proof reference is rejected without a proof.

## Layout

- `agent.mjs` — the endpoint. Verifies the HMAC signature over the raw body
  before parsing (fail closed), mirrors the circuit's decision rule, produces
  the proof in-process, signs every response. Binds localhost; all secrets
  come from environment variables only.
- `relay-client.mjs` — keeps one outbound WebSocket to the relay and
  dispatches forwarded tasks to the local endpoint.
- `relay/worker.mjs` — a Cloudflare Worker + Durable Object that exposes the
  public HTTPS endpoint and forwards each request through the agent's
  WebSocket, returning the agent's signed response verbatim. The relay never
  sees the game HMAC secret; it only moves bytes.
- `relay/wrangler.toml` — Worker/Durable Object configuration.
- `circuits/verification_key.json` — the official circuit verification key.

## Circuit artifacts

The proving artifacts are the platform's official files (downloaded from the
Agent Games circuit-info endpoint) and are not committed because they are
binary; verify any copy against these SHA-256 hashes:

- `gatekeeper.wasm` — `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`
- `gatekeeper_final.zkey` — `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`

Registered VK hash (gatekeeper): `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`

## Running

```sh
npm install
AGENT_GAMES_SECRET=<dashboard Rotate Secret value> node agent.mjs
RELAY_URL=wss://<your-relay>/agent-connect RELAY_TOKEN=<relay token> node relay-client.mjs
```

## License

MIT
