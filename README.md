# Proof Gatekeeper Agent — zkVerify Agent Games, Season 01

A deterministic Proof Gatekeeper agent for the zkVerify Agent Games.
It receives signed task envelopes from the platform, verifies the HMAC-SHA256
signature over the raw body, evaluates the payment condition with plain
deterministic checks, and answers with a signed decision plus a real Groth16
proof generated locally with snarkjs against the official gatekeeper circuit.

## Decision rules (fail closed — anything uncertain is a REJECT)

- `proof_vk != registered_vk` → REJECT / VK_SUBSTITUTION
- `public_balance < minimum` → REJECT / THRESHOLD_MISMATCH
- `current_block > expiry_block` → REJECT / EXPIRED_CONDITION
- `recipient != condition_recipient` → REJECT / RECIPIENT_MISMATCH
- `amount > max_transfer` → REJECT / AMOUNT_OVERFLOW
- `proof_tx` seen in an earlier task → REJECT / PROOF_REUSED (no proof attached)
- otherwise → APPROVE / VALID_CONDITION, with a Groth16 proof whose public
  signals mirror the task inputs and the decision bit

The circuit itself refuses to prove a decision that contradicts the inputs,
so the encoded decision can never disagree with the checks. Responses are
signed with the same HMAC secret (`x-agent-games-signature` header).

## Layout

- `api/agent.mjs` — Vercel serverless entry (raw body, signed responses)
- `lib/gatekeeper.mjs` — HMAC verification, decision logic, proving, seen-set
- `lib/vkey.mjs` — verification key exported from the official zkey
- `circuits/` — official gatekeeper circuit artifacts (wasm + zkey)
- `server.mjs` — local development server with the same core

## Configuration

- `AGENT_GAMES_HMAC_SECRET` — the secret issued by the Agent Games dashboard
- `GK_SALT` — private salt input for the circuit
- Optional Upstash Redis REST env vars persist the proof-tx seen-set

Live endpoint: https://agent-gatekeeper-alfians.vercel.app/api/agent
