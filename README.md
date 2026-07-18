# kxco-pq-sdk

[![npm](https://img.shields.io/npm/v/kxco-pq-sdk.svg)](https://www.npmjs.com/package/kxco-pq-sdk)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-sdk)](https://socket.dev/npm/package/kxco-pq-sdk)
[![node](https://img.shields.io/node/v/kxco-pq-sdk.svg)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/KnightsbridgeAIQ/kxco-pq-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-pq-sdk/actions/workflows/ci.yml)

Institution identity layer for the KXCO stack — ML-DSA-65 hierarchical credentials, HSM-backed signing, and optional on-chain anchoring via Armature L1.

---

## When to use this

This package is for **institutions participating in the KXCO network**. Use it when you need to:

- Issue post-quantum credentials to KYC-verified users
- Sign attestations (documents, trades, regulatory submissions) as an institution or user
- Verify the full credential chain offline — no network call required
- Store institution keys in a hardware security module (PKCS#11, encrypted file, or memory)

If you are building an agent, relay, or encrypted channel, this is not the right package.

---

## Install

```sh
npm install kxco-pq-sdk
```

---

## Quick start

```js
import { KxcoIdentity, mlDsa } from 'kxco-pq-sdk'

// Institution: generate identity once, store keypair securely
const institution = await KxcoIdentity.create()

// User: generate keypair (e.g. in a browser or mobile app)
const userKeypair = mlDsa.ml_dsa65.keygen()

// Institution: issue a credential after KYC approval
const credential = await institution.issue(userKeypair.publicKey, {
  role:      'verified-user',
  authority: ['sign:transactions'],
  expiresIn: '365d',
})

// User: reconstruct a signing identity from keypair + credential
const userIdentity = KxcoIdentity.fromCredential({ keypair: userKeypair, credential })

// User: sign a document or transaction
const envelope = await userIdentity.attest(
  { action: 'transfer', amount: 1000, currency: 'GBP' },
  { purpose: 'trade-confirmation' },
)

// Verifier: check the full chain offline
const result = KxcoIdentity.verifyChain({
  envelope,
  credential,
  institutionPublicKey: await institution.getPublicKey(),
})
// result.valid, result.role, result.authority, result.issuedBy
```

---

## API

### `KxcoIdentity.create(opts?)`

Creates an institution (root) identity. Generates a new ML-DSA-65 keypair unless `keypair` or `hsm` is supplied.

| Option | Type | Description |
|---|---|---|
| `keypair` | `{ publicKey, secretKey }` | Existing keypair — generated if omitted |
| `hsm` | `PqHsm \| AuditedHsm` | HSM instance for production key storage |
| `label` | `string` | Required when `hsm` is provided |
| `auditLog` | `AuditLog` | Logs `identity:created` |
| `chain` | `KxcoChain` | Registers institution on Armature L1 |
| `metadataUrl` | `string` | Passed to chain registration |

### `institution.issue(userPublicKey, opts)`

Issues a signed credential to a user. Institution identities only.

| Option | Type | Description |
|---|---|---|
| `role` | `string` | Required. e.g. `'verified-user'`, `'compliance-officer'` |
| `authority` | `string[]` | Default `[]`. e.g. `['sign:transactions']` |
| `metadata` | `object` | Arbitrary key/value — e.g. Sumsub applicant ID |
| `expiresIn` | `string` | `'365d'`, `'24h'`, `'30m'`, `'60s'` |
| `auditLog` | `AuditLog` | Logs `credential:issued` |
| `chain` | `KxcoChain` | Anchors credential on Armature L1 |

Returns a plain JSON object. Serialise and deliver to the user over HTTP.

### `institution.revoke(userKid, opts?)`

Revokes a user credential. Institution identities only. Does nothing locally — side effects are the audit log entry and the on-chain revocation.

| Option | Type | Description |
|---|---|---|
| `reason` | `string` | Optional revocation reason |
| `auditLog` | `AuditLog` | Logs `credential:revoked` |
| `chain` | `KxcoChain` | Anchors revocation on Armature L1 |

### `KxcoIdentity.fromCredential({ keypair, credential })`

Reconstructs a user's signing identity from their keypair and a received credential. Returns a `KxcoIdentity` with `role`, `authority`, `parentKid`, and `metadata` populated.

### `identity.attest(data, opts?)`

Signs arbitrary data and returns a self-contained envelope. `data` can be a string, `Buffer`, `Uint8Array`, or any JSON-serialisable object.

| Option | Type | Description |
|---|---|---|
| `purpose` | `string` | e.g. `'regulatory-report'`, `'trade-confirmation'` |
| `aud` | `string` | Intended audience |
| `exp` | `string` | ISO 8601 expiry |
| `context` | `object` | Additional fields merged into the envelope |

### `identity.sign(message)`

Raw ML-DSA-65 signing. Returns a `Uint8Array` signature. Prefer `attest()` for structured envelopes.

### `identity.verify(envelope)`

Verifies that this identity signed the envelope. Returns `{ valid, payload, iss, role, authority, iat, ... }`.

### `KxcoIdentity.verifyChain({ envelope, credential, institutionPublicKey })`

Verifies the full chain offline: institution signed the credential, user signed the envelope, `iss` matches `userKid`, nothing expired.

```js
const result = KxcoIdentity.verifyChain({
  envelope,
  credential,
  institutionPublicKey,  // Uint8Array — fetch from institution's well-known URL
})
// result.valid, result.role, result.authority, result.metadata, result.issuedBy
```

### Identity properties

| Property | Institution | User |
|---|---|---|
| `kid` | 16-hex fingerprint | 16-hex fingerprint |
| `role` | `null` | e.g. `'verified-user'` |
| `authority` | `null` | `string[]` |
| `parentKid` | `null` | institution kid |
| `credential` | `null` | signed credential object |
| `metadata` | `{}` | `{}` |

---

## HSM backends

Import from `kxco-pq-sdk`. All implement the `PqHsm` interface.

| Backend | Use case |
|---|---|
| `MemoryBackend` | Testing only — keys are not persisted |
| `FileBackend` | Encrypted JSON file — suitable for server environments without hardware HSM |
| `Pkcs11Backend` | Hardware HSM via PKCS#11 — production institution keys |
| `AuditedHsm` | Wraps any backend and writes every keygen/sign/delete to an `AuditLog` |

```js
import { KxcoIdentity, AuditedHsm, PqHsm, FileBackend, AuditLog, mlDsa } from 'kxco-pq-sdk'

const logKeypair = mlDsa.ml_dsa65.keygen()
const log        = new AuditLog({ keypair: logKeypair })
const hsm        = new PqHsm(new FileBackend({ path: './institution.json', password: process.env.HSM_PASSWORD }))
const auditedHsm = new AuditedHsm(hsm, log)

const institution = await KxcoIdentity.create({ hsm: auditedHsm, label: 'institution-key' })
```

---

## Chain integration

Pass a `KxcoChain` instance from `kxco-pq-chain` to `create`, `issue`, or `revoke` to anchor operations on Armature L1. The `chain` parameter is optional on all three methods — omit it to run fully offline. When provided, `create` calls `chain.registerInstitution`, `issue` calls `chain.issueCredential`, and `revoke` calls `chain.revokeCredential`. Credential chain verification via `verifyChain` is always offline and requires no chain connection.

---

## What this does NOT do

- No relay client — use `kxco-pq-chain` directly for chain communication
- No agent identity — this package is for institutions and their issued users
- No encrypted channels — attestation envelopes are signed, not encrypted

---

## Part of the KXCO stack

| Package | Role |
|---|---|
| `kxco-post-quantum` | ML-DSA-65, ML-KEM primitives |
| `kxco-pq-attest` | Standalone attestation without identity |
| `kxco-pq-audit` | Tamper-evident audit log |
| `kxco-pq-hsm` | HSM backends |
| `kxco-pq-sdk` | This package — institution identity layer |
| `kxco-pq-chain` | Armature L1 chain client |

---

## Security

Cryptography: **ML-DSA-65** (NIST FIPS 204) via [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum), independently audited by Cure53 in 2024. No custom cryptography.

To report a vulnerability: [security@kxco.ai](mailto:security@kxco.ai) — do not open a public issue.

---

## Authors

Shayne Heffernan and John Heffernan — [kxco.ai](https://kxco.ai)

---

## Supported runtimes

Node.js **20.19+** (current LTS and later). ESM-only. New features and bug
fixes land on the latest major version; security fixes are backported one
major version.

## License

Apache-2.0 © 2026 KXCO by Knightsbridge
