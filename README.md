# kxco-pq-sdk

[![npm](https://img.shields.io/npm/v/kxco-pq-sdk.svg)](https://www.npmjs.com/package/kxco-pq-sdk)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-sdk)](https://socket.dev/npm/package/kxco-pq-sdk)
[![node](https://img.shields.io/node/v/kxco-pq-sdk.svg)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Post-quantum identity SDK. Hierarchical ML-DSA-65 credentials — institution signs → user identity issued → user signs documents, transactions, and regulatory submissions. Chain is offline-verifiable with no central registry.

Built on [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) via the [audited @noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) library (Cure53, 2024).

---

## The identity model

```
Institution Identity (root, HSM-backed)
    └── User Identity (issued after KYC verification)
            └── Signed document / transaction / attestation
```

An **institution identity** is the root signing key for an organisation. A **user identity** is issued by the institution after KYC — it carries a signed credential binding the user's public key to their role and authority. Any counterparty can verify the full chain offline.

This follows the [GLEIF vLEI pattern](https://www.gleif.org/en/vlei/introducing-the-verifiable-lei-vlei): KXCO → Institution → User.

---

## Install

```sh
npm install kxco-pq-sdk
```

---

## Quick start

```js
import { KxcoIdentity, mlDsa } from 'kxco-pq-sdk'

// Institution: create identity once, store keypair securely
const institutionIdentity = await KxcoIdentity.create()

// User: generate keypair (e.g. in browser)
const userKeypair = mlDsa.ml_dsa65.keygen()

// Institution: issue credential after KYC approval
const credential = await institutionIdentity.issue(userKeypair.publicKey, {
  role:      'verified-user',
  authority: ['sign:transactions', 'access:chain'],
  metadata:  { sumsubApplicantId: 'applicant_42', country: 'GB' },
  expiresIn: '365d',
})

// User: activate identity using their keypair + received credential
const userIdentity = KxcoIdentity.fromCredential({
  keypair:    userKeypair,
  credential,
})

// User: sign a document, transaction, or regulatory submission
const envelope = await userIdentity.attest(
  { action: 'transfer', amount: 1000, currency: 'GBP' },
  { purpose: 'trade-confirmation', aud: 'counterparty-kid' },
)

// Verifier: check the full chain
const result = KxcoIdentity.verifyChain({
  envelope,
  credential,
  institutionPublicKey: await institutionIdentity.getPublicKey(),
})
// result.valid === true
// result.role, result.authority, result.metadata, result.issuedBy available
```

---

## API

### `KxcoIdentity.create(opts?)`

Creates an institution (root) identity.

```js
const identity = await KxcoIdentity.create({
  keypair,   // existing { publicKey, secretKey } — generated if omitted
  hsm,       // PqHsm or AuditedHsm — use for production institution keys
  label,     // required if hsm provided
  auditLog,  // optional AuditLog — logs 'identity:created'
})
```

### `institutionIdentity.issue(userPublicKey, opts)`

Issues a signed credential to a user. Institution identities only.

```js
const credential = await institutionIdentity.issue(userPublicKey, {
  role:      'compliance-officer',        // required
  authority: ['sign:regulatory-report'],  // default []
  metadata:  { sumsubApplicantId: '...' },
  expiresIn: '365d',                      // '365d', '24h', '30m', '60s'
  auditLog,                               // optional — logs 'credential:issued'
})
```

Returns a plain JSON object (serialise and deliver to user over HTTP).

### `KxcoIdentity.fromCredential({ keypair, credential })`

Reconstructs a user's signing identity from their keypair and a received credential.

```js
const userIdentity = KxcoIdentity.fromCredential({ keypair, credential })
```

### `identity.attest(data, opts?)`

Signs arbitrary data. Returns a self-contained envelope.

```js
const envelope = await identity.attest(data, {
  purpose: 'regulatory-report',
  aud:     'FCA',
  exp:     new Date(Date.now() + 86400000).toISOString(),
  context: { customField: 'value' },
})
```

`data` can be a string, `Uint8Array`, `Buffer`, or any JSON-serialisable object.

### `identity.verify(envelope)`

Verifies that this identity signed the envelope.

```js
const result = await identity.verify(envelope)
// { valid: true, payload: Uint8Array, iss, role, authority, iat, ... }
```

### `KxcoIdentity.verifyChain({ envelope, credential, institutionPublicKey })`

Verifies the full chain: institution signed the credential, user signed the envelope, iss matches, nothing expired. Offline — no network call.

```js
const result = KxcoIdentity.verifyChain({
  envelope,
  credential,
  institutionPublicKey,  // Uint8Array from institution's well-known URL
})
```

### Identity properties

| Property     | Institution | User          |
|--------------|-------------|---------------|
| `kid`        | 16-hex      | 16-hex        |
| `role`       | `null`      | e.g. `'staff'`|
| `authority`  | `null`      | `string[]`    |
| `parentKid`  | `null`      | institution kid |
| `credential` | `null`      | signed object |
| `metadata`   | `{}`        | `{}`          |

---

## Use cases

**Document signing**
```js
// Hash the PDF, sign the hash
const pdfBytes = fs.readFileSync('report.pdf')
const envelope = await complianceOfficer.attest(pdfBytes, {
  purpose: 'regulatory-report',
  aud:     'FCA',
})
// Deliver envelope alongside PDF. Verifier calls verifyChain().
```

**Trade confirmation**
```js
const envelope = await traderIdentity.attest(
  { orderId: 'TX-001', side: 'BUY', qty: 10000, price: 1.2345 },
  { purpose: 'trade-confirmation' },
)
```

**KYC attestation to a third party**
```js
// Third party calls:
const result = KxcoIdentity.verifyChain({
  envelope,
  credential,
  institutionPublicKey: fetchedFromWellKnownUrl,
})
if (result.valid && result.authority.includes('access:platform')) {
  // admit user
}
```

---

## Audited HSM signing

Use `AuditedHsm` to auto-log all HSM operations to a tamper-evident `AuditLog`.

```js
import { KxcoIdentity, AuditedHsm, AuditLog, PqHsm, FileBackend, mlDsa } from 'kxco-pq-sdk'

const logKeypair = mlDsa.ml_dsa65.keygen()
const log        = new AuditLog({ keypair: logKeypair })
const hsm        = new PqHsm(new FileBackend({ path: './institution.json', password: process.env.HSM_PASSWORD }))
const auditedHsm = new AuditedHsm(hsm, log)

const institution = await KxcoIdentity.create({ hsm: auditedHsm, label: 'institution-key' })
// Every keygen, sign, and deleteKey is written to log.
```

---

## Re-exports

`kxco-pq-sdk` re-exports everything you need from the ecosystem:

```js
import {
  // Identity
  KxcoIdentity, AuditedHsm,

  // HSM
  PqHsm, MemoryBackend, FileBackend, Pkcs11Backend,

  // Audit log
  AuditLog, FileAuditLog,

  // Raw attestation (kxco-pq-attest)
  attest, verify,

  // Primitives
  mlDsa, mlKem, fingerprint, kidEquals,
} from 'kxco-pq-sdk'
```

---

## Security

Cryptography: **ML-DSA-65** (NIST FIPS 204) via [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum), independently audited by Cure53 in 2024. No custom cryptography.

To report a vulnerability: [security@kxco.ai](mailto:security@kxco.ai) — do not open a public issue.

Advisory feed: [github.com/JackKXCO/kxco-pq-sdk/security/advisories](https://github.com/JackKXCO/kxco-pq-sdk/security/advisories)

---

## Funding

Supported by [Knightsbridge](https://knightsbridgelaw.com) · Shayne Heffernan · John Heffernan

- [kxco.ai](https://kxco.ai) — KXCO platform
- [Armature L1](https://chain.kxco.ai) — post-quantum blockchain

---

## License

Apache-2.0 © 2026 KXCO by Knightsbridge
