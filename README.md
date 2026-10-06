# kxco-pq-sdk

**Post-quantum institution identity: issue ML-DSA-87 and ML-DSA-65 credentials to your users and verify the whole chain offline.**

[![npm](https://img.shields.io/npm/v/kxco-pq-sdk?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-sdk)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-sdk?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-sdk)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-sdk)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-sdk)](https://socket.dev/npm/package/kxco-pq-sdk)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-sdk.svg)](https://nodejs.org)
[![CI](https://github.com/KnightsbridgeAIQ/kxco-pq-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-pq-sdk/actions/workflows/ci.yml)

Institution identity layer for the KXCO stack: ML-DSA-87 and ML-DSA-65 hierarchical credentials, HSM-backed signing, and optional on-chain anchoring via Armature L1.

- **Credentials with a structure.** The institution key signs a credential for each user, carrying a role and an authority list, so the institution key is never handed round and a user can be revoked without re-keying the institution.
- **Offline verification.** `KxcoIdentity.verifyChain` checks the institution's signature on the credential, the user's signature on the envelope and every expiry, from those two objects and the institution's public key, with no network call.
- **Every field it returns is signed.** A credential's role, authority, metadata and expiry sit inside the institution's signature, and an envelope's issuer, role, authority, expiry, purpose and audience inside the user's, each behind a version prefix. `verify` and `verifyChain` return only signed fields: `context` fields travel in the envelope unsigned, and are never returned.
- **Keys on your HSM, every signature on the record.** PKCS#11 hardware, an encrypted file or memory behind one interface, and `AuditedHsm` writes each keygen, signature, decapsulation and deletion to a tamper-evident audit log by construction.
- **Anchored on Armature L1 when you want it.** Pass a `KxcoChain` to `create`, `issue` or `revoke` and the institution, the credential or the revocation is recorded on chain.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).
- **A supply chain you can check.** SLSA provenance and a CycloneDX SBOM on every release since 1.1.5, third-party dependencies pinned to exact versions, and every GitHub Action pinned by commit SHA.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [HSM backends](#hsm-backends) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## When to use this

This package is for **institutions participating in the KXCO network**. Use it when you need to:

- Issue post-quantum credentials to KYC-verified users
- Sign attestations (documents, trades, regulatory submissions) as an institution or user
- Verify the full credential chain offline, with no network call
- Store institution keys behind one interface: a PKCS#11 hardware security module, an encrypted file, or memory

For an AI agent's identity, a relay client or an encrypted channel, use [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent), [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) or [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls).

## Install

```sh
npm install kxco-pq-sdk
```

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

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

## API

### `KxcoIdentity.create(opts?)`

Creates an institution (root) identity. Generates a new ML-DSA-65 keypair, or an ML-DSA-87 one with `alg: 'ML-DSA-87'`, unless `keypair` or `hsm` is supplied.

| Option | Type | Description |
|---|---|---|
| `keypair` | `{ publicKey, secretKey }` | Existing keypair, generated if omitted |
| `hsm` | `PqHsm \| AuditedHsm` | HSM instance for production key storage |
| `label` | `string` | Required when `hsm` is provided |
| `auditLog` | `AuditLog` | Logs `identity:created` |
| `chain` | `KxcoChain` | Registers institution on Armature L1 |
| `metadataUrl` | `string` | Passed to chain registration |
| `alg` | `'ML-DSA-65' \| 'ML-DSA-87'` | Parameter set for a key generated here or in the `hsm`. Defaults to `'ML-DSA-65'`. A `keypair` decides its own set, and a stated `alg` that disagrees with it is refused |

### `institution.issue(userPublicKey, opts)`

Issues a signed credential to a user. Institution identities only.

| Option | Type | Description |
|---|---|---|
| `role` | `string` | Required. e.g. `'verified-user'`, `'compliance-officer'` |
| `authority` | `string[]` | Default `[]`. e.g. `['sign:transactions']` |
| `metadata` | `object` | Arbitrary key/value, e.g. Sumsub applicant ID |
| `expiresIn` | `string` | `'365d'`, `'24h'`, `'30m'`, `'60s'` |
| `auditLog` | `AuditLog` | Logs `credential:issued` |
| `chain` | `KxcoChain` | Anchors credential on Armature L1 |

Returns a plain JSON object. Serialise and deliver to the user over HTTP.

An ML-DSA-65 institution issues exactly the credential it always has. An
ML-DSA-87 institution's credential carries `alg: 'ML-DSA-87'` and is signed over
`kxco-credential-v1.1`, which puts the algorithm on the second line of the
signed message. The user's key may be of either set; its length decides.

### `institution.revoke(userKid, opts?)`

Revokes a user credential. Institution identities only. The revocation is recorded as an audit log entry and anchored on-chain, so pass `auditLog`, `chain` or both.

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
| `context` | `object` | Additional fields merged into the envelope. They are not signed, and `verify` and `verifyChain` never return them. A context `alg` naming `'ML-DSA-65'` or `'ML-DSA-87'` is refused, because `alg` names the signing algorithm |

An ML-DSA-87 identity's envelope carries `alg: 'ML-DSA-87'` and is signed over
`kxco-identity-attest-v1.1`, with the algorithm on the second line. An ML-DSA-65
envelope is unchanged.
### `identity.sign(message)`

Raw ML-DSA signing in the set the secret key belongs to. Returns a `Uint8Array` signature. Prefer `attest()` for structured envelopes.

### `identity.verify(envelope)`

Verifies that this identity signed the envelope. Returns `{ valid, alg, payload, iss, role, authority, iat, ... }`.

The key decides the algorithm. An envelope with no `alg`, or one naming neither
set, is read as ML-DSA-65, which is how every envelope made before the field
reads. An envelope whose `alg` names the other set from the key is refused with
`'algorithm does not match key'`.

### `KxcoIdentity.verifyChain({ envelope, credential, institutionPublicKey })`

Verifies the full chain offline: institution signed the credential, user signed the envelope, `iss` matches `userKid`, nothing expired.

```js
const result = KxcoIdentity.verifyChain({
  envelope,
  credential,
  institutionPublicKey,  // Uint8Array, fetched from the institution's well-known URL
})
// result.valid, result.role, result.authority, result.metadata, result.issuedBy
```

The institution key decides the credential's algorithm in the same way: a
credential whose `alg` names the other set from `institutionPublicKey` is refused
with `'credential algorithm does not match the institution key'`. `result.alg`
is the set the user's envelope verified under.

### Identity properties

| Property | Institution | User |
|---|---|---|
| `kid` | 16-hex fingerprint | 16-hex fingerprint |
| `role` | `null` | e.g. `'verified-user'` |
| `authority` | `null` | `string[]` |
| `parentKid` | `null` | institution kid |
| `credential` | `null` | signed credential object |
| `metadata` | `{}` | `{}` |
| `alg` | `'ML-DSA-65'` or `'ML-DSA-87'`, from the key | the same, from the user's key |

## HSM backends

Import from `kxco-pq-sdk`. All implement the `PqHsm` interface.

| Backend | Use case |
|---|---|
| `MemoryBackend` | Testing and development, with keys held in memory for the life of the process |
| `FileBackend` | Encrypted JSON file, for server environments without a hardware HSM |
| `Pkcs11Backend` | Hardware HSM via PKCS#11, for production institution keys |
| `AuditedHsm` | Wraps any backend and writes every keygen/sign/delete to an `AuditLog` |

```js
import { KxcoIdentity, AuditedHsm, PqHsm, FileBackend, AuditLog, mlDsa } from 'kxco-pq-sdk'

const logKeypair = mlDsa.ml_dsa65.keygen()
const log        = new AuditLog({ keypair: logKeypair })
const hsm        = new PqHsm(new FileBackend({ path: './institution.json', password: process.env.HSM_PASSWORD }))
const auditedHsm = new AuditedHsm(hsm, log)

const institution = await KxcoIdentity.create({ hsm: auditedHsm, label: 'institution-key' })
```

## Chain integration

Pass your `KxcoChain` from `kxco-pq-chain` to `create`, `issue`, or `revoke` to anchor operations on Armature L1. The `chain` parameter is optional on all three methods: omit it to run fully offline. When provided, `create` calls `chain.registerInstitution`, `issue` calls `chain.issueCredential`, and `revoke` calls `chain.revokeCredential`. `verifyChain` always checks a credential chain offline, with no chain connection.

## The KXCO post-quantum family

This package gives an institution, and every user it credentials, a post-quantum
identity. The rest of the family covers the jobs around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Every release since 1.1.5 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-sdk@<version>`. A CycloneDX
SBOM is published, from v1.1.5, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

**ML-DSA-87**, **ML-DSA-65** (NIST FIPS 204) and **ML-KEM-768** (NIST FIPS 203) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.1.5: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.1.5
- `npm run evidence` regenerates the whole bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

To report a vulnerability, email [security@kxco.ai](mailto:security@kxco.ai) rather than opening a public issue.

## Supported runtimes

Node.js **20.19+** (current LTS and later). ESM-only. New features and bug
fixes land on the latest major version; security fixes are backported one
major version.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)
