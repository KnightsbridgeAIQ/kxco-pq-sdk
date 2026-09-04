# Changelog

## 2.0.0

**`KxcoIdentity` exposes `publicKeyHex`.** kxco-pq-chain 2.1 sends the public
key with a write so the chain can bind it to the registry record, and looks
for exactly that property. Without it, handing a `KxcoIdentity` to `KxcoChain`
fails with `PUBLIC_KEY_REQUIRED`, which made "upgrade the package and you are
migrated" untrue for the identity type this SDK recommends. HSM-backed
identities have it too: only the secret stays behind the hardware boundary.

Re-exports the verification modes, and corrects a claim that should not have
been made.

### Added

`networkConfig`, `networkConfigFromEnv`, `applyVerifyMode`, `readAnchor`,
`KeyRegistry`, `FAILURE`, `VERIFY_MODES`, `CHAIN_ID`, `meter` and `usageEvent`
from the new `kxco-pq-network`. Three modes:

- `signature` — the maths. Offline, free, no server in the path.
- `anchored` — plus an Armature L1 anchor carried by the envelope. Still no
  HTTP at verify time.
- `anchored+live` — plus a live key-registry lookup, which is the only thing
  that can tell you a key was revoked an hour ago. Needs a licence, and fails
  closed if the registry cannot be reached.

`verifyAsync`, `generateClassicalKeypair` and `CLASSICAL_ALGORITHMS` from
`kxco-pq-attest` 2.x. `verify` is unchanged and still synchronous.

`seed`, `jws` and `backend` from `kxco-post-quantum` 1.6: RFC 9964 seed-form
keys and AKP JWKs, compact JWS with the RFC 9964 algorithm names, and a report
of which backend is doing the maths.

### Changed

`kxco-pq-attest` moves to 2.x, which makes envelope version 2 the default. The
anchor is now inside the signed message rather than attached after signing.
Version 1 envelopes still verify unchanged.

### Corrected

The README claimed `@noble/post-quantum` was "independently audited by Cure53
in 2024". **It was not.** No Cure53 engagement has ever covered
`@noble/post-quantum`; it is self-audited by its maintainer only. The other
Noble packages were audited separately and at different dates: hashes by
Cure53 in Jan 2022, curves by Trail of Bits, Kudelski and Cure53 across
2023-2024, ciphers by Cure53 in Sep 2024. This SDK has had no third-party
assessment either. Both are now stated plainly, with a pointer to the evidence
that does exist: the ACVP vectors and the interoperability matrix, which a
customer can re-run.

The `quantum-safe` keyword is removed from the manifest.

## 1.1.6

Earlier releases. See git history.
