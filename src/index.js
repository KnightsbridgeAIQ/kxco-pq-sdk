// Own
export { KxcoIdentity }   from './identity.js'
export { AuditedHsm }     from './audited-hsm.js'
export { KxcoPqSdkError } from './errors.js'

// kxco-pq-hsm
export { PqHsm, MemoryBackend, FileBackend, Pkcs11Backend } from 'kxco-pq-hsm'

// kxco-pq-audit
export { AuditLog, FileAuditLog } from 'kxco-pq-audit'

// kxco-pq-attest
//
// `verify` is synchronous and covers the signature and anchored modes.
// `verifyAsync` covers anchored+live, which needs a live registry lookup, and
// the dual-signature check. Asking `verify` for either throws rather than
// quietly answering something weaker.
export {
  attest, verify, verifyAsync,
  generateClassicalKeypair, CLASSICAL_ALGORITHMS,
} from 'kxco-pq-attest'

// kxco-pq-network — the three verification modes, and the key registry behind
// anchored+live. Signature mode is free and offline; anchored+live needs a
// licence and fails closed when the registry cannot be reached.
export {
  networkConfig, networkConfigFromEnv, applyVerifyMode, readAnchor,
  KeyRegistry, KxcoPqNetworkError, FAILURE, VERIFY_MODES, CHAIN_ID,
  meter, usageEvent,
} from 'kxco-pq-network'

// kxco-post-quantum
export { mlDsa, mlKem, fingerprint, kidEquals, seed, jws, backend } from 'kxco-post-quantum'

// The Category 5 parameter sets. A new identity is ML-DSA-87 and signs
// through mlDsa87; mlDsa above is ML-DSA-65, for an identity made with
// `alg: 'ML-DSA-65'` or from an ML-DSA-65 key.
export { mlDsa87, mlKem1024 } from 'kxco-post-quantum'
