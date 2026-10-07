import { mlDsa, mlDsa87 } from 'kxco-post-quantum'
import { fingerprint } from 'kxco-post-quantum'
import { KxcoPqSdkError } from './errors.js'

const ATTEST_VERSION    = '1'
const CREDENTIAL_VERSION = '1'

// ── Parameter sets ──────────────────────────────────────────────────────────
//
// The KEY decides the algorithm: a key's length names its ML-DSA parameter
// set. A new key is ML-DSA-87 unless the caller asks for ML-DSA-65. ML-DSA-65
// is the only set the v1 signing messages ever meant. A record signed with
// ML-DSA-87 carries `alg: 'ML-DSA-87'` and is
// signed over a v1.1 message, whose first line differs from v1 and whose
// second line is the algorithm, so the algorithm is inside the signed bytes
// and neither message can be read as the other. A record whose `alg` names
// neither set is read as v1, which means ML-DSA-65: that is how every record
// made before this field existed reads, including envelopes that carried an
// unsigned `alg` among their context fields.
const SETS = Object.freeze({
  'ML-DSA-65': Object.freeze({ module: mlDsa,   hsmAlg: 'ml-dsa-65', publicKeyBytes: 1952, secretKeyBytes: 4032 }),
  'ML-DSA-87': Object.freeze({ module: mlDsa87, hsmAlg: 'ml-dsa-87', publicKeyBytes: 2592, secretKeyBytes: 4896 }),
})
// The set a key generated here, or in the hsm, gets when no `alg` is passed.
const DEFAULT_ALG = 'ML-DSA-87'
// The set a record with no `alg` means. Every v1 message is ML-DSA-65, so
// this stays ML-DSA-65 for as long as v1 records exist.
const V1_ALG = 'ML-DSA-65'

function algForPublicKey(publicKey) {
  for (const [name, set] of Object.entries(SETS)) if (publicKey?.length === set.publicKeyBytes) return name
  return null
}

function algForSecretKey(secretKey) {
  for (const [name, set] of Object.entries(SETS)) if (secretKey?.length === set.secretKeyBytes) return name
  return null
}

// The algorithm a record states, or null when it states none this SDK reads,
// in which case it is a v1 record and means ML-DSA-65.
const statedAlg = (record) => (Object.hasOwn(SETS, record?.alg) ? record.alg : null)

const enc = new TextEncoder()

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

function fromB64url(s) {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

function parseDuration(str) {
  const m = str.match(/^(\d+)(d|h|m|s)$/)
  if (!m) throw new KxcoPqSdkError(`invalid duration '${str}' — use e.g. '365d', '24h', '30m'`)
  const n = parseInt(m[1], 10)
  const ms = { d: 86400000, h: 3600000, m: 60000, s: 1000 }
  return n * ms[m[2]]
}

// ── Signing messages ────────────────────────────────────────────────────────

function messageVersion(tag, alg) {
  return alg === null ? [`${tag}-v1`] : [`${tag}-v1.1`, alg]
}

function attestSigningMsg(payloadB64, iss, parentKid, role, authority, iat, exp, purpose, aud, alg = null) {
  return enc.encode([
    ...messageVersion('kxco-identity-attest', alg),
    payloadB64,
    iss,
    parentKid  ?? '',
    role       ?? '',
    JSON.stringify(authority ?? []),
    iat,
    exp        ?? '',
    purpose    ?? '',
    aud        ?? '',
  ].join('\n'))
}

function credentialSigningMsg(cred) {
  return enc.encode([
    ...messageVersion('kxco-credential', statedAlg(cred)),
    cred.userKid,
    cred.userPublicKey,
    cred.issuedBy,
    cred.role,
    JSON.stringify(cred.authority ?? []),
    JSON.stringify(cred.metadata  ?? {}),
    cred.issuedAt,
    cred.expiresAt ?? '',
  ].join('\n'))
}

// ── Field types ─────────────────────────────────────────────────────────────
//
// The signing messages are built from each field's text, so a field of
// another type would be read as whatever its text happens to be: a
// one-element array as its element, an object as its toString. Every field
// that goes into a message has to be the type issue() or attest() writes.

const isText         = (v) => typeof v === 'string' && v !== ''
const isObject       = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

// Both messages are also one field per line. A text field holding a line
// break would let the same signature cover the same bytes split into
// different fields, so none may hold one. The text has to be well-formed
// Unicode too, because an unpaired surrogate encodes to the same bytes as
// U+FFFD. authority and metadata go in as JSON text, which escapes both.
const isOneLine    = (v) => typeof v === 'string' && !/[\r\n]/.test(v) && v.isWellFormed()
const optionalLine = (v) => v === undefined || isOneLine(v)

// JSON text is one spelling of a value, except for a number too large for a
// double: 1e400 reads as Infinity and writes as null, so it could stand in for
// a signed null. authority and metadata may hold only finite numbers, however
// deep. Walked with a list rather than by recursion, so no depth of nesting
// can overflow the stack. -0 writes as 0 and is left alone, since the two
// compare equal.
function allFinite(value) {
  const pending = [value]
  const seen = new Set()
  while (pending.length) {
    const v = pending.pop()
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) return false
    } else if (v !== null && typeof v === 'object' && !seen.has(v)) {
      seen.add(v)
      for (const item of Object.values(v)) pending.push(item)
    }
  }
  return true
}

function credentialFieldError(cred) {
  for (const name of ['userKid', 'userPublicKey', 'issuedBy', 'role', 'issuedAt']) {
    if (!isOneLine(cred[name])) return `${name} must be one line of well-formed text`
  }
  if (!optionalLine(cred.expiresAt)) return 'expiresAt must be one line of well-formed text'
  // Absent or null is signed exactly as [] and {} (the message writes
  // `authority ?? []` and `metadata ?? {}`), so both spellings mean the same
  // and credentials issued with either keep verifying.
  if (!(cred.authority == null || Array.isArray(cred.authority))) return 'authority must be an array'
  if (!(cred.metadata == null || isObject(cred.metadata))) return 'metadata must be an object'
  if (!allFinite(cred.authority) || !allFinite(cred.metadata)) {
    return 'authority and metadata may hold only finite numbers'
  }
  return null
}

// An expiry nobody can read as a date is treated as passed. Read the other way,
// it would never expire.
function hasExpired(expiry) {
  const at = new Date(expiry)
  return Number.isNaN(at.getTime()) || at < new Date()
}

// ── Internal verify (no KxcoIdentity instance needed) ──────────────────────

function verifyEnvelope(envelope, publicKey) {
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, error: 'malformed envelope' }
  }
  if (envelope['kxco-identity-attest'] !== ATTEST_VERSION) {
    return { valid: false, error: 'unsupported version' }
  }
  const { payload, iss, parent_kid, role, authority, iat, exp, purpose, aud, signature } = envelope
  if (![payload, iss, iat].every(isOneLine) || !isText(iss) || !isText(iat) || !isText(signature) ||
      ![parent_kid, role, exp, purpose, aud].every(optionalLine) ||
      !(authority === undefined || (Array.isArray(authority) && allFinite(authority)))) {
    return { valid: false, error: 'malformed envelope' }
  }
  if (exp !== undefined && hasExpired(exp)) {
    return { valid: false, error: 'expired' }
  }
  // The key decides. A key of neither set verifies nothing, as before; a key
  // of the other set from the one the envelope states is refused, not tried.
  const stated = statedAlg(envelope)
  const alg = stated ?? V1_ALG
  const keyAlg = algForPublicKey(publicKey)
  if (keyAlg !== null && keyAlg !== alg) {
    return { valid: false, error: 'algorithm does not match key' }
  }
  let ok
  try {
    // Built inside the try: some runtimes cannot write JSON nested deeply
    // enough, and an envelope that cannot be read back is not verified.
    const msg = attestSigningMsg(payload, iss, parent_kid, role, authority, iat, exp, purpose, aud, stated)
    ok = keyAlg !== null &&
      SETS[alg].module.verify(new Uint8Array(publicKey), msg, Buffer.from(fromB64url(signature)).toString('hex'))
  } catch {
    ok = false
  }
  if (!ok) return { valid: false, error: 'signature invalid' }
  return {
    valid:     true,
    alg,
    payload:   fromB64url(payload),
    iss,
    ...(parent_kid && { parent_kid }),
    ...(role       && { role }),
    ...(authority  && { authority }),
    iat,
    ...(exp        && { exp }),
    ...(purpose    && { purpose }),
    ...(aud        && { aud }),
  }
}

// ── KxcoIdentity ────────────────────────────────────────────────────────────

export class KxcoIdentity {
  #kid
  #keypair    // { publicKey, secretKey? } — secretKey absent for public-key-only instances
  #hsm        // AuditedHsm | PqHsm | null
  #hsmLabel   // string | null
  #role       // string | null
  #authority  // string[] | null
  #parentKid  // string | null
  #credential // credential envelope | null
  #metadata   // {}

  constructor(opts) {
    this.#kid        = opts.kid
    this.#keypair    = opts.keypair   ?? null
    this.#hsm        = opts.hsm       ?? null
    this.#hsmLabel   = opts.hsmLabel  ?? null
    this.#role       = opts.role      ?? null
    this.#authority  = opts.authority ?? null
    this.#parentKid  = opts.parentKid ?? null
    this.#credential = opts.credential ?? null
    this.#metadata   = opts.metadata  ?? {}
  }

  get kid()        { return this.#kid }
  get role()       { return this.#role }
  get authority()  { return this.#authority ? [...this.#authority] : null }
  get parentKid()  { return this.#parentKid }
  get credential() { return this.#credential ? { ...this.#credential } : null }
  get metadata()   { return { ...this.#metadata } }

  /**
   * This identity's ML-DSA parameter set, 'ML-DSA-65' or 'ML-DSA-87', read
   * from its public key. An identity reconstructed from a credential without
   * key material reads it from the credential's user key.
   */
  get alg() {
    const pk = this.#keypair?.publicKey ??
      (this.#credential ? fromB64url(this.#credential.userPublicKey) : null)
    return algForPublicKey(pk) ?? V1_ALG
  }

  // ── Factory: institution identity ────────────────────────────────────────

  static async create({ keypair, hsm, label, auditLog, chain, metadataUrl, alg } = {}) {
    let kid, kp = null, hsmRef = null, hsmLabel = null

    // `alg` picks the parameter set for a key made here, and defaults to
    // ML-DSA-87. A keypair brought in decides its own set, and an `alg` that
    // disagrees with it is refused rather than believed.
    if (alg !== undefined && !Object.hasOwn(SETS, alg)) {
      throw new KxcoPqSdkError(`alg must be 'ML-DSA-65' or 'ML-DSA-87', got ${JSON.stringify(alg)}`)
    }
    const wanted = alg ?? DEFAULT_ALG

    if (hsm) {
      if (!label) throw new KxcoPqSdkError('label is required when using hsm')
      const { publicKey } = await hsm.keygen(label, SETS[wanted].hsmAlg)
      if (algForPublicKey(publicKey) !== wanted) {
        throw new KxcoPqSdkError(`the hsm returned a key that is not ${wanted}`)
      }
      kid      = fingerprint(publicKey)
      kp       = { publicKey }
      hsmRef   = hsm
      hsmLabel = label
    } else if (keypair) {
      const keyAlg = algForPublicKey(keypair.publicKey)
      if (alg !== undefined && keyAlg !== alg) {
        throw new KxcoPqSdkError(`alg is ${alg} but the keypair is ${keyAlg ?? 'neither ML-DSA-65 nor ML-DSA-87'}`)
      }
      kid = fingerprint(keypair.publicKey)
      kp  = keypair
    } else {
      // Random keygen has no wrapper equivalent; the raw keygen is reached
      // through the wrapper's own re-export, as ML-DSA-65 always has been.
      kp  = wanted === 'ML-DSA-87' ? mlDsa87.ml_dsa87.keygen() : mlDsa.ml_dsa65.keygen()
      kid = fingerprint(kp.publicKey)
    }

    if (auditLog) {
      await auditLog.append('identity:created', { kid, type: 'institution' })
    }

    const identity = new KxcoIdentity({ kid, keypair: kp, hsm: hsmRef, hsmLabel })

    if (chain) {
      const publicKey = await identity.getPublicKey()
      await chain.registerInstitution({
        publicKeyHex: Buffer.from(publicKey).toString('hex'),
        ...(metadataUrl && { metadataUrl }),
      })
    }

    return identity
  }

  // ── Factory: reconstruct user identity from keypair + issued credential ──

  static fromCredential({ keypair, credential }) {
    if (!credential || credential['kxco-credential'] !== CREDENTIAL_VERSION) {
      throw new KxcoPqSdkError('invalid or missing credential')
    }
    return new KxcoIdentity({
      kid:        credential.userKid,
      keypair,
      role:       credential.role,
      authority:  credential.authority,
      parentKid:  credential.issuedBy,
      credential,
      metadata:   credential.metadata ?? {},
    })
  }

  // ── Key access ───────────────────────────────────────────────────────────

  async getPublicKey() {
    if (this.#hsm) return this.#hsm.getPublicKey(this.#hsmLabel)
    return this.#keypair.publicKey
  }

  /**
   * This identity's ML-DSA public key as hex, or null when it is not held
   * locally.
   *
   * kxco-pq-chain 2.1 sends the public key with a write so the chain can bind
   * it to the registry record, and it looks for exactly this property. Without
   * it, passing a KxcoIdentity to KxcoChain fails with PUBLIC_KEY_REQUIRED,
   * which made "upgrade the package" untrue for the identity type this SDK
   * tells people to use.
   *
   * A getter rather than a promise because that is the shape the client reads.
   * An HSM-backed identity has one too: only the SECRET stays behind the
   * hardware boundary, and keygen hands back the public key. Null is reserved
   * for an identity reconstructed from a credential with no key material.
   */
  get publicKeyHex() {
    const pk = this.#keypair?.publicKey
    return pk ? Buffer.from(pk).toString('hex') : null
  }

  // ── Raw signing (exposed for advanced use; prefer attest()) ──────────────

  async sign(message) {
    if (this.#hsm) return this.#hsm.sign(this.#hsmLabel, message)
    if (!this.#keypair?.secretKey) {
      throw new KxcoPqSdkError('this identity has no signing key — reconstruct with fromCredential({ keypair, credential })')
    }
    // The secret key decides which set signs.
    const alg = algForSecretKey(this.#keypair.secretKey)
    if (alg === null) throw new KxcoPqSdkError('the secret key is neither ML-DSA-65 nor ML-DSA-87')
    return Buffer.from(SETS[alg].module.sign(new Uint8Array(this.#keypair.secretKey), new Uint8Array(message)), 'hex')
  }

  // ── Issue a credential for a user (institution identity only) ────────────

  async issue(userPublicKey, { role, authority = [], metadata = {}, expiresIn, auditLog, chain } = {}) {
    if (this.#parentKid) {
      throw new KxcoPqSdkError('only institution identities can issue credentials')
    }
    if (!role) throw new KxcoPqSdkError('issue: role is required')

    const userKeyBytes = new Uint8Array(userPublicKey)
    const userKid      = fingerprint(userKeyBytes)
    const issuedAt     = new Date().toISOString()
    const expiresAt    = expiresIn
      ? new Date(Date.now() + parseDuration(expiresIn)).toISOString()
      : undefined

    // ML-DSA-65 credentials keep exactly the v1 shape; an ML-DSA-87 issuer
    // records its algorithm, which puts the credential on the v1.1 message.
    const issuerAlg = this.alg
    const cred = {
      'kxco-credential': CREDENTIAL_VERSION,
      ...(issuerAlg !== V1_ALG && { alg: issuerAlg }),
      userKid,
      userPublicKey: b64url(userKeyBytes),
      issuedBy:     this.#kid,
      role,
      authority,
      metadata,
      issuedAt,
      ...(expiresAt && { expiresAt }),
    }
    // Refused here rather than signed into a credential verifyChain refuses.
    const problem = credentialFieldError(cred)
    if (problem) throw new KxcoPqSdkError(`issue: ${problem}`)

    const sig = await this.sign(credentialSigningMsg(cred))
    cred.signature = b64url(sig)

    if (auditLog) {
      await auditLog.append('credential:issued', { userKid, issuedBy: this.#kid, role })
    }

    if (chain) {
      const expiresAtSec = expiresAt ? Math.floor(new Date(expiresAt).getTime() / 1000) : 0
      await chain.issueCredential({
        userKid,
        userPublicKeyHex: Buffer.from(userKeyBytes).toString('hex'),
        role,
        ...(expiresAtSec && { expiresAt: expiresAtSec }),
      })
    }

    return cred
  }

  // ── Revoke a user credential (institution identity only) ─────────────────

  async revoke(userKid, { reason, auditLog, chain } = {}) {
    if (this.#parentKid) {
      throw new KxcoPqSdkError('only institution identities can revoke credentials')
    }
    if (!userKid) throw new KxcoPqSdkError('revoke: userKid is required')

    if (auditLog) {
      await auditLog.append('credential:revoked', { userKid, revokedBy: this.#kid, reason })
    }

    if (chain) {
      await chain.revokeCredential({ userKid, ...(reason && { reason }) })
    }
  }

  // ── Attest arbitrary data ─────────────────────────────────────────────────

  async attest(data, { purpose, aud, exp, context = {} } = {}) {
    for (const [name, value] of [['purpose', purpose], ['aud', aud], ['exp', exp]]) {
      if (value != null && !isOneLine(value)) {
        throw new KxcoPqSdkError(`attest: ${name} must be one line of well-formed text`)
      }
    }
    if (exp && Number.isNaN(new Date(exp).getTime())) {
      throw new KxcoPqSdkError('attest: exp must be a date')
    }
    let payloadBytes
    if (typeof data === 'string') {
      payloadBytes = enc.encode(data)
    } else if (ArrayBuffer.isView(data) || data instanceof ArrayBuffer) {
      payloadBytes = new Uint8Array(data)
    } else {
      payloadBytes = enc.encode(JSON.stringify(data))
    }
    const payloadB64 = b64url(payloadBytes)

    const iat = new Date().toISOString()

    // The signer's algorithm, recorded only for ML-DSA-87 so ML-DSA-65
    // envelopes keep exactly the v1 shape. Context fields are unsigned, so one
    // may not claim to be the signer's algorithm.
    const signerAlg = this.alg === V1_ALG ? null : this.alg
    if (Object.hasOwn(SETS, context?.alg)) {
      throw new KxcoPqSdkError('attest: context may not set alg; it names the signing algorithm')
    }

    const envelope = {
      'kxco-identity-attest': ATTEST_VERSION,
      payload:   payloadB64,
      iss:       this.#kid,
      ...(this.#parentKid  && { parent_kid: this.#parentKid }),
      ...(this.#role       && { role:       this.#role }),
      ...(this.#authority  && { authority:  this.#authority }),
      iat,
      ...(exp     && { exp }),
      ...(purpose && { purpose }),
      ...(aud     && { aud }),
      ...context,
      ...(signerAlg && { alg: signerAlg }),
    }

    const msg = attestSigningMsg(
      payloadB64,
      this.#kid,
      this.#parentKid  ?? null,
      this.#role       ?? null,
      this.#authority  ?? null,
      iat,
      exp     ?? null,
      purpose ?? null,
      aud     ?? null,
      signerAlg,
    )

    const sig = await this.sign(msg)
    envelope.signature = b64url(sig)
    return envelope
  }

  // ── Verify an envelope this identity signed ──────────────────────────────

  async verify(envelope) {
    const pk = await this.getPublicKey()
    return verifyEnvelope(envelope, pk)
  }

  // ── Verify full credential chain ─────────────────────────────────────────

  static verifyChain({ envelope, credential, institutionPublicKey }) {
    if (!credential || credential['kxco-credential'] !== CREDENTIAL_VERSION) {
      return { valid: false, error: 'invalid credential' }
    }
    if (credentialFieldError(credential) || typeof credential.signature !== 'string') {
      return { valid: false, error: 'invalid credential' }
    }
    if (credential.expiresAt !== undefined && hasExpired(credential.expiresAt)) {
      return { valid: false, error: 'credential expired' }
    }

    // Verify the institution signed this credential. The institution's key
    // decides the algorithm; a credential that states the other set from it is
    // refused rather than tried.
    const credAlg = statedAlg(credential) ?? V1_ALG
    const institutionAlg = algForPublicKey(institutionPublicKey)
    if (institutionAlg !== null && institutionAlg !== credAlg) {
      return { valid: false, error: 'credential algorithm does not match the institution key' }
    }
    let credOk
    try {
      // Built inside the try, for the reason verifyEnvelope gives.
      const credMsg = credentialSigningMsg(credential)
      credOk = institutionAlg !== null && SETS[credAlg].module.verify(
        new Uint8Array(institutionPublicKey),
        credMsg,
        Buffer.from(fromB64url(credential.signature)).toString('hex'),
      )
    } catch {
      credOk = false
    }
    if (!credOk) return { valid: false, error: 'credential signature invalid' }

    // Envelope iss must match credential userKid
    if (!envelope || envelope.iss !== credential.userKid) {
      return { valid: false, error: 'envelope iss does not match credential userKid' }
    }

    // Verify the envelope signature with the user's public key (from credential)
    const userPublicKey = fromB64url(credential.userPublicKey)
    const envResult = verifyEnvelope(envelope, userPublicKey)
    if (!envResult.valid) return envResult

    return {
      ...envResult,
      role:      credential.role,
      authority: credential.authority,
      metadata:  credential.metadata,
      issuedBy:  credential.issuedBy,
    }
  }
}
