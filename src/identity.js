import { mlDsa } from 'kxco-post-quantum'
import { fingerprint } from 'kxco-post-quantum'
import { KxcoPqSdkError } from './errors.js'

const ATTEST_VERSION    = '1'
const CREDENTIAL_VERSION = '1'

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

function attestSigningMsg(payloadB64, iss, parentKid, role, authority, iat, exp, purpose, aud) {
  return enc.encode([
    'kxco-identity-attest-v1',
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
    'kxco-credential-v1',
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

// ── Internal verify (no KxcoIdentity instance needed) ──────────────────────

function verifyEnvelope(envelope, publicKey) {
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, error: 'malformed envelope' }
  }
  if (envelope['kxco-identity-attest'] !== ATTEST_VERSION) {
    return { valid: false, error: 'unsupported version' }
  }
  const { payload, iss, parent_kid, role, authority, iat, exp, purpose, aud, signature } = envelope
  if (!payload || !iss || !iat || !signature) {
    return { valid: false, error: 'malformed envelope' }
  }
  if (exp && new Date(exp) < new Date()) {
    return { valid: false, error: 'expired' }
  }
  const msg = attestSigningMsg(payload, iss, parent_kid, role, authority, iat, exp, purpose, aud)
  let ok
  try {
    ok = mlDsa.ml_dsa65.verify(new Uint8Array(publicKey), msg, fromB64url(signature))
  } catch {
    ok = false
  }
  if (!ok) return { valid: false, error: 'signature invalid' }
  return {
    valid:     true,
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

  // ── Factory: institution identity ────────────────────────────────────────

  static async create({ keypair, hsm, label, auditLog } = {}) {
    let kid, kp = null, hsmRef = null, hsmLabel = null

    if (hsm) {
      if (!label) throw new KxcoPqSdkError('label is required when using hsm')
      const { publicKey } = await hsm.keygen(label, 'ml-dsa-65')
      kid      = fingerprint(publicKey)
      kp       = { publicKey }
      hsmRef   = hsm
      hsmLabel = label
    } else if (keypair) {
      kid = fingerprint(keypair.publicKey)
      kp  = keypair
    } else {
      kp  = mlDsa.ml_dsa65.keygen()
      kid = fingerprint(kp.publicKey)
    }

    if (auditLog) {
      await auditLog.append('identity:created', { kid, type: 'institution' })
    }

    return new KxcoIdentity({ kid, keypair: kp, hsm: hsmRef, hsmLabel })
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

  // ── Raw signing (exposed for advanced use; prefer attest()) ──────────────

  async sign(message) {
    if (this.#hsm) return this.#hsm.sign(this.#hsmLabel, message)
    if (!this.#keypair?.secretKey) {
      throw new KxcoPqSdkError('this identity has no signing key — reconstruct with fromCredential({ keypair, credential })')
    }
    return mlDsa.ml_dsa65.sign(new Uint8Array(this.#keypair.secretKey), new Uint8Array(message))
  }

  // ── Issue a credential for a user (institution identity only) ────────────

  async issue(userPublicKey, { role, authority = [], metadata = {}, expiresIn, auditLog } = {}) {
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

    const cred = {
      'kxco-credential': CREDENTIAL_VERSION,
      userKid,
      userPublicKey: b64url(userKeyBytes),
      issuedBy:     this.#kid,
      role,
      authority,
      metadata,
      issuedAt,
      ...(expiresAt && { expiresAt }),
    }

    const sig = await this.sign(credentialSigningMsg(cred))
    cred.signature = b64url(sig)

    if (auditLog) {
      await auditLog.append('credential:issued', { userKid, issuedBy: this.#kid, role })
    }

    return cred
  }

  // ── Attest arbitrary data ─────────────────────────────────────────────────

  async attest(data, { purpose, aud, exp, context = {} } = {}) {
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
    if (credential.expiresAt && new Date(credential.expiresAt) < new Date()) {
      return { valid: false, error: 'credential expired' }
    }

    // Verify the institution signed this credential
    const credMsg = credentialSigningMsg(credential)
    let credOk
    try {
      credOk = mlDsa.ml_dsa65.verify(
        new Uint8Array(institutionPublicKey),
        credMsg,
        fromB64url(credential.signature),
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
