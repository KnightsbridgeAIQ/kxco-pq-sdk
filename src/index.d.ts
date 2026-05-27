// kxco-pq-sdk — TypeScript declarations

export class KxcoPqSdkError extends Error {
  name: 'KxcoPqSdkError'
}

// ── Credential issued by an institution to a user ─────────────────────────

export interface KxcoCredential {
  'kxco-credential': '1'
  userKid: string
  userPublicKey: string       // base64url-encoded ML-DSA-65 public key
  issuedBy: string            // institution kid
  role: string
  authority: string[]
  metadata: Record<string, unknown>
  issuedAt: string            // ISO 8601
  expiresAt?: string          // ISO 8601
  signature: string           // base64url, institution's ML-DSA-65 signature
}

// ── Signed attestation envelope ───────────────────────────────────────────

export interface AttestationEnvelope {
  'kxco-identity-attest': '1'
  payload: string             // base64url-encoded data
  iss: string                 // signer kid
  parent_kid?: string
  role?: string
  authority?: string[]
  iat: string                 // ISO 8601
  exp?: string                // ISO 8601
  purpose?: string
  aud?: string
  signature: string           // base64url
  [key: string]: unknown      // context fields
}

// ── Verification results ──────────────────────────────────────────────────

export interface VerifyResult {
  valid: boolean
  error?: string
  payload?: Uint8Array
  iss?: string
  parent_kid?: string
  role?: string
  authority?: string[]
  iat?: string
  exp?: string
  purpose?: string
  aud?: string
}

export interface ChainVerifyResult extends VerifyResult {
  role?: string
  authority?: string[]
  metadata?: Record<string, unknown>
  issuedBy?: string
}

// ── KxcoIdentity ──────────────────────────────────────────────────────────

export interface CreateOptions {
  keypair?: { publicKey: Uint8Array; secretKey: Uint8Array }
  hsm?: import('kxco-pq-hsm').PqHsm
  label?: string
  auditLog?: import('kxco-pq-audit').AuditLog
}

export interface IssueOptions {
  role: string
  authority?: string[]
  metadata?: Record<string, unknown>
  expiresIn?: string          // e.g. '365d', '24h', '30m'
  auditLog?: import('kxco-pq-audit').AuditLog
}

export interface AttestOptions {
  purpose?: string
  aud?: string
  exp?: string
  context?: Record<string, unknown>
}

export interface VerifyChainOptions {
  envelope: AttestationEnvelope
  credential: KxcoCredential
  institutionPublicKey: Uint8Array | Buffer
}

export class KxcoIdentity {
  readonly kid: string
  readonly role: string | null
  readonly authority: string[] | null
  readonly parentKid: string | null
  readonly credential: KxcoCredential | null
  readonly metadata: Record<string, unknown>

  /** Create an institution (root) identity. */
  static create(opts?: CreateOptions): Promise<KxcoIdentity>

  /** Reconstruct a user identity from their keypair and an issued credential. */
  static fromCredential(opts: {
    keypair: { publicKey: Uint8Array; secretKey: Uint8Array }
    credential: KxcoCredential
  }): KxcoIdentity

  /** Verify a full credential chain without instantiating an identity. */
  static verifyChain(opts: VerifyChainOptions): ChainVerifyResult

  /** Raw ML-DSA-65 public key bytes. */
  getPublicKey(): Promise<Uint8Array>

  /** Raw ML-DSA-65 signature over message. */
  sign(message: Uint8Array | Buffer): Promise<Uint8Array>

  /** Issue a signed credential to a user. Institution identities only. */
  issue(userPublicKey: Uint8Array | Buffer, opts: IssueOptions): Promise<KxcoCredential>

  /** Produce a signed attestation envelope. */
  attest(data: string | Uint8Array | Buffer, opts?: AttestOptions): Promise<AttestationEnvelope>

  /** Verify that this identity signed the given envelope. */
  verify(envelope: AttestationEnvelope): Promise<VerifyResult>
}

// ── AuditedHsm ────────────────────────────────────────────────────────────

export class AuditedHsm {
  constructor(hsm: import('kxco-pq-hsm').PqHsm, auditLog: import('kxco-pq-audit').AuditLog)
  keygen(label: string, alg?: 'ml-dsa-65' | 'ml-kem-768'): Promise<{ publicKey: Uint8Array }>
  sign(label: string, message: Uint8Array | Buffer): Promise<Uint8Array>
  decapsulate(label: string, ciphertext: Uint8Array | Buffer): Promise<Uint8Array>
  getPublicKey(label: string): Promise<Uint8Array>
  listKeys(): Promise<Array<{ label: string; alg: string }>>
  deleteKey(label: string): Promise<void>
}

// ── Re-exports ────────────────────────────────────────────────────────────

export {
  PqHsm,
  MemoryBackend,
  FileBackend,
  Pkcs11Backend,
} from 'kxco-pq-hsm'

export {
  AuditLog,
  FileAuditLog,
} from 'kxco-pq-audit'

export {
  attest,
  verify,
} from 'kxco-pq-attest'

export {
  mlDsa,
  mlKem,
  fingerprint,
  kidEquals,
} from 'kxco-post-quantum'
