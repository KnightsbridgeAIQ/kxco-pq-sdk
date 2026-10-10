// kxco-pq-sdk — TypeScript declarations

export class KxcoPqSdkError extends Error {
  name: 'KxcoPqSdkError'
}

/** The ML-DSA parameter sets an identity can hold. ML-DSA-87 is the default for a new key. */
export type IdentityAlgorithm = 'ML-DSA-87' | 'ML-DSA-65'

// ── Credential issued by an institution to a user ─────────────────────────

export interface KxcoCredential {
  'kxco-credential': '1'
  /**
   * The issuing institution's signature algorithm, inside the signed bytes.
   * Present on credentials an ML-DSA-87 institution issues; absent means
   * ML-DSA-65, which is how every credential made before this field reads.
   */
  alg?: IdentityAlgorithm
  userKid: string
  userPublicKey: string       // base64url-encoded ML-DSA-87 or ML-DSA-65 public key
  issuedBy: string            // institution kid
  role: string
  authority: string[]
  metadata: Record<string, unknown>
  issuedAt: string            // ISO 8601
  expiresAt?: string          // ISO 8601
  signature: string           // base64url, the institution's ML-DSA signature, in the set `alg` names
}

// ── Signed attestation envelope ───────────────────────────────────────────

export interface AttestationEnvelope {
  'kxco-identity-attest': '1'
  /**
   * The signer's algorithm, inside the signed bytes. Present on envelopes an
   * ML-DSA-87 identity signs; absent means ML-DSA-65.
   */
  alg?: IdentityAlgorithm
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
  /** The parameter set the envelope was verified under, on success. */
  alg?: IdentityAlgorithm
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

/** Minimal KxcoChain interface — pass any kxco-pq-chain KxcoChain instance */
export interface ChainClient {
  registerInstitution(opts: { publicKeyHex: string; metadataUrl?: string }): Promise<{ txHash: string; blockNumber: number }>
  issueCredential(opts: { userKid: string; userPublicKeyHex: string; role: string; expiresAt?: number }): Promise<{ txHash: string; blockNumber: number }>
  revokeCredential(opts: { userKid: string; reason?: string }): Promise<{ txHash: string; blockNumber: number }>
}

export interface CreateOptions {
  keypair?: { publicKey: Uint8Array; secretKey: Uint8Array }
  hsm?: import('kxco-pq-hsm').PqHsm
  label?: string
  auditLog?: import('kxco-pq-audit').AuditLog
  chain?: ChainClient
  metadataUrl?: string
  /**
   * The parameter set for a key made here, randomly or in the hsm. Defaults to
   * 'ML-DSA-87'. A keypair brought in decides its own set, and an alg that
   * disagrees with it is refused.
   */
  alg?: IdentityAlgorithm
}

export interface IssueOptions {
  role: string
  authority?: string[]
  metadata?: Record<string, unknown>
  expiresIn?: string          // e.g. '365d', '24h', '30m'
  auditLog?: import('kxco-pq-audit').AuditLog
  chain?: ChainClient
}

export interface RevokeOptions {
  reason?: string
  auditLog?: import('kxco-pq-audit').AuditLog
  chain?: ChainClient
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
  /** This identity's parameter set, read from its public key. */
  readonly alg: IdentityAlgorithm

  /** Create an institution (root) identity. */
  static create(opts?: CreateOptions): Promise<KxcoIdentity>

  /** Reconstruct a user identity from their keypair and an issued credential. */
  static fromCredential(opts: {
    keypair: { publicKey: Uint8Array; secretKey: Uint8Array }
    credential: KxcoCredential
  }): KxcoIdentity

  /** Verify a full credential chain without instantiating an identity. */
  static verifyChain(opts: VerifyChainOptions): ChainVerifyResult

  /** Raw ML-DSA public key bytes: 2592 for ML-DSA-87, 1952 for ML-DSA-65. */
  getPublicKey(): Promise<Uint8Array>

  /** Raw ML-DSA signature over message, in the set the secret key belongs to. */
  sign(message: Uint8Array | Buffer): Promise<Uint8Array>

  /** Issue a signed credential to a user. Institution identities only. */
  issue(userPublicKey: Uint8Array | Buffer, opts: IssueOptions): Promise<KxcoCredential>

  /** Revoke a user credential on-chain. Institution identities only. */
  revoke(userKid: string, opts?: RevokeOptions): Promise<void>

  /** Produce a signed attestation envelope. */
  attest(data: string | Uint8Array | Buffer, opts?: AttestOptions): Promise<AttestationEnvelope>

  /** Verify that this identity signed the given envelope. */
  verify(envelope: AttestationEnvelope): Promise<VerifyResult>
}

// ── AuditedHsm ────────────────────────────────────────────────────────────

export class AuditedHsm {
  constructor(hsm: import('kxco-pq-hsm').PqHsm, auditLog: import('kxco-pq-audit').AuditLog)
  /** The default algorithm is 'ml-dsa-87'; pass 'ml-dsa-65' for an ML-DSA-65 key, or 'ml-kem-1024' or 'ml-kem-768' for a KEM key. */
  keygen(label: string, alg?: 'ml-dsa-87' | 'ml-dsa-65' | 'ml-kem-1024' | 'ml-kem-768'): Promise<{ publicKey: Uint8Array }>
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
  mlDsa87,
  mlKem1024,
  fingerprint,
  kidEquals,
} from 'kxco-post-quantum'
