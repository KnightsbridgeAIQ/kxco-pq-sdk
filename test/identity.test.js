import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { KxcoIdentity, KxcoPqSdkError, AuditedHsm, AuditLog, PqHsm, MemoryBackend } from '../src/index.js'

// Keypairs generated once — keygen is the slow step
let institutionKp, userKp, otherKp

before(() => {
  institutionKp = mlDsa.ml_dsa65.keygen()
  userKp        = mlDsa.ml_dsa65.keygen()
  otherKp       = mlDsa.ml_dsa65.keygen()
})

// ── KxcoIdentity.create ──────────────────────────────────────────────────

test('create: returns identity with 16-char kid', async () => {
  const id = await KxcoIdentity.create({ keypair: institutionKp })
  assert.ok(typeof id.kid === 'string' && id.kid.length === 16)
  assert.equal(id.role, null)
  assert.equal(id.authority, null)
  assert.equal(id.parentKid, null)
  assert.equal(id.credential, null)
})

test('create: generates keypair when none supplied', async () => {
  const id = await KxcoIdentity.create()
  assert.ok(typeof id.kid === 'string' && id.kid.length === 16)
})

test('create: logs to auditLog when provided', async () => {
  const logKp = mlDsa.ml_dsa65.keygen()
  const log   = new AuditLog({ keypair: logKp })
  const id    = await KxcoIdentity.create({ keypair: institutionKp, auditLog: log })
  const entries = await log.export()
  assert.equal(entries.length, 1)
  assert.equal(entries[0].operation, 'identity:created')
  assert.equal(entries[0].metadata.kid, id.kid)
})

// ── issue ────────────────────────────────────────────────────────────────

test('issue: returns well-formed credential', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, {
    role: 'verified-user',
    authority: ['sign:transactions'],
    metadata: { sumsubApplicantId: 'abc123' },
  })

  assert.equal(cred['kxco-credential'], '1')
  assert.ok(typeof cred.userKid === 'string' && cred.userKid.length === 16)
  assert.equal(cred.issuedBy, inst.kid)
  assert.equal(cred.role, 'verified-user')
  assert.deepEqual(cred.authority, ['sign:transactions'])
  assert.equal(cred.metadata.sumsubApplicantId, 'abc123')
  assert.ok(typeof cred.signature === 'string' && cred.signature.length > 0)
  assert.ok(!cred.expiresAt)
})

test('issue: sets expiresAt when expiresIn supplied', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const before = Date.now()
  const cred = await inst.issue(userKp.publicKey, { role: 'staff', expiresIn: '30d' })
  const after = Date.now()

  const exp = new Date(cred.expiresAt).getTime()
  assert.ok(exp > before + 29 * 86400000)
  assert.ok(exp < after  + 31 * 86400000)
})

test('issue: throws without role', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  await assert.rejects(() => inst.issue(userKp.publicKey, {}), /role is required/)
})

test('issue: throws when called on user identity', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, { role: 'verified-user' })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  await assert.rejects(
    () => user.issue(otherKp.publicKey, { role: 'sub-user' }),
    /only institution identities/,
  )
})

test('issue: logs to auditLog when provided', async () => {
  const logKp = mlDsa.ml_dsa65.keygen()
  const log   = new AuditLog({ keypair: logKp })
  const inst  = await KxcoIdentity.create({ keypair: institutionKp })
  await inst.issue(userKp.publicKey, { role: 'staff', auditLog: log })
  const entries = await log.export()
  assert.equal(entries[0].operation, 'credential:issued')
})

// ── fromCredential ───────────────────────────────────────────────────────

test('fromCredential: builds user identity with correct fields', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, {
    role: 'compliance-officer',
    authority: ['sign:regulatory-report'],
    metadata: { country: 'GB' },
  })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })

  assert.equal(user.kid, cred.userKid)
  assert.equal(user.role, 'compliance-officer')
  assert.deepEqual(user.authority, ['sign:regulatory-report'])
  assert.equal(user.parentKid, inst.kid)
  assert.equal(user.metadata.country, 'GB')
})

test('fromCredential: throws on invalid credential', () => {
  assert.throws(() => KxcoIdentity.fromCredential({ keypair: userKp, credential: {} }), /invalid/)
})

// ── attest ───────────────────────────────────────────────────────────────

test('attest: institution identity produces envelope with correct shape', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const env  = await inst.attest('hello world')

  assert.equal(env['kxco-identity-attest'], '1')
  assert.ok(typeof env.payload === 'string')
  assert.equal(env.iss, inst.kid)
  assert.ok(!env.parent_kid)
  assert.ok(!env.role)
  assert.ok(typeof env.iat === 'string')
  assert.ok(typeof env.signature === 'string')
})

test('attest: user identity includes parent_kid, role, authority', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, {
    role: 'trader',
    authority: ['sign:trade-confirmation'],
  })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const env  = await user.attest({ order: 'BUY', qty: 100 })

  assert.equal(env.parent_kid, inst.kid)
  assert.equal(env.role, 'trader')
  assert.deepEqual(env.authority, ['sign:trade-confirmation'])
})

test('attest: purpose, aud, exp fields pass through', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const exp  = new Date(Date.now() + 3600000).toISOString()
  const env  = await inst.attest('doc', { purpose: 'regulatory-report', aud: 'FCA', exp })

  assert.equal(env.purpose, 'regulatory-report')
  assert.equal(env.aud, 'FCA')
  assert.equal(env.exp, exp)
})

test('attest: binary payload round-trips', async () => {
  const inst  = await KxcoIdentity.create({ keypair: institutionKp })
  const bytes = new Uint8Array([0, 1, 2, 255, 254])
  const env   = await inst.attest(bytes)
  const result = await inst.verify(env)
  assert.deepEqual(result.payload, bytes)
})

// ── verify (instance) ────────────────────────────────────────────────────

test('verify: valid envelope returns valid=true', async () => {
  const inst   = await KxcoIdentity.create({ keypair: institutionKp })
  const env    = await inst.attest('sign me')
  const result = await inst.verify(env)
  assert.equal(result.valid, true)
  assert.equal(Buffer.from(result.payload).toString(), 'sign me')
})

test('verify: wrong key returns valid=false', async () => {
  const inst  = await KxcoIdentity.create({ keypair: institutionKp })
  const other = await KxcoIdentity.create({ keypair: otherKp })
  const env   = await inst.attest('test')
  assert.equal((await other.verify(env)).valid, false)
})

test('verify: tampered payload returns valid=false', async () => {
  const inst    = await KxcoIdentity.create({ keypair: institutionKp })
  const env     = await inst.attest('original')
  const tampered = { ...env, payload: env.payload.slice(0, -4) + 'AAAA' }
  assert.equal((await inst.verify(tampered)).valid, false)
})

test('verify: tampered signature returns valid=false', async () => {
  const inst    = await KxcoIdentity.create({ keypair: institutionKp })
  const env     = await inst.attest('original')
  const tampered = { ...env, signature: env.signature.slice(0, -4) + 'AAAA' }
  assert.equal((await inst.verify(tampered)).valid, false)
})

test('verify: expired envelope returns valid=false', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const exp  = new Date(Date.now() - 1000).toISOString()
  const env  = await inst.attest('expired', { exp })
  assert.equal((await inst.verify(env)).valid, false)
  assert.equal((await inst.verify(env)).error, 'expired')
})

test('verify: unsupported version returns valid=false', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const env  = { ...(await inst.attest('x')), 'kxco-identity-attest': '99' }
  assert.equal((await inst.verify(env)).valid, false)
  assert.equal((await inst.verify(env)).error, 'unsupported version')
})

// ── verifyChain ──────────────────────────────────────────────────────────

test('verifyChain: full chain valid', async () => {
  const inst  = await KxcoIdentity.create({ keypair: institutionKp })
  const cred  = await inst.issue(userKp.publicKey, {
    role: 'authorised-signatory',
    authority: ['sign:contracts'],
  })
  const user  = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const env   = await user.attest('binding contract')

  const result = KxcoIdentity.verifyChain({
    envelope: env,
    credential: cred,
    institutionPublicKey: institutionKp.publicKey,
  })

  assert.equal(result.valid, true)
  assert.equal(result.role, 'authorised-signatory')
  assert.deepEqual(result.authority, ['sign:contracts'])
  assert.equal(result.issuedBy, inst.kid)
  assert.equal(Buffer.from(result.payload).toString(), 'binding contract')
})

test('verifyChain: tampered credential returns valid=false', async () => {
  const inst   = await KxcoIdentity.create({ keypair: institutionKp })
  const cred   = await inst.issue(userKp.publicKey, { role: 'staff' })
  const user   = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const env    = await user.attest('doc')

  const tampered = { ...cred, role: 'admin' }
  const result = KxcoIdentity.verifyChain({
    envelope: env,
    credential: tampered,
    institutionPublicKey: institutionKp.publicKey,
  })
  assert.equal(result.valid, false)
  assert.equal(result.error, 'credential signature invalid')
})

test('verifyChain: wrong institution key returns valid=false', async () => {
  const inst  = await KxcoIdentity.create({ keypair: institutionKp })
  const cred  = await inst.issue(userKp.publicKey, { role: 'staff' })
  const user  = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const env   = await user.attest('doc')

  const result = KxcoIdentity.verifyChain({
    envelope: env,
    credential: cred,
    institutionPublicKey: otherKp.publicKey,
  })
  assert.equal(result.valid, false)
})

test('verifyChain: tampered envelope returns valid=false', async () => {
  const inst  = await KxcoIdentity.create({ keypair: institutionKp })
  const cred  = await inst.issue(userKp.publicKey, { role: 'staff' })
  const user  = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const env   = await user.attest('original')

  const tampered = { ...env, payload: env.payload.slice(0, -4) + 'AAAA' }
  const result = KxcoIdentity.verifyChain({
    envelope: tampered,
    credential: cred,
    institutionPublicKey: institutionKp.publicKey,
  })
  assert.equal(result.valid, false)
})

test('verifyChain: iss mismatch returns valid=false', async () => {
  const inst  = await KxcoIdentity.create({ keypair: institutionKp })
  const cred  = await inst.issue(userKp.publicKey, { role: 'staff' })
  const env   = await inst.attest('by institution, not user')

  const result = KxcoIdentity.verifyChain({
    envelope: env,
    credential: cred,
    institutionPublicKey: institutionKp.publicKey,
  })
  assert.equal(result.valid, false)
  assert.equal(result.error, 'envelope iss does not match credential userKid')
})

test('verifyChain: expired credential returns valid=false', async () => {
  const inst  = await KxcoIdentity.create({ keypair: institutionKp })
  const cred  = await inst.issue(userKp.publicKey, { role: 'staff', expiresIn: '1s' })
  const user  = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  // Backdate expiresAt to simulate expiry (re-sign not possible — test credential path)
  const expired = { ...cred, expiresAt: new Date(Date.now() - 5000).toISOString() }
  const env   = await user.attest('doc')

  const result = KxcoIdentity.verifyChain({
    envelope: env,
    credential: expired,
    institutionPublicKey: institutionKp.publicKey,
  })
  assert.equal(result.valid, false)
  assert.equal(result.error, 'credential expired')
})

// ── metadata round-trip ──────────────────────────────────────────────────

test('metadata: Sumsub claims survive full issuance round-trip', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, {
    role: 'verified-user',
    authority: ['sign:transactions', 'access:chain'],
    metadata: {
      sumsubApplicantId: 'applicant_42',
      country: 'GB',
      verificationLevel: 'kyc-1',
      verifiedAt: '2026-05-27T00:00:00.000Z',
    },
    expiresIn: '365d',
  })

  assert.equal(cred.metadata.sumsubApplicantId, 'applicant_42')
  assert.equal(cred.metadata.country, 'GB')

  const user   = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  assert.equal(user.metadata.country, 'GB')

  const env    = await user.attest({ action: 'transfer', amount: 100 })
  const result = KxcoIdentity.verifyChain({
    envelope: env,
    credential: cred,
    institutionPublicKey: institutionKp.publicKey,
  })
  assert.equal(result.valid, true)
  assert.equal(result.metadata.sumsubApplicantId, 'applicant_42')
})

// ── AuditedHsm ──────────────────────────────────────────────────────────

test('AuditedHsm: keygen, sign, deleteKey are logged', async () => {
  const logKp  = mlDsa.ml_dsa65.keygen()
  const log    = new AuditLog({ keypair: logKp })
  const hsm    = new PqHsm(new MemoryBackend())
  const aHsm   = new AuditedHsm(hsm, log)

  await aHsm.keygen('my-key', 'ml-dsa-65')
  const { publicKey } = await aHsm.getPublicKey('my-key')
  await aHsm.sign('my-key', new Uint8Array([1, 2, 3]))
  await aHsm.deleteKey('my-key')

  const entries = await log.export()
  const ops = entries.map(e => e.operation)
  assert.ok(ops.includes('hsm:keygen'))
  assert.ok(ops.includes('hsm:sign'))
  assert.ok(ops.includes('hsm:deleteKey'))
})

test('AuditedHsm: getPublicKey and listKeys are not logged', async () => {
  const logKp = mlDsa.ml_dsa65.keygen()
  const log   = new AuditLog({ keypair: logKp })
  const hsm   = new PqHsm(new MemoryBackend())
  const aHsm  = new AuditedHsm(hsm, log)

  await aHsm.keygen('k', 'ml-dsa-65')
  await log.export() // drain keygen entry
  // reset by counting from here
  const countAfterKeygen = (await log.export()).length

  await aHsm.getPublicKey('k')
  await aHsm.listKeys()

  const entries = await log.export()
  assert.equal(entries.length, countAfterKeygen) // no new entries
})

test('AuditedHsm: throws without auditLog', () => {
  const hsm = new PqHsm(new MemoryBackend())
  assert.throws(() => new AuditedHsm(hsm, null), /auditLog is required/)
})

test('AuditedHsm: institution identity works with AuditedHsm', async () => {
  const logKp = mlDsa.ml_dsa65.keygen()
  const log   = new AuditLog({ keypair: logKp })
  const hsm   = new PqHsm(new MemoryBackend())
  const aHsm  = new AuditedHsm(hsm, log)

  const inst = await KxcoIdentity.create({ hsm: aHsm, label: 'institution-key' })
  const cred = await inst.issue(userKp.publicKey, { role: 'staff' })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const env  = await user.attest('signed by user')

  const instPk = await inst.getPublicKey()
  const result = KxcoIdentity.verifyChain({
    envelope: env,
    credential: cred,
    institutionPublicKey: instPk,
  })
  assert.equal(result.valid, true)
})

// ── the property kxco-pq-chain 2.1 reads ───────────────────────────────────

test('an institution identity exposes publicKeyHex', async () => {
  // kxco-pq-chain 2.1 sends the public key with a write so the chain can bind
  // it to the registry record, and it looks for exactly this property. Without
  // it, handing a KxcoIdentity to KxcoChain fails with PUBLIC_KEY_REQUIRED,
  // which made "upgrade the package" untrue for the identity type this SDK
  // tells people to use.
  const keypair = mlDsa.keypairFromMaster(Buffer.alloc(32, 0x21), 'publickeyhex-test')
  const id = await KxcoIdentity.create({ keypair })

  assert.equal(typeof id.publicKeyHex, 'string')
  assert.equal(id.publicKeyHex.length, 1952 * 2, 'ML-DSA-65 public key is 1952 bytes')
  assert.match(id.publicKeyHex, /^[0-9a-f]+$/)

  // The property must describe THIS identity, not merely be well formed.
  assert.equal(fingerprint(Buffer.from(id.publicKeyHex, 'hex')), id.kid)
})

// ── field types, line breaks and empty data ─────────────────────────────

// The version 1 credential signing message, as every issuer has written it.
// Used to sign credentials that issue() itself no longer produces.
function signCredentialV1(fields, secretKey) {
  const msg = new TextEncoder().encode([
    'kxco-credential-v1', fields.userKid, fields.userPublicKey, fields.issuedBy, fields.role,
    JSON.stringify(fields.authority ?? []), JSON.stringify(fields.metadata ?? {}),
    fields.issuedAt, fields.expiresAt ?? '',
  ].join('\n'))
  return { ...fields, signature: Buffer.from(mlDsa.sign(secretKey, msg), 'hex').toString('base64url') }
}

const viaJson = (value) => JSON.parse(JSON.stringify(value))
const ODD = [{ toString: null }, { toString: 1 }, [{ toString: 1 }], { valueOf: null, toString: null }]

test('issue refuses a role that is not one line of well-formed text, and field types verifyChain refuses', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  for (const opts of [
    { role: 'viewer\n["admin:all"]' },
    { role: 'viewer\r' },
    { role: '\r\nadmin' },
    { role: 'caf\uD800' },
    { role: 5 },
    { role: ['staff'] },
    { role: { toString: () => 'staff' } },
    { role: 'staff', authority: 'sign:x' },
    { role: 'staff', authority: { 0: 'sign:x' } },
    { role: 'staff', metadata: ['a'] },
    { role: 'staff', metadata: 'a' },
  ]) {
    await assert.rejects(
      () => inst.issue(userKp.publicKey, opts),
      (e) => e instanceof KxcoPqSdkError,
      JSON.stringify(opts),
    )
  }
  // Line breaks inside authority and metadata go in as JSON text, which escapes them.
  const cred = await inst.issue(userKp.publicKey, {
    role: 'staff', authority: ['a\nb'], metadata: { address: '1 High St\nLondon' },
  })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const result = KxcoIdentity.verifyChain({
    envelope: await user.attest('doc'), credential: viaJson(cred), institutionPublicKey: institutionKp.publicKey,
  })
  assert.equal(result.valid, true, result.error)
  assert.equal(result.metadata.address, '1 High St\nLondon')
})

test('a credential signed over a line break in a text field is refused, and so is the same signature split another way', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: await inst.issue(userKp.publicKey, { role: 'staff' }) })
  const envelope = await user.attest('doc')
  const issuedAt = new Date().toISOString()
  const cred = signCredentialV1({
    'kxco-credential': '1',
    userKid: fingerprint(userKp.publicKey),
    userPublicKey: Buffer.from(userKp.publicKey).toString('base64url'),
    issuedBy: inst.kid,
    role: 'viewer\n["admin:all"]',
    authority: [],
    metadata: {},
    issuedAt,
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
  }, institutionKp.secretKey)
  const split = {
    ...cred, role: 'viewer', authority: ['admin:all'], metadata: [],
    issuedAt: '{}', expiresAt: cred.issuedAt + '\n' + cred.expiresAt,
  }
  for (const credential of [cred, split]) {
    assert.deepEqual(
      KxcoIdentity.verifyChain({ envelope, credential: viaJson(credential), institutionPublicKey: institutionKp.publicKey }),
      { valid: false, error: 'invalid credential' },
    )
  }
})

test('a credential expiry that does not parse as a date is treated as expired', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, { role: 'staff' })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const envelope = await user.attest('doc')
  const signed = (expiresAt) => signCredentialV1({ ...cred, expiresAt }, institutionKp.secretKey)
  for (const credential of [
    signed('never'), signed('2026-13-45'), signed(''),
    // No expiry was signed, and an empty one reads the same in the message.
    { ...cred, expiresAt: '' },
  ]) {
    assert.deepEqual(
      KxcoIdentity.verifyChain({ envelope, credential: viaJson(credential), institutionPublicKey: institutionKp.publicKey }),
      { valid: false, error: 'credential expired' },
      JSON.stringify(credential.expiresAt),
    )
  }
})

test('authority and metadata that are null or absent read as the empty values they were signed as', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const spellings = (cred) => {
    const { authority: _a, ...noAuthority } = cred
    const { metadata: _m, ...noMetadata } = cred
    return [
      ['authority null', { ...cred, authority: null }],
      ['authority removed', noAuthority],
      ['metadata null', { ...cred, metadata: null }],
      ['metadata removed', noMetadata],
    ]
  }

  // Issued empty, or issued with null, all four spellings carry the same signed bytes.
  for (const opts of [{ role: 'staff' }, { role: 'staff', authority: null, metadata: null }]) {
    const cred = await inst.issue(userKp.publicKey, opts)
    const envelope = await KxcoIdentity.fromCredential({ keypair: userKp, credential: cred }).attest('doc')
    assert.equal(KxcoIdentity.verifyChain({ envelope, credential: cred, institutionPublicKey: institutionKp.publicKey }).valid, true, JSON.stringify(opts))
    for (const [name, credential] of spellings(cred)) {
      assert.equal(KxcoIdentity.verifyChain({ envelope, credential, institutionPublicKey: institutionKp.publicKey }).valid, true, name)
    }
  }

  // Issued with values, dropping them changes what was signed.
  const full = await inst.issue(userKp.publicKey, { role: 'staff', authority: ['sign:x'], metadata: { k: 'v' } })
  const envelope = await KxcoIdentity.fromCredential({ keypair: userKp, credential: full }).attest('doc')
  for (const [name, credential] of spellings(full)) {
    assert.equal(KxcoIdentity.verifyChain({ envelope, credential, institutionPublicKey: institutionKp.publicKey }).valid, false, name)
  }
})

test('every signed credential field must be the type issue() writes', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, { role: 'staff', expiresIn: '30d' })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const envelope = await user.attest('doc')
  const { role: _r, ...noRole } = cred
  for (const [name, credential] of [
    ['authority as an object', { ...cred, authority: {} }],
    ['metadata as a list', { ...cred, metadata: [] }],
    ['role as a list', { ...cred, role: ['staff'] }],
    ['role removed', noRole],
    ['expiresAt as a list', { ...cred, expiresAt: [cred.expiresAt] }],
    ['expiresAt null', { ...cred, expiresAt: null }],
    ['issuedAt as a list', { ...cred, issuedAt: [cred.issuedAt] }],
    ['issuedBy as a list', { ...cred, issuedBy: [cred.issuedBy] }],
    ['userKid as a list', { ...cred, userKid: [cred.userKid] }],
    ['userPublicKey as a list', { ...cred, userPublicKey: [cred.userPublicKey] }],
    ['signature as a list', { ...cred, signature: [cred.signature] }],
  ]) {
    assert.deepEqual(
      KxcoIdentity.verifyChain({ envelope, credential: viaJson(credential), institutionPublicKey: institutionKp.publicKey }),
      { valid: false, error: 'invalid credential' },
      name,
    )
  }
})

test('empty data attests and verifies, through verify and through verifyChain', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, { role: 'staff' })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  for (const empty of ['', new Uint8Array(0), Buffer.alloc(0)]) {
    const own = await inst.verify(viaJson(await inst.attest(empty)))
    assert.equal(own.valid, true, own.error)
    assert.equal(own.payload.length, 0)
    const chained = KxcoIdentity.verifyChain({
      envelope: viaJson(await user.attest(empty)), credential: cred, institutionPublicKey: institutionKp.publicKey,
    })
    assert.equal(chained.valid, true, chained.error)
    assert.equal(chained.payload.length, 0)
  }
})

test('an envelope field of another type than attest writes is refused', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, { role: 'staff', authority: ['sign:x'] })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const env = await user.attest('doc', {
    purpose: 'report', aud: 'FCA', exp: new Date(Date.now() + 3600000).toISOString(),
  })
  const plain = await user.attest('doc')
  for (const [name, envelope] of [
    ['payload', { ...env, payload: [env.payload] }],
    ['iss', { ...env, iss: [env.iss] }],
    ['iat', { ...env, iat: [env.iat] }],
    ['role', { ...env, role: [env.role] }],
    ['authority null', { ...env, authority: null }],
    ['authority as text', { ...env, authority: '["sign:x"]' }],
    ['parent_kid', { ...env, parent_kid: [env.parent_kid] }],
    ['exp', { ...env, exp: [env.exp] }],
    ['purpose', { ...env, purpose: [env.purpose] }],
    ['aud', { ...env, aud: [env.aud] }],
    ['purpose null', { ...plain, purpose: null }],
    ['signature', { ...env, signature: [env.signature] }],
  ]) {
    assert.deepEqual(await user.verify(viaJson(envelope)), { valid: false, error: 'malformed envelope' }, name)
    const chained = KxcoIdentity.verifyChain({ envelope: viaJson(envelope), credential: cred, institutionPublicKey: institutionKp.publicKey })
    assert.equal(chained.valid, false, name)
  }
})

test('verify and verifyChain return a result, never a throw, for JSON fields that carry their own toString', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, { role: 'staff', expiresIn: '30d' })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const env = await user.attest('doc', { purpose: 'report' })
  const credentialFields = ['userKid', 'userPublicKey', 'issuedBy', 'role', 'authority', 'metadata', 'issuedAt', 'expiresAt', 'signature']
  const envelopeFields = ['payload', 'iss', 'parent_kid', 'role', 'authority', 'iat', 'exp', 'purpose', 'aud', 'signature']
  for (const odd of ODD) {
    for (const field of credentialFields) {
      const result = KxcoIdentity.verifyChain({
        envelope: env, credential: viaJson({ ...cred, [field]: odd }), institutionPublicKey: institutionKp.publicKey,
      })
      assert.equal(result.valid, false, `credential ${field}`)
    }
    for (const field of envelopeFields) {
      const envelope = viaJson({ ...env, [field]: odd })
      assert.equal((await user.verify(envelope)).valid, false, `envelope ${field}`)
      assert.equal(KxcoIdentity.verifyChain({ envelope, credential: cred, institutionPublicKey: institutionKp.publicKey }).valid, false)
    }
  }
  // The two shapes first seen to throw.
  assert.equal(KxcoIdentity.verifyChain({
    envelope: {}, credential: JSON.parse('{"kxco-credential":"1","role":{"toString":null}}'), institutionPublicKey: institutionKp.publicKey,
  }).valid, false)
  assert.equal((await inst.verify(JSON.parse(
    '{"kxco-identity-attest":"1","payload":"AA","iss":"x","iat":{"toString":null},"signature":"AA"}',
  ))).valid, false)
})

test('attest refuses a purpose, audience or expiry that is not text', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  for (const opts of [{ purpose: 5 }, { aud: ['FCA'] }, { exp: new Date(Date.now() + 3600000) }, { exp: 0 }]) {
    await assert.rejects(() => inst.attest('doc', opts), (e) => e instanceof KxcoPqSdkError, Object.keys(opts)[0])
  }
})

// The version 1 envelope signing message, as attest has always written it.
// Used to sign envelopes that attest() itself no longer produces.
function signEnvelopeV1(fields, secretKey) {
  const msg = new TextEncoder().encode([
    'kxco-identity-attest-v1', fields.payload, fields.iss, fields.parent_kid ?? '', fields.role ?? '',
    JSON.stringify(fields.authority ?? []), fields.iat, fields.exp ?? '', fields.purpose ?? '', fields.aud ?? '',
  ].join('\n'))
  return { ...fields, signature: Buffer.from(mlDsa.sign(secretKey, msg), 'hex').toString('base64url') }
}

test('attest refuses a purpose, audience or expiry that is not one line of well-formed text, and an expiry that is not a date', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  for (const opts of [
    { purpose: 'invoice\nFCA' }, { aud: 'FCA\r' }, { purpose: '\r\n' }, { aud: 'caf\uD800' },
    { exp: new Date(Date.now() + 3600000).toISOString() + '\n' }, { exp: 'never' },
  ]) {
    await assert.rejects(() => inst.attest('doc', opts), (e) => e instanceof KxcoPqSdkError, JSON.stringify(opts))
  }
})

test('an envelope signed over a line break in a text field is refused, and so is the same signature split another way', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const base = {
    'kxco-identity-attest': '1', payload: Buffer.from('doc').toString('base64url'), iss: inst.kid, iat: new Date().toISOString(),
  }
  const signed = signEnvelopeV1({ ...base, purpose: 'invoice\nFCA' }, institutionKp.secretKey)
  for (const [name, envelope] of [
    ['as signed', signed],
    ['into the audience', { ...signed, purpose: 'invoice', aud: 'FCA\n' }],
    ['into the expiry', { ...signed, exp: '\ninvoice', purpose: 'FCA' }],
    ['into the issue time', { ...signed, iat: signed.iat + '\n', exp: 'invoice', purpose: 'FCA' }],
  ]) {
    assert.deepEqual(await inst.verify(viaJson(envelope)), { valid: false, error: 'malformed envelope' }, name)
  }
  // An unpaired surrogate encodes to the same bytes as U+FFFD.
  const replacement = signEnvelopeV1({ ...base, aud: 'caf�' }, institutionKp.secretKey)
  assert.equal((await inst.verify(viaJson(replacement))).valid, true)
  assert.deepEqual(await inst.verify({ ...replacement, aud: 'caf\uD800' }), { valid: false, error: 'malformed envelope' })
})

test('an envelope expiry that does not parse as a date is treated as expired', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const base = {
    'kxco-identity-attest': '1', payload: Buffer.from('doc').toString('base64url'), iss: inst.kid, iat: new Date().toISOString(),
  }
  for (const envelope of [
    signEnvelopeV1({ ...base, exp: 'never' }, institutionKp.secretKey),
    signEnvelopeV1({ ...base, exp: '2026-13-45' }, institutionKp.secretKey),
    // No expiry was signed, and an empty one reads the same in the message.
    { ...(await inst.attest('doc')), exp: '' },
  ]) {
    assert.deepEqual(await inst.verify(viaJson(envelope)), { valid: false, error: 'expired' }, JSON.stringify(envelope.exp))
  }
})

test('a number that is not finite, anywhere inside authority or metadata, is refused at issue and at verify', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  for (const opts of [
    { authority: [Infinity] }, { authority: ['a', [NaN]] },
    { metadata: { a: -Infinity } }, { metadata: { a: [{ b: NaN }] } },
  ]) {
    await assert.rejects(
      () => inst.issue(userKp.publicKey, { role: 'staff', ...opts }),
      (e) => e instanceof KxcoPqSdkError,
      Object.keys(opts)[0],
    )
  }

  // 1e400 reads as Infinity and writes as null, so it could stand in for a signed null.
  const cred = await inst.issue(userKp.publicKey, {
    role: 'staff', authority: ['sign:x', null], metadata: { a: null, list: [[null]] },
  })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const envelope = await user.attest('doc')
  const text = JSON.stringify(cred)
  const chain = (credential) =>
    KxcoIdentity.verifyChain({ envelope, credential, institutionPublicKey: institutionKp.publicKey })
  assert.equal(chain(JSON.parse(text)).valid, true)
  for (const swapped of [
    text.replace('"a":null', '"a":1e400'),
    text.replace('"sign:x",null', '"sign:x",-1e400'),
    text.replace('[[null]]', '[[1e400]]'),
  ]) {
    assert.notEqual(swapped, text)
    assert.deepEqual(chain(JSON.parse(swapped)), { valid: false, error: 'invalid credential' })
  }
  const envSwapped = JSON.parse(JSON.stringify(envelope).replace('"sign:x",null', '"sign:x",1e400'))
  assert.deepEqual(await user.verify(envSwapped), { valid: false, error: 'malformed envelope' })
})

test('authority and metadata nested to any depth give a result, never a throw, and a number that is not finite at the bottom is refused', async () => {
  const inst = await KxcoIdentity.create({ keypair: institutionKp })
  const cred = await inst.issue(userKp.publicKey, { role: 'staff' })
  const user = KxcoIdentity.fromCredential({ keypair: userKp, credential: cred })
  const enc = new TextEncoder()
  const sign = (secretKey, message) => Buffer.from(mlDsa.sign(secretKey, enc.encode(message)), 'hex').toString('base64url')
  // Written as text throughout, so the test itself never serialises the nesting.
  const depth = 100000
  const nested = (bottom) => '['.repeat(depth) + bottom + ']'.repeat(depth)
  const issuedAt = new Date().toISOString()

  const metadata = (bottom) => `{"a":null,"deep":${nested(bottom)}}`
  const credSignature = sign(institutionKp.secretKey, [
    'kxco-credential-v1', cred.userKid, cred.userPublicKey, inst.kid, 'staff', '[]', metadata('null'), issuedAt, '',
  ].join('\n'))
  const credential = (meta) => JSON.parse(
    `{"kxco-credential":"1","userKid":"${cred.userKid}","userPublicKey":"${cred.userPublicKey}",` +
    `"issuedBy":"${inst.kid}","role":"staff","authority":[],"metadata":${meta},` +
    `"issuedAt":"${issuedAt}","signature":"${credSignature}"}`,
  )
  const payload = Buffer.from('doc').toString('base64url')
  const envSignature = sign(userKp.secretKey, [
    'kxco-identity-attest-v1', payload, cred.userKid, '', '', nested('null'), issuedAt, '', '', '',
  ].join('\n'))
  const envelope = (authority) => JSON.parse(
    `{"kxco-identity-attest":"1","payload":"${payload}","iss":"${cred.userKid}",` +
    `"authority":${authority},"iat":"${issuedAt}","signature":"${envSignature}"}`,
  )
  const plainEnvelope = await user.attest('doc')
  const chain = (c, e = plainEnvelope) => KxcoIdentity.verifyChain({ envelope: e, credential: c, institutionPublicKey: institutionKp.publicKey })

  // As signed. Whether a runtime can serialise this depth decides valid; it never throws.
  assert.equal(typeof chain(credential(metadata('null'))).valid, 'boolean')
  assert.equal(typeof (await user.verify(envelope(nested('null')))).valid, 'boolean')

  assert.deepEqual(chain(credential(metadata('1e400'))), { valid: false, error: 'invalid credential' })
  assert.deepEqual(await user.verify(envelope(nested('-1e400'))), { valid: false, error: 'malformed envelope' })
})

test('an HSM-backed identity exposes its public key too', async () => {
  // Only the SECRET stays behind the hardware boundary. keygen returns the
  // public key, so the verified path works for HSM identities as well, and
  // the getter must agree with the async accessor rather than diverge.
  const pk = new Uint8Array(1952).fill(7)
  const hsm = {
    keygen: async () => ({ publicKey: pk }),
    getPublicKey: async () => pk,
    sign: async () => new Uint8Array(3309),
  }
  const id = await KxcoIdentity.create({ hsm, label: 'probe' })

  assert.equal(id.publicKeyHex, Buffer.from(pk).toString('hex'))
  assert.equal(
    Buffer.from(await id.getPublicKey()).toString('hex'),
    id.publicKeyHex,
    'the getter and the async accessor must not disagree',
  )
})
