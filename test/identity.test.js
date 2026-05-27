import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { mlDsa } from 'kxco-post-quantum'
import { KxcoIdentity, AuditedHsm, AuditLog, PqHsm, MemoryBackend } from '../src/index.js'

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
