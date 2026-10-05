// ML-DSA-87 identities, credentials and envelopes: the key decides the set,
// an ML-DSA-87 record carries its algorithm inside the signed bytes, the other
// set's key is refused, and ML-DSA-65 records made before any of this verify.

import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mlDsa, mlDsa87 as wrapperMlDsa87, mlKem1024 as wrapperMlKem1024, fingerprint } from 'kxco-post-quantum'
import { KxcoIdentity, KxcoPqSdkError, mlDsa87, mlKem1024 } from '../src/index.js'

const LEGACY = JSON.parse(readFileSync(new URL('./fixtures/legacy-65.json', import.meta.url), 'utf-8'))
const verifyChain = (envelope, credential, institutionPublicKey) =>
  KxcoIdentity.verifyChain({ envelope, credential, institutionPublicKey })

let i65, i87, u65, u87
before(() => {
  i65 = mlDsa.ml_dsa65.keygen()
  i87 = wrapperMlDsa87.ml_dsa87.keygen()
  u65 = mlDsa.ml_dsa65.keygen()
  u87 = wrapperMlDsa87.ml_dsa87.keygen()
})

test('mlDsa87 and mlKem1024 are re-exported from kxco-post-quantum', () => {
  assert.equal(mlDsa87, wrapperMlDsa87)
  assert.equal(mlKem1024, wrapperMlKem1024)
})

test("create({ alg: 'ML-DSA-87' }): a random ML-DSA-87 identity", async () => {
  const id = await KxcoIdentity.create({ alg: 'ML-DSA-87' })
  assert.equal(id.alg, 'ML-DSA-87')
  assert.equal((await id.getPublicKey()).length, 2592)
  assert.equal(id.publicKeyHex.length, 2592 * 2)
  assert.equal(id.kid, fingerprint(await id.getPublicKey()))
})

test('create: ML-DSA-65 stays the default, and a keypair decides its own set', async () => {
  assert.equal((await KxcoIdentity.create()).alg, 'ML-DSA-65')
  assert.equal((await KxcoIdentity.create({ keypair: i87 })).alg, 'ML-DSA-87')
  assert.equal((await KxcoIdentity.create({ keypair: i65 })).alg, 'ML-DSA-65')
})

test('create: an alg that disagrees with the keypair, or names neither set, is refused', async () => {
  await assert.rejects(KxcoIdentity.create({ keypair: i65, alg: 'ML-DSA-87' }), KxcoPqSdkError)
  await assert.rejects(KxcoIdentity.create({ keypair: i87, alg: 'ML-DSA-65' }), KxcoPqSdkError)
  await assert.rejects(KxcoIdentity.create({ alg: 'ML-DSA-44' }), KxcoPqSdkError)
})

test("create({ hsm, alg: 'ML-DSA-87' }): asks the hsm for ml-dsa-87 and refuses a key of another set", async () => {
  const asked = []
  const hsm = (kp) => ({
    keygen: async (label, alg) => { asked.push(alg); return { publicKey: kp.publicKey } },
    getPublicKey: async () => kp.publicKey,
    sign: async (label, message) => Buffer.from(wrapperMlDsa87.sign(kp.secretKey, message), 'hex'),
  })
  const id = await KxcoIdentity.create({ hsm: hsm(i87), label: 'k', alg: 'ML-DSA-87' })
  assert.deepEqual(asked, ['ml-dsa-87'])
  assert.equal(id.alg, 'ML-DSA-87')
  const env = await id.attest('from the hsm')
  assert.equal(env.alg, 'ML-DSA-87')
  assert.equal((await id.verify(env)).valid, true)
  await assert.rejects(KxcoIdentity.create({ hsm: hsm(i65), label: 'k', alg: 'ML-DSA-87' }), KxcoPqSdkError)
})

test('attest: an ML-DSA-87 identity signs an envelope that names ML-DSA-87 and verifies', async () => {
  const id = await KxcoIdentity.create({ keypair: i87 })
  const env = await id.attest('category five', { purpose: 'test' })
  assert.equal(env.alg, 'ML-DSA-87')
  assert.equal(Buffer.from(env.signature, 'base64url').length, 4627)
  const r = await id.verify(env)
  assert.equal(r.valid, true)
  assert.equal(r.alg, 'ML-DSA-87')
  assert.equal(Buffer.from(r.payload).toString(), 'category five')
})

test('attest: an ML-DSA-65 identity keeps the v1 envelope, with no alg field', async () => {
  const id = await KxcoIdentity.create({ keypair: i65 })
  const env = await id.attest('category three')
  assert.equal(Object.hasOwn(env, 'alg'), false)
  const r = await id.verify(env)
  assert.equal(r.valid, true)
  assert.equal(r.alg, 'ML-DSA-65')
})

test('envelope: the alg field is inside the signed bytes', async () => {
  const id = await KxcoIdentity.create({ keypair: i87 })
  const env = await id.attest('category five')
  // Stripped, the envelope reads as v1 / ML-DSA-65, which the ML-DSA-87 key refuses.
  const { alg, ...stripped } = env
  assert.equal(alg, 'ML-DSA-87')
  assert.deepEqual(await id.verify(stripped), { valid: false, error: 'algorithm does not match key' })
  // Restated as ML-DSA-65 and checked against an ML-DSA-65 key: the set agrees,
  // the signature cannot.
  const other = await KxcoIdentity.create({ keypair: i65 })
  assert.deepEqual(await other.verify({ ...env, alg: 'ML-DSA-65' }), { valid: false, error: 'signature invalid' })
})

test('envelope: a key of the other set is refused, not tried', async () => {
  const id87 = await KxcoIdentity.create({ keypair: i87 })
  const id65 = await KxcoIdentity.create({ keypair: i65 })
  assert.deepEqual(await id65.verify(await id87.attest('x')), { valid: false, error: 'algorithm does not match key' })
  assert.deepEqual(await id87.verify(await id65.attest('x')), { valid: false, error: 'algorithm does not match key' })
})

test('attest: a context field may not claim to be the signing algorithm', async () => {
  const id = await KxcoIdentity.create({ keypair: i65 })
  await assert.rejects(id.attest('x', { context: { alg: 'ML-DSA-87' } }), KxcoPqSdkError)
  // A context alg that names neither set stays an ordinary unsigned field, as before.
  const env = await id.attest('x', { context: { alg: 'sha256' } })
  assert.equal(env.alg, 'sha256')
  assert.equal((await id.verify(env)).valid, true)
})

test('issue: an ML-DSA-87 institution records its alg in the credential, and the chain verifies', async () => {
  const inst = await KxcoIdentity.create({ keypair: i87 })
  const cred = await inst.issue(u87.publicKey, { role: 'signer', authority: ['sign:x'] })
  assert.equal(cred.alg, 'ML-DSA-87')
  assert.equal(Buffer.from(cred.signature, 'base64url').length, 4627)
  const user = KxcoIdentity.fromCredential({ keypair: u87, credential: cred })
  assert.equal(user.alg, 'ML-DSA-87')
  const env = await user.attest('as an -87 user')
  const r = verifyChain(env, cred, i87.publicKey)
  assert.equal(r.valid, true)
  assert.equal(r.alg, 'ML-DSA-87')
  assert.equal(r.role, 'signer')
})

test('issue: the sets mix freely between institution and user, each key deciding its own', async () => {
  const inst65 = await KxcoIdentity.create({ keypair: i65 })
  const cred = await inst65.issue(u87.publicKey, { role: 'signer' })
  assert.equal(Object.hasOwn(cred, 'alg'), false, 'an ML-DSA-65 issuer keeps the v1 credential')
  const user = KxcoIdentity.fromCredential({ keypair: u87, credential: cred })
  assert.equal(verifyChain(await user.attest('x'), cred, i65.publicKey).valid, true)

  const inst87 = await KxcoIdentity.create({ keypair: i87 })
  const cred2 = await inst87.issue(u65.publicKey, { role: 'signer' })
  const user2 = KxcoIdentity.fromCredential({ keypair: u65, credential: cred2 })
  assert.equal(verifyChain(await user2.attest('x'), cred2, i87.publicKey).valid, true)
})

test('verifyChain: an institution key of the other set from the credential is refused', async () => {
  const inst = await KxcoIdentity.create({ keypair: i87 })
  const cred = await inst.issue(u65.publicKey, { role: 'signer' })
  const user = KxcoIdentity.fromCredential({ keypair: u65, credential: cred })
  const env = await user.attest('x')
  assert.deepEqual(verifyChain(env, cred, i65.publicKey),
    { valid: false, error: 'credential algorithm does not match the institution key' })
  // The alg is signed: stripping it from an ML-DSA-87 credential does not pass
  // it off as ML-DSA-65.
  const { alg, ...stripped } = cred
  assert.equal(alg, 'ML-DSA-87')
  assert.deepEqual(verifyChain(env, stripped, i87.publicKey),
    { valid: false, error: 'credential algorithm does not match the institution key' })
  assert.deepEqual(verifyChain(env, stripped, i65.publicKey),
    { valid: false, error: 'credential signature invalid' })
})

test('records made by 2.0.5, before ML-DSA-87, still verify', async () => {
  const instKey = Buffer.from(LEGACY.institutionPublicKey, 'hex')
  assert.equal(Object.hasOwn(LEGACY.credential, 'alg'), false)
  const r = verifyChain(LEGACY.envelope, LEGACY.credential, instKey)
  assert.equal(r.valid, true)
  assert.equal(r.alg, 'ML-DSA-65')
  assert.equal(r.purpose, 'legacy-fixture')
  assert.deepEqual(r.metadata, { desk: 'legacy' })

  const inst = await KxcoIdentity.create({ keypair: { publicKey: instKey } })
  const own = await inst.verify(LEGACY.instEnvelope)
  assert.equal(own.valid, true)
  assert.equal(own.alg, 'ML-DSA-65')

  // The same records against an ML-DSA-87 key are refused for the set, not tried.
  assert.deepEqual(verifyChain(LEGACY.envelope, LEGACY.credential, i87.publicKey),
    { valid: false, error: 'credential algorithm does not match the institution key' })
})

// The bytes themselves, rebuilt from the published layout, so another
// implementation can produce them: v1.1 replaces the first line and puts the
// algorithm on the second, and the rest is the v1 message unchanged.
const lines = (...xs) => new TextEncoder().encode(xs.join('\n'))
const sigHex = (b64) => Buffer.from(b64, 'base64url').toString('hex')

test('wire format: an ML-DSA-87 envelope is signed over kxco-identity-attest-v1.1 with the algorithm on line 2', async () => {
  const id = await KxcoIdentity.create({ keypair: i87 })
  const e = await id.attest('bytes', { purpose: 'p', aud: 'a' })
  const rest = [e.payload, e.iss, e.parent_kid ?? '', e.role ?? '', JSON.stringify(e.authority ?? []),
    e.iat, e.exp ?? '', e.purpose ?? '', e.aud ?? '']
  assert.equal(wrapperMlDsa87.verify(i87.publicKey, lines('kxco-identity-attest-v1.1', 'ML-DSA-87', ...rest), sigHex(e.signature)), true)
  assert.equal(wrapperMlDsa87.verify(i87.publicKey, lines('kxco-identity-attest-v1', ...rest), sigHex(e.signature)), false)
})

test('wire format: an ML-DSA-87 credential is signed over kxco-credential-v1.1 with the algorithm on line 2', async () => {
  const inst = await KxcoIdentity.create({ keypair: i87 })
  const c = await inst.issue(u65.publicKey, { role: 'r', authority: ['x'], metadata: { m: 1 } })
  const rest = [c.userKid, c.userPublicKey, c.issuedBy, c.role, JSON.stringify(c.authority ?? []),
    JSON.stringify(c.metadata ?? {}), c.issuedAt, c.expiresAt ?? '']
  assert.equal(wrapperMlDsa87.verify(i87.publicKey, lines('kxco-credential-v1.1', 'ML-DSA-87', ...rest), sigHex(c.signature)), true)
  assert.equal(wrapperMlDsa87.verify(i87.publicKey, lines('kxco-credential-v1', ...rest), sigHex(c.signature)), false)
})
