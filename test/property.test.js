// Property-based tests with fast-check.
//
// The example tests beside this file issue a handful of credentials and check
// each one. These ask what has to hold for ANY credential an institution
// issues and ANY envelope a holder signs: that the whole chain verifies
// offline, that a change to anything the signatures cover is refused, that
// expiry is enforced to the millisecond, and that input which is not a signed
// credential or envelope never verifies. fast-check
// generates the inputs and, when a property breaks, shrinks the failing case
// to the smallest one that still breaks it.
//
// No chain: nothing here passes a `chain`, so nothing reaches a network.

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { KxcoIdentity, mlDsa, fingerprint } from '../src/index.js'

// Every case signs at least once, so the run counts stay modest.
const RUNS = { numRuns: 20 }

const INSTITUTION = mlDsa.keypairFromMaster(new Uint8Array(32).fill(5), 'kxco-pq-sdk-property-tests-institution')
const STRANGER = mlDsa.keypairFromMaster(new Uint8Array(32).fill(6), 'kxco-pq-sdk-property-tests-stranger')
const institution = await KxcoIdentity.create({ keypair: INSTITUTION })
const stranger = await KxcoIdentity.create({ keypair: STRANGER })

const b64url = (bytes) => Buffer.from(bytes).toString('base64url')
const viaJson = (value) => JSON.parse(JSON.stringify(value))

// What a caller hands to issue(), and what a holder signs. Payloads are
// never empty here: the round trip is stated for data with at least one byte.
const master = fc.uint8Array({ minLength: 32, maxLength: 32 })
const role = fc.string({ minLength: 1, maxLength: 40, unit: 'binary' })
const authority = fc.array(fc.string({ maxLength: 30, unit: 'binary' }), { maxLength: 4 })
const metadata = fc.dictionary(fc.string({ maxLength: 12 }), fc.jsonValue({ maxDepth: 2 }), { maxKeys: 4 })
const payload = fc.oneof(
  fc.string({ minLength: 1, maxLength: 200, unit: 'binary' }),
  fc.uint8Array({ minLength: 1, maxLength: 2048 }),
  fc.dictionary(fc.string({ maxLength: 12 }), fc.jsonValue({ maxDepth: 2 }), { maxKeys: 4 }),
)
const purpose = fc.option(fc.string({ minLength: 1, maxLength: 30 }), { nil: undefined })
const aud = fc.option(fc.string({ minLength: 1, maxLength: 30 }), { nil: undefined })

// The bytes attest() signs for a given piece of data.
function bytesOf(data) {
  if (typeof data === 'string') return Buffer.from(new TextEncoder().encode(data))
  if (data instanceof Uint8Array) return Buffer.from(data)
  return Buffer.from(JSON.stringify(data))
}

// Change one hex digit to a different value.
function changeDigit(hexValue, at, by) {
  const i = at % hexValue.length
  const next = ((parseInt(hexValue[i], 16) + 1 + (by % 15)) % 16).toString(16)
  return hexValue.slice(0, i) + next + hexValue.slice(i + 1)
}

// Flip one bit of a base64url value.
function flipBit(value, at, bit) {
  const bytes = Buffer.from(value, 'base64url')
  bytes[at % bytes.length] ^= 1 << bit
  return bytes.toString('base64url')
}

// One user: a keypair, a credential issued to it, and the identity it
// reconstructs from the two.
async function enrol(m, opts) {
  const keypair = mlDsa.keypairFromMaster(m, 'kxco-pq-sdk-property-tests-user')
  const credential = await institution.issue(keypair.publicKey, opts)
  return { keypair, credential, user: KxcoIdentity.fromCredential({ keypair, credential }) }
}

const verifyChain = (envelope, credential, institutionPublicKey = INSTITUTION.publicKey) =>
  KxcoIdentity.verifyChain({ envelope, credential, institutionPublicKey })

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('issue then verifyChain: any credential verifies offline, through JSON, with any non-empty data its holder signs', async () => {
  await fc.assert(fc.asyncProperty(master, role, authority, metadata, payload, purpose, aud,
    async (m, r, a, md, data, p, au) => {
      const { keypair, credential, user } = await enrol(m, { role: r, authority: a, metadata: md })
      const envelope = await user.attest(data, { purpose: p, aud: au })
      const result = verifyChain(viaJson(envelope), viaJson(credential))
      assert.equal(result.valid, true, result.error)
      assert.ok(Buffer.from(result.payload).equals(bytesOf(data)))
      assert.equal(result.role, r)
      assert.deepEqual(result.authority, a)
      assert.equal(JSON.stringify(result.metadata), JSON.stringify(md))
      assert.equal(result.issuedBy, institution.kid)
      assert.equal(result.iss, fingerprint(keypair.publicKey))
      assert.equal(result.purpose, p)
      assert.equal(result.aud, au)
      assert.equal(verifyChain(envelope, credential, STRANGER.publicKey).valid, false, 'another institution key')
      return true
    }), RUNS)
})

test('verifyChain: any changed credential field is refused', async () => {
  const fields = ['userKid', 'userPublicKey', 'issuedBy', 'role', 'authority', 'metadata', 'issuedAt', 'expiresAt', 'signature', 'version']
  await fc.assert(fc.asyncProperty(master, role, authority, metadata, fc.boolean(), fc.constantFrom(...fields),
    fc.string({ minLength: 1, maxLength: 8 }), fc.nat(), fc.nat(7),
    async (m, r, a, md, expires, field, text, at, bit) => {
      const { credential, user } = await enrol(m, { role: r, authority: a, metadata: md, ...(expires ? { expiresIn: '30d' } : {}) })
      const envelope = await user.attest('a document')
      const c = viaJson(credential)
      switch (field) {
        case 'userKid': c.userKid = changeDigit(c.userKid, at, bit); break
        case 'userPublicKey': c.userPublicKey = b64url(STRANGER.publicKey); break
        case 'issuedBy': c.issuedBy = changeDigit(c.issuedBy, at, bit); break
        case 'role': c.role += text; break
        case 'authority': c.authority = [...c.authority, text]; break
        case 'metadata': c.metadata = { ...c.metadata, ['k_' + text]: text }; break
        case 'issuedAt': c.issuedAt = new Date(Date.parse(c.issuedAt) + 1 + at).toISOString(); break
        case 'expiresAt': c.expiresAt = new Date(Date.parse(c.expiresAt ?? c.issuedAt) + 86400000 + at).toISOString(); break
        case 'signature': c.signature = flipBit(c.signature, at, bit); break
        case 'version': c['kxco-credential'] += text; break
      }
      fc.pre(JSON.stringify(c) !== JSON.stringify(viaJson(credential)))
      const result = verifyChain(envelope, c)
      return result.valid === false && typeof result.error === 'string'
    }), RUNS)
})

test('envelopes: any non-empty data attested verifies under its signer, not under another key, and any changed signed field is refused', async () => {
  const fields = ['payload', 'iss', 'iat', 'exp', 'purpose', 'aud', 'role', 'authority', 'parent_kid', 'signature', 'version']
  await fc.assert(fc.asyncProperty(payload, purpose, aud, fc.constantFrom(...fields),
    fc.string({ minLength: 1, maxLength: 8 }), fc.nat(), fc.nat(7),
    async (data, p, au, field, text, at, bit) => {
      const envelope = viaJson(await institution.attest(data, { purpose: p, aud: au }))
      const good = await institution.verify(envelope)
      assert.equal(good.valid, true, good.error)
      assert.ok(Buffer.from(good.payload).equals(bytesOf(data)))
      assert.equal(good.iss, institution.kid)
      assert.equal((await stranger.verify(envelope)).valid, false, 'another key')

      const e = viaJson(envelope)
      const future = new Date(Date.now() + 86400000 + at).toISOString()
      switch (field) {
        case 'payload': e.payload = flipBit(e.payload, at, bit); break
        case 'iss': e.iss = changeDigit(e.iss, at, bit); break
        case 'iat': e.iat = new Date(Date.parse(e.iat) + 1 + at).toISOString(); break
        case 'exp': e.exp = future; break
        case 'purpose': e.purpose = (e.purpose ?? '') + text; break
        case 'aud': e.aud = (e.aud ?? '') + text; break
        case 'role': e.role = text; break
        case 'authority': e.authority = [text]; break
        case 'parent_kid': e.parent_kid = changeDigit(institution.kid, at, bit); break
        case 'signature': e.signature = flipBit(e.signature, at, bit); break
        case 'version': e['kxco-identity-attest'] += text; break
      }
      const bad = await institution.verify(e)
      return bad.valid === false && typeof bad.error === 'string'
    }), RUNS)
})

test('expiry: a credential or an envelope is refused from the first millisecond after it expires, and not before', async () => {
  const duration = fc.tuple(fc.nat(1000), fc.constantFrom(['s', 1000], ['m', 60000], ['h', 3600000], ['d', 86400000]))
  const start = fc.integer({ min: Date.parse('2001-01-01'), max: Date.parse('2090-01-01') })
  await fc.assert(fc.asyncProperty(master, start, duration, fc.integer({ min: 1, max: 86400000 }),
    async (m, t0, [n, [unit, ms]], extra) => {
      const credentialEnd = t0 + n * ms
      // The envelope outlives the credential, so each expiry is seen on its own.
      const envelopeEnd = credentialEnd + extra
      mock.timers.enable({ apis: ['Date'], now: t0 })
      try {
        const { credential, user } = await enrol(m, { role: 'staff', expiresIn: `${n}${unit}` })
        const envelope = await user.attest('a document', { exp: new Date(envelopeEnd).toISOString() })
        assert.equal(Date.parse(credential.expiresAt), credentialEnd)

        assert.equal(verifyChain(envelope, credential).valid, true, 'at issue')
        mock.timers.tick(n * ms)
        assert.equal(verifyChain(envelope, credential).valid, true, 'at the instant the credential expires')
        mock.timers.tick(1)
        assert.deepEqual(verifyChain(envelope, credential), { valid: false, error: 'credential expired' })

        mock.timers.tick(extra - 1)
        assert.equal((await user.verify(envelope)).valid, true, 'at the instant the envelope expires')
        mock.timers.tick(1)
        assert.deepEqual(await user.verify(envelope), { valid: false, error: 'expired' })
        return true
      } finally {
        mock.timers.reset()
      }
    }), RUNS)
})

test('fail closed: arbitrary JSON as a credential or an envelope never verifies', async () => {
  const { credential, user } = await enrol(new Uint8Array(32).fill(8), { role: 'staff', authority: ['sign:x'] })
  const envelope = await user.attest('a document')
  const junk = fc.jsonValue({ maxDepth: 2 })
  // A signature-sized value, so a forged object reaches the real verifier.
  const signature = fc.oneof(junk, fc.uint8Array({ minLength: 3309, maxLength: 3309 }).map(b64url))
  // Objects that carry the right version tag, with every other field arbitrary.
  const forgedCredential = fc.record({
    'kxco-credential': fc.constant('1'),
    userKid: fc.oneof(junk, fc.constant(credential.userKid)),
    userPublicKey: fc.oneof(junk, fc.constant(credential.userPublicKey)),
    issuedBy: fc.oneof(junk, fc.constant(institution.kid)),
    role: junk, authority: junk, metadata: junk, issuedAt: junk,
    expiresAt: junk,
    signature,
  }, { requiredKeys: ['kxco-credential', 'signature'] })
  const forgedEnvelope = fc.record({
    'kxco-identity-attest': fc.constant('1'),
    payload: junk,
    iss: fc.oneof(junk, fc.constant(credential.userKid)),
    iat: junk, exp: junk, role: junk, authority: junk, parent_kid: junk, purpose: junk, aud: junk,
    signature,
  }, { requiredKeys: ['kxco-identity-attest', 'iss', 'signature'] })
  const anyCredential = fc.oneof(junk, forgedCredential)
  const anyEnvelope = fc.oneof(junk, forgedEnvelope)
  await fc.assert(fc.asyncProperty(fc.oneof(
    fc.tuple(anyCredential, fc.constant(envelope)),
    fc.tuple(fc.constant(credential), anyEnvelope),
    fc.tuple(anyCredential, anyEnvelope),
  ), async ([c, e]) => {
    // A call that throws has not verified anything either.
    const outcome = async (call) => { try { return (await call()).valid } catch { return false } }
    if (await outcome(() => verifyChain(viaJson(e), viaJson(c))) !== false) return false
    return e === envelope || await outcome(() => user.verify(viaJson(e))) === false
  }), { numRuns: 200 })
})
