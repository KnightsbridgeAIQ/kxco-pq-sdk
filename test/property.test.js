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

// What a caller hands to issue(), and what a holder signs, empty data
// included. A role is one line of text: issue() refuses a line break, and a
// property below covers that.
const master = fc.uint8Array({ minLength: 32, maxLength: 32 })
const role = fc.string({ minLength: 1, maxLength: 40, unit: 'binary', size: 'max' }).filter((r) => !/[\r\n]/.test(r))
const authority = fc.array(fc.string({ maxLength: 30, unit: 'binary' }), { maxLength: 4 })
const metadata = fc.dictionary(fc.string({ maxLength: 12 }), fc.jsonValue({ maxDepth: 2 }), { maxKeys: 4 })
const payload = fc.oneof(
  fc.constantFrom('', new Uint8Array(0)),
  fc.string({ maxLength: 200, unit: 'binary', size: 'max' }),
  fc.uint8Array({ maxLength: 2048, size: 'max' }),
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

test('issue then verifyChain: any credential verifies offline, through JSON, with any data its holder signs', async () => {
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

test('verifyChain: any changed credential field is refused, in value or in JSON type', async () => {
  const fields = [
    'userKid', 'userPublicKey', 'issuedBy', 'role', 'authority', 'metadata', 'issuedAt', 'expiresAt', 'signature', 'version',
    // The same value as another JSON type, or absent where issue() writes it.
    'role as a list', 'userKid as a list', 'issuedAt as a list', 'authority as null', 'authority removed',
    'metadata as null', 'metadata removed', 'expiresAt as another type',
  ]
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
        case 'role as a list': c.role = [c.role]; break
        case 'userKid as a list': c.userKid = [c.userKid]; break
        case 'issuedAt as a list': c.issuedAt = [c.issuedAt]; break
        case 'authority as null': c.authority = null; break
        case 'authority removed': delete c.authority; break
        case 'metadata as null': c.metadata = null; break
        case 'metadata removed': delete c.metadata; break
        // Absent reads as empty text in the message; present, it becomes a list.
        case 'expiresAt as another type': c.expiresAt = c.expiresAt === undefined ? '' : [c.expiresAt]; break
      }
      fc.pre(JSON.stringify(c) !== JSON.stringify(viaJson(credential)))
      const result = verifyChain(envelope, viaJson(c))
      return result.valid === false && typeof result.error === 'string'
    }), RUNS)
})

test('envelopes: any data attested verifies under its signer, not under another key, and any changed signed field is refused, in value or in JSON type', async () => {
  const fields = [
    'payload', 'iss', 'iat', 'exp', 'purpose', 'aud', 'role', 'authority', 'parent_kid', 'signature', 'version',
    'payload as a list', 'iat as a list', 'role as a list', 'authority as null', 'purpose as a list',
  ]
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
        case 'payload as a list': e.payload = [e.payload]; break
        case 'iat as a list': e.iat = [e.iat]; break
        // The institution signs with no role, which reads as empty text.
        case 'role as a list': e.role = [e.role ?? '']; break
        case 'authority as null': e.authority = null; break
        case 'purpose as a list': e.purpose = [e.purpose ?? '']; break
      }
      // Empty data has no byte to flip.
      fc.pre(JSON.stringify(e) !== JSON.stringify(envelope))
      const bad = await institution.verify(viaJson(e))
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

// The credential signing message, version 1, as issuers have always written it.
function credentialMessage(c) {
  return new TextEncoder().encode([
    'kxco-credential-v1', c.userKid, c.userPublicKey, c.issuedBy, c.role,
    JSON.stringify(c.authority ?? []), JSON.stringify(c.metadata ?? {}), c.issuedAt, c.expiresAt ?? '',
  ].join('\n'))
}

// A line break inside a text field is the one way two different credentials
// could share a signing message. So issue() refuses one, and a credential an
// issuer signed over one anyway never verifies, however the signed text is
// split back into the eight fields.
test('a role holding a line break is refused at issue, and a credential signed over one never verifies, however its text is split into fields', async () => {
  const lineBreak = fc.constantFrom('\n', '\r', '\r\n')
  const piece = fc.string({ maxLength: 12 })
  const brokenRole = fc.tuple(piece, fc.array(fc.tuple(lineBreak, piece), { minLength: 1, maxLength: 3 }))
    .map(([head, rest]) => head + rest.map(([b, s]) => b + s).join(''))
  const { keypair, credential: genuine } = await enrol(new Uint8Array(32).fill(9), { role: 'staff' })
  const envelope = await KxcoIdentity.fromCredential({ keypair, credential: genuine }).attest('a document')
  // One rank per line boundary; the seven highest-ranked boundaries are the cuts.
  const ranks = fc.array(fc.nat(), { minLength: 16, maxLength: 16 })
  await fc.assert(fc.asyncProperty(brokenRole, authority, fc.boolean(), ranks,
    async (r, a, expires, rank) => {
      await assert.rejects(
        () => institution.issue(keypair.publicKey, { role: r, authority: a }),
        (e) => e.name === 'KxcoPqSdkError',
      )
      const fields = {
        userKid: genuine.userKid, userPublicKey: genuine.userPublicKey, issuedBy: institution.kid,
        role: r, authority: a, metadata: {}, issuedAt: genuine.issuedAt,
        ...(expires ? { expiresAt: new Date(Date.now() + 86400000).toISOString() } : {}),
      }
      const message = credentialMessage(fields)
      const signature = b64url(Buffer.from(mlDsa.sign(INSTITUTION.secretKey, message), 'hex'))
      const signed = { 'kxco-credential': '1', ...fields, signature }

      // The same text after the version line, cut into eight fields at other line breaks.
      const lines = new TextDecoder().decode(message).split('\n').slice(1)
      const at = Array.from({ length: lines.length - 1 }, (_, i) => i + 1)
        .sort((x, y) => rank[y - 1] - rank[x - 1] || x - y).slice(0, 7).sort((x, y) => x - y)
      const parts = [0, ...at].map((from, i) => lines.slice(from, [...at, lines.length][i]).join('\n'))
      const json = (text) => { try { return JSON.parse(text) } catch { return text } }
      const resplit = {
        'kxco-credential': '1',
        userKid: parts[0], userPublicKey: parts[1], issuedBy: parts[2], role: parts[3],
        authority: json(parts[4]), metadata: json(parts[5]), issuedAt: parts[6],
        ...(parts[7] === '' ? {} : { expiresAt: parts[7] }),
        signature,
      }
      return verifyChain(envelope, viaJson(signed)).valid === false &&
        verifyChain(envelope, viaJson(resplit)).valid === false
    }), RUNS)
})

// The envelope signing message, version 1, as attest has always written it.
function envelopeMessage(e) {
  return new TextEncoder().encode([
    'kxco-identity-attest-v1', e.payload, e.iss, e.parent_kid ?? '', e.role ?? '',
    JSON.stringify(e.authority ?? []), e.iat, e.exp ?? '', e.purpose ?? '', e.aud ?? '',
  ].join('\n'))
}

test('a purpose, audience or expiry holding a line break is refused at attest, and an envelope signed over one never verifies, however its text is split into fields', async () => {
  const lineBreak = fc.constantFrom('\n', '\r', '\r\n')
  const piece = fc.string({ maxLength: 12 })
  const broken = fc.tuple(piece, fc.array(fc.tuple(lineBreak, piece), { minLength: 1, maxLength: 3 }))
    .map(([head, rest]) => head + rest.map(([b, s]) => b + s).join(''))
  // One rank per line boundary; the eight highest-ranked boundaries are the cuts.
  const ranks = fc.array(fc.nat(), { minLength: 16, maxLength: 16 })
  await fc.assert(fc.asyncProperty(fc.constantFrom('purpose', 'aud', 'exp'), broken, ranks, async (field, text, rank) => {
    await assert.rejects(() => institution.attest('a document', { [field]: text }), (e) => e.name === 'KxcoPqSdkError')
    const fields = {
      'kxco-identity-attest': '1', payload: b64url(Buffer.from('a document')), iss: institution.kid,
      iat: new Date().toISOString(), [field]: text,
    }
    const message = envelopeMessage(fields)
    const signed = { ...fields, signature: b64url(Buffer.from(mlDsa.sign(INSTITUTION.secretKey, message), 'hex')) }

    // The same text after the version line, cut into nine fields at other line breaks.
    const lines = new TextDecoder().decode(message).split('\n').slice(1)
    const at = Array.from({ length: lines.length - 1 }, (_, i) => i + 1)
      .sort((x, y) => rank[y - 1] - rank[x - 1] || x - y).slice(0, 8).sort((x, y) => x - y)
    const parts = [0, ...at].map((from, i) => lines.slice(from, [...at, lines.length][i]).join('\n'))
    const json = (value) => { try { return JSON.parse(value) } catch { return value } }
    const optional = (value) => (value === '' ? undefined : value)
    const resplit = {
      'kxco-identity-attest': '1', payload: parts[0], iss: parts[1], parent_kid: optional(parts[2]),
      role: optional(parts[3]), authority: json(parts[4]), iat: parts[5], exp: optional(parts[6]),
      purpose: optional(parts[7]), aud: optional(parts[8]), signature: signed.signature,
    }
    return (await institution.verify(viaJson(signed))).valid === false &&
      (await institution.verify(viaJson(resplit))).valid === false
  }), RUNS)
})

// 1e400 reads as Infinity and writes as null, so it could stand in for a signed null.
test('verifyChain: a null anywhere in authority or metadata, swapped for a number too large for a double, is refused', async () => {
  const withNull = fc.array(fc.oneof(fc.string({ maxLength: 10 }), fc.constant(null)), { minLength: 1, maxLength: 4 })
  const metadataWithNull = metadata.map((md) => ({ ...md, unset: null }))
  await fc.assert(fc.asyncProperty(master, withNull, metadataWithNull, fc.nat(), fc.constantFrom('1e400', '-1e400'),
    async (m, a, md, at, large) => {
      const { credential, user } = await enrol(m, { role: 'staff', authority: a, metadata: md })
      const envelope = await user.attest('a document')
      const text = JSON.stringify(credential)
      const spots = [...text.matchAll(/(?<=[[,:])null(?=[\],}])/g)].map((match) => match.index)
      const i = spots[at % spots.length]
      const swapped = text.slice(0, i) + large + text.slice(i + 4)
      return verifyChain(envelope, JSON.parse(text)).valid === true &&
        verifyChain(envelope, JSON.parse(swapped)).valid === false
    }), RUNS)
})

test('fail closed: arbitrary JSON as a credential or an envelope never verifies, and never throws', async () => {
  const { credential, user } = await enrol(new Uint8Array(32).fill(8), { role: 'staff', authority: ['sign:x'] })
  const envelope = await user.attest('a document')
  // Any JSON value, and objects that carry their own toString, which a field
  // read as text would call.
  const junk = fc.oneof(
    fc.jsonValue({ maxDepth: 2 }),
    fc.constantFrom({ toString: null }, { toString: 1 }, [{ toString: 1 }], { valueOf: null, toString: null }),
  )
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
    if (verifyChain(viaJson(e), viaJson(c)).valid !== false) return false
    return e === envelope || (await user.verify(viaJson(e))).valid === false
  }), { numRuns: 200 })
})
