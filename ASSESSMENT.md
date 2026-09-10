# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

Institution identity for the KXCO stack, and the place where custody, audit,
attestation and verification are wired together correctly so a deployment does
not have to.

Two properties are this package's own, and they are the reason to use it rather
than assemble the parts by hand:

**Hierarchical credentials.** An institution key issues subordinate credentials
instead of being handed round. A subordinate compromise does not yield the
institution key, and a subordinate can be revoked without re-keying the
institution. That is the difference between one key with many copies and an
identity with a structure.

**`AuditedHsm` binds signing to the record.** A signature made through this path
is written to the audit log by construction, not because the caller remembered
to. The failure mode it removes is the common one: the signature that happened
and was never recorded. Wiring custody to the log at the type level rather than
in a runbook is a control, and it is one this package enforces rather than
recommends.

Underneath, each concern is owned by the package built for it, and each is
assessed there:

| Concern | Owner |
|---|---|
| Key custody, on token or in memory | `kxco-pq-hsm` |
| A record whose tampering is detectable | `kxco-pq-audit` |
| An envelope that verifies offline | `kxco-pq-attest` |
| Whether a key is still trusted | `kxco-pq-network` |
| That the algorithms are correct | `kxco-post-quantum` |

That is a composed stack rather than a monolith, and it is why a buyer can
assess exactly the part their control framework cares about instead of taking
the whole thing on faith.

## Scope

This package is the composition. Its properties are largely the properties of
what it composes, which is a feature of the design and a fact worth knowing when
scoping a review: read the owner of each concern alongside this, and a claim
that is really about custody gets checked against the custody package.

Nothing in `src/` opens a socket. Chain and registry calls go through
`kxco-pq-network` and `kxco-pq-chain`, which reach `chain.kxco.ai` and
`relay.kxco.ai`; both negotiate the hybrid key exchange group `X25519MLKEM768`
under TLS 1.3, measured 7 September 2026 with OpenSSL 3.5.6.

**Rotation is handled end to end.** Hierarchical credentials exist so keys can
change, and the audit log verifies across a rotation: entries record the kid
that signed them and `verify()` takes every key the log was signed under. The
piece that most often breaks in a composed identity system works here.

## Agility

**Inherited twice over.** Primitives from `kxco-post-quantum`; format decisions
from whichever sibling owns the artefact. This package introduces no wire format
of its own, so it adds no migration surface of its own.

**The composition is where a migration is sequenced**, and this is the package
that shows the order: primitives, then the packages that own formats, then the
chain and relay that must accept them, then this. Assembling that sequence is
the work; having one place where the assembly is expressed is the point of this
package existing.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation and
a CycloneDX SBOM at a permanent unauthenticated URL, plus an evidence bundle
from `npm run evidence` recording identity, the test run, the SBOM and the
`kxco-post-quantum` version actually installed rather than the range declared.
`04-sbom.cyclonedx.json` in that bundle is the file that describes exactly which
versions of the five dependencies were assessed together.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** No hardware ceiling of its own. With `Pkcs11Backend` the token's
firmware decides which mechanisms exist, which is the one place in the family
where a date depends on a vendor; see `kxco-pq-hsm`.

**Runtime.** Node 20.19 and later, with Node 24 and later running the primitives
in OpenSSL 3.5 for roughly 4x to 8x per operation.

## Correcting this document

Every claim here is checkable against `src/` and the sibling repositories. If one
does not match, that is a defect worth reporting through the repository's issues.
