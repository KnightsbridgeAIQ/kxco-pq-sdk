# Assessment notes

Where this package's boundary falls, what agility it has, and what constrains
its lifecycle.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) and is
published in that package's evidence bundle. It is referenced here, never
restated.

## Boundary

**What the assessed thing is, and why it is the hardest one to scope.** This
package is a composition. It binds institution identity to HSM custody, an
audit log, attestation and the verification modes, and it depends on four
sibling packages to do it. Almost nothing here is a primitive operation; almost
everything is an arrangement of other packages' operations.

The practical consequence for an assessment: **assessing this package alone
tells a buyer very little.** Its properties are mostly the properties of what
it composes, and those are assessed in their own repositories:

| Concern | Where it is actually decided |
|---|---|
| Key custody, on-token or in memory | `kxco-pq-hsm` |
| Whether the record survives tampering | `kxco-pq-audit` |
| Whether an envelope verifies offline | `kxco-pq-attest` |
| Whether a revoked key is caught | `kxco-pq-network` |
| Whether the algorithms are correct | `kxco-post-quantum` |

Read those alongside this. A claim made about this package that is really a
claim about one of them should be checked against that package's own notes.

**What the composition itself contributes.** Two things, and they are the parts
worth assessing here rather than elsewhere:

- *Hierarchy.* Credentials are hierarchical, so an institution key issues
  subordinate credentials rather than being handed round. The security property
  is that a subordinate compromise does not yield the institution key.
- *`AuditedHsm`.* Signing and the audit record are bound together, so a
  signature made through this path is recorded by construction rather than by
  the caller remembering to. That is a real control and it is this package's
  own.

**Operate: no network of its own.** Nothing in `src/` opens a socket. Chain and
registry calls happen through `kxco-pq-network` and `kxco-pq-chain`, which
reach `chain.kxco.ai` and `relay.kxco.ai`. Both negotiate the hybrid key
exchange group `X25519MLKEM768` under TLS 1.3, measured 7 September 2026 with
OpenSSL 3.5.6; both present ECDSA P-384 certificates, so endpoint
authentication is classical. The details are in those packages' notes.

**Retain history.** Inherited from `kxco-pq-audit`, including its limitation:
`verify(publicKey)` there takes one key for a whole log, so a log spanning a
key rotation cannot be verified as a single artefact. That matters more here
than there, because hierarchical credentials exist precisely so that keys can
change. A deployment that rotates subordinate keys and keeps one audit log
across the rotation will hit this.

**Start and update.** Every release carries a SLSA provenance attestation,
tying the published tarball to the commit and workflow that built it, and a
CycloneDX SBOM as a GitHub Release asset at a permanent unauthenticated URL
rather than an expiring build artifact. Both are checkable without asking us
for anything.

What this package does not have is release-asset signing with ML-DSA-65
against a committed public key. That is the primitives package, it is the
stronger control, and it should not be read across to this one.

## Agility

**Inherited twice over.** Primitives from `kxco-post-quantum`; format decisions
from whichever sibling owns the artefact. This package introduces no wire
format of its own and therefore has no version prefix of its own to offer.

**The composition is where agility gets hard, and it is worth stating.** A
parameter-set change has to move through four packages plus the chain and the
relay before this package can present a coherent story, and they release
independently. Nothing coordinates them. That is the most significant agility
constraint in the family and it lives here, at the point where the pieces are
assembled, rather than in any one piece.

## Lifecycle

**Assess `origin/main`, and know that this working tree is ahead of it.**
Verified 8 September 2026: `origin/main`, this checkout and npm all read 2.0.0,
so the published artefact does correspond to `origin/main`.

The local working branch `feat/verification-modes-and-registry` carries **33
commits that have never been pushed** to the remote, and is 3 behind
`origin/main`. That is the largest divergence in the family. A clone from
GitHub is not what sits on the maintainer's machine, and that unpublished work
exists in only one place. The evidence bundle records the branch it was built
from in `01-identity.json`.

**Supported versions.** One line moving forward. This package is at 2.x while
much of the family is at 1.x; major numbers are per package and there is no
coordinated release train.

**Pins, and here the range problem compounds.** `kxco-post-quantum` is declared
`^1.6.0`, resolved to **1.6.0** in the tree the evidence bundle was last built
from, against a current primitives release of 1.7.2. The four sibling
dependencies are also declared as ranges. So the assessed configuration of this
package is a resolution of five ranges rather than a fixed set, and two
installs of the same version of this package can differ in five places at once.

`02-primitives.json` records the primitives resolution. The SBOM in
`04-sbom.cyclonedx.json` records the rest, and for this package it is the file
that actually describes what was assessed.

**Ceiling.** No hardware ceiling of its own. It inherits one: with
`Pkcs11Backend` the token's firmware decides which mechanisms exist, and that
is the single place in the family where hardware replacement is the remedy. See
`kxco-pq-hsm`.

**Blocking dependencies.** The upstream library, four sibling packages, and the
KXCO relay and registry services where the live modes are used.

**Roadmap.** No external audit of this package, no bug bounty.

## Correcting this document

Every claim here is checkable against `src/` and the sibling repositories. If
one does not match, that is a defect worth reporting through the repository's
issues.
