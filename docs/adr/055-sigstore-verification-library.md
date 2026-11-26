# ADR 055: Sigstore verification library

## Status

Proposed

## Context

mql can read how a host is configured to trust signatures, but it cannot
verify one. `containers.policy` exposes the configured Fulcio CA path and OIDC
issuer (`providers/os/resources/os.lr`), and `container.image` has a
reference, name and repository with no signature or attestation field. Before
this change no `go.mod` in the repository required a Sigstore module directly;
`github.com/sigstore/sigstore-go` v1.2.1 was in the module graph only through
`github.com/moby/buildkit`.

A policy such as "only images signed by our release workflow run here" needs
three answers per artifact: is there a signature or attestation, does it
verify against the certificate authority and the transparency log, and is the
signer one the policy accepts. Container images need the answer now. Model
directories signed with the OpenSSF model signing format, npm packages, GitHub
releases and Python packages need the same answer later, and Go programs that
depend on this module need it outside a scan. The verification code must live
once, so that every caller judges the same artifact the same way.

This record covers the library only. The `.lr` resources that expose it
(`sigstore.attestation`, `container.image.signatures` and `.attestations`,
`sigstore.verification`, and the signature fields on `ai.model`) are a separate
change on top of it.

## Decision

### 1. One package in the root module

`providers-sdk/v1/sigstore` wraps `github.com/sigstore/sigstore-go`. Its entry
points:

- `VerifyOCI(ctx, ref name.Digest, p Policy, opts...) ([]Result, error)`
  verifies every signature and attestation stored for **one platform
  manifest**: cosign `sha256-<digest>.sig` and `.att` tags, Sigstore bundles
  attached as OCI 1.1 referrers (or through the referrers tag schema), and,
  with `WithIndex`, the BuildKit attestation manifests an image index lists for
  that platform manifest. An image index digest is refused with
  `ErrIndexSubject` (`MalformedData`): an index is never a subject.
- `VerifyBlob(ctx, digest, bundle, p Policy, opts...) (Result, error)` for a
  detached Sigstore bundle.
- `VerifyModel(ctx, fsys, dir, bundle, opts...) (ModelResult, error)` for an
  OpenSSF model signature over a model directory (decision 6).
- `Policy{Accept []Signer, NotBefore, Digests}` and `ParseSigners` for the
  string forms (decision 4).

Legacy cosign layers are converted into a Sigstore bundle v0.1 (the
certificate or key, the signed entry timestamp and the canonical log entry they
carry), so every layout is verified by the same sigstore-go code path.

### 2. Validity and acceptance are two facts

- `SignatureValid`: the signature verifies against the trust root, a
  transparency-log entry or timestamp verifies, and the signature is bound to
  the subject digest being verified (sigstore-go's `WithArtifactDigest` for an
  in-toto subject or a message digest; for a cosign simple-signing payload, the
  `docker-manifest-digest` it names is checked as well).
- `Accepted`: `Policy.Accepts(result)`, a pure function of the validity and
  identity fields. It is exported so that a caller holding its policy elsewhere
  (a platform applying a per-tenant list to results a host reported) reaches
  the same answer.
- `Verified` is `SignatureValid && Accepted`, the one fact a trust decision
  reads.

Identity is matched by this package after sigstore-go has verified the
signature with `WithoutIdentitiesUnsafe`; sigstore-go's own identity check is
not used, so validity can be reported under any policy. An empty policy
accepts no signer. The identity fields (`Issuer`, `SAN`, `SignerRepository`,
`SignerWorkflowRef`, `KeyFingerprint`, `SignedAt`) are filled only when the
signature is valid; an identity read from a signature that did not verify is
attacker-chosen text and is never reported. A signature that verifies over its
own payload but names another subject reads `SignatureValid: false,
SubjectMismatch: true`, so a copied signature is reported as such and never as
signed.

### 3. Exact, anchored matching

Every signer pattern (`SANRegexp`, `IssuerRegexp`, `Repository`,
`WorkflowRef`) is compiled as `^(?:pattern)$`, so it matches the whole value.
`Issuer` is compared with `==`. `ExactKeyless(issuer, identity)` quotes an
identity with `regexp.QuoteMeta` for callers that match one value exactly. A
pattern that accepts arbitrary identities or issuers (`.*`, `.+`) is refused
when the policy is built.

### 4. Signer forms

`ParseSigners` reads a comma-separated list:

- `github-actions:<owner>/<repo-glob>[@<workflow-path>@<ref-glob>]`: issuer
  `https://token.actions.githubusercontent.com`, the source repository and the
  workflow identity matched as anchored patterns. The owner is literal.
- `gitlab-ci:[<host>/]<group>/<project-glob>`: issuer `https://<host>`
  (default `gitlab.com`) and the CI config ref URI form of GitLab's ID token
  (`https://<host>/<group>/<project>//<path>@refs/...`). The host is pinned, so
  a self-managed instance's identities are never accepted under `gitlab.com`.
- `oidc:<issuer>|<subject-regexp>`.
- `key:<sha256-fingerprint>`: a public key (ECDSA P-256/P-384/P-521, Ed25519,
  RSA of 2048 bits or more), found in a PEM key set passed with the list or to
  the verifier. Its fingerprint is `sha256:<hex>` of the DER
  SubjectPublicKeyInfo.

A glob's `*` matches within one path segment. A key signer requires a verified
transparency-log entry unless the signer sets `RequireTlog` to false. A key
signature without a log entry is reported `SignatureValid: true,
TransparencyLogged: false`, and the default key signer does not accept it. A
keyless signer never matches a key signature and the reverse. The result names
the signer kind (`keyless` or `key`) so a check can require keyless.

### 5. Trust root: a fixed order, no rollback

`LoadTrustRoot` selects exactly one root:

1. a configured private root (`TrustOptions.PrivateRoot`), and nothing else;
2. the TUF repository's root, refreshed, cached under the cache directory;
3. when the repository cannot be reached, the cached root, only while every
   cached TUF role (root, timestamp, snapshot, targets) is within its expiry;
4. a root embedded in the caller's binary, only when no TUF root was ever
   fetched into that cache directory.

The highest TUF targets version used is recorded per repository. A root whose
targets version is below that record, or below the version the caller says its
embedded root was copied from, is refused with `ErrTrustRootRollback`, so
blocking the TUF repository cannot roll the root back to keys a later update
revoked. Once a root was fetched, the embedded root is never used again on that
machine, even when it is newer than the cache; offline, verification then fails
until the repository is reachable. An expired cache that cannot be refreshed is
`ErrTrustRootExpired` (`Unavailable`), never a fall back to the embedded copy.
The default root is the public-good instance.

### 6. Model signatures

`VerifyModel` reads an OpenSSF model signing bundle: a DSSE envelope around an
in-toto statement with predicate type `https://model_signing/signature/v1.0`
(resources with name, algorithm and digest; SHA-256 or BLAKE2b) or
`https://model_signing/Digests/v0.1` (one subject per file). It checks that the
v1.0 subject digest is the SHA-256 over the resource digests in name order,
verifies the signature bound to that digest, then streams every signed file
through `afero` with a 1 MiB buffer. Its `Status` is:

- `verified`: the signature is valid and every signed file matches. It never
  means the signer is accepted; the caller applies `Policy.Accepts` to the
  embedded `Result`.
- `invalid`: the signature does not verify, a signed file differs, a signed
  path is absolute, contains `..` or resolves through a symlink outside the
  model root, or a file the signature does not cover is a weight, pickle,
  Python or model config file.
- `unverifiable`: the key or certificate is not trusted here, or the predicate
  type, serialization method or subject construction is not one this reads.
- `incomplete`: signed files are missing, or the byte bound (16 GiB by default,
  `WithModelByteBound`) was reached.

Symlinks are followed only inside the model root (`WithModelRoot`, for a
Hugging Face cache whose snapshots link into its blob store). Documentation
files outside the signature are listed in `ExtraFiles` and do not change
`verified`. A file the scan may not read is `Forbidden`.

### 7. Downgrade detection

`ModelResult.ManifestDigest` and `Result.SubjectDigests` name what was signed,
and `Result.SignedAt` the earliest verified timestamp. A policy may set
`Digests` (only these subjects are accepted) and `NotBefore` (a signature
older than this, or one with no verified time, is not accepted), so a valid
signature over an older release put in place of the current one is refused
when the caller pins it. Without a pin, freshness is not checked, and the
result says so by carrying the time and digest rather than a verdict.

### 8. Errors follow the error kinds

No signature is an empty list and no error. A registry refusal is
`Unauthenticated` or `Forbidden`; a registry or log that cannot be reached is
`Unavailable`; a bundle passed to `VerifyBlob` or `VerifyModel` that does not
parse is `MalformedData`. One unparsable layer among several on an image is
reported as an invalid result with its reason, so it cannot hide the others. A
verification that could not run (no trust root, an expired cache) is an error,
never `Verified: false`.

### 9. Cache without acceptance

`WithCache` reuses verifications across calls, keyed by the trust root's
digest, the configured key set, the subject and the signed bytes. It stores
validity and identity only; acceptance is computed on every call against that
call's policy, so a warm cache can never carry one policy's acceptance into
another call. Errors are never cached.

## Security implications

- **Threat model.** This code decides whether an artifact is trusted. The
  failures that matter are accepting a signature over another digest
  (decision 2 binds the subject, and checks the simple-signing digest too),
  accepting any signer (decision 3 anchors every pattern and refuses
  match-anything patterns; an empty policy accepts nothing), turning a check
  that could not run into a pass (decision 8), rolling the trust root back
  (decision 5), and a warm cache bypassing a policy (decision 9).
- **Reporting validity apart from acceptance** adds one risk: a check that reads
  `SignatureValid` alone accepts an attacker's own valid signature. The field
  documentation says so; trust decisions read `Verified`.
- **Attacker-controlled input.** Bundles, layers and model statements are
  parsed with size bounds (64 MiB per layer, 16 MiB per bundle, at most 64
  signatures per subject). Nothing a bundle names beyond the trust root is
  trusted, and no URL in a bundle is fetched. Model paths are checked before a
  file is opened.
- **Residual risk.** A compromised identity on the allowlist signs anything;
  policies should pin the workflow, not only the repository. Deleting both the
  TUF cache and the recorded version on a host lets the embedded root be used
  again; the embedded root is release-bound, so that is no older than the
  binary. A key signer moves trust to key custody; the result names the kind
  and fingerprint so content can require keyless.
- **Supply chain.** The root module now requires sigstore-go v1.2.1 directly,
  with its TUF client (go-tuf v2), protobuf-specs, rekor and timestamp-authority
  packages. v1.2.1 was already in the module graph; a later sigstore-go raises
  shared dependencies (golang.org/x/*, go-containerregistry) for every provider
  module and is a separate dependency update.

## Performance implications

- **Expected impact.** Per platform manifest: one HEAD, two tag lookups and
  one referrers call to the registry, then offline verification when the
  bundle carries its log proof or signed entry timestamp. One TUF refresh per
  process for the default root. Model verification hashes signed files at disk
  speed, only when a signature exists, bounded by the byte bound.
- **Evidence.** Measured only on synthetic fixtures: the package's tests,
  including TUF loads, registry round trips against an in-memory registry and
  model hashing, run in well under a second. Not measured against a public
  registry or the public-good TUF repository, which this environment cannot
  reach.
- **Scale assumptions.** A cluster scan has tens of distinct digests; the cache
  makes a repeated digest free.
- **Regression budget.** No caller exists yet, so no scan pays anything until
  the resources land; they are to stay behind an opt-in until measured on 100
  public digests.

## Consequences

### Positive

- One verifier for images, blobs and models, with typed results and error
  kinds, usable from providers and from other Go programs.
- Policies can require a signer by workflow, by GitLab project, or by key.

### Negative

- The root module gains a sizeable dependency tree, and seven provider modules
  needed `go mod tidy` for the shared versions it raises.
- sigstore-go v1.2.1 is not the newest release.

### Follow-up

- The `.lr` resources on top of the package.
- Certificate-chain trust material for publishers that sign models with their
  own certificate authority.
- Cross-check `VerifyModel` against a bundle produced by the reference model
  signing tool, and the OCI layouts against recorded public images.
- Move to a newer sigstore-go with a dependency update across provider modules.

## Alternatives considered

### Port a hand-written cosign verifier

Rejected: a hand-written verifier covers one layout (the cosign `.att` tag),
and several copies of security-critical code drift. sigstore-go covers bundles
v0.1 to v0.3, inclusion proofs and timestamp authorities.

### Shell out to `cosign verify`

Rejected: providers never use `os/exec`, the binary is not present on most
targets, and its text output is not a typed result.

### Verify only on a central service

Rejected as the only path: an admission review and an air-gapped scan need the
answer locally. A central cache can still deduplicate results across scans.

### Use sigstore-go's identity matching

Rejected: it requires an identity at verification time, so validity could not
be reported under an empty policy, and acceptance could not be applied later
with the same rule.
