// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sigstore verifies Sigstore signatures and in-toto attestations on
// container images, detached blobs and model directories, and reports who
// signed them. It keeps two facts apart:
//
//   - validity: the signature verifies against the trust root and the
//     transparency log, and is bound to the subject digest being verified;
//   - acceptance: a Policy accepts the signer identity.
//
// Verified is both. Validity is reported under any policy, including an empty
// one; an empty policy accepts no signer. A verification that could not run
// (a trust root that cannot be refreshed, an unreachable registry) is an
// error, never a result with Verified false.
package sigstore

import (
	"encoding/json"
	"time"
)

// Envelope is where a signature or attestation was found.
type Envelope string

const (
	// EnvelopeCosignSignature is a cosign signature, an image tagged
	// sha256-<digest>.sig whose layers are simple-signing payloads.
	EnvelopeCosignSignature Envelope = "cosign-sig"
	// EnvelopeCosignAttestation is a cosign attestation, an image tagged
	// sha256-<digest>.att whose layers are DSSE envelopes.
	EnvelopeCosignAttestation Envelope = "cosign-att"
	// EnvelopeOCIReferrer is a Sigstore bundle attached as an OCI 1.1 referrer.
	EnvelopeOCIReferrer Envelope = "oci-referrer"
	// EnvelopeBuildKitIndex is a BuildKit attestation manifest in an image
	// index. BuildKit does not sign these, so they are never valid.
	EnvelopeBuildKitIndex Envelope = "buildkit-index"
	// EnvelopeSigstoreBundle is a detached Sigstore bundle.
	EnvelopeSigstoreBundle Envelope = "sigstore-bundle"
)

// SignerKind is how a signer is identified.
type SignerKind string

const (
	// SignerKeyless is a certificate identity issued for an OIDC token.
	SignerKeyless SignerKind = "keyless"
	// SignerKey is a long-lived public key.
	SignerKey SignerKind = "key"
)

// Material is a material or resolved dependency named by SLSA provenance.
type Material struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
}

// Result is one signature or attestation and what its verification found.
type Result struct {
	// SignatureValid is true when the signature verifies against the trust
	// root, the transparency-log or timestamp evidence holds, and the
	// signature is bound to the subject digest that was verified. It says
	// nothing about who signed: an attacker's own valid signature is valid.
	// Trust decisions read Verified.
	SignatureValid bool
	// Accepted is true when the policy of the call accepts the signer.
	Accepted bool
	// Verified is SignatureValid && Accepted.
	Verified bool

	// SubjectMismatch is true when the signature itself verifies but covers
	// another subject: a signature copied from another image or artifact.
	// SignatureValid is false then, and no identity is reported.
	SubjectMismatch bool
	// Reason says why SignatureValid is false.
	Reason string

	// The identity fields are filled only when SignatureValid is true. An
	// identity read from a signature that did not verify is attacker-chosen
	// text and is never reported.
	SignerKind SignerKind
	// KeyFingerprint is "sha256:<hex>" of the public key's DER
	// SubjectPublicKeyInfo, for a key signer.
	KeyFingerprint string
	// Issuer is the OIDC issuer of the signing certificate.
	Issuer string
	// SAN is the signing certificate's subject alternative name.
	SAN string
	// SignerRepository is the source repository the signing workflow ran in
	// (Fulcio's source repository URI extension).
	SignerRepository string
	// SignerWorkflowRef is the workflow identity that signed (Fulcio's build
	// signer URI extension).
	SignerWorkflowRef string
	// SignedAt is the earliest verified timestamp of the signature: the
	// transparency log's integrated time or a timestamp authority's time.
	// Zero when no timestamp was verified.
	SignedAt time.Time
	// TransparencyLogged is true when a transparency-log entry of this
	// signature was verified.
	TransparencyLogged bool

	// SubjectDigests are the digests the signature or attestation covers, as
	// "<algorithm>:<hex>".
	SubjectDigests []string
	// PredicateType is the in-toto predicate type, empty for a signature.
	PredicateType string
	// SLSABuildLevel is the SLSA build level a verification summary
	// attestation states as verified; 0 when none is stated.
	SLSABuildLevel int
	BuilderID      string
	BuildType      string
	// SourceRepository and SourceRevision are what SLSA provenance names as
	// the build's source.
	SourceRepository string
	SourceRevision   string
	Materials        []Material

	Envelope Envelope
	// Payload is the signed payload: the in-toto statement of an attestation
	// or the simple-signing document of a signature. It is attacker-controlled
	// unless SignatureValid is true; when it is, it is the payload the
	// signature covers, never one read from elsewhere.
	Payload []byte `json:"-"`
}

// Predicate returns the predicate of an attestation's in-toto statement.
func (r Result) Predicate() json.RawMessage {
	var st struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if json.Unmarshal(r.Payload, &st) != nil {
		return nil
	}
	return st.Predicate
}

// CoversDigest reports whether digest ("sha256:<hex>") is a subject.
func (r Result) CoversDigest(digest string) bool {
	for _, d := range r.SubjectDigests {
		if d == digest {
			return true
		}
	}
	return false
}

// clearIdentity drops every identity field, for a result whose signature did
// not verify.
func (r *Result) clearIdentity() {
	r.SignerKind, r.KeyFingerprint, r.Issuer, r.SAN = "", "", "", ""
	r.SignerRepository, r.SignerWorkflowRef = "", ""
	r.SignedAt, r.TransparencyLogged = time.Time{}, false
}
