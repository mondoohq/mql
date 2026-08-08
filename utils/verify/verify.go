// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

// SignaturePolicy controls how the optional manifest signature is treated.
type SignaturePolicy int

const (
	// SignatureAuto verifies the signature when both a pinned public key and a
	// signature are available, and otherwise proceeds on checksum alone
	// (logging that the artifact was unsigned). This is the default while the
	// release pipeline is still being extended to publish signatures.
	SignatureAuto SignaturePolicy = iota

	// SignatureRequire fails closed: verification errors unless a valid
	// signature is present. Use in strict/critical fleets once signatures are
	// published fleet-wide.
	SignatureRequire

	// SignatureOff skips signature verification entirely and relies on the
	// checksum gate only. Intended for testing and tightly controlled mirrors.
	SignatureOff
)

// ParseSignaturePolicy maps the mondoo.yml `verify_signature` string
// ("auto" | "require" | "off") to a SignaturePolicy. Unknown values fall back
// to SignatureAuto with a warning, so a config typo never silently disables
// the checksum gate.
func ParseSignaturePolicy(s string) SignaturePolicy {
	switch s {
	case "", "auto":
		return SignatureAuto
	case "require":
		return SignatureRequire
	case "off":
		return SignatureOff
	default:
		log.Warn().Str("value", s).Msg("unknown verify_signature policy, defaulting to 'auto'")
		return SignatureAuto
	}
}

// Verifier verifies downloaded artifacts against a checksum manifest and an
// optional pinned minisign public key. It is safe for concurrent use; it holds
// only immutable configuration.
type Verifier struct {
	// pubKey is the minisign public key pinned into the binary at build time.
	// Nil means no key is compiled in (signature verification is unavailable).
	pubKey *MinisignPublicKey
	// policy controls signature enforcement.
	policy SignaturePolicy
}

// NewVerifier builds a Verifier. pinnedPublicKey may be empty when no signing
// key has been provisioned yet; in that case signature verification is
// unavailable and, under SignatureAuto, artifacts are accepted on checksum
// alone. Under SignatureRequire an empty key is a hard configuration error at
// verification time (fail closed).
func NewVerifier(pinnedPublicKey string, policy SignaturePolicy) (*Verifier, error) {
	v := &Verifier{policy: policy}
	if pinnedPublicKey != "" {
		pk, err := ParseMinisignPublicKey(pinnedPublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "invalid pinned minisign public key")
		}
		v.pubKey = pk
	}
	return v, nil
}

// Inputs bundles everything needed to verify one artifact. The caller fetches
// the pieces (the package does no network I/O):
//
//   - Filename is the artifact's base name as it appears in the manifest.
//   - Artifact is the downloaded bytes to verify.
//   - Manifest is the raw SHA256SUMS file.
//   - Signature is the raw detached minisign signature over Manifest, or empty
//     if none was published.
type Inputs struct {
	Filename  string
	Artifact  []byte
	Manifest  []byte
	Signature []byte
}

// Result reports what was actually checked, for logging and telemetry.
type Result struct {
	SHA256           string // the verified digest
	SignatureChecked bool   // whether a signature was verified
}

// Verify runs the gates in order — signature over the manifest first (so a
// tampered manifest is rejected before we trust any digest in it), then the
// artifact checksum against that manifest.
//
// Ordering rationale: the checksum gate only proves "the artifact matches a
// digest in this manifest". That is worthless if the manifest itself is
// attacker-controlled. Verifying the manifest signature first turns the
// checksum into a meaningful authenticity check.
func (v *Verifier) Verify(in Inputs) (*Result, error) {
	res := &Result{}

	// Gate 1: manifest signature (authenticity), subject to policy.
	sigChecked, err := v.verifyManifestSignature(in.Manifest, in.Signature)
	if err != nil {
		return nil, err
	}
	res.SignatureChecked = sigChecked

	// Gate 2: artifact checksum (integrity), against the now-trusted manifest.
	sums, err := ParseSHA256SUMS(in.Manifest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse checksum manifest")
	}
	digest, err := sums.VerifyBytes(in.Filename, in.Artifact)
	if err != nil {
		return nil, err
	}
	res.SHA256 = digest

	return res, nil
}

// VerifyPrehashed is Verify for artifacts whose SHA256 has already been
// computed while streaming them to disk (e.g. a large binary download), so the
// bytes need not be held in memory. sha256Hex is the lower-case hex digest of
// the artifact. All other semantics — signature-first ordering and the
// signature policy — match Verify.
func (v *Verifier) VerifyPrehashed(filename, sha256Hex string, manifest, signature []byte) (*Result, error) {
	res := &Result{}

	sigChecked, err := v.verifyManifestSignature(manifest, signature)
	if err != nil {
		return nil, err
	}
	res.SignatureChecked = sigChecked

	sums, err := ParseSHA256SUMS(manifest)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse checksum manifest")
	}
	expected, ok := sums.Digest(filename)
	if !ok {
		return nil, errors.Wrapf(ErrChecksumNotFound, "file %q", filename)
	}
	if !strings.EqualFold(sha256Hex, expected) {
		return nil, errors.Wrapf(ErrChecksumMismatch,
			"file %q: expected %s, computed %s", filename, expected, strings.ToLower(sha256Hex))
	}
	res.SHA256 = strings.ToLower(sha256Hex)
	return res, nil
}

// verifyManifestSignature applies the signature policy to the manifest and its
// detached signature. It returns whether a signature was actually verified.
func (v *Verifier) verifyManifestSignature(manifest, signature []byte) (bool, error) {
	switch v.policy {
	case SignatureOff:
		return false, nil

	case SignatureRequire:
		if v.pubKey == nil {
			return false, errors.New("verify_signature is 'require' but no signing key is pinned into this build")
		}
		if len(signature) == 0 {
			return false, errors.New("verify_signature is 'require' but no signature was published for this artifact")
		}
		if err := v.pubKey.Verify(manifest, string(signature)); err != nil {
			return false, err
		}
		return true, nil

	case SignatureAuto:
		fallthrough
	default:
		// Best-effort: verify when we can, otherwise proceed on checksum alone.
		if v.pubKey == nil || len(signature) == 0 {
			log.Debug().Msg("no signature available; verifying artifact by checksum only")
			return false, nil
		}
		if err := v.pubKey.Verify(manifest, string(signature)); err != nil {
			// A present-but-invalid signature is always fatal, even under
			// 'auto'. "Auto" relaxes the requirement that a signature exist,
			// not the requirement that a signature which does exist be valid.
			return false, err
		}
		return true, nil
	}
}
