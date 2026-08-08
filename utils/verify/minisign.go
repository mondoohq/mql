// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"

	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/blake2b"
)

// minisign is a small, dependency-free implementation of minisign signature
// verification (https://jedisct1.github.io/minisign/). We verify the detached
// signature published over the SHA256SUMS manifest against a public key pinned
// into the binary at build time, so authenticity does not depend on any
// network service or external tool — important for air-gapped fleets.
//
// Wire format (all fields little-endian is irrelevant here; they are opaque
// byte runs):
//
//	Public key (base64, 42 bytes):
//	  [0:2]   signature algorithm  ("Ed")
//	  [2:10]  key id               (8 bytes)
//	  [10:42] Ed25519 public key   (32 bytes)
//
//	Signature file (.minisig / .sig, two base64 blocks):
//	  block 1 (74 bytes):
//	    [0:2]   signature algorithm  ("Ed" = pure, "ED" = prehashed BLAKE2b-512)
//	    [2:10]  key id               (8 bytes)
//	    [10:74] Ed25519 signature    (64 bytes) over the (possibly prehashed) content
//	  block 2 (64 bytes):
//	    Ed25519 "global" signature over (block-1 signature || trusted comment)
//
// Verification checks: (1) the key id in the signature matches the pinned
// public key, (2) the content signature is valid under the pinned key, and
// (3) the global signature is valid, which binds the trusted comment so it
// cannot be swapped.

const (
	minisignAlgPure      = "Ed" // Ed25519 over the raw content
	minisignAlgPrehashed = "ED" // Ed25519 over BLAKE2b-512(content)

	minisignPubKeyLen  = 2 + 8 + ed25519.PublicKeySize // 42
	minisignSigLen     = 2 + 8 + ed25519.SignatureSize // 74
	minisignKeyIDLen   = 8
	minisignKeyIDStart = 2
	minisignKeyIDEnd   = 10
)

// ErrSignatureInvalid is returned when a signature does not verify against the
// pinned public key (bad signature, wrong key, tampered content, or a swapped
// trusted comment).
var ErrSignatureInvalid = errors.New("minisign signature verification failed")

// MinisignPublicKey is a parsed minisign public key.
type MinisignPublicKey struct {
	keyID [minisignKeyIDLen]byte
	key   ed25519.PublicKey
}

// ParseMinisignPublicKey parses a minisign public key. It accepts either the
// full two-line public-key file (an "untrusted comment:" line followed by the
// base64 payload) or the bare base64 payload on its own — whichever is more
// convenient to embed as a build-time constant.
func ParseMinisignPublicKey(s string) (*MinisignPublicKey, error) {
	payload, err := lastBase64Line(s)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read minisign public key")
	}

	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64-decode minisign public key")
	}
	if len(raw) != minisignPubKeyLen {
		return nil, errors.Newf("invalid minisign public key length: got %d, want %d", len(raw), minisignPubKeyLen)
	}
	if alg := string(raw[0:2]); alg != minisignAlgPure {
		return nil, errors.Newf("unsupported minisign public key algorithm: %q", alg)
	}

	res := &MinisignPublicKey{key: ed25519.PublicKey(raw[10:42])}
	copy(res.keyID[:], raw[minisignKeyIDStart:minisignKeyIDEnd])
	return res, nil
}

// minisignSignature is a parsed minisign signature file.
type minisignSignature struct {
	algorithm      string
	keyID          [minisignKeyIDLen]byte
	signature      []byte // 64-byte Ed25519 signature over the (prehashed) content
	trustedComment string
	globalSig      []byte // 64-byte Ed25519 signature over (signature || trustedComment)
}

// parseMinisignSignature parses a .minisig / .sig file. The format is:
//
//	untrusted comment: <text>
//	<base64 signature block>
//	trusted comment: <text>
//	<base64 global signature>
func parseMinisignSignature(s string) (*minisignSignature, error) {
	lines := splitNonEmptyLines(s)
	if len(lines) < 4 {
		return nil, errors.New("malformed minisign signature: expected 4 lines")
	}

	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64-decode signature block")
	}
	if len(sigRaw) != minisignSigLen {
		return nil, errors.Newf("invalid minisign signature length: got %d, want %d", len(sigRaw), minisignSigLen)
	}

	commentLine := strings.TrimSpace(lines[2])
	if !strings.HasPrefix(commentLine, "trusted comment:") {
		return nil, errors.New("malformed minisign signature: missing trusted comment line")
	}
	trustedComment := strings.TrimSpace(strings.TrimPrefix(commentLine, "trusted comment:"))

	globalSig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64-decode global signature")
	}
	if len(globalSig) != ed25519.SignatureSize {
		return nil, errors.Newf("invalid global signature length: got %d, want %d", len(globalSig), ed25519.SignatureSize)
	}

	res := &minisignSignature{
		algorithm:      string(sigRaw[0:2]),
		signature:      sigRaw[10:74],
		trustedComment: trustedComment,
		globalSig:      globalSig,
	}
	copy(res.keyID[:], sigRaw[minisignKeyIDStart:minisignKeyIDEnd])
	return res, nil
}

// Verify checks a minisign signature over content against this public key. It
// verifies both the content signature and the global signature (which binds
// the trusted comment). content is the exact bytes that were signed (for us,
// the raw SHA256SUMS manifest).
func (pk *MinisignPublicKey) Verify(content []byte, signatureFile string) error {
	sig, err := parseMinisignSignature(signatureFile)
	if err != nil {
		return err
	}

	if sig.keyID != pk.keyID {
		return errors.Wrapf(ErrSignatureInvalid, "signature key id does not match the pinned public key")
	}

	// Determine what was actually signed: the raw content ("Ed") or its
	// BLAKE2b-512 prehash ("ED", minisign's default for large/streamed files).
	var signed []byte
	switch sig.algorithm {
	case minisignAlgPure:
		signed = content
	case minisignAlgPrehashed:
		sum := blake2b.Sum512(content)
		signed = sum[:]
	default:
		return errors.Newf("unsupported minisign signature algorithm: %q", sig.algorithm)
	}

	if !ed25519.Verify(pk.key, signed, sig.signature) {
		return errors.Wrap(ErrSignatureInvalid, "content signature is not valid")
	}

	// The global signature covers the content signature concatenated with the
	// trusted comment. Verifying it ensures the trusted comment (which may
	// carry the artifact name/version) was not altered.
	globalSigned := append(append([]byte{}, sig.signature...), []byte(sig.trustedComment)...)
	if !ed25519.Verify(pk.key, globalSigned, sig.globalSig) {
		return errors.Wrap(ErrSignatureInvalid, "global signature (trusted comment) is not valid")
	}

	return nil
}

// lastBase64Line returns the last non-empty, non-comment line of s, which for
// a minisign public key is the base64 payload. A bare payload passes through
// unchanged.
func lastBase64Line(s string) (string, error) {
	lines := splitNonEmptyLines(s)
	if len(lines) == 0 {
		return "", errors.New("empty input")
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "untrusted comment:") || strings.HasPrefix(line, "trusted comment:") {
			continue
		}
		return line, nil
	}
	return "", errors.New("no base64 payload found")
}

// splitNonEmptyLines splits s on newlines and drops purely empty lines,
// tolerating both LF and CRLF endings.
func splitNonEmptyLines(s string) []string {
	raw := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	res := make([]string, 0, len(raw))
	for _, l := range raw {
		if strings.TrimSpace(l) != "" {
			res = append(res, l)
		}
	}
	return res
}
