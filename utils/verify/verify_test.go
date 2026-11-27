// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

// --- test helpers: build minisign-format keys and signatures in-process -----

type testSigner struct {
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	keyID   [8]byte
	pubText string
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	s := &testSigner{pub: pub, priv: priv}
	_, err = rand.Read(s.keyID[:])
	require.NoError(t, err)

	raw := make([]byte, 0, minisignPubKeyLen)
	raw = append(raw, []byte(minisignAlgPure)...) // "Ed" is the algorithm tag in the public key
	raw = append(raw, s.keyID[:]...)
	raw = append(raw, s.pub...)
	s.pubText = "untrusted comment: test key\n" + base64.StdEncoding.EncodeToString(raw) + "\n"
	return s
}

// sign builds a minisign signature file over content using the given algorithm
// ("Ed" pure or "ED" prehashed).
func (s *testSigner) sign(algorithm string, content []byte, trustedComment string) string {
	var signed []byte
	switch algorithm {
	case minisignAlgPure:
		signed = content
	case minisignAlgPrehashed:
		sum := blake2b.Sum512(content)
		signed = sum[:]
	default:
		panic("bad algorithm")
	}

	sig := ed25519.Sign(s.priv, signed)

	block := make([]byte, 0, minisignSigLen)
	block = append(block, []byte(algorithm)...)
	block = append(block, s.keyID[:]...)
	block = append(block, sig...)

	global := ed25519.Sign(s.priv, append(append([]byte{}, sig...), []byte(trustedComment)...))

	return fmt.Sprintf("untrusted comment: signature\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(block),
		trustedComment,
		base64.StdEncoding.EncodeToString(global),
	)
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// --- checksum tests ---------------------------------------------------------

func TestParseSHA256SUMS(t *testing.T) {
	artifact := []byte("provider binary contents")
	digest := sha256hex(artifact)

	t.Run("gnu two-space format", func(t *testing.T) {
		manifest := []byte(digest + "  os_1.2.3_linux_amd64.tar.xz\n")
		sums, err := ParseSHA256SUMS(manifest)
		require.NoError(t, err)
		got, ok := sums.Digest("os_1.2.3_linux_amd64.tar.xz")
		assert.True(t, ok)
		assert.Equal(t, digest, got)
	})

	t.Run("binary-mode asterisk marker", func(t *testing.T) {
		manifest := []byte(digest + " *os_1.2.3_linux_amd64.tar.xz\n")
		sums, err := ParseSHA256SUMS(manifest)
		require.NoError(t, err)
		_, ok := sums.Digest("os_1.2.3_linux_amd64.tar.xz")
		assert.True(t, ok)
	})

	t.Run("relative path indexed by base name", func(t *testing.T) {
		manifest := []byte(digest + "  dist/os_1.2.3_linux_amd64.tar.xz\n")
		sums, err := ParseSHA256SUMS(manifest)
		require.NoError(t, err)
		_, ok := sums.Digest("os_1.2.3_linux_amd64.tar.xz")
		assert.True(t, ok)
	})

	t.Run("comments and blank lines tolerated", func(t *testing.T) {
		manifest := []byte("# a comment\n\n" + digest + "  file.tar.xz\n\n")
		sums, err := ParseSHA256SUMS(manifest)
		require.NoError(t, err)
		assert.Len(t, sums.digests, 1)
	})

	t.Run("empty manifest rejected", func(t *testing.T) {
		_, err := ParseSHA256SUMS([]byte("# only comments\n\n"))
		assert.Error(t, err)
	})

	t.Run("malformed digest rejected", func(t *testing.T) {
		_, err := ParseSHA256SUMS([]byte("nothex  file.tar.xz\n"))
		assert.Error(t, err)
	})
}

func TestSHA256SUMS_Verify(t *testing.T) {
	artifact := []byte("provider binary contents")
	digest := sha256hex(artifact)
	manifest := []byte(digest + "  os_1.2.3_linux_amd64.tar.xz\n")
	sums, err := ParseSHA256SUMS(manifest)
	require.NoError(t, err)

	t.Run("match", func(t *testing.T) {
		got, err := sums.VerifyBytes("os_1.2.3_linux_amd64.tar.xz", artifact)
		require.NoError(t, err)
		assert.Equal(t, digest, got)
	})

	t.Run("mismatch", func(t *testing.T) {
		_, err := sums.VerifyBytes("os_1.2.3_linux_amd64.tar.xz", []byte("tampered"))
		assert.ErrorIs(t, err, ErrChecksumMismatch)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := sums.VerifyBytes("other.tar.xz", artifact)
		assert.ErrorIs(t, err, ErrChecksumNotFound)
	})
}

// --- minisign tests ---------------------------------------------------------

func TestMinisign_Verify(t *testing.T) {
	signer := newTestSigner(t)
	pk, err := ParseMinisignPublicKey(signer.pubText)
	require.NoError(t, err)

	content := []byte("the sha256sums manifest body")

	t.Run("prehashed (ED) valid", func(t *testing.T) {
		sig := signer.sign(minisignAlgPrehashed, content, "timestamp:1 file:SHA256SUMS")
		assert.NoError(t, pk.Verify(content, sig))
	})

	t.Run("pure (Ed) valid", func(t *testing.T) {
		sig := signer.sign(minisignAlgPure, content, "timestamp:1 file:SHA256SUMS")
		assert.NoError(t, pk.Verify(content, sig))
	})

	t.Run("tampered content rejected", func(t *testing.T) {
		sig := signer.sign(minisignAlgPrehashed, content, "tc")
		err := pk.Verify([]byte("different manifest"), sig)
		assert.ErrorIs(t, err, ErrSignatureInvalid)
	})

	t.Run("swapped trusted comment rejected", func(t *testing.T) {
		sig := signer.sign(minisignAlgPrehashed, content, "original")
		// Tamper with the trusted comment line only; the global signature must fail.
		tampered := swapTrustedComment(t, sig, "attacker")
		err := pk.Verify(content, tampered)
		assert.ErrorIs(t, err, ErrSignatureInvalid)
	})

	t.Run("wrong key rejected", func(t *testing.T) {
		other := newTestSigner(t)
		sig := other.sign(minisignAlgPrehashed, content, "tc")
		err := pk.Verify(content, sig)
		assert.ErrorIs(t, err, ErrSignatureInvalid)
	})
}

// swapTrustedComment replaces the trusted-comment text while leaving both
// base64 blocks intact, simulating an attacker editing the human-readable line.
func swapTrustedComment(t *testing.T, sigFile, replacement string) string {
	t.Helper()
	lines := splitNonEmptyLines(sigFile)
	require.Len(t, lines, 4)
	lines[2] = "trusted comment: " + replacement
	return lines[0] + "\n" + lines[1] + "\n" + lines[2] + "\n" + lines[3] + "\n"
}

// --- Verifier (combined) tests ---------------------------------------------

func TestVerifier_Verify(t *testing.T) {
	signer := newTestSigner(t)
	artifact := []byte("os_1.2.3_linux_amd64.tar.xz bytes")
	filename := "os_1.2.3_linux_amd64.tar.xz"
	manifest := []byte(sha256hex(artifact) + "  " + filename + "\n")
	sig := []byte(signer.sign(minisignAlgPrehashed, manifest, "file:SHA256SUMS"))

	t.Run("auto with valid signature checks both gates", func(t *testing.T) {
		v, err := NewVerifier(signer.pubText, SignatureAuto)
		require.NoError(t, err)
		res, err := v.Verify(Inputs{Filename: filename, Artifact: artifact, Manifest: manifest, Signature: sig})
		require.NoError(t, err)
		assert.True(t, res.SignatureChecked)
		assert.Equal(t, sha256hex(artifact), res.SHA256)
	})

	t.Run("auto without signature proceeds on checksum", func(t *testing.T) {
		v, err := NewVerifier(signer.pubText, SignatureAuto)
		require.NoError(t, err)
		res, err := v.Verify(Inputs{Filename: filename, Artifact: artifact, Manifest: manifest})
		require.NoError(t, err)
		assert.False(t, res.SignatureChecked)
	})

	t.Run("auto with invalid signature fails", func(t *testing.T) {
		v, err := NewVerifier(signer.pubText, SignatureAuto)
		require.NoError(t, err)
		bad := []byte(newTestSigner(t).sign(minisignAlgPrehashed, manifest, "tc"))
		_, err = v.Verify(Inputs{Filename: filename, Artifact: artifact, Manifest: manifest, Signature: bad})
		assert.ErrorIs(t, err, ErrSignatureInvalid)
	})

	t.Run("require without signature fails closed", func(t *testing.T) {
		v, err := NewVerifier(signer.pubText, SignatureRequire)
		require.NoError(t, err)
		_, err = v.Verify(Inputs{Filename: filename, Artifact: artifact, Manifest: manifest})
		assert.Error(t, err)
	})

	t.Run("require without pinned key fails closed", func(t *testing.T) {
		v, err := NewVerifier("", SignatureRequire)
		require.NoError(t, err)
		_, err = v.Verify(Inputs{Filename: filename, Artifact: artifact, Manifest: manifest, Signature: sig})
		assert.Error(t, err)
	})

	t.Run("tampered artifact fails checksum even with valid manifest signature", func(t *testing.T) {
		v, err := NewVerifier(signer.pubText, SignatureAuto)
		require.NoError(t, err)
		_, err = v.Verify(Inputs{Filename: filename, Artifact: []byte("tampered"), Manifest: manifest, Signature: sig})
		assert.ErrorIs(t, err, ErrChecksumMismatch)
	})

	t.Run("off skips signature", func(t *testing.T) {
		v, err := NewVerifier(signer.pubText, SignatureOff)
		require.NoError(t, err)
		res, err := v.Verify(Inputs{Filename: filename, Artifact: artifact, Manifest: manifest, Signature: sig})
		require.NoError(t, err)
		assert.False(t, res.SignatureChecked)
	})

	t.Run("VerifyPrehashed matches Verify semantics", func(t *testing.T) {
		v, err := NewVerifier(signer.pubText, SignatureAuto)
		require.NoError(t, err)

		res, err := v.VerifyPrehashed(filename, sha256hex(artifact), manifest, sig)
		require.NoError(t, err)
		assert.True(t, res.SignatureChecked)
		assert.Equal(t, sha256hex(artifact), res.SHA256)

		// Wrong precomputed digest is a mismatch.
		_, err = v.VerifyPrehashed(filename, sha256hex([]byte("other")), manifest, sig)
		assert.ErrorIs(t, err, ErrChecksumMismatch)

		// Unknown file is not found.
		_, err = v.VerifyPrehashed("nope.tar.gz", sha256hex(artifact), manifest, sig)
		assert.ErrorIs(t, err, ErrChecksumNotFound)
	})
}
