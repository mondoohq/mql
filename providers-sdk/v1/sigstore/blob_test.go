// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Synthetic: every bundle is built by the test harness in verify_test.go.

type blobCase struct {
	s        *testSigstore
	artifact []byte
	digest   string
	payload  []byte
	signer   testSigner
}

func newBlobCase(t *testing.T) blobCase {
	s := newTestSigstore(t)
	artifact := []byte("release.tar.gz contents")
	return blobCase{
		s: s, artifact: artifact, digest: "sha256:" + sha256Hex(artifact),
		payload: statementJSON(t, "https://slsa.dev/provenance/v1", map[string]any{}, sha256Hex(artifact)),
		signer:  s.keyless(githubIdentity("acme/app", ".github/workflows/release.yml", "refs/tags/v1.2.0")),
	}
}

func TestVerifyBlob_KeylessValid(t *testing.T) {
	c := newBlobCase(t)
	p, err := ParseSigners("github-actions:acme/*")
	require.NoError(t, err)
	r, err := VerifyBlob(context.Background(), c.digest, c.s.dsseBundle(c.signer, c.payload, bundleOpts{}), p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.True(t, r.SignatureValid, r.Reason)
	assert.True(t, r.Accepted)
	assert.True(t, r.Verified)
	assert.Equal(t, SignerKeyless, r.SignerKind)
	assert.Equal(t, GitHubActionsIssuer, r.Issuer)
	assert.Equal(t, "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.2.0", r.SAN)
	assert.Equal(t, "https://github.com/acme/app", r.SignerRepository)
	assert.Equal(t, r.SAN, r.SignerWorkflowRef)
	assert.True(t, r.TransparencyLogged)
	assert.Equal(t, c.s.now.Unix(), r.SignedAt.Unix())
	assert.Equal(t, "https://slsa.dev/provenance/v1", r.PredicateType)
	assert.Equal(t, EnvelopeSigstoreBundle, r.Envelope)
}

func TestVerifyBlob_EmptyPolicyReportsIdentityNotAcceptance(t *testing.T) {
	c := newBlobCase(t)
	r, err := VerifyBlob(context.Background(), c.digest, c.s.dsseBundle(c.signer, c.payload, bundleOpts{}), Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.True(t, r.SignatureValid, r.Reason)
	assert.NotEmpty(t, r.SAN, "identity is reported under an empty policy")
	assert.False(t, r.Accepted)
	assert.False(t, r.Verified)
}

func TestVerifyBlob_SignatureOnOtherDigest(t *testing.T) {
	c := newBlobCase(t)
	other := "sha256:" + sha256Hex([]byte("another artifact"))
	p, err := ParseSigners("github-actions:acme/*")
	require.NoError(t, err)
	r, err := VerifyBlob(context.Background(), other, c.s.dsseBundle(c.signer, c.payload, bundleOpts{}), p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.False(t, r.SignatureValid)
	assert.True(t, r.SubjectMismatch, r.Reason)
	assert.False(t, r.Verified)
	assert.Empty(t, r.SAN, "no identity for a signature that is not valid for this subject")
	assert.Empty(t, r.Issuer)
}

func TestVerifyBlob_TamperedPayloadInvalid(t *testing.T) {
	c := newBlobCase(t)
	b := c.s.dsseBundle(c.signer, c.payload, bundleOpts{})
	// Swap the signed payload for another statement over the same subject.
	other := statementJSON(t, "https://slsa.dev/provenance/v1", map[string]any{"x": 1}, sha256Hex(c.artifact))
	tampered := replaceB64(t, b, c.payload, other)
	r, err := VerifyBlob(context.Background(), c.digest, tampered, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.False(t, r.SignatureValid)
	assert.False(t, r.SubjectMismatch)
	assert.Empty(t, r.SAN, "an identity read from a bundle that did not verify is never reported")
}

func TestVerifyBlob_UntrustedCAInvalid(t *testing.T) {
	c := newBlobCase(t)
	otherRoot, otherRootKey, err := caGenerateRoot()
	require.NoError(t, err)
	sg := c.s.keylessFrom(otherRoot, otherRootKey, githubIdentity("acme/app", ".github/workflows/release.yml", "refs/heads/main"))
	r, err := VerifyBlob(context.Background(), c.digest, c.s.dsseBundle(sg, c.payload, bundleOpts{}), Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.False(t, r.SignatureValid)
	assert.Empty(t, r.SAN)
}

func TestVerifyBlob_LoggedOutsideCertificateValidity(t *testing.T) {
	// A Fulcio certificate lives minutes; a log time past it means the
	// signature was made with a key after its certificate expired.
	c := newBlobCase(t)
	b := c.s.dsseBundle(c.signer, c.payload, bundleOpts{logAt: c.s.now.Add(time.Hour)})
	r, err := VerifyBlob(context.Background(), c.digest, b, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.False(t, r.SignatureValid)
}

func TestVerifyBlob_KeylessWithoutLogInvalid(t *testing.T) {
	c := newBlobCase(t)
	r, err := VerifyBlob(context.Background(), c.digest, c.s.dsseBundle(c.signer, c.payload, bundleOpts{noLog: true}), Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.False(t, r.SignatureValid, "a keyless signature needs a verified time")
}

func TestVerifyBlob_KeySigner(t *testing.T) {
	c := newBlobCase(t)
	sg := newKeySigner(t)
	b := c.s.dsseBundle(sg, c.payload, bundleOpts{})
	p, err := ParseSigners("key:"+sg.fingerprint(t), sg.verifierPEM(t))
	require.NoError(t, err)
	r, err := VerifyBlob(context.Background(), c.digest, b, p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.True(t, r.SignatureValid, r.Reason)
	assert.True(t, r.Verified)
	assert.Equal(t, SignerKey, r.SignerKind)
	assert.Equal(t, sg.fingerprint(t), r.KeyFingerprint)
	assert.True(t, r.TransparencyLogged)
	assert.Empty(t, r.SAN)

	// Signed by another key than the configured one.
	other := newKeySigner(t)
	p2, err := ParseSigners("key:"+other.fingerprint(t), other.verifierPEM(t))
	require.NoError(t, err)
	r2, err := VerifyBlob(context.Background(), c.digest, b, p2, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.False(t, r2.SignatureValid, "the signing key is not a configured key")
	assert.False(t, r2.Verified)

	// A bundle whose hint names the configured key but was signed by another.
	forged := c.s.dsseBundle(other, c.payload, bundleOpts{keyHint: sg.fingerprint(t)})
	r3, err := VerifyBlob(context.Background(), c.digest, forged, p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.False(t, r3.SignatureValid)
}

func TestVerifyBlob_KeyNoTlogRequired(t *testing.T) {
	c := newBlobCase(t)
	sg := newKeySigner(t)
	b := c.s.dsseBundle(sg, c.payload, bundleOpts{noLog: true})
	p, err := ParseSigners("key:"+sg.fingerprint(t), sg.verifierPEM(t))
	require.NoError(t, err)
	r, err := VerifyBlob(context.Background(), c.digest, b, p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.True(t, r.SignatureValid, r.Reason)
	assert.False(t, r.TransparencyLogged)
	assert.False(t, r.Verified, "the default policy requires a log entry")

	optOut := false
	p2, err := NewPolicy(Signer{PublicKey: string(sg.verifierPEM(t)), RequireTlog: &optOut})
	require.NoError(t, err)
	r2, err := VerifyBlob(context.Background(), c.digest, b, p2, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.True(t, r2.Verified)
}

func TestVerifyBlob_MessageSignature(t *testing.T) {
	c := newBlobCase(t)
	b := c.s.messageBundle(c.signer, c.artifact)
	r, err := VerifyBlob(context.Background(), c.digest, b, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.True(t, r.SignatureValid, r.Reason)

	r2, err := VerifyBlob(context.Background(), "sha256:"+sha256Hex([]byte("other")), b, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.False(t, r2.SignatureValid)
	assert.True(t, r2.SubjectMismatch)
}

func TestVerifyBlob_MalformedBundle(t *testing.T) {
	c := newBlobCase(t)
	_, err := VerifyBlob(context.Background(), c.digest, []byte(`{"mediaType":"nope"}`), Policy{}, WithTrustRoot(c.s.trust))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}

func TestVerifyBlob_NoTrustRootIsAnError(t *testing.T) {
	// A verification that cannot run is an error, never verified: false.
	c := newBlobCase(t)
	_, err := VerifyBlob(context.Background(), c.digest, c.s.dsseBundle(c.signer, c.payload, bundleOpts{}), Policy{},
		WithTrustOptions(TrustOptions{CacheDir: t.TempDir(), Offline: true}))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoTrustRoot)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
}
