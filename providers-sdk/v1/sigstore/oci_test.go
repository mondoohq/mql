// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Synthetic: an in-memory registry (go-containerregistry's), with images,
// cosign tags, referrers and BuildKit attestation manifests pushed by the
// test in the layouts cosign and BuildKit write.

type ociCase struct {
	s      *testSigstore
	host   string
	repo   name.Repository
	img    v1.Image
	digest name.Digest
}

func newOCICase(t *testing.T) ociCase {
	s := newTestSigstore(t)
	srv := httptest.NewServer(registry.New(registry.Logger(nilLogger())))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	repo, err := name.NewRepository(u.Host + "/acme/app")
	require.NoError(t, err)
	img, err := random.Image(128, 1)
	require.NoError(t, err)
	require.NoError(t, remote.Write(repo.Tag("v1"), img))
	d, err := img.Digest()
	require.NoError(t, err)
	return ociCase{s: s, host: u.Host, repo: repo, img: img, digest: repo.Digest(d.String())}
}

func (c ociCase) hex() string { return strings.TrimPrefix(c.digest.DigestStr(), "sha256:") }

// pushCosign pushes layers as the image cosign tags sha256-<hex>.<suffix>.
func (c ociCase) pushCosign(t *testing.T, subject name.Digest, suffix string, mt types.MediaType, layers ...[2]any) {
	img := empty.Image
	for _, l := range layers {
		var err error
		img, err = mutate.Append(img, mutate.Addendum{
			Layer: static.NewLayer(l[0].([]byte), mt), Annotations: l[1].(map[string]string),
		})
		require.NoError(t, err)
	}
	tag := subject.Context().Tag(strings.Replace(subject.DigestStr(), ":", "-", 1) + "." + suffix)
	require.NoError(t, remote.Write(tag, img))
}

func (c ociCase) attestation(t *testing.T, sg testSigner, digestHex string, logged bool) [2]any {
	blob, ann := c.s.cosignLayer(sg, EnvelopeCosignAttestation, statementJSON(t, "https://spdx.dev/Document", map[string]any{"spdxVersion": "SPDX-2.3"}, digestHex), logged)
	return [2]any{blob, ann}
}

func simpleSigningDoc(t *testing.T, ref string, digest string) []byte {
	b, err := json.Marshal(map[string]any{"critical": map[string]any{
		"identity": map[string]string{"docker-reference": ref},
		"image":    map[string]string{"docker-manifest-digest": digest},
		"type":     "cosign container image signature",
	}, "optional": nil})
	require.NoError(t, err)
	return b
}

func TestVerifyOCI_CosignAttestationKeyless(t *testing.T) {
	c := newOCICase(t)
	sg := c.s.keyless(githubIdentity("acme/app", ".github/workflows/release.yml", "refs/heads/main"))
	c.pushCosign(t, c.digest, "att", "application/vnd.dsse.envelope.v1+json", c.attestation(t, sg, c.hex(), true))
	p, err := ParseSigners("github-actions:acme/app")
	require.NoError(t, err)

	rs, err := VerifyOCI(context.Background(), c.digest, p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	r := rs[0]
	assert.Equal(t, EnvelopeCosignAttestation, r.Envelope)
	assert.True(t, r.SignatureValid, r.Reason)
	assert.True(t, r.Verified)
	assert.True(t, r.TransparencyLogged)
	assert.Equal(t, "https://spdx.dev/Document", r.PredicateType)
	assert.Equal(t, []string{c.digest.DigestStr()}, r.SubjectDigests)
	assert.JSONEq(t, `{"spdxVersion":"SPDX-2.3"}`, string(r.Predicate()))

	// The same signature under a policy that names another signer.
	other, err := ParseSigners("github-actions:acme/other")
	require.NoError(t, err)
	rs, err = VerifyOCI(context.Background(), c.digest, other, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.True(t, rs[0].SignatureValid)
	assert.False(t, rs[0].Verified)
}

func TestVerifyOCI_CopiedSignatureWrongSubject(t *testing.T) {
	// A valid attestation of image A copied to image B's .att tag.
	c := newOCICase(t)
	sg := c.s.keyless(githubIdentity("acme/app", ".github/workflows/release.yml", "refs/heads/main"))
	other, err := random.Image(64, 1)
	require.NoError(t, err)
	require.NoError(t, remote.Write(c.repo.Tag("other"), other))
	od, err := other.Digest()
	require.NoError(t, err)
	c.pushCosign(t, c.digest, "att", "application/vnd.dsse.envelope.v1+json", c.attestation(t, sg, od.Hex, true))
	p, err := ParseSigners("github-actions:acme/app")
	require.NoError(t, err)

	rs, err := VerifyOCI(context.Background(), c.digest, p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.False(t, rs[0].SignatureValid)
	assert.True(t, rs[0].SubjectMismatch, rs[0].Reason)
	assert.False(t, rs[0].Verified)
	assert.Empty(t, rs[0].SAN)
}

func TestVerifyOCI_UnloggedKeylessAttestationInvalid(t *testing.T) {
	c := newOCICase(t)
	sg := c.s.keyless(githubIdentity("acme/app", ".github/workflows/release.yml", "refs/heads/main"))
	c.pushCosign(t, c.digest, "att", "application/vnd.dsse.envelope.v1+json", c.attestation(t, sg, c.hex(), false))
	rs, err := VerifyOCI(context.Background(), c.digest, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.False(t, rs[0].SignatureValid)
	assert.Empty(t, rs[0].SAN)
}

func TestVerifyOCI_KeySignedAttestation(t *testing.T) {
	c := newOCICase(t)
	sg := newKeySigner(t)
	c.pushCosign(t, c.digest, "att", "application/vnd.dsse.envelope.v1+json", c.attestation(t, sg, c.hex(), true))
	p, err := ParseSigners("key:"+sg.fingerprint(t), sg.verifierPEM(t))
	require.NoError(t, err)
	rs, err := VerifyOCI(context.Background(), c.digest, p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.True(t, rs[0].Verified, rs[0].Reason)
	assert.Equal(t, SignerKey, rs[0].SignerKind)
	assert.Equal(t, sg.fingerprint(t), rs[0].KeyFingerprint)

	// Without the key, the signature cannot be verified: invalid, never an
	// identity.
	rs, err = VerifyOCI(context.Background(), c.digest, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.False(t, rs[0].SignatureValid)
	assert.Empty(t, rs[0].KeyFingerprint)
}

func TestVerifyOCI_KeySignedUnloggedTriesConfiguredKeys(t *testing.T) {
	c := newOCICase(t)
	sg := newKeySigner(t)
	c.pushCosign(t, c.digest, "att", "application/vnd.dsse.envelope.v1+json", c.attestation(t, sg, c.hex(), false))
	optOut := false
	p, err := NewPolicy(Signer{PublicKey: string(sg.verifierPEM(t)), RequireTlog: &optOut})
	require.NoError(t, err)
	decoy := newKeySigner(t)
	rs, err := VerifyOCI(context.Background(), c.digest, p, WithTrustRoot(c.s.trust), WithKeys(decoy.verifierPEM(t)))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.True(t, rs[0].Verified, rs[0].Reason)
	assert.Equal(t, sg.fingerprint(t), rs[0].KeyFingerprint)
	assert.False(t, rs[0].TransparencyLogged)
}

func TestVerifyOCI_CosignSignature(t *testing.T) {
	c := newOCICase(t)
	sg := c.s.keyless(githubIdentity("acme/app", ".github/workflows/release.yml", "refs/heads/main"))
	good, goodAnn := c.s.cosignLayer(sg, EnvelopeCosignSignature, simpleSigningDoc(t, c.repo.Name(), c.digest.DigestStr()), true)
	c.pushCosign(t, c.digest, "sig", "application/vnd.dev.cosign.simplesigning.v1+json", [2]any{good, goodAnn})
	p, err := ParseSigners("github-actions:acme/app")
	require.NoError(t, err)
	rs, err := VerifyOCI(context.Background(), c.digest, p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.Equal(t, EnvelopeCosignSignature, rs[0].Envelope)
	assert.True(t, rs[0].Verified, rs[0].Reason)
	assert.Equal(t, []string{c.digest.DigestStr()}, rs[0].SubjectDigests)
}

func TestVerifyOCI_CosignSignatureOfAnotherDigest(t *testing.T) {
	c := newOCICase(t)
	sg := c.s.keyless(githubIdentity("acme/app", ".github/workflows/release.yml", "refs/heads/main"))
	doc := simpleSigningDoc(t, c.repo.Name(), "sha256:"+sha256Hex([]byte("another image")))
	blob, ann := c.s.cosignLayer(sg, EnvelopeCosignSignature, doc, true)
	c.pushCosign(t, c.digest, "sig", "application/vnd.dev.cosign.simplesigning.v1+json", [2]any{blob, ann})
	rs, err := VerifyOCI(context.Background(), c.digest, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.False(t, rs[0].SignatureValid)
	assert.True(t, rs[0].SubjectMismatch)
	assert.Empty(t, rs[0].SAN)
}

func TestVerifyOCI_Referrer(t *testing.T) {
	c := newOCICase(t)
	sg := c.s.keyless(githubIdentity("acme/app", ".github/workflows/build.yml", "refs/heads/main"))
	b := c.s.dsseBundle(sg, statementJSON(t, "https://slsa.dev/provenance/v1", map[string]any{}, c.hex()), bundleOpts{})
	const mt = "application/vnd.dev.sigstore.bundle.v0.3+json"
	art, err := mutate.Append(mutate.ConfigMediaType(empty.Image, mt), mutate.Addendum{Layer: static.NewLayer(b, mt)})
	require.NoError(t, err)
	desc, err := remote.Head(c.digest)
	require.NoError(t, err)
	withSubject := mutate.Subject(art, *desc).(v1.Image)
	ad, err := withSubject.Digest()
	require.NoError(t, err)
	require.NoError(t, remote.Write(c.repo.Digest(ad.String()), withSubject))

	p, err := ParseSigners("github-actions:acme/app@.github/workflows/build.yml@refs/heads/main")
	require.NoError(t, err)
	rs, err := VerifyOCI(context.Background(), c.digest, p, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.Equal(t, EnvelopeOCIReferrer, rs[0].Envelope)
	assert.True(t, rs[0].Verified, rs[0].Reason)
}

func TestVerifyOCI_IndexPerPlatform(t *testing.T) {
	c := newOCICase(t)
	// A BuildKit index: the platform image and its attestation manifest.
	stmt := statementJSON(t, "https://spdx.dev/Document", map[string]any{}, c.hex())
	attImg, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(stmt, "application/vnd.in-toto+json"), Annotations: map[string]string{buildkitPredicate: "https://spdx.dev/Document"},
	})
	require.NoError(t, err)
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: c.img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: attImg, Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{buildkitRefType: buildkitManifestType, buildkitRefDigest: c.digest.DigestStr()},
		}},
	)
	require.NoError(t, remote.WriteIndex(c.repo.Tag("multi"), idx))
	idxDigest, err := idx.Digest()
	require.NoError(t, err)
	indexRef := c.repo.Digest(idxDigest.String())

	_, err = VerifyOCI(context.Background(), indexRef, Policy{}, WithTrustRoot(c.s.trust))
	assert.ErrorIs(t, err, ErrIndexSubject, "an index digest is never a subject")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))

	rs, err := VerifyOCI(context.Background(), c.digest, Policy{}, WithTrustRoot(c.s.trust), WithIndex(indexRef))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.Equal(t, EnvelopeBuildKitIndex, rs[0].Envelope)
	assert.False(t, rs[0].SignatureValid, "BuildKit attestations are not signed")
	assert.Equal(t, []string{c.digest.DigestStr()}, rs[0].SubjectDigests)
	assert.NotContains(t, rs[0].SubjectDigests, idxDigest.String())
}

func TestVerifyOCI_NoSignatureIsEmpty(t *testing.T) {
	c := newOCICase(t)
	rs, err := VerifyOCI(context.Background(), c.digest, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	assert.Empty(t, rs)
}

func TestVerifyOCI_MalformedLayerIsInvalidNotError(t *testing.T) {
	c := newOCICase(t)
	sg := c.s.keyless(githubIdentity("acme/app", ".github/workflows/release.yml", "refs/heads/main"))
	c.pushCosign(t, c.digest, "att", "application/vnd.dsse.envelope.v1+json",
		[2]any{[]byte("not json"), map[string]string{}}, c.attestation(t, sg, c.hex(), true))
	rs, err := VerifyOCI(context.Background(), c.digest, Policy{}, WithTrustRoot(c.s.trust))
	require.NoError(t, err)
	require.Len(t, rs, 2)
	assert.False(t, rs[0].SignatureValid)
	assert.Contains(t, rs[0].Reason, "does not parse")
	assert.True(t, rs[1].SignatureValid, rs[1].Reason)
}

func TestVerifyOCI_RegistryUnavailable(t *testing.T) {
	c := newOCICase(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(srv.URL)
	srv.Close()
	ref, err := name.NewDigest(u.Host + "/acme/app@" + c.digest.DigestStr())
	require.NoError(t, err)
	_, err = VerifyOCI(context.Background(), ref, Policy{}, WithTrustRoot(c.s.trust))
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
}

func TestVerifyOCI_RegistryForbidden(t *testing.T) {
	c := newOCICase(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	ref, err := name.NewDigest(u.Host + "/acme/app@" + c.digest.DigestStr())
	require.NoError(t, err)
	_, err = VerifyOCI(context.Background(), ref, Policy{}, WithTrustRoot(c.s.trust))
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
}
