// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Synthetic: model directories and OpenSSF model signing bundles built by
// the test. The statement layout (predicate type, resources with name,
// algorithm and digest, serialization, and a subject digest over the
// resource digests in name order) follows the model signing format's
// documentation; no bundle made by the reference signing tool was available
// to this test, so the layout is not cross-checked against one.

var modelFiles = map[string]string{
	"config.json":       `{"model_type":"llama"}`,
	"model.safetensors": "weights-weights-weights",
	"tokenizer.json":    `{"version":"1.0"}`,
}

func writeModel(t *testing.T, fsys afero.Fs, dir string, files map[string]string) {
	for name, content := range files {
		p := filepath.Join(dir, name)
		require.NoError(t, fsys.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, afero.WriteFile(fsys, p, []byte(content), 0o644))
	}
}

func modelResources(files map[string]string) []modelResource {
	var out []modelResource
	for name, content := range files {
		sum := sha256.Sum256([]byte(content))
		out = append(out, modelResource{Name: name, Algorithm: "sha256", Digest: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// modelStatement is a v1.0 model signing statement over resources.
func modelStatement(t *testing.T, resources []modelResource) []byte {
	d := manifestDigest(resources)
	b, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "model", "digest": map[string]string{"sha256": d[len("sha256:"):]}}},
		"predicateType": ModelSigningV1Predicate,
		"predicate": map[string]any{
			"resources":     resources,
			"serialization": map[string]any{"method": "files", "hash_type": "sha256", "allow_symlinks": false, "ignore_paths": []string{".git"}},
		},
	})
	require.NoError(t, err)
	return b
}

type modelCase struct {
	s    *testSigstore
	fsys afero.Fs
	dir  string
	sg   testSigner
}

func newModelCase(t *testing.T) modelCase {
	s := newTestSigstore(t)
	fsys := afero.NewMemMapFs()
	dir := "/models/llama"
	writeModel(t, fsys, dir, modelFiles)
	return modelCase{s: s, fsys: fsys, dir: dir, sg: s.keyless(identity{SAN: "publisher@models.example.com", Issuer: "https://accounts.example.com"})}
}

func (c modelCase) bundle(t *testing.T) []byte {
	return c.s.dsseBundle(c.sg, modelStatement(t, modelResources(modelFiles)), bundleOpts{})
}

func (c modelCase) verify(t *testing.T, b []byte, opts ...Option) ModelResult {
	r, err := VerifyModel(context.Background(), c.fsys, c.dir, b, append([]Option{WithTrustRoot(c.s.trust)}, opts...)...)
	require.NoError(t, err)
	return r
}

func TestVerifyModel_Verified(t *testing.T) {
	c := newModelCase(t)
	r := c.verify(t, c.bundle(t))
	assert.Equal(t, ModelVerified, r.Status, r.Reason)
	assert.True(t, r.SignatureValid)
	assert.Equal(t, "publisher@models.example.com", r.SAN)
	assert.Equal(t, "https://accounts.example.com", r.Issuer)
	assert.Equal(t, manifestDigest(modelResources(modelFiles)), r.ManifestDigest)
	assert.Equal(t, int64(len(modelFiles["config.json"])+len(modelFiles["model.safetensors"])+len(modelFiles["tokenizer.json"])), r.BytesHashed)
	assert.Empty(t, r.ExtraFiles)

	// Verified never means accepted: acceptance is the caller's policy.
	assert.False(t, r.Accepted)
	p, err := NewPolicy(ExactKeyless("https://accounts.example.com", "publisher@models.example.com"))
	require.NoError(t, err)
	assert.True(t, p.Accepts(r.Result))
	other, err := NewPolicy(ExactKeyless("https://accounts.example.com", "someone@models.example.com"))
	require.NoError(t, err)
	assert.False(t, other.Accepts(r.Result))
}

func TestVerifyModel_TamperedWeightInvalid(t *testing.T) {
	c := newModelCase(t)
	b := c.bundle(t)
	require.NoError(t, afero.WriteFile(c.fsys, filepath.Join(c.dir, "model.safetensors"), []byte("swapped"), 0o644))
	r := c.verify(t, b)
	assert.Equal(t, ModelInvalid, r.Status)
	assert.Equal(t, []string{"model.safetensors"}, r.MismatchedFiles)
}

func TestVerifyModel_ExtraFiles(t *testing.T) {
	c := newModelCase(t)
	b := c.bundle(t)
	writeModel(t, c.fsys, c.dir, map[string]string{"README.md": "# docs", ".git/HEAD": "ref", "model.sig": "bundle"})
	r := c.verify(t, b)
	assert.Equal(t, ModelVerified, r.Status, "documentation outside the signature does not change verified")
	assert.Equal(t, []string{"README.md"}, r.ExtraFiles, "ignored paths and the signature file are not extra")

	writeModel(t, c.fsys, c.dir, map[string]string{"extra.pkl": "pickle"})
	r = c.verify(t, b)
	assert.Equal(t, ModelInvalid, r.Status, "an unsigned pickle beside a signed model")
	assert.Contains(t, r.ExtraFiles, "extra.pkl")
}

func TestVerifyModel_MissingFileIncomplete(t *testing.T) {
	c := newModelCase(t)
	b := c.bundle(t)
	require.NoError(t, c.fsys.Remove(filepath.Join(c.dir, "tokenizer.json")))
	r := c.verify(t, b)
	assert.Equal(t, ModelIncomplete, r.Status)
	assert.Equal(t, []string{"tokenizer.json"}, r.MissingFiles)
}

func TestVerifyModel_ByteBound(t *testing.T) {
	c := newModelCase(t)
	r := c.verify(t, c.bundle(t), WithModelByteBound(30))
	assert.Equal(t, ModelIncomplete, r.Status)
	assert.Contains(t, r.Reason, "30-byte bound")
	assert.LessOrEqual(t, r.BytesHashed, int64(30))
}

func TestVerifyModel_UnknownPredicateUnverifiable(t *testing.T) {
	c := newModelCase(t)
	st := statementJSON(t, "https://model_signing/signature/v9", map[string]any{}, sha256Hex([]byte("x")))
	r := c.verify(t, c.s.dsseBundle(c.sg, st, bundleOpts{}))
	assert.Equal(t, ModelUnverifiable, r.Status)
}

func TestVerifyModel_SubjectNotOverResources(t *testing.T) {
	c := newModelCase(t)
	var st map[string]any
	require.NoError(t, json.Unmarshal(modelStatement(t, modelResources(modelFiles)), &st))
	st["subject"] = []any{map[string]any{"name": "model", "digest": map[string]string{"sha256": sha256Hex([]byte("other"))}}}
	b, err := json.Marshal(st)
	require.NoError(t, err)
	r := c.verify(t, c.s.dsseBundle(c.sg, b, bundleOpts{}))
	assert.Equal(t, ModelUnverifiable, r.Status)
	assert.False(t, r.SignatureValid)
}

func TestVerifyModel_KeySigner(t *testing.T) {
	c := newModelCase(t)
	sg := newKeySigner(t)
	b := c.s.dsseBundle(sg, modelStatement(t, modelResources(modelFiles)), bundleOpts{})

	r := c.verify(t, b)
	assert.Equal(t, ModelUnverifiable, r.Status, "a key the configuration does not hold")
	assert.Empty(t, r.KeyFingerprint)

	r = c.verify(t, b, WithKeys(sg.verifierPEM(t)))
	assert.Equal(t, ModelVerified, r.Status, r.Reason)
	assert.Equal(t, SignerKey, r.SignerKind)
	assert.Equal(t, sg.fingerprint(t), r.KeyFingerprint)
}

func TestVerifyModel_UntrustedCertificateUnverifiable(t *testing.T) {
	c := newModelCase(t)
	otherRoot, otherKey, err := caGenerateRoot()
	require.NoError(t, err)
	sg := c.s.keylessFrom(otherRoot, otherKey, identity{SAN: "publisher@models.example.com", Issuer: "https://accounts.example.com"})
	r := c.verify(t, c.s.dsseBundle(sg, modelStatement(t, modelResources(modelFiles)), bundleOpts{}))
	assert.Equal(t, ModelUnverifiable, r.Status)
	assert.Empty(t, r.SAN)
}

func TestVerifyModel_UnloggedKeylessUnverifiable(t *testing.T) {
	c := newModelCase(t)
	r := c.verify(t, c.s.dsseBundle(c.sg, modelStatement(t, modelResources(modelFiles)), bundleOpts{noLog: true}))
	assert.Equal(t, ModelUnverifiable, r.Status)
	assert.Empty(t, r.SAN)
}

func TestVerifyModel_BadSignatureInvalid(t *testing.T) {
	c := newModelCase(t)
	st := modelStatement(t, modelResources(modelFiles))
	b := c.s.dsseBundle(c.sg, st, bundleOpts{})
	// The same statement with one digest changed, keeping the signature.
	res := modelResources(modelFiles)
	res[0].Digest = sha256Hex([]byte("other"))
	r := c.verify(t, replaceB64(t, b, st, modelStatement(t, res)))
	assert.Equal(t, ModelInvalid, r.Status)
	assert.False(t, r.SignatureValid)
	assert.Empty(t, r.SAN)
}

func TestVerifyModel_ManifestPathTraversalInvalid(t *testing.T) {
	for _, name := range []string{"../secret", "/etc/passwd", "a/../../b", "a\\b"} {
		c := newModelCase(t)
		res := append(modelResources(modelFiles), modelResource{Name: name, Algorithm: "sha256", Digest: sha256Hex([]byte("x"))})
		r := c.verify(t, c.s.dsseBundle(c.sg, modelStatement(t, res), bundleOpts{}))
		assert.Equal(t, ModelInvalid, r.Status, name)
		assert.Contains(t, r.Reason, "unsafe paths", name)
	}
}

func TestVerifyModel_Symlinks(t *testing.T) {
	// A Hugging Face style cache: the snapshot links into the blob store.
	root := t.TempDir()
	blobs := filepath.Join(root, "blobs")
	snap := filepath.Join(root, "snapshots", "abc123")
	require.NoError(t, os.MkdirAll(blobs, 0o755))
	require.NoError(t, os.MkdirAll(snap, 0o755))
	for name, content := range modelFiles {
		blob := filepath.Join(blobs, sha256Hex([]byte(content)))
		require.NoError(t, os.WriteFile(blob, []byte(content), 0o644))
		require.NoError(t, os.Symlink(filepath.Join("..", "..", "blobs", sha256Hex([]byte(content))), filepath.Join(snap, name)))
	}
	s := newTestSigstore(t)
	sg := s.keyless(identity{SAN: "publisher@models.example.com", Issuer: "https://accounts.example.com"})
	b := s.dsseBundle(sg, modelStatement(t, modelResources(modelFiles)), bundleOpts{})
	fsys := afero.NewOsFs()

	r, err := VerifyModel(context.Background(), fsys, snap, b, WithTrustRoot(s.trust), WithModelRoot(root))
	require.NoError(t, err)
	assert.Equal(t, ModelVerified, r.Status, r.Reason)

	// Without the cache root, the links leave the model directory.
	r, err = VerifyModel(context.Background(), fsys, snap, b, WithTrustRoot(s.trust))
	require.NoError(t, err)
	assert.Equal(t, ModelInvalid, r.Status)

	// A link out of the cache root is refused even with it.
	outside := filepath.Join(t.TempDir(), "weights")
	require.NoError(t, os.WriteFile(outside, []byte(modelFiles["model.safetensors"]), 0o644))
	require.NoError(t, os.Remove(filepath.Join(snap, "model.safetensors")))
	require.NoError(t, os.Symlink(outside, filepath.Join(snap, "model.safetensors")))
	r, err = VerifyModel(context.Background(), fsys, snap, b, WithTrustRoot(s.trust), WithModelRoot(root))
	require.NoError(t, err)
	assert.Equal(t, ModelInvalid, r.Status)
	assert.Contains(t, r.Reason, "model.safetensors")
}

func TestVerifyModel_V01Predicate(t *testing.T) {
	c := newModelCase(t)
	var digests []any
	for _, res := range modelResources(modelFiles) {
		digests = append(digests, map[string]any{"name": res.Name, "digest": map[string]string{"sha256": res.Digest}})
	}
	b, err := json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "subject": digests,
		"predicateType": ModelSigningV01Predicate, "predicate": map[string]any{"unused": "Unused"},
	})
	require.NoError(t, err)
	r := c.verify(t, c.s.dsseBundle(c.sg, b, bundleOpts{}))
	assert.Equal(t, ModelVerified, r.Status, r.Reason)
}

func TestVerifyModel_PinnedDigestRefusesDowngrade(t *testing.T) {
	// An older release, validly signed by the same publisher, put in place
	// of the current one: valid, and refused by a policy that pins the
	// current manifest digest.
	c := newModelCase(t)
	r := c.verify(t, c.bundle(t))
	require.Equal(t, ModelVerified, r.Status)
	p, err := NewPolicy(ExactKeyless("https://accounts.example.com", "publisher@models.example.com"))
	require.NoError(t, err)
	p.Digests = []string{"sha256:" + sha256Hex([]byte("current release manifest"))}
	assert.False(t, p.Accepts(r.Result))
	p.Digests = []string{r.ManifestDigest}
	assert.True(t, p.Accepts(r.Result))
}

func TestVerifyModel_Forbidden(t *testing.T) {
	c := newModelCase(t)
	b := c.bundle(t)
	_, err := VerifyModel(context.Background(), denyFs{Fs: c.fsys, deny: "model.safetensors"}, c.dir, b, WithTrustRoot(c.s.trust))
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
}

func TestVerifyModel_MalformedBundle(t *testing.T) {
	c := newModelCase(t)
	_, err := VerifyModel(context.Background(), c.fsys, c.dir, []byte("{"), WithTrustRoot(c.s.trust))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}

func TestSafeModelPath(t *testing.T) {
	for name, ok := range map[string]bool{
		"model.safetensors": true, "sub/dir/file.bin": true,
		"": false, ".": false, "..": false, "../x": false, "/abs": false, "a//b": false, "a/./b": false, "a\\b": false,
	} {
		_, got := safeModelPath(name)
		assert.Equal(t, ok, got, name)
	}
}

// denyFs refuses to open one file, as a file the scan may not read.
type denyFs struct {
	afero.Fs
	deny string
}

func (d denyFs) Open(name string) (afero.File, error) {
	if filepath.Base(name) == d.deny {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.Fs.Open(name)
}
