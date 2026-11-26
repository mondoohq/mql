// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"go.mondoo.com/mql/llx"
)

// Synthetic: a TUF repository built by the test with go-tuf's metadata
// types, one ed25519 key for every role, served through a fetcher instead of
// the network. Its target is a trusted_root.json from the test Sigstore.

const fakeTUFURL = "https://tuf.test.invalid"

type fakeTUF struct {
	t       *testing.T
	signer  signature.Signer
	files   map[string][]byte
	root    []byte
	offline bool
	calls   int
}

func newFakeTUF(t *testing.T) *fakeTUF {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := signature.LoadSigner(priv, crypto.Hash(0))
	require.NoError(t, err)
	key, err := metadata.KeyFromPublicKey(priv.Public())
	require.NoError(t, err)
	r := metadata.Root(time.Now().AddDate(1, 0, 0))
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		require.NoError(t, r.Signed.AddKey(key, role))
	}
	_, err = r.Sign(signer)
	require.NoError(t, err)
	rb, err := r.ToBytes(false)
	require.NoError(t, err)
	return &fakeTUF{t: t, signer: signer, root: rb, files: map[string][]byte{"1.root.json": rb}}
}

// publish makes version v of targets, snapshot and timestamp, holding
// trustedRoot, valid until expires.
func (f *fakeTUF) publish(v int64, trustedRoot []byte, expires time.Time) {
	t := f.t
	tg := metadata.Targets(expires)
	tg.Signed.Version = v
	tf, err := metadata.TargetFile().FromBytes(trustedRootTarget, trustedRoot, "sha256")
	require.NoError(t, err)
	tg.Signed.Targets[trustedRootTarget] = tf
	_, err = tg.Sign(f.signer)
	require.NoError(t, err)
	tb, err := tg.ToBytes(false)
	require.NoError(t, err)

	sn := metadata.Snapshot(expires)
	sn.Signed.Version = v
	sn.Signed.Meta["targets.json"] = metadata.MetaFile(v)
	_, err = sn.Sign(f.signer)
	require.NoError(t, err)
	sb, err := sn.ToBytes(false)
	require.NoError(t, err)

	ts := metadata.Timestamp(expires)
	ts.Signed.Version = v
	ts.Signed.Meta["snapshot.json"] = metadata.MetaFile(v)
	_, err = ts.Sign(f.signer)
	require.NoError(t, err)
	tsb, err := ts.ToBytes(false)
	require.NoError(t, err)

	sum := sha256.Sum256(trustedRoot)
	f.files[fmt.Sprintf("%d.targets.json", v)] = tb
	f.files[fmt.Sprintf("%d.snapshot.json", v)] = sb
	f.files["timestamp.json"] = tsb
	f.files["targets/"+hex.EncodeToString(sum[:])+"."+trustedRootTarget] = trustedRoot
}

func (f *fakeTUF) DownloadFile(u string, _ int64, _ time.Duration) ([]byte, error) {
	f.calls++
	if f.offline {
		return nil, errors.New("dial tcp: connection refused")
	}
	p := strings.TrimPrefix(u, fakeTUFURL+"/")
	if b, ok := f.files[p]; ok {
		return b, nil
	}
	return nil, &metadata.ErrDownloadHTTP{StatusCode: 404, URL: u}
}

func (f *fakeTUF) options(dir string) TrustOptions {
	return TrustOptions{CacheDir: dir, TUFRoot: f.root, RepositoryURL: fakeTUFURL, Fetcher: f}
}

func TestLoadTrustRoot_PrivateFirst(t *testing.T) {
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.publish(3, s.rootJSON, time.Now().AddDate(0, 1, 0))
	o := f.options(t.TempDir())
	o.PrivateRoot = s.rootJSON
	o.Embedded, o.EmbeddedVersion = s.rootJSON, 1
	tr, err := LoadTrustRoot(context.Background(), o)
	require.NoError(t, err)
	assert.Equal(t, TrustPrivate, tr.Source)
	assert.Zero(t, f.calls, "a private root consults nothing else")
}

func TestLoadTrustRoot_TUFRefresh(t *testing.T) {
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.publish(3, s.rootJSON, time.Now().AddDate(0, 1, 0))
	dir := t.TempDir()
	o := f.options(dir)
	o.Embedded, o.EmbeddedVersion = s.rootJSON, 2
	tr, err := LoadTrustRoot(context.Background(), o)
	require.NoError(t, err)
	assert.Equal(t, TrustTUF, tr.Source)
	assert.Equal(t, int64(3), tr.Version)
	assert.Equal(t, "tuf@3", tr.String())
	assert.Equal(t, int64(3), readTrustState(dir).Highest[fakeTUFURL], "the version used is recorded")
}

func TestTrustRoot_OfflineUsesCacheWithinExpiry(t *testing.T) {
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.publish(5, s.rootJSON, time.Now().AddDate(0, 1, 0))
	dir := t.TempDir()
	o := f.options(dir)
	o.Embedded, o.EmbeddedVersion = s.rootJSON, 2
	_, err := LoadTrustRoot(context.Background(), o)
	require.NoError(t, err)

	f.offline = true
	tr, err := LoadTrustRoot(context.Background(), o)
	require.NoError(t, err)
	assert.Equal(t, TrustTUFCache, tr.Source, "the cache wins over the embedded root once fetched")
	assert.Equal(t, int64(5), tr.Version)
}

func TestTrustRoot_ExpiredCacheFailsClosed(t *testing.T) {
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.publish(5, s.rootJSON, time.Now().Add(48*time.Hour))
	dir := t.TempDir()
	o := f.options(dir)
	_, err := LoadTrustRoot(context.Background(), o)
	require.NoError(t, err)

	f.offline = true
	o.Embedded, o.EmbeddedVersion = s.rootJSON, 2
	o.Now = func() time.Time { return time.Now().Add(72 * time.Hour) }
	tr, err := LoadTrustRoot(context.Background(), o)
	require.Error(t, err)
	assert.Nil(t, tr)
	assert.ErrorIs(t, err, ErrTrustRootExpired)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err), "never falls back to the embedded root")
}

func TestTrustRoot_CacheOlderThanEmbeddedFailsClosed(t *testing.T) {
	// Once a root was fetched, the embedded one is never used, even when it
	// is newer than the cache: offline, the verification fails instead.
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.publish(5, s.rootJSON, time.Now().AddDate(0, 1, 0))
	o := f.options(t.TempDir())
	_, err := LoadTrustRoot(context.Background(), o)
	require.NoError(t, err)
	f.offline = true
	o.Embedded, o.EmbeddedVersion = s.rootJSON, 9
	_, err = LoadTrustRoot(context.Background(), o)
	assert.ErrorIs(t, err, ErrTrustRootRollback)
}

func TestTrustRoot_OfflineUsesEmbedded(t *testing.T) {
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.offline = true
	o := f.options(t.TempDir())
	o.Embedded, o.EmbeddedVersion = s.rootJSON, 14
	tr, err := LoadTrustRoot(context.Background(), o)
	require.NoError(t, err)
	assert.Equal(t, TrustEmbedded, tr.Source)
	assert.Equal(t, "embedded@14", tr.String())
}

func TestTrustRoot_CachedNewerNeverReplacedByEmbedded(t *testing.T) {
	// The machine once used targets version 20; its metadata is gone (or was
	// removed to force a rollback). The embedded root is older and must not
	// be used.
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.offline = true
	dir := t.TempDir()
	writeTrustState(dir, trustState{Highest: map[string]int64{fakeTUFURL: 20}})
	o := f.options(dir)
	o.Embedded, o.EmbeddedVersion = s.rootJSON, 14
	_, err := LoadTrustRoot(context.Background(), o)
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
}

func TestTrustRoot_RollbackBelowEmbeddedRefused(t *testing.T) {
	// A fresh machine is served TUF metadata older than the root the caller
	// embeds: a rollback a fresh TUF client cannot see on its own.
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.publish(3, s.rootJSON, time.Now().AddDate(0, 1, 0))
	o := f.options(t.TempDir())
	o.Embedded, o.EmbeddedVersion = s.rootJSON, 14
	_, err := LoadTrustRoot(context.Background(), o)
	assert.ErrorIs(t, err, ErrTrustRootRollback)
}

func TestTrustRoot_RollbackBelowRecordedRefused(t *testing.T) {
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.publish(3, s.rootJSON, time.Now().AddDate(0, 1, 0))
	dir := t.TempDir()
	writeTrustState(dir, trustState{Highest: map[string]int64{fakeTUFURL: 7}})
	_, err := LoadTrustRoot(context.Background(), f.options(dir))
	assert.ErrorIs(t, err, ErrTrustRootRollback)
}

func TestTrustRoot_NoneAtAll(t *testing.T) {
	f := newFakeTUF(t)
	f.offline = true
	_, err := LoadTrustRoot(context.Background(), f.options(t.TempDir()))
	assert.ErrorIs(t, err, ErrNoTrustRoot)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
}

func TestTrustRoot_VerifiesWithFetchedRoot(t *testing.T) {
	// End to end: the root fetched through TUF verifies a bundle.
	s := newTestSigstore(t)
	f := newFakeTUF(t)
	f.publish(2, s.rootJSON, time.Now().AddDate(0, 1, 0))
	artifact := []byte("a")
	sg := s.keyless(githubIdentity("acme/app", ".github/workflows/release.yml", "refs/heads/main"))
	b := s.dsseBundle(sg, statementJSON(t, "https://example.test/p", map[string]any{}, sha256Hex(artifact)), bundleOpts{})
	r, err := VerifyBlob(context.Background(), "sha256:"+sha256Hex(artifact), b, Policy{}, WithTrustOptions(f.options(t.TempDir())))
	require.NoError(t, err)
	assert.True(t, r.SignatureValid, r.Reason)
}

func TestReadTrustState_Corrupt(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "trust-state.json"), []byte("{"), 0o600))
	s := readTrustState(dir)
	assert.NotNil(t, s.Highest)
	b, _ := json.Marshal(s)
	assert.JSONEq(t, `{"highest":{}}`, string(b))
}
