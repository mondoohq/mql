// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/utils/verify"
)

// verifiedFakeRegistry is a fakeRegistry that also serves verification
// sidecars.
type verifiedFakeRegistry struct {
	*fakeRegistry
	manifest    []byte
	manifestErr error
	sigErr      error
}

func (r *verifiedFakeRegistry) DownloadChecksums(ctx context.Context, name, version string) ([]byte, bool, error) {
	if r.manifestErr != nil {
		return nil, false, r.manifestErr
	}
	return r.manifest, r.manifest != nil, nil
}

func (r *verifiedFakeRegistry) DownloadSignature(ctx context.Context, name, version string) ([]byte, bool, error) {
	return nil, false, r.sigErr
}

func sha256Line(filename string, data []byte) string {
	return fmt.Sprintf("%x  %s\n", sha256.Sum256(data), filename)
}

func useSignaturePolicy(t *testing.T, p verify.SignaturePolicy) {
	t.Helper()
	orig := providerSignaturePolicy()
	SetProviderSignaturePolicy(p)
	t.Cleanup(func() { SetProviderSignaturePolicy(orig) })
}

func TestVerifyProviderDownload(t *testing.T) {
	ctx := context.Background()
	// Synthetic: the manifest format is what `shasum -a 256` writes in
	// scripts/provider_bundler.sh; the archive bytes are made up.
	archive := []byte("archive bytes")
	files := map[string][]byte{"testp_1.2.3_linux_amd64.tar.xz": archive}
	good := []byte(sha256Line("testp_1.2.3_linux_amd64.tar.xz", archive) + sha256Line("testp_1.2.3_schema.json", []byte("{}")))

	use := func(t *testing.T, reg ProviderRegistry) {
		orig := registry
		registry = reg
		t.Cleanup(func() { registry = orig })
	}

	t.Run("matching manifest", func(t *testing.T) {
		use(t, &verifiedFakeRegistry{fakeRegistry: &fakeRegistry{}, manifest: good})
		assert.NoError(t, verifyProviderDownload(ctx, "testp", "1.2.3", files))
	})

	t.Run("tampered archive", func(t *testing.T) {
		use(t, &verifiedFakeRegistry{fakeRegistry: &fakeRegistry{}, manifest: good})
		err := verifyProviderDownload(ctx, "testp", "1.2.3", map[string][]byte{"testp_1.2.3_linux_amd64.tar.xz": []byte("other bytes")})
		assert.ErrorIs(t, err, verify.ErrChecksumMismatch)
	})

	t.Run("file the manifest does not list", func(t *testing.T) {
		use(t, &verifiedFakeRegistry{fakeRegistry: &fakeRegistry{}, manifest: good})
		err := verifyProviderDownload(ctx, "testp", "1.2.3", map[string][]byte{"testp_1.2.3_darwin_arm64.tar.xz": archive})
		assert.ErrorIs(t, err, verify.ErrChecksumNotFound)
	})

	t.Run("one bad file among several fails", func(t *testing.T) {
		use(t, &verifiedFakeRegistry{fakeRegistry: &fakeRegistry{}, manifest: good})
		err := verifyProviderDownload(ctx, "testp", "1.2.3", map[string][]byte{
			"testp_1.2.3_linux_amd64.tar.xz": archive,
			"testp_1.2.3_schema.json":        []byte(`{"tampered":true}`),
		})
		assert.ErrorIs(t, err, verify.ErrChecksumMismatch)
	})

	t.Run("signature fetch failure under auto", func(t *testing.T) {
		use(t, &verifiedFakeRegistry{fakeRegistry: &fakeRegistry{}, manifest: good, sigErr: errors.New("403")})
		assert.NoError(t, verifyProviderDownload(ctx, "testp", "1.2.3", files))
	})

	unverifiable := map[string]ProviderRegistry{
		"manifest not published":   &verifiedFakeRegistry{fakeRegistry: &fakeRegistry{}},
		"manifest fetch fails":     &verifiedFakeRegistry{fakeRegistry: &fakeRegistry{}, manifestErr: errors.New("403")},
		"registry without sidecar": &fakeRegistry{},
	}
	for name, reg := range unverifiable {
		t.Run(name+" under auto", func(t *testing.T) {
			use(t, reg)
			assert.NoError(t, verifyProviderDownload(ctx, "testp", "1.2.3", files))
		})
		t.Run(name+" under require", func(t *testing.T) {
			use(t, reg)
			useSignaturePolicy(t, verify.SignatureRequire)
			assert.Error(t, verifyProviderDownload(ctx, "testp", "1.2.3", files))
		})
	}

	t.Run("off still checks a published manifest", func(t *testing.T) {
		use(t, &verifiedFakeRegistry{fakeRegistry: &fakeRegistry{}, manifest: good})
		useSignaturePolicy(t, verify.SignatureOff)
		err := verifyProviderDownload(ctx, "testp", "1.2.3", map[string][]byte{"testp_1.2.3_linux_amd64.tar.xz": []byte("other bytes")})
		assert.ErrorIs(t, err, verify.ErrChecksumMismatch)
	})
}

// A download that does not match its manifest is never unpacked.
func TestInstallRejectsArchiveNotMatchingManifest(t *testing.T) {
	const name = "testp"
	const version = "1.2.3"
	archive := testProviderArchive(t, name, version)
	archiveName := fmt.Sprintf("%s_%s_%s_%s.tar.xz", name, version, runtime.GOOS, runtime.GOARCH)

	reg := &verifiedFakeRegistry{
		fakeRegistry: &fakeRegistry{latest: version, archive: archive},
		manifest:     []byte(sha256Line(archiveName, []byte("the archive that was published"))),
	}
	dir := useTestProviderPath(t, reg)

	_, err := Install(name, version)
	require.ErrorIs(t, err, verify.ErrChecksumMismatch)
	assert.NoDirExists(t, filepath.Join(dir, name))

	// The same archive installs once the manifest agrees with it.
	reg.manifest = []byte(sha256Line(archiveName, archive))
	installed, err := Install(name, version)
	require.NoError(t, err)
	assert.Equal(t, version, installed.Version)
}

// Schema-only installs are checked against the release names of provider.json
// and schema.json in the same manifest.
func TestInstallSchemaOnlyVerifiesMetadata(t *testing.T) {
	const name = "testp"
	const version = "1.2.3"
	confJSON := []byte(`{"Name":"testp","ID":"testp","Version":"1.2.3"}`)
	schemaJSON := []byte(`{"resources":{}}`)

	reg := &verifiedFakeRegistry{
		fakeRegistry: &fakeRegistry{latest: version, confJSON: confJSON, schemaJSON: schemaJSON},
		manifest: []byte(sha256Line(name+"_"+version+"_provider.json", confJSON) +
			sha256Line(name+"_"+version+"_schema.json", []byte(`{"resources":{"other":{}}}`))),
	}
	useTestProviderPath(t, reg)

	_, err := InstallSchemaOnly(name, version)
	require.ErrorIs(t, err, verify.ErrChecksumMismatch)

	reg.manifest = []byte(sha256Line(name+"_"+version+"_provider.json", confJSON) +
		sha256Line(name+"_"+version+"_schema.json", schemaJSON))
	installed, err := InstallSchemaOnly(name, version)
	require.NoError(t, err)
	assert.False(t, installed.HasBinary)
}
