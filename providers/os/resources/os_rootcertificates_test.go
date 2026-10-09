// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// certBundleRuntime builds a runtime whose filesystem holds only the named
// bundle paths. A path mapped to a symlink mode is what an lstat reports for
// the canonical bundle path on SUSE and RHEL.
func certBundleRuntime(t *testing.T, files map[string]*mock.MockFileData) *plugin.Runtime {
	t.Helper()

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "sles",
			Version: "15.7",
			Family:  []string{"suse", "linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{Files: files}))
	require.NoError(t, err)

	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func bundleFile(mode os.FileMode) *mock.MockFileData {
	return &mock.MockFileData{
		Content:  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		StatData: mock.FileInfo{Mode: mode, Size: 60},
	}
}

func initedPaths(t *testing.T, runtime *plugin.Runtime) []string {
	t.Helper()

	args, _, err := initOsRootCertificates(runtime, map[string]*llx.RawData{})
	require.NoError(t, err)

	raw, ok := args["files"]
	require.True(t, ok)

	paths := []string{}
	for _, f := range raw.Value.([]any) {
		paths = append(paths, f.(*mqlFile).Path.Data)
	}
	return paths
}

// Every SUSE ships /etc/ssl/ca-bundle.pem as a symlink into
// /var/lib/ca-certificates. The permissions come from an lstat, so requiring
// isFile skipped it and os.rootCertificates reported zero trusted roots on all
// of SLES 12, 15 and 16 and openSUSE Leap -- which reads as a host that trusts
// nothing.
func TestOsRootCertificates_SymlinkedBundleIsUsed(t *testing.T) {
	runtime := certBundleRuntime(t, map[string]*mock.MockFileData{
		"/etc/ssl/ca-bundle.pem": bundleFile(os.ModeSymlink | 0o777),
	})

	assert.Equal(t, []string{"/etc/ssl/ca-bundle.pem"}, initedPaths(t, runtime))
}

// On RHEL 9 all three of ca-bundle.crt, cert.pem and tls-ca-bundle.pem are the
// same 146 certificates, two of them by symlink. Accepting symlinks without
// stopping at the first match would report the bundle three times over.
func TestOsRootCertificates_DuplicateBundlesAreNotCountedTwice(t *testing.T) {
	runtime := certBundleRuntime(t, map[string]*mock.MockFileData{
		"/etc/pki/tls/certs/ca-bundle.crt":                  bundleFile(os.ModeSymlink | 0o777),
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem": bundleFile(0o644),
		"/etc/ssl/cert.pem":                                 bundleFile(os.ModeSymlink | 0o777),
	})

	// the first path that exists wins, which is what Go's own root pool does
	assert.Equal(t, []string{"/etc/pki/tls/certs/ca-bundle.crt"}, initedPaths(t, runtime))
}

func TestOsRootCertificates_PlainFileBundle(t *testing.T) {
	runtime := certBundleRuntime(t, map[string]*mock.MockFileData{
		"/etc/ssl/certs/ca-certificates.crt": bundleFile(0o644),
	})

	assert.Equal(t, []string{"/etc/ssl/certs/ca-certificates.crt"}, initedPaths(t, runtime))
}

// A directory sitting on a bundle path is not a bundle.
func TestOsRootCertificates_DirectoryIsSkipped(t *testing.T) {
	runtime := certBundleRuntime(t, map[string]*mock.MockFileData{
		"/etc/ssl/certs/ca-certificates.crt": {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		"/etc/ssl/ca-bundle.pem":             bundleFile(0o644),
	})

	assert.Equal(t, []string{"/etc/ssl/ca-bundle.pem"}, initedPaths(t, runtime))
}

// A host with no bundle at all reports none, without erroring.
func TestOsRootCertificates_NoBundle(t *testing.T) {
	runtime := certBundleRuntime(t, map[string]*mock.MockFileData{})

	assert.Empty(t, initedPaths(t, runtime))
}

// Solaris 11.4 is detected into the linux family, but keeps its bundle under
// /etc/certs, which no Linux path names: os.rootCertificates read zero roots
// on a host that trusts 186.
func TestOsRootCertificates_Solaris(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "solaris",
			Version: "11.4",
			Family:  []string{"linux", "unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{Files: map[string]*mock.MockFileData{
		"/etc/certs/ca-certificates.crt": bundleFile(0o644),
	}}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	assert.Equal(t, []string{"/etc/certs/ca-certificates.crt"}, initedPaths(t, runtime))
}

// AIX keeps no bundle under any Linux or BSD path: os.rootCertificates
// errored with "not supported on this platform".
func TestOsRootCertificates_Aix(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "aix",
			Version: "7.3",
			Family:  []string{"unix", "os"},
		},
	}, mock.WithData(&mock.TomlData{Files: map[string]*mock.MockFileData{
		"/var/ssl/certs/ca-bundle.crt": bundleFile(0o644),
	}}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	assert.Equal(t, []string{"/var/ssl/certs/ca-bundle.crt"}, initedPaths(t, runtime))
}
