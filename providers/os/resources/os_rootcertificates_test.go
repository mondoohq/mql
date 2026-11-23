// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/network/resources/certificates"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
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

// Solaris keeps its bundle under /etc/certs, which no Linux path names:
// os.rootCertificates read zero roots on a host that trusts 186.
func TestOsRootCertificates_Solaris(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "solaris",
			Version: "11.4",
			Family:  []string{"unix", "os"},
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

// AIX 7.1 ships no bundle: every root is a .crt in /var/ssl/certs, itself a
// link into /opt/freeware/etc/ssl/certs, with an OpenSSL hash link to it.
// The .crt entries are read, the hash links are not, so each root counts
// once.
func TestOsRootCertificates_AixWithoutBundle(t *testing.T) {
	dir := &mock.MockFileData{Path: "/var/ssl/certs", StatData: mock.FileInfo{IsDir: true, Mode: os.ModeDir | 0o755}}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "aix", Version: "7.1", Family: []string{"unix", "os"}},
	}, mock.WithData(&mock.TomlData{Files: map[string]*mock.MockFileData{
		"/var/ssl/certs": dir,
		"/var/ssl/certs/GlobalSign_Root_CA_-_R3.crt": certAt("/var/ssl/certs/GlobalSign_Root_CA_-_R3.crt"),
		"/var/ssl/certs/Entrust_Root_Certification_Authority_-_G2.crt": {
			Path:     "/var/ssl/certs/Entrust_Root_Certification_Authority_-_G2.crt",
			Content:  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			StatData: mock.FileInfo{Mode: os.ModeSymlink | 0o777, Size: 60},
		},
		"/var/ssl/certs/062cdee6.0": {
			Path:     "/var/ssl/certs/062cdee6.0",
			StatData: mock.FileInfo{Mode: os.ModeSymlink | 0o777},
		},
	}}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	assert.ElementsMatch(t, []string{
		"/var/ssl/certs/GlobalSign_Root_CA_-_R3.crt",
		"/var/ssl/certs/Entrust_Root_Certification_Authority_-_G2.crt",
	}, initedPaths(t, runtime))
}

// certAt is a certificate file the mock lists in its directory, which
// needs the file's path.
func certAt(p string) *mock.MockFileData {
	f := bundleFile(0o644)
	f.Path = p
	return f
}

// With the bundle present, AIX 7.3 reads it alone, not the per-root files.
func TestOsRootCertificates_AixBundleWins(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "aix", Version: "7.3", Family: []string{"unix", "os"}},
	}, mock.WithData(&mock.TomlData{Files: map[string]*mock.MockFileData{
		"/var/ssl/certs/ca-bundle.crt":               bundleFile(0o644),
		"/var/ssl/certs/GlobalSign_Root_CA_-_R3.crt": bundleFile(0o644),
	}}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	assert.Equal(t, []string{"/var/ssl/certs/ca-bundle.crt"}, initedPaths(t, runtime))
}

// storeRuntime builds a Windows runtime, with the store command answering as given.
func storeRuntime(t *testing.T, platform *inventory.Platform, command string, out *mock.Command) *plugin.Runtime {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{Platform: platform}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{command: out},
	}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// storeContent runs the init and returns its files and content.
func storeContent(t *testing.T, runtime *plugin.Runtime) ([]any, []any) {
	t.Helper()
	args, _, err := initOsRootCertificates(runtime, map[string]*llx.RawData{})
	require.NoError(t, err)
	return args["files"].Value.([]any), args["content"].Value.([]any)
}

// commonNames parses content the way the shared certificates resource does.
func commonNames(t *testing.T, content []any) ([]string, int) {
	t.Helper()
	require.Len(t, content, 1)
	certs, skipped, err := certificates.ParseCertsFromPEMPartial(strings.NewReader(content[0].(string)))
	require.NoError(t, err)
	names := []string{}
	for _, c := range certs {
		names = append(names, c.Subject.CommonName)
	}
	return names, skipped
}

var windowsServer2022 = &inventory.Platform{
	Name:    "windows",
	Version: "20348",
	Family:  []string{"windows", "os"},
}

// Windows errored with "root certificates are not supported on this
// platform: windows 20348". The roots come from LocalMachine\Root.
//
// Measured: Windows Server 2022 Datacenter (build 20348), 2026-11-22, two of
// the 33 entries RootCertificatesScript returned there.
func TestOsRootCertificates_Windows(t *testing.T) {
	data, err := os.ReadFile("windows/testdata/root-store.json")
	require.NoError(t, err)
	runtime := storeRuntime(t, windowsServer2022, powershell.Encode(windows.RootCertificatesScript),
		&mock.Command{Stdout: string(data)})

	files, content := storeContent(t, runtime)
	assert.Empty(t, files)
	names, skipped := commonNames(t, content)
	assert.Equal(t, []string{"Microsoft Root Certificate Authority 2011", "Amazon Root CA 3"}, names)
	assert.Equal(t, 0, skipped)
}

// Synthetic: a store entry without valid bytes; no target showed this. It
// is counted as unparseable rather than dropped.
func TestOsRootCertificates_WindowsBadEntryIsUnparseable(t *testing.T) {
	data, err := os.ReadFile("windows/testdata/root-store.json")
	require.NoError(t, err)
	out := strings.Replace(string(data), "[", `[{"Location":"LocalMachine","Store":"Root","Thumbprint":"AA","Der":"not base64"},`, 1)
	runtime := storeRuntime(t, windowsServer2022, powershell.Encode(windows.RootCertificatesScript),
		&mock.Command{Stdout: out})

	_, content := storeContent(t, runtime)
	names, skipped := commonNames(t, content)
	assert.Len(t, names, 2)
	assert.Equal(t, 1, skipped)
}

// Synthetic: an empty Root store; no target showed this. It is an empty
// list, not a bundle that fails to parse.
func TestOsRootCertificates_WindowsEmptyStore(t *testing.T) {
	runtime := storeRuntime(t, windowsServer2022, powershell.Encode(windows.RootCertificatesScript),
		&mock.Command{Stdout: ""})

	_, content := storeContent(t, runtime)
	assert.Empty(t, content)
}

// Synthetic: the store cannot be read; no target showed this. An error, not
// an empty list that reads as a host trusting no CA.
func TestOsRootCertificates_WindowsStoreUnreadable(t *testing.T) {
	runtime := storeRuntime(t, windowsServer2022, powershell.Encode(windows.RootCertificatesScript),
		&mock.Command{Stderr: "Access is denied.", ExitStatus: 1})

	_, _, err := initOsRootCertificates(runtime, map[string]*llx.RawData{})
	assert.ErrorContains(t, err, "Access is denied.")
}
