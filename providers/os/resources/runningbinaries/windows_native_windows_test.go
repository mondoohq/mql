// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package runningbinaries

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/sys/windows"
)

// These run on the Windows CI runner. They compare the native reads with the
// PowerShell path on the same machine, which is what has to hold before the
// native path may answer in its place.

func windowsConn(t *testing.T, native bool) shared.Connection {
	if native {
		t.Setenv(shared.WindowsNativeEnv, "1")
	} else {
		t.Setenv(shared.WindowsNativeEnv, "0")
	}
	return local.NewConnection(0, &inventory.Config{}, &inventory.Asset{
		Platform: &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}},
	})
}

func byKey(bins []Binary) map[string]Binary {
	res := map[string]Binary{}
	for _, b := range bins {
		res[WindowsPathKey(b.Path)] = b
	}
	return res
}

func TestNativeListWindowsFindsItself(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	bins, ok := nativeListWindows()
	require.True(t, ok)

	self, found := byKey(bins)[WindowsPathKey(exe)]
	require.True(t, found, "the test process is not among the running binaries")
	assert.Contains(t, self.Pids, int64(os.Getpid()))
	assert.False(t, self.System)
}

func TestNativeListWindowsMatchesPowerShell(t *testing.T) {
	native, err := listWindows(windowsConn(t, true))
	require.NoError(t, err)
	ps, err := listWindows(windowsConn(t, false))
	require.NoError(t, err)

	// Windows PowerShell reads a process's path through its main module,
	// which a protected process refuses, so it can list fewer files. Every
	// file both list must agree.
	nativeByKey := byKey(native)
	var both int
	for _, p := range ps {
		n, ok := nativeByKey[WindowsPathKey(p.Path)]
		if !ok {
			continue
		}
		both++
		assert.Equal(t, p.System, n.System, p.Path)
		assert.Equal(t, p.VersionInfo, n.VersionInfo, p.Path)
	}
	assert.Greater(t, both, 0, "no running binary was listed by both paths")
}

func TestNativeSignaturesMatchPowerShell(t *testing.T) {
	bins, err := listWindows(windowsConn(t, false))
	require.NoError(t, err)
	paths := make([]string, 0, len(bins))
	for _, b := range bins {
		paths = append(paths, b.Path)
	}

	native, err := WindowsSignatures(windowsConn(t, true), paths)
	require.NoError(t, err)
	ps, err := WindowsSignatures(windowsConn(t, false), paths)
	require.NoError(t, err)

	var both int
	for key, p := range ps {
		n, ok := native[key]
		if !ok {
			continue
		}
		both++
		assert.Equal(t, p, n, key)
	}
	assert.Greater(t, both, 0, "no signature was read by both paths")
}

func TestNativeSignatureOfWindows(t *testing.T) {
	systemRoot, err := windows.GetSystemWindowsDirectory()
	require.NoError(t, err)

	sig := nativeSignature(filepath.Join(systemRoot, "System32", "kernel32.dll"))
	assert.Equal(t, SignatureValid, sig.Status)
	cert := signerCertificate(t, sig)
	assert.Equal(t, []string{"Microsoft Corporation"}, cert.Subject.Organization)
	assert.True(t, strings.HasPrefix(cert.Subject.CommonName, "Microsoft"), cert.Subject.CommonName)
}

func signerCertificate(t *testing.T, sig Signature) *x509.Certificate {
	t.Helper()
	require.NotEmpty(t, sig.Certificate, "no signing certificate")
	cert, err := x509.ParseCertificate(sig.Certificate)
	require.NoError(t, err)
	return cert
}

func TestNativeSignatureFromCatalog(t *testing.T) {
	// Files of Windows that carry no signature of their own are signed only
	// through a system catalog. A file without an embedded signature is
	// either listed in a catalog, and then signed by Microsoft, or not
	// signed at all: software installs unsigned tools into System32 too
	// (the runner image puts docker.exe there).
	systemRoot, err := windows.GetSystemWindowsDirectory()
	require.NoError(t, err)
	files, err := filepath.Glob(filepath.Join(systemRoot, "System32", "*.exe"))
	require.NoError(t, err)

	var fromCatalog int
	for _, f := range files {
		path16, err := windows.UTF16PtrFromString(f)
		require.NoError(t, err)
		sig, inCatalog := catalogSignature(f, path16)
		fileInfo := windows.WinTrustFileInfo{FilePath: path16}
		fileInfo.Size = uint32(unsafe.Sizeof(fileInfo))
		if code, _ := verifyTrust(windows.WTD_CHOICE_FILE, unsafe.Pointer(&fileInfo)); code != trustENoSignature {
			continue
		}
		if !inCatalog {
			assert.Equal(t, Signature{Status: SignatureNotSigned}, nativeSignature(f), f)
			continue
		}
		fromCatalog++
		assert.Equal(t, SignatureValid, sig.Status, f)
		assert.Equal(t, []string{"Microsoft Corporation"}, signerCertificate(t, sig).Subject.Organization, f)
		assert.Equal(t, sig, nativeSignature(f), f)
	}
	assert.Greater(t, fromCatalog, 0, "no file in System32 verified through a catalog")
}

func TestNativeSignatureNotSigned(t *testing.T) {
	// the test binary the Go toolchain just linked is not signed
	exe, err := os.Executable()
	require.NoError(t, err)
	assert.Equal(t, Signature{Status: SignatureNotSigned}, nativeSignature(exe))
}

func TestNativeInstallerOwnersMatchPowerShell(t *testing.T) {
	bins, ok := nativeListWindows()
	require.True(t, ok)
	paths := make([]string, 0, len(bins))
	for _, b := range bins {
		paths = append(paths, b.Path)
	}

	native, err := WindowsInstallerOwners(windowsConn(t, true), paths)
	require.NoError(t, err)
	ps, err := WindowsInstallerOwners(windowsConn(t, false), paths)
	require.NoError(t, err)

	// PowerShell answers for the processes it can read, which may be fewer
	for key, product := range ps {
		assert.Equal(t, product, native[key], key)
	}
	psList, err := listWindows(windowsConn(t, false))
	require.NoError(t, err)
	psListed := byKey(psList)
	for key, product := range native {
		if _, ok := psListed[key]; ok {
			assert.Equal(t, product, ps[key], key)
		}
	}
	t.Logf("%d running binaries installed by Windows Installer: %v", len(native), native)
}
