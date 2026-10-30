// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupWindowsImages(t *testing.T) {
	bins := groupWindowsImages([]windowsImage{
		{Pid: 1204, Path: `C:\Windows\System32\svchost.exe`},
		{Pid: 988, Path: `C:\WINDOWS\system32\svchost.exe`},
		{Pid: 4410, Path: `C:\Tools\agent.exe`},
		{Pid: 12, Path: ""},
	}, `C:\WINDOWS`)

	assert.Equal(t, []Binary{
		// one entry per file however Windows spelled the path, with the
		// spelling of the first process
		{Path: `C:\Windows\System32\svchost.exe`, Pids: []int64{988, 1204}, System: true},
		{Path: `C:\Tools\agent.exe`, Pids: []int64{4410}},
	}, bins)

	assert.Equal(t, []Binary{}, groupWindowsImages(nil, `C:\Windows`))
}

func TestVersionInfoTranslations(t *testing.T) {
	// German (0x0407) in Unicode (0x04b0), then US English in Windows-1252
	translation := []byte{0x07, 0x04, 0xb0, 0x04, 0x09, 0x04, 0xe4, 0x04}
	assert.Equal(t, []string{"040704b0", "040904e4", "040904b0", "04090000"}, versionInfoTranslations(translation))

	// a resource without a translation table is read in US English
	assert.Equal(t, []string{"040904b0", "040904e4", "04090000"}, versionInfoTranslations(nil))
}

func TestWinTrustStatus(t *testing.T) {
	assert.Equal(t, SignatureValid, winTrustStatus(0))
	assert.Equal(t, SignatureNotSigned, winTrustStatus(trustENoSignature))
	assert.Equal(t, SignatureNotSigned, winTrustStatus(trustEProviderUnknown))
	assert.Equal(t, SignatureInvalid, winTrustStatus(trustEBadDigest))
	assert.Equal(t, SignatureInvalid, winTrustStatus(cryptEBadMsg))
	assert.Equal(t, SignatureUntrusted, winTrustStatus(trustEExplicitDistrust))
	// CERT_E_UNTRUSTEDROOT: PowerShell reports UnknownError, and so does this
	assert.Equal(t, SignatureUnknown, winTrustStatus(0x800B0109))
}

func TestCatalogMemberTag(t *testing.T) {
	assert.Equal(t, "00AB10FF", catalogMemberTag([]byte{0x00, 0xab, 0x10, 0xff}))
}

func TestPreferSignature(t *testing.T) {
	catalog := Signature{Status: SignatureValid, Certificate: []byte("catalog signer")}
	embedded := Signature{Status: SignatureValid, Certificate: []byte("embedded signer")}
	notSigned := Signature{Status: SignatureNotSigned}
	badCatalog := Signature{Status: SignatureUnknown, Certificate: []byte("example")}

	// signed both ways: the catalog's signer, as Get-AuthenticodeSignature reports it
	assert.Equal(t, catalog, preferSignature(&catalog, embedded))
	// signed only through a catalog
	assert.Equal(t, catalog, preferSignature(&catalog, notSigned))
	// in no catalog
	assert.Equal(t, embedded, preferSignature(nil, embedded))
	assert.Equal(t, notSigned, preferSignature(nil, notSigned))
	// a catalog entry that does not verify yields to a signature that does
	assert.Equal(t, embedded, preferSignature(&badCatalog, embedded))
	// and is the answer only when the file carries none of its own
	assert.Equal(t, badCatalog, preferSignature(&badCatalog, notSigned))
}
