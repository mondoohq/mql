// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
)

// testCertificate returns the DER encoding of a self-signed certificate
// for the subject.
func testCertificate(t *testing.T, cn, org string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func TestParseWindowsSignatures(t *testing.T) {
	publisher := testCertificate(t, "Microsoft Windows Publisher", "Microsoft Corporation")
	example := testCertificate(t, "Example Corp", "Example Corp")
	b64 := base64.StdEncoding.EncodeToString
	data := []byte(`[
  {"Path": "C:\\Windows\\System32\\svchost.exe", "Status": "Valid", "Certificate": "` + b64(publisher) + `"},
  {"Path": "C:\\Tools\\unsigned.exe", "Status": "NotSigned", "Certificate": ""},
  {"Path": "C:\\Tools\\patched.exe", "Status": "HashMismatch", "Certificate": "` + b64(example) + `"},
  {"Path": "C:\\Tools\\nocert.exe", "Status": "UnknownError", "Certificate": null}
]`)
	sigs, err := parseWindowsSignatures(data)
	require.NoError(t, err)

	assert.Equal(t, map[string]Signature{
		`c:\windows\system32\svchost.exe`: {Status: SignatureValid, Certificate: publisher},
		`c:\tools\unsigned.exe`:           {Status: SignatureNotSigned},
		`c:\tools\patched.exe`:            {Status: SignatureInvalid, Certificate: example},
		`c:\tools\nocert.exe`:             {Status: SignatureUnknown},
	}, sigs)

	// looked up the way Windows compares paths
	_, ok := sigs[WindowsPathKey(`C:\WINDOWS\System32\svchost.exe`)]
	assert.True(t, ok)

	_, err = parseWindowsSignatures([]byte(`[{"Path": "C:\\a.exe", "Status": "Valid", "Certificate": "not base64!"}]`))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}

func TestWindowsSignatureStatus(t *testing.T) {
	assert.Equal(t, SignatureNotSigned, windowsSignatureStatus("NotSupportedFileFormat"))
	assert.Equal(t, SignatureUnknown, windowsSignatureStatus("UnknownError"))
	assert.Equal(t, SignatureUnknown, windowsSignatureStatus(""))
}

func TestParseDarwinSignatures(t *testing.T) {
	teams := testCertificate(t, "Developer ID Application: Microsoft Corporation (UBF8T346G9)", "Microsoft Corporation")
	apple := testCertificate(t, "Software Signing", "Apple Inc.")
	example := testCertificate(t, "Developer ID Application: Example Corp (ABCDE12345)", "Example Corp")
	b64 := base64.StdEncoding.EncodeToString

	// DarwinSignatures output for one file per kind of signature, in the
	// format codesign -dvv writes its details
	records := "P\t/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams\t0\n" +
		"D\tExecutable=/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams\n" +
		"D\tAuthority=Developer ID Application: Microsoft Corporation (UBF8T346G9)\n" +
		"D\tTeamIdentifier=UBF8T346G9\n" +
		"C\t" + b64(teams) + "\n" +
		"P\t/usr/libexec/logd\t0\n" +
		"D\tAuthority=Software Signing\n" +
		"C\t" + b64(apple) + "\n" +
		"P\t/Users/dev/go/bin/tool\t0\n" +
		"D\tSignature=adhoc\n" +
		"P\t/usr/local/bin/unsigned\t1\n" +
		"D\t/usr/local/bin/unsigned: code object is not signed at all\n" +
		"P\t/Applications/Patched.app/Contents/MacOS/Patched\t1\n" +
		"C\t" + b64(example) + "\n" +
		// intact, but by a certificate that does not chain to Apple
		"P\t/opt/selfsigned\t3\n" +
		"C\t" + b64(example) + "\n" +
		// a certificate that does not decode is left out
		"P\t/opt/garbled\t0\n" +
		"C\tnot base64!\n" +
		// removed by an update while its process still runs
		"P\t/Applications/Old.app/Contents/MacOS/Old\t1\n" +
		"D\t/Applications/Old.app/Contents/MacOS/Old: No such file or directory\n"

	sigs := parseDarwinSignatures(strings.NewReader(records))
	assert.Equal(t, map[string]Signature{
		"/Applications/Microsoft Teams.app/Contents/MacOS/MSTeams": {Status: SignatureValid, Certificate: teams},
		"/usr/libexec/logd":                                {Status: SignatureValid, Certificate: apple},
		"/Users/dev/go/bin/tool":                           {Status: SignatureAdhoc},
		"/usr/local/bin/unsigned":                          {Status: SignatureNotSigned},
		"/Applications/Patched.app/Contents/MacOS/Patched": {Status: SignatureInvalid, Certificate: example},
		"/opt/selfsigned":                                  {Status: SignatureUntrusted, Certificate: example},
		"/opt/garbled":                                     {Status: SignatureValid},
	}, sigs)
}

func TestDarwinSignaturesScript(t *testing.T) {
	der := testCertificate(t, "Developer ID Application: Example Corp (ABCDE12345)", "Example Corp")
	certFile := filepath.Join(t.TempDir(), "leaf.der")
	require.NoError(t, os.WriteFile(certFile, der, 0o644))

	// a stand-in codesign: verifies one file, displays details for every
	// file and extracts the certificate of the signed one
	stubTool(t, "codesign", `for f; do :; done
if [ "$1" = "--verify" ]; then
  [ "$3" = "-R=anchor apple generic" ] || exit 2
  [ "$f" = "/opt/signed" ]; exit $?
fi
prefix=
for a; do case "$a" in --extract-certificates=*) prefix=${a#--extract-certificates=} ;; esac; done
case "$f" in
  /opt/signed) printf 'Executable=/opt/signed\nAuthority=Developer ID Application: Example Corp (ABCDE12345)\n' >&2
    cp '`+certFile+`' "${prefix}0" ;;
  *) echo "$f: code object is not signed at all" >&2; exit 1 ;;
esac
`)
	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	paths := []string{"/opt/signed", "/opt/it's unsigned"}
	// more files than one command verifies
	for i := range darwinSignatureBatch * 2 {
		paths = append(paths, fmt.Sprintf("/opt/unsigned-%d", i))
	}
	sigs, err := DarwinSignatures(conn, paths)
	require.NoError(t, err)
	assert.Len(t, sigs, len(paths))
	assert.Equal(t, Signature{Status: SignatureValid, Certificate: der}, sigs["/opt/signed"])
	// the certificate of one file is not carried over to the next
	assert.Equal(t, Signature{Status: SignatureNotSigned}, sigs["/opt/it's unsigned"])
	assert.Equal(t, Signature{Status: SignatureNotSigned}, sigs[fmt.Sprintf("/opt/unsigned-%d", darwinSignatureBatch*2-1)])
}
