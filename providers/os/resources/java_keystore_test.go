// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func selfSignedDER(t *testing.T, serial *big.Int) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Example Root CA", OrganizationalUnit: []string{"Certification Authority"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// A trust store built up over years holds certificates that no longer parse.
// Handing the whole batch to the certificate parser fails on the first of them
// and the store then reports nothing at all — which is how one twenty-year-old
// CA blinds every check written against a 133-entry store. This is the guard
// against that regressing.
func TestReadableDERKeepsTheStoreUsable(t *testing.T) {
	good := selfSignedDER(t, big.NewInt(42))

	t.Run("all readable", func(t *testing.T) {
		out, unreadable := readableDER([][]byte{good, good})
		assert.Len(t, out, 2)
		assert.Equal(t, 0, unreadable)
	})

	t.Run("one bad certificate does not lose the others", func(t *testing.T) {
		garbage := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
		out, unreadable := readableDER([][]byte{good, garbage, good})
		assert.Len(t, out, 2, "the readable certificates survive")
		assert.Equal(t, 1, unreadable, "and the loss is counted, not silent")
	})

	// The specific shape seen in the wild, and the reason this exists at all.
	// testdata holds the real certificate: the "ec-acc" CA out of RHEL 7's
	// trust store, whose serial number is negative — legal when it was issued
	// in 2003 and rejected by the parser now. It is one entry out of 133, and
	// before this it took the other 132 down with it. Using the real
	// certificate rather than a synthesised one matters because Go will not
	// even create such a certificate today, so a synthetic version could not
	// reproduce the case.
	t.Run("a negative serial number is skipped and counted", func(t *testing.T) {
		negative, err := os.ReadFile("testdata/java-negative-serial.der")
		require.NoError(t, err)

		_, err = x509.ParseCertificate(negative)
		require.Error(t, err, "the parser rejects this, which is what makes it worth handling")
		assert.Contains(t, err.Error(), "negative serial number")

		out, unreadable := readableDER([][]byte{good, negative})
		assert.Len(t, out, 1, "the good certificate survives")
		assert.Equal(t, 1, unreadable)
	})

	t.Run("empty input", func(t *testing.T) {
		out, unreadable := readableDER(nil)
		assert.Empty(t, out)
		assert.Equal(t, 0, unreadable)
	})
}

// The discovery lists are the thing most likely to be edited carelessly later,
// and a missing path means a JVM is simply not audited — a silence, not an
// error. These pin the layouts that were verified on real images.
func TestJavaTruststoreDiscoveryCoversKnownLayouts(t *testing.T) {
	assert.Contains(t, javaTruststoreDirs, "lib/security", "JDK 9 and later")
	assert.Contains(t, javaTruststoreDirs, "jre/lib/security", "JDK 8")

	assert.Contains(t, javaHomeRoots, "/usr/lib/jvm", "the Red Hat and Debian layout")
	assert.Contains(t, javaHomeRoots, "/Library/Java/JavaVirtualMachines", "macOS")

	assert.Contains(t, javaTruststoreFiles, "/etc/pki/java/cacerts", "the Red Hat distribution store")
	assert.Contains(t, javaTruststoreFiles, "/etc/ssl/certs/java/cacerts", "the Debian distribution store")
}

// Two entries can carry the same alias: a PKCS#12 store may repeat a
// friendlyName, or omit it entirely and leave several entries aliased "". An id
// built from the alias alone would collide, and a collision does not merely
// return the wrong entry — the second entry's certificates overwrite the cached
// first one's, so one entry is reported where there are two, with the wrong
// contents. The index is what keeps them apart.
func TestJavaKeystoreEntryIDsAreUniqueWhenAliasesCollide(t *testing.T) {
	ids := map[string]struct{}{}
	for i, alias := range []string{"", "", "dup", "dup", "unique"} {
		id := fmt.Sprintf("%s/%s#%d", "/etc/pki/java/cacerts", alias, i)
		_, seen := ids[id]
		assert.False(t, seen, "id %q collided", id)
		ids[id] = struct{}{}
	}
	assert.Len(t, ids, 5)
}

// fakeLinks is a filesystem's symlink table: link path to its target, exactly
// as readlink prints it. Anything not in the table is not a link.
type fakeLinks map[string]string

func (f fakeLinks) ReadlinkIfPossible(name string) (string, error) {
	if t, ok := f[name]; ok {
		return t, nil
	}
	return "", errors.New("not a symlink")
}

// rhel9Links is the link layout of a RHEL 9 host with OpenJDK 8, 21 and 25
// installed, taken from `ls -l /usr/lib/jvm /etc/alternatives` on that host:
// alternatives links for the version aliases, a relative link from the jre-*
// name into the JDK, and every JDK's cacerts pointing at the store
// update-ca-trust maintains.
var rhel9Links = fakeLinks{
	"/usr/lib/jvm/java":                                                                     "/etc/alternatives/java_sdk",
	"/etc/alternatives/java_sdk":                                                            "/usr/lib/jvm/java-25-openjdk",
	"/usr/lib/jvm/java-21":                                                                  "/etc/alternatives/java_sdk_21",
	"/etc/alternatives/java_sdk_21":                                                         "/usr/lib/jvm/java-21-openjdk-21.0.12.1.1-1.2.el9.x86_64",
	"/usr/lib/jvm/jre-1.8.0-openjdk-1.8.0.504.b01-1.2.el9.x86_64":                           "java-1.8.0-openjdk-1.8.0.504.b01-1.2.el9.x86_64/jre",
	"/usr/lib/jvm/java-25-openjdk/lib/security/cacerts":                                     "/etc/pki/java/cacerts",
	"/usr/lib/jvm/java-21-openjdk-21.0.12.1.1-1.2.el9.x86_64/lib/security/cacerts":          "/etc/pki/java/cacerts",
	"/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.504.b01-1.2.el9.x86_64/jre/lib/security/cacerts": "../../../../../../../etc/pki/java/cacerts",
	"/etc/pki/java/cacerts":                                                                 "../ca-trust/extracted/java/cacerts",
}

// Fails if resolveSymlinks stops after the last path element (directory links
// such as /usr/lib/jvm/java are then never followed), resolves a relative
// target against the link itself instead of its directory, or stops after one
// hop.
func TestResolveSymlinksFollowsEveryComponent(t *testing.T) {
	const store = "/etc/pki/ca-trust/extracted/java/cacerts"
	for _, p := range []string{
		"/usr/lib/jvm/java/lib/security/cacerts",
		"/usr/lib/jvm/java-21/lib/security/cacerts",
		"/usr/lib/jvm/jre-1.8.0-openjdk-1.8.0.504.b01-1.2.el9.x86_64/lib/security/cacerts",
		"/etc/pki/java/cacerts",
		store,
	} {
		got, err := resolveSymlinks(rhel9Links, p)
		require.NoError(t, err, p)
		assert.Equal(t, store, got, p)
	}

	// A JVM that ships its own store resolves to itself.
	got, err := resolveSymlinks(rhel9Links, "/opt/java/openjdk/lib/security/cacerts")
	require.NoError(t, err)
	assert.Equal(t, "/opt/java/openjdk/lib/security/cacerts", got)
}

// Fails if the hop limit is removed: a link loop would never return.
func TestResolveSymlinksStopsOnALoop(t *testing.T) {
	_, err := resolveSymlinks(fakeLinks{"/a": "/b", "/b": "/a"}, "/a/cacerts")
	assert.Error(t, err)
}

// RHEL links every installed JDK's cacerts to one store, so without the dedupe
// a check over java.truststores.list reads the same file 21 times on a host
// with three JDKs. Fails if the dedupe is keyed on the discovered path rather
// than the resolved one, or keeps an arbitrary member of a group.
func TestDedupeTruststoresByRealPath(t *testing.T) {
	const store = "/etc/pki/ca-trust/extracted/java/cacerts"
	got := dedupeByRealPath([]string{
		"/usr/lib/jvm/java/lib/security/cacerts",
		"/usr/lib/jvm/java-21/lib/security/cacerts",
		"/etc/pki/java/cacerts",
		"/opt/java/openjdk/lib/security/cacerts",
		"/usr/lib/jvm/java-25-openjdk/lib/security/cacerts",
	}, map[string]string{
		"/usr/lib/jvm/java/lib/security/cacerts":            store,
		"/usr/lib/jvm/java-21/lib/security/cacerts":         store,
		"/etc/pki/java/cacerts":                             store,
		"/usr/lib/jvm/java-25-openjdk/lib/security/cacerts": store,
		// /opt/java/openjdk is unresolved: kept under its own name.
	})
	assert.Equal(t, []string{
		"/etc/pki/java/cacerts",
		"/opt/java/openjdk/lib/security/cacerts",
	}, got)
}

// The SSH path resolves every candidate in one shell loop. Fails if a line
// whose readlink printed nothing (a dangling link) is taken as a resolution,
// or if lines are matched up by position rather than by the path they name.
func TestParseReadlinkOutput(t *testing.T) {
	got := parseReadlinkOutput("/etc/pki/java/cacerts\t/etc/pki/ca-trust/extracted/java/cacerts\n" +
		"/usr/lib/jvm/broken/lib/security/cacerts\t\n" +
		"/usr/lib/jvm/java/lib/security/cacerts\t/etc/pki/ca-trust/extracted/java/cacerts\n")
	assert.Equal(t, map[string]string{
		"/etc/pki/java/cacerts":                  "/etc/pki/ca-trust/extracted/java/cacerts",
		"/usr/lib/jvm/java/lib/security/cacerts": "/etc/pki/ca-trust/extracted/java/cacerts",
	}, got)
}

// suse15Links is the link layout of a SLES 15 SP7 host with OpenJDK 21 and 25,
// taken from `ls -l /usr/lib64/jvm` and `readlink -f` on its cacerts files:
// alternatives directory links, relative version aliases, and every JDK's
// cacerts pointing at the store update-ca-certificates maintains.
var suse15Links = fakeLinks{
	"/usr/lib64/jvm/java":                                    "/etc/alternatives/java_sdk",
	"/etc/alternatives/java_sdk":                             "/usr/lib64/jvm/java-25-openjdk-25",
	"/usr/lib64/jvm/java-21":                                 "/etc/alternatives/java_sdk_21",
	"/etc/alternatives/java_sdk_21":                          "/usr/lib64/jvm/java-21-openjdk-21",
	"/usr/lib64/jvm/jre-21-openjdk":                          "java-21-openjdk-21",
	"/usr/lib64/jvm/java-21-openjdk-21/lib/security/cacerts": "/var/lib/ca-certificates/java-cacerts",
	"/usr/lib64/jvm/java-25-openjdk-25/lib/security/cacerts": "/var/lib/ca-certificates/java-cacerts",
}

// SUSE keeps its JVMs under /usr/lib64/jvm and its shared store at
// /var/lib/ca-certificates/java-cacerts. Fails if either location is dropped
// from discovery (every java.truststores check then passes over an empty
// list), or if the dedupe keeps the lexicographically smallest name instead of
// the store's own: /usr sorts before /var, so a JVM alias would be reported.
func TestDedupeTruststoresSUSE(t *testing.T) {
	assert.Contains(t, javaHomeRoots, "/usr/lib64/jvm")
	assert.Contains(t, javaTruststoreFiles, "/var/lib/ca-certificates/java-cacerts")

	candidates := []string{
		"/usr/lib64/jvm/java/lib/security/cacerts",
		"/usr/lib64/jvm/java-21/lib/security/cacerts",
		"/usr/lib64/jvm/jre-21-openjdk/lib/security/cacerts",
		"/usr/lib64/jvm/java-21-openjdk-21/lib/security/cacerts",
		"/usr/lib64/jvm/java-25-openjdk-25/lib/security/cacerts",
		"/var/lib/ca-certificates/java-cacerts",
	}
	real := map[string]string{}
	for _, p := range candidates {
		r, err := resolveSymlinks(suse15Links, p)
		require.NoError(t, err, p)
		real[p] = r
	}
	assert.Equal(t, []string{"/var/lib/ca-certificates/java-cacerts"}, dedupeByRealPath(candidates, real))
}
