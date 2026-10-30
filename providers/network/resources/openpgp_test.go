// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/openpgp holds /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release from a
// RHEL 9 host, an armored file with two key blocks (gpg --show-keys lists
// both fingerprints below), and the same keys after gpg --dearmor.
var rhelReleaseFingerprints = []string{
	"567e347ad0044ade55ba8a5f199e2f91fd431d51",
	"7e4624258c406535d56d6f135054e4a45a6340b3",
}

func readOpenpgpTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/openpgp/" + name)
	require.NoError(t, err)
	return string(data)
}

func fingerprints(entities openpgp.EntityList) []string {
	res := []string{}
	for _, e := range entities {
		res = append(res, hex.EncodeToString(e.PrimaryKey.Fingerprint))
	}
	return res
}

func TestReadKeyRingReadsEveryArmoredBlock(t *testing.T) {
	entities, err := readKeyRing(readOpenpgpTestdata(t, "rhel9-redhat-release.asc"))
	require.NoError(t, err)
	assert.Equal(t, rhelReleaseFingerprints, fingerprints(entities))
}

func TestReadKeyRingIgnoresMarkerTextBetweenBlocks(t *testing.T) {
	asc := readOpenpgpTestdata(t, "rhel9-redhat-release.asc")
	end := strings.Index(asc, "-----END PGP PUBLIC KEY BLOCK-----") + len("-----END PGP PUBLIC KEY BLOCK-----\n")
	content := asc[:end] + "\nThe next key starts at -----BEGIN PGP PUBLIC KEY BLOCK----- below.\n-----BEGIN PGP stray\n" + asc[end:]

	entities, err := readKeyRing(content)
	require.NoError(t, err)
	assert.Equal(t, rhelReleaseFingerprints, fingerprints(entities))
}

func TestReadKeyRingReadsBinaryKeyring(t *testing.T) {
	entities, err := readKeyRing(readOpenpgpTestdata(t, "rhel9-redhat-release.gpg"))
	require.NoError(t, err)
	assert.Equal(t, rhelReleaseFingerprints, fingerprints(entities))
}

func TestReadKeyRingSkipsNonKeyBlocks(t *testing.T) {
	asc := readOpenpgpTestdata(t, "rhel9-redhat-release.asc")
	first := asc[:strings.Index(asc, "-----END PGP PUBLIC KEY BLOCK-----")+len("-----END PGP PUBLIC KEY BLOCK-----\n")]
	sig := "-----BEGIN PGP SIGNATURE-----\n\nwsBcBAABCAAQBQJn\n=AAAA\n-----END PGP SIGNATURE-----\n"

	entities, err := readKeyRing("some text before\n" + sig + first)
	require.NoError(t, err)
	assert.Equal(t, rhelReleaseFingerprints[:1], fingerprints(entities))

	_, err = readKeyRing(sig)
	assert.EqualError(t, err, "expected public or private key block, got: PGP SIGNATURE")
}

func TestReadKeyRingRejectsOtherContent(t *testing.T) {
	for _, content := range []string{"", "garbage\n", "-----BEGIN PGP but no header line"} {
		_, err := readKeyRing(content)
		assert.Error(t, err, "content %q", content)
	}
}
