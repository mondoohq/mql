// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package secretid

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every value in this file is synthetic: no target was scanned. The token is
// not in any provider's format, the private-key body is the base64 of the
// alphabet and digits, the IBAN is ISO 13616's documentation example, the card
// number is a widely published test number and the SSN is a published invalid
// example. The PEM armor is assembled at run time so that secret scanners do
// not report this file.

var (
	beginRSA = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
	endRSA   = "-----" + "END RSA PRIVATE KEY" + "-----"
	beginSSH = "-----" + "BEGIN OPENSSH PRIVATE KEY" + "-----"
	endSSH   = "-----" + "END OPENSSH PRIVATE KEY" + "-----"
)

const (
	testToken = "tok_canonical_test_value_0001"
	pemBody1  = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY"
	pemBody2  = "WVowMTIzNDU2Nzg5"
	pemCanon  = pemBody1 + pemBody2
)

// testKey returns the golden-vector key: bytes 0x00 to 0x1f, or 0x20 to 0x3f
// for the second key.
func testKey(t *testing.T, id string, offset byte) *Key {
	t.Helper()
	b := make([]byte, KeySize)
	for i := range b {
		b[i] = offset + byte(i)
	}
	k, err := NewKey(id, b)
	require.NoError(t, err)
	return k
}

func TestCanonical(t *testing.T) {
	plainPEM := beginRSA + "\n" + pemBody1 + "\n" + pemBody2 + "\n" + endRSA + "\n"
	cases := []struct {
		name            string
		value           string
		secretType      string
		credentialClass string
		want            string
	}{
		// Synthetic: steps 1 and 2.
		{name: "plain value unchanged", value: testToken, want: testToken},
		{name: "surrounding ASCII whitespace", value: " \t" + testToken + "\r\n", want: testToken},
		{name: "double quotes", value: `"` + testToken + `"`, want: testToken},
		{name: "single quotes", value: `'` + testToken + `'`, want: testToken},
		{name: "backticks", value: "`" + testToken + "`", want: testToken},
		{name: "whitespace then quotes", value: `  "` + testToken + `"  `, want: testToken},
		{name: "only one pair of quotes", value: `""` + testToken + `""`, want: `"` + testToken + `"`},
		{name: "mismatched quotes kept", value: `"` + testToken + `'`, want: `"` + testToken + `'`},
		{name: "leading quote only kept", value: `"` + testToken, want: `"` + testToken},
		{name: "single quote character kept", value: `"`, want: `"`},
		{name: "whitespace inside quotes kept", value: `" ` + testToken + ` "`, want: " " + testToken + " "},
		{name: "case is not folded", value: "TOK_Canonical", want: "TOK_Canonical"},
		{name: "non-ASCII space is not stripped", value: " " + testToken, want: " " + testToken},
		{name: "inner whitespace kept for other types", value: "abc def", secretType: "password", want: "abc def"},
		{name: "empty", value: "", want: ""},
		{name: "whitespace only", value: " \t ", want: ""},

		// Synthetic: step 3, the forms a committed private key takes.
		{name: "pem LF", value: plainPEM, secretType: SecretTypePrivateKey, want: pemCanon},
		{name: "pem CRLF", value: strings.ReplaceAll(plainPEM, "\n", "\r\n"), secretType: SecretTypePrivateKey, want: pemCanon},
		{name: "pem JSON-escaped in quotes",
			value:      `"` + beginRSA + `\n` + pemBody1 + `\n` + pemBody2 + `\n` + endRSA + `\n"`,
			secretType: SecretTypePrivateKey, want: pemCanon},
		{name: "pem JSON-escaped CRLF",
			value:      beginRSA + `\r\n` + pemBody1 + `\r\n` + pemBody2 + `\r\n` + endRSA,
			secretType: SecretTypePrivateKey, want: pemCanon},
		{name: "pem reindented",
			value:      "    " + beginRSA + "\n      " + pemBody1 + "\n      " + pemBody2 + "\n    " + endRSA,
			secretType: SecretTypePrivateKey, want: pemCanon},
		{name: "pem body rewrapped", value: beginRSA + "\n" + pemCanon + "\n" + endRSA, secretType: SecretTypePrivateKey, want: pemCanon},
		{name: "openssh armor", value: beginSSH + "\n" + pemBody1 + "\n" + pemBody2 + "\n" + endSSH, secretType: SecretTypePrivateKey, want: pemCanon},
		{name: "raw hex private key", value: "0x0123abcd", secretType: SecretTypePrivateKey, want: "0x0123abcd"},
		{name: "armor not removed for other types", value: plainPEM, secretType: "api-key", want: strings.TrimSpace(plainPEM)},

		// Synthetic: step 4, personal data written two ways.
		{name: "iban with spaces and lower case", value: "de89 3704 0044 0532 0130 00", secretType: SecretTypeIBAN, credentialClass: CredentialClassPersonalData, want: "DE89370400440532013000"},
		{name: "iban compact", value: "DE89370400440532013000", secretType: SecretTypeIBAN, credentialClass: CredentialClassPersonalData, want: "DE89370400440532013000"},
		{name: "card with hyphens", value: "4111-1111-1111-1111", secretType: "credit-card", credentialClass: CredentialClassPersonalData, want: "4111111111111111"},
		{name: "card with spaces", value: "4111 1111 1111 1111", secretType: "credit-card", credentialClass: CredentialClassPersonalData, want: "4111111111111111"},
		{name: "ssn", value: "078-05-1120", secretType: "ssn", credentialClass: CredentialClassPersonalData, want: "078051120"},
		{name: "personal data letters not upper-cased outside iban", value: "ab-cd", secretType: "passport", credentialClass: CredentialClassPersonalData, want: "abcd"},
		{name: "hyphens kept outside personal data", value: "abc-def", secretType: SecretTypeIBAN, want: "abc-def"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Canonical(tc.value, tc.secretType, tc.credentialClass))
		})
	}
}

// TestGoldenVectors pins scheme v1. The expected ids were computed with
// Python's hmac and hashlib modules, independently of this package:
//
//	hmac.new(key, domain.encode() + b"\0" + canonical.encode(), hashlib.sha256).hexdigest()
//
// with key bytes(range(32)) and bytes(range(32, 64)). Producers in another
// language must reproduce these vectors. A failure here means every secret id
// on the platform would change: add a new version instead.
func TestGoldenVectors(t *testing.T) {
	k1 := testKey(t, "k1", 0x00)
	k2 := testKey(t, "k2", 0x20)

	cases := []struct {
		canonical string
		k1, k2    string
	}{
		{testToken,
			"v1:7a067f7f3f37fe23a3ab20ecaacf371f134373e425ccfbe371e42e07d3a7bc45",
			"v1:aeaae3a50acb6b2de96e520b09de64459b68a615fdc7852dce0ce88eb6d1198d"},
		{pemCanon,
			"v1:ed8a289eec1f40efc7e519c75430a78bd83ee80839961a8050ed3648d2fd33e7",
			"v1:7f785984d3f874835cd4cb74f37560744759b532f72af97d550f7ddb4447d3d3"},
		{"DE89370400440532013000",
			"v1:d1da9d17083ff49a4258dc5bf685c1bc287aa5310e0b70e73329128dbdef796c",
			"v1:eb7789380dcabf17b3f074b23be3f79276722a063e08f028e60e1d4f764d138f"},
		{"4111111111111111",
			"v1:202259ff2e14fc9a1ce07f74f58abfe8fb6236004b2f87fcf9170404fddd13f8",
			"v1:bbd38ee4def52b60d7e5e0e0b5ef2194fab18c3ee6cfbd94f7e25d112fced582"},
		{"078051120",
			"v1:167eb1e080e4e138f9e3f1c889e518d619174d8508641f606c3771e6ed65a89d",
			"v1:038a0fb8b1c05a84e7c0952e0b1329e1009744bac33432a61dbc7e72a382f59e"},
	}
	for _, tc := range cases {
		t.Run(tc.canonical, func(t *testing.T) {
			got, err := ID(k1, tc.canonical)
			require.NoError(t, err)
			assert.Equal(t, tc.k1, got)

			ids, err := IDs([]*Key{k1, k2}, tc.canonical)
			require.NoError(t, err)
			assert.Equal(t, []string{tc.k1, tc.k2}, ids)
		})
	}

	const matched = `token: "` + testToken + `"`
	t.Run("occurrence id", func(t *testing.T) {
		got, err := OccurrenceID(k1, "generic-api-key", "config/app.yaml", 12, matched)
		require.NoError(t, err)
		assert.Equal(t, "v1:4f6fa5e3791f3680b94f06df0fce8168", got)
	})
	t.Run("line hash", func(t *testing.T) {
		got, err := LineHash(k1, matched)
		require.NoError(t, err)
		assert.Equal(t, "75c0a55079678b04:k1", got)
	})
}

// TestEqualValuesEqualIDs checks the end to end property producers rely on:
// every form of one credential gives one id, and distinct credentials do not.
func TestEqualValuesEqualIDs(t *testing.T) {
	k := testKey(t, "k1", 0)
	id := func(value, secretType, class string) string {
		t.Helper()
		got, err := ID(k, Canonical(value, secretType, class))
		require.NoError(t, err)
		return got
	}

	// Synthetic: one private key in four encodings.
	lf := beginRSA + "\n" + pemBody1 + "\n" + pemBody2 + "\n" + endRSA
	forms := []string{
		lf,
		strings.ReplaceAll(lf, "\n", "\r\n"),
		`"` + strings.ReplaceAll(lf, "\n", `\n`) + `"`,
		"  " + strings.ReplaceAll(lf, "\n", "\n  "),
	}
	want := id(forms[0], SecretTypePrivateKey, "")
	for _, f := range forms[1:] {
		assert.Equal(t, want, id(f, SecretTypePrivateKey, ""))
	}
	// Synthetic: two keys of one type must not merge into one id.
	other := beginRSA + "\n" + pemBody2 + "\n" + endRSA
	assert.NotEqual(t, want, id(other, SecretTypePrivateKey, ""))

	// Synthetic: rule metadata outside the canonical steps does not change the id.
	assert.Equal(t, id(testToken, "api-key", "write-access"), id(testToken, "generic-secret", "generic"))

	// Synthetic: ids are case-sensitive.
	assert.NotEqual(t, id("abcDEF", "", ""), id("abcdef", "", ""))
}

func TestIDErrors(t *testing.T) {
	k := testKey(t, "k1", 0)

	_, err := ID(k, "")
	assert.ErrorIs(t, err, ErrEmptyValue)

	_, err = ID(nil, testToken)
	assert.ErrorIs(t, err, ErrNoKey)

	_, err = IDs(nil, testToken)
	assert.ErrorIs(t, err, ErrNoKey)

	_, err = IDs([]*Key{k, nil}, testToken)
	assert.ErrorIs(t, err, ErrNoKey)

	_, err = OccurrenceID(k, "rule\x00x", "a.go", 1, "x")
	assert.ErrorIs(t, err, ErrInvalidInput)
	_, err = OccurrenceID(k, "rule", "a\x00.go", 1, "x")
	assert.ErrorIs(t, err, ErrInvalidInput)

	_, err = LineHash(nil, "x")
	assert.ErrorIs(t, err, ErrNoKey)
}

func TestOccurrenceID(t *testing.T) {
	k := testKey(t, "k1", 0)
	occ := func(rule, path string, line int, code string) string {
		t.Helper()
		got, err := OccurrenceID(k, rule, path, line, code)
		require.NoError(t, err)
		return got
	}
	base := occ("r", "dir/a.yaml", 3, "x")

	// Synthetic: a Windows path gives the id a forward-slash path gives.
	assert.Equal(t, base, occ("r", `dir\a.yaml`, 3, "x"))

	// Synthetic: each field changes the id, including fields that would
	// collide without separators ("r"+"dir/a.yaml" against "rd"+"ir/a.yaml").
	assert.NotEqual(t, base, occ("r", "dir/a.yaml", 4, "x"))
	assert.NotEqual(t, base, occ("r", "dir/b.yaml", 3, "x"))
	assert.NotEqual(t, base, occ("q", "dir/a.yaml", 3, "x"))
	assert.NotEqual(t, base, occ("r", "dir/a.yaml", 3, "y"))
	assert.NotEqual(t, base, occ("rd", "ir/a.yaml", 3, "x"))
	assert.Len(t, base, len("v1:")+occurrenceHexLen)
}

func TestLineHash(t *testing.T) {
	k := testKey(t, "k1", 0)
	lh := func(code string) string {
		t.Helper()
		got, err := LineHash(k, code)
		require.NoError(t, err)
		return got
	}
	// Synthetic: only the trimmed first line counts.
	assert.Equal(t, lh("token: x"), lh("   token: x  \nsecond line"))
	assert.Equal(t, lh("token: x"), lh("token: x\r\nsecond"))
	assert.NotEqual(t, lh("token: x"), lh("token: y"))

	// Synthetic: the keyed hash differs from the unkeyed form and between keys.
	k2 := testKey(t, "k2", 0x20)
	other, err := LineHash(k2, "token: x")
	require.NoError(t, err)
	assert.NotEqual(t, lh("token: x"), other)
	assert.True(t, strings.HasSuffix(other, ":k1"))
}

// TestIDsDomainSeparated checks that the three identifiers of one input
// differ, which the domain strings guarantee.
func TestIDsDomainSeparated(t *testing.T) {
	k := testKey(t, "k1", 0)
	sid, err := ID(k, "x")
	require.NoError(t, err)
	lh, err := LineHash(k, "x")
	require.NoError(t, err)
	assert.NotEqual(t, strings.TrimPrefix(sid, "v1:")[:lineHashHexLen], strings.TrimSuffix(lh, ":k1"))
}
