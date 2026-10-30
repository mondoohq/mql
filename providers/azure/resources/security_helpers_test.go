// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyVaultKeyURI(t *testing.T) {
	tests := []struct {
		name    string
		vault   string
		key     string
		version string
		want    string
	}{
		{
			// The shape ARM actually returns: keyVaultUri carries a trailing
			// slash. Appending "/keys/" without trimming produced "//keys/",
			// which parseKeyVaultId rejects.
			name:  "trailing slash on the vault uri is trimmed",
			vault: "https://myvault.vault.azure.net/", key: "cmk",
			want: "https://myvault.vault.azure.net/keys/cmk",
		},
		{
			name:  "no trailing slash still works",
			vault: "https://myvault.vault.azure.net", key: "cmk",
			want: "https://myvault.vault.azure.net/keys/cmk",
		},
		{
			name:  "version is appended when present",
			vault: "https://myvault.vault.azure.net/", key: "cmk", version: "abc123",
			want: "https://myvault.vault.azure.net/keys/cmk/abc123",
		},
		{
			name:  "managed hsm uri",
			vault: "https://myhsm.managedhsm.azure.net/", key: "cmk",
			want: "https://myhsm.managedhsm.azure.net/keys/cmk",
		},
		{"missing vault yields empty", "", "cmk", "", ""},
		{"missing key yields empty", "https://myvault.vault.azure.net/", "", "", ""},
		{"a bare slash is not a vault", "/", "cmk", "", ""},
		{"whitespace is not a vault", "   ", "cmk", "", ""},
		{
			name:  "blank version is not appended",
			vault: "https://myvault.vault.azure.net/", key: "cmk", version: "  ",
			want: "https://myvault.vault.azure.net/keys/cmk",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, keyVaultKeyURI(tc.vault, tc.key, tc.version))
		})
	}
}

// The URI this helper builds is fed straight to parseKeyVaultId, so the
// contract that matters is not the string shape but that the result actually
// parses. Asserting against the real parser is what would have caught the
// original bug: the naive concatenation produced a plausible-looking URI that
// only the regex rejected.
func TestKeyVaultKeyURIRoundTripsThroughTheParser(t *testing.T) {
	cases := []struct {
		name            string
		vault, key, ver string
		wantVault       string
		wantName        string
		wantVersion     string
	}{
		{"arm shape with trailing slash", "https://myvault.vault.azure.net/", "cmk", "", "myvault", "cmk", ""},
		{"with version", "https://myvault.vault.azure.net/", "cmk", "v1", "myvault", "cmk", "v1"},
		{"managed hsm", "https://myhsm.managedhsm.azure.net/", "cmk", "", "myhsm", "cmk", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uri := keyVaultKeyURI(tc.vault, tc.key, tc.ver)
			require.NotEmpty(t, uri)

			parsed, err := parseKeyVaultId(uri)
			require.NoError(t, err, "the URI this helper builds must parse: %q", uri)
			assert.Equal(t, tc.wantVault, parsed.Vault)
			assert.Equal(t, "keys", parsed.Type)
			assert.Equal(t, tc.wantName, parsed.Name)
			assert.Equal(t, tc.wantVersion, parsed.Version)
		})
	}
}

// Pin the regression directly: the pre-fix concatenation must be the thing that
// fails, so a future refactor that reintroduces it cannot pass silently.
func TestNaiveConcatenationIsRejectedByTheParser(t *testing.T) {
	const armVaultURI = "https://myvault.vault.azure.net/" // as ARM returns it

	naive := armVaultURI + "/keys/" + "cmk"
	assert.Contains(t, naive, "//keys/")
	_, err := parseKeyVaultId(naive)
	require.Error(t, err, "the doubled separator must not parse -- this is the bug being fixed")

	fixed := keyVaultKeyURI(armVaultURI, "cmk", "")
	_, err = parseKeyVaultId(fixed)
	require.NoError(t, err)
}
