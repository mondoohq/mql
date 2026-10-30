// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shadow_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/shadow"
)

func TestParseShadow(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	f, err := mock.FileSystem().Open("/etc/shadow")
	require.NoError(t, err)
	defer f.Close()

	shadowEntries, err := shadow.ParseShadow(f)
	require.NoError(t, err)

	assert.Equal(t, 27, len(shadowEntries))

	// 18368 days + jan 1 1970 = 2020-04-16 00:00:00 +0000 UTC
	date := time.Date(2020, 0o4, 16, 0, 0, 0, 0, time.UTC)
	expected := &shadow.ShadowEntry{
		User:         "chris",
		Password:     "*",
		LastChanged:  &date,
		MinDays:      "0",
		MaxDays:      "99999",
		WarnDays:     "7",
		InactiveDays: "",
		ExpiryDates:  "",
		Reserved:     "",
	}
	found := findUser(shadowEntries, "chris")
	assert.Equal(t, expected, found)
}

func TestParseShadow_PasswordWithDoubleQuote(t *testing.T) {
	// A double quote anywhere in the line must be treated literally. The old
	// csv-based parser interpreted it as a CSV quote and corrupted the entry.
	input := `alice:$6$ab"cd$hashvalue:18900:0:99999:7:::
bob:!:18900:0:99999:7:::
`
	entries, err := shadow.ParseShadow(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 2)

	alice := findUser(entries, "alice")
	require.NotNil(t, alice)
	assert.Equal(t, `$6$ab"cd$hashvalue`, alice.Password)

	bob := findUser(entries, "bob")
	require.NotNil(t, bob)
	assert.Equal(t, "!", bob.Password)
}

func TestParseShadow_ShortLineErrors(t *testing.T) {
	// A line with fewer than 9 fields must produce an error rather than panic.
	input := "broken:x:18900\n"
	_, err := shadow.ParseShadow(strings.NewReader(input))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid shadow entry")
}

func findUser(shadowEntries []shadow.ShadowEntry, user string) *shadow.ShadowEntry {
	for i := range shadowEntries {
		if shadowEntries[i].User == user {
			return &shadowEntries[i]
		}
	}
	return nil
}
