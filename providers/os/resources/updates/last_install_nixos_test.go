// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The epoch `stat -c %Y /nix/var/nix/profiles/system` printed on a NixOS 26.05
// EC2 host, whose generation 1 was activated on 2026-09-11 11:33:56 UTC --
// the date nix-env --list-generations shows for it.
func TestParseNixosProfileMtime(t *testing.T) {
	update, err := ParseNixosProfileMtime(strings.NewReader("1789126436\n"))
	require.NoError(t, err)
	require.NotNil(t, update)

	assert.Equal(t, LastUpdateSourceNixosGeneration, update.Source)
	assert.Equal(t, time.Unix(1789126436, 0).UTC(), update.Time)
	assert.Equal(t, time.UTC, update.Time.Location(),
		"epoch seconds carry no zone, so the answer is UTC and not the scanner's local time")
}

// stat prints one line, but a shell wrapper can add another.
func TestParseNixosProfileMtimeTrailingOutput(t *testing.T) {
	update, err := ParseNixosProfileMtime(strings.NewReader("1789126436\nwarning: something\n"))
	require.NoError(t, err)
	require.NotNil(t, update)
	assert.Equal(t, int64(1789126436), update.Time.Unix())
}

// A host where the command printed nothing has no answer, not an answer of
// zero: the epoch would be 1970 and the host would read as decades unpatched.
func TestParseNixosProfileMtimeEmpty(t *testing.T) {
	update, err := ParseNixosProfileMtime(strings.NewReader("\n"))
	require.NoError(t, err)
	assert.Nil(t, update)
}

func TestParseNixosProfileMtimeZero(t *testing.T) {
	update, err := ParseNixosProfileMtime(strings.NewReader("0\n"))
	require.NoError(t, err)
	assert.Nil(t, update, "epoch zero is not a date a system was activated on")
}

// This is the failure the command is shaped to avoid, and the reader is what
// has to reject it. Nix normalizes every mtime in the store to epoch 1, so a
// reader that followed the symlink lands exactly here -- and validation
// downstream drops a zero time and a future one but has no reason to distrust
// 1970, which would report the host as unpatched since the epoch.
func TestParseNixosProfileMtimeNormalizedStoreMtime(t *testing.T) {
	update, err := ParseNixosProfileMtime(strings.NewReader("1\n"))
	require.NoError(t, err)
	assert.Nil(t, update, "a normalized store mtime must not report a host as patched in 1970")

	// Spelling out why the reader carries this rather than leaving it to
	// validation, so a later change does not move it there.
	assert.NotNil(t,
		ValidateLastInstalledUpdate(&LastInstalledUpdate{
			Time:   time.Unix(1, 0).UTC(),
			Source: LastUpdateSourceNixosGeneration,
		}, time.Now()),
		"validation accepts a 1970 timestamp, which is why this reader rejects it")
}

func TestParseNixosProfileMtimeNotANumber(t *testing.T) {
	_, err := ParseNixosProfileMtime(strings.NewReader("stat: cannot stat '/nix/var/nix/profiles/system'\n"))
	require.Error(t, err, "an error from stat must not parse as a date")
}
