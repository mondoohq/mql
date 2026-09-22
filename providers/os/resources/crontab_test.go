// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// A bare `crontab.entry` leaves `file` unset, so id() must report the missing
// file rather than dereferencing a nil *mqlFile.
func TestCrontabEntryID(t *testing.T) {
	e := &mqlCrontabEntry{}
	// GetFile short-circuits on an already-resolved field, so mark it set with a
	// nil value -- the shape the runtime produces for a bare entry.
	e.File.State = plugin.StateIsSet | plugin.StateIsNull

	id, err := e.id()
	require.Error(t, err)
	assert.Empty(t, id)
	assert.Contains(t, err.Error(), "missing file")
}

// SUSE stores per-user crontabs in /var/spool/cron/tabs, one directory below
// the RHEL location that was already scanned. Walking both layouts must find
// root's crontab exactly once, and the tabs directory itself must never be
// reported as a user named "tabs" while /var/spool/cron is walked.
func TestCollectUserCrontabFilesSUSE(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	require.NoError(t, afs.MkdirAll("/var/spool/cron/tabs", 0o700))
	require.NoError(t, afs.WriteFile("/var/spool/cron/tabs/root",
		[]byte("0 5 * * * /usr/sbin/aide --check\n"), 0o600))

	got := collectUserCrontabFiles(afs, userCrontabDirs)

	assert.Equal(t, []userCrontabFile{
		{user: "root", path: "/var/spool/cron/tabs/root"},
	}, got)
}

// The other distro layouts keep working, and the editor / backup droppings
// that live beside a real crontab are not users.
func TestCollectUserCrontabFiles(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for _, path := range []string{
		"/var/spool/cron/crontabs/alice",
		"/var/spool/cron/crontabs/.hidden",
		"/var/spool/cron/crontabs/alice~",
		"/var/spool/cron/crontabs/alice.bak",
		"/var/spool/cron/bob",
		"/usr/lib/cron/tabs/carol",
	} {
		require.NoError(t, afs.WriteFile(path, []byte("@daily /bin/true\n"), 0o600))
	}

	got := collectUserCrontabFiles(afs, userCrontabDirs)

	// Directory order, then file name order within a directory.
	assert.Equal(t, []userCrontabFile{
		{user: "alice", path: "/var/spool/cron/crontabs/alice"},
		{user: "bob", path: "/var/spool/cron/bob"},
		{user: "carol", path: "/usr/lib/cron/tabs/carol"},
	}, got)
}

// A host with no spool directories at all (a stripped container image) yields
// nothing rather than erroring the whole crontab.entries walk.
func TestCollectUserCrontabFilesMissingDirs(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	assert.Empty(t, collectUserCrontabFiles(afs, userCrontabDirs))
}
