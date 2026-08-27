// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Entry sub-resources are reachable through their singular accessor
// (`limits.entry`, `logrotate.entry`, `crontab.entry`) with no arguments. The
// runtime then builds the resource with `file` unset, so id() runs against a
// nil *mqlFile. It must report that, not dereference it.
func TestEntryID_MissingFile(t *testing.T) {
	t.Run("limits.entry", func(t *testing.T) {
		id, err := (&mqlLimitsEntry{}).id()
		require.Error(t, err)
		assert.Empty(t, id)
		assert.Contains(t, err.Error(), "missing file")
	})

	t.Run("logrotate.entry", func(t *testing.T) {
		id, err := (&mqlLogrotateEntry{}).id()
		require.Error(t, err)
		assert.Empty(t, id)
		assert.Contains(t, err.Error(), "missing file")
	})

	t.Run("crontab.entry", func(t *testing.T) {
		e := &mqlCrontabEntry{}
		// GetFile short-circuits on an already-resolved field, so mark it set
		// with a nil value -- the shape the runtime produces for a bare entry.
		e.File.State = plugin.StateIsSet | plugin.StateIsNull
		id, err := e.id()
		require.Error(t, err)
		assert.Empty(t, id)
		assert.Contains(t, err.Error(), "missing file")
	})
}

// A populated entry still produces the composite id it always did.
func TestEntryID_WithFile(t *testing.T) {
	f := &mqlFile{}
	f.Path.Data = "/etc/security/limits.conf"
	f.Path.State = plugin.StateIsSet

	le := &mqlLimitsEntry{}
	le.File.Data = f
	le.File.State = plugin.StateIsSet
	le.LineNumber.Data = 42
	le.LineNumber.State = plugin.StateIsSet

	id, err := le.id()
	require.NoError(t, err)
	assert.Equal(t, "/etc/security/limits.conf:42", id)

	lf := &mqlFile{}
	lf.Path.Data = "/etc/logrotate.conf"
	lf.Path.State = plugin.StateIsSet

	lge := &mqlLogrotateEntry{}
	lge.File.Data = lf
	lge.File.State = plugin.StateIsSet
	lge.LineNumber.Data = 7
	lge.LineNumber.State = plugin.StateIsSet
	lge.Path.Data = "/var/log/syslog"
	lge.Path.State = plugin.StateIsSet

	id, err = lge.id()
	require.NoError(t, err)
	assert.Equal(t, "/etc/logrotate.conf:7:/var/log/syslog", id)
}
