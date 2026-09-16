// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func targetFs(t *testing.T) afero.Fs {
	t.Helper()

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/basic.target", []byte(`[Unit]
Description=Basic System
Requires=sysinit.target
Wants=sockets.target timers.target paths.target slices.target
After=sysinit.target sockets.target paths.target slices.target tmp.mount
`), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/multi-user.target", []byte(`[Unit]
Description=Multi-User System
Requires=basic.target
After=basic.target

[Install]
Alias=default.target
`), 0o644))
	// a unit file the local admin overrides takes precedence over the vendor one
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/basic.target", []byte(`[Unit]
Description=Basic System (local override)
`), 0o644))
	return fs
}

func TestListSystemdFSTargetNames(t *testing.T) {
	names := ListSystemdFSTargetNames(targetFs(t))
	assert.Equal(t, []string{"basic", "multi-user"}, names)
}

// `systemctl list-unit-files` names the targets without a running systemd, but
// `systemctl show` needs the bus. It failing left every target reporting a
// blank description and no dependencies -- named, but read as carrying
// nothing. The unit files hold all of it except the runtime state.
func TestReadSystemdFSTargetProperties(t *testing.T) {
	props := ReadSystemdFSTargetProperties(targetFs(t), []string{"basic", "multi-user"})
	require.Contains(t, props, "basic")
	require.Contains(t, props, "multi-user")

	// /etc/systemd/system wins over /usr/lib/systemd/system
	assert.Equal(t, "Basic System (local override)", props["basic"]["Description"])
	assert.Equal(t, "/etc/systemd/system/basic.target", props["basic"]["FragmentPath"])
	assert.Equal(t, "loaded", props["basic"]["LoadState"])

	assert.Equal(t, "Multi-User System", props["multi-user"]["Description"])
	assert.Equal(t, "basic.target", props["multi-user"]["Requires"])
	assert.Equal(t, "basic.target", props["multi-user"]["After"])

	// a target with no [Install] section cannot be enabled, which is what
	// systemctl calls "static"; one that has an [Install] section but is not
	// symlinked into a .wants/.requires directory is "disabled", not blank
	assert.Equal(t, "static", props["basic"]["UnitFileState"])
	assert.Equal(t, "disabled", props["multi-user"]["UnitFileState"])
}

// A target symlinked into a .wants directory reads as enabled.
func TestReadSystemdFSTargetProperties_EnabledTarget(t *testing.T) {
	fs := targetFs(t)
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/default.target.wants/multi-user.target", []byte(""), 0o644))

	props := ReadSystemdFSTargetProperties(fs, []string{"multi-user"})
	assert.Equal(t, "enabled", props["multi-user"]["UnitFileState"])
}

// A repeated list setting accumulates rather than replacing, matching systemd.
func TestReadSystemdFSTargetProperties_RepeatedListSetting(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.target", []byte(`[Unit]
Description=Demo
Wants=one.service
Wants=two.service
`), 0o644))

	props := ReadSystemdFSTargetProperties(fs, []string{"demo"})
	assert.Equal(t, "one.service two.service", props["demo"]["Wants"])
}

// A target whose unit file is not there is left out rather than reported as a
// target carrying nothing.
func TestReadSystemdFSTargetProperties_MissingUnitFile(t *testing.T) {
	props := ReadSystemdFSTargetProperties(targetFs(t), []string{"basic", "does-not-exist"})
	assert.Contains(t, props, "basic")
	assert.NotContains(t, props, "does-not-exist")
}
