// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// Only an absent path means the tool's config is absent. A stat that failed
// for another reason, such as an SSH transport that stalled mid-scan
// ("could not parse file stat"), must not read as "not installed".
func TestConfigStatError(t *testing.T) {
	missing := fmt.Errorf("stat /home/alice/.continue: %w", fs.ErrNotExist)
	notDir := &fs.PathError{Op: "stat", Path: "/home/alice/.claude.json/x", Err: syscall.ENOTDIR}
	denied := &fs.PathError{Op: "stat", Path: "/home/alice/.claude", Err: fs.ErrPermission}
	stalled := errors.New("could not parse file stat: '/home/alice/.continue'")

	assert.NoError(t, configStatError(missing), "a missing path is an absence")
	assert.NoError(t, configStatError(notDir), "a path under a file is an absence")
	assert.Equal(t, stalled, configStatError(stalled), "a failed stat is an error")

	t.Run("v13 reads a refused stat as absent", func(t *testing.T) {
		require.False(t, plugin.StructuredErrors())
		assert.NoError(t, configStatError(denied))
	})
	t.Run("structured errors", func(t *testing.T) {
		enableStructuredErrorsForTest(t)
		err := configStatError(denied)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
		assert.NoError(t, configStatError(missing))
	})
}

func toolTestRuntime(t *testing.T, platform *inventory.Platform) *plugin.Runtime {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{Platform: platform}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/home/alice/.continue": {Path: "/home/alice/.continue", StatData: mock.FileInfo{Mode: fs.ModeDir | 0o755, IsDir: true}},
		},
	}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestConfigPresent(t *testing.T) {
	rt := toolTestRuntime(t, &inventory.Platform{Name: "rockylinux", Version: "9.6", Family: []string{"redhat", "linux", "unix", "os"}})
	ok, err := configPresent(rt, "/home/alice/.continue", false)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = configPresent(rt, "/home/alice/.continue", true)
	require.NoError(t, err)
	assert.False(t, ok, "a directory is not a config file")
	ok, err = configPresent(rt, "/home/alice/.codex", false)
	require.NoError(t, err)
	assert.False(t, ok)
}

// A connection whose platform came back empty must not report the OS as a
// package named "" with the purl "pkg:platform/".
func TestResolveOSRuntimePackageEmptyPlatform(t *testing.T) {
	_, err := resolveOSRuntimePackage(toolTestRuntime(t, &inventory.Platform{}))
	assert.Error(t, err)

	pkg, err := resolveOSRuntimePackage(toolTestRuntime(t, &inventory.Platform{Name: "sles", Title: "SUSE Linux Enterprise Server 15 SP7", Version: "15.7", Family: []string{"suse", "linux", "unix", "os"}}))
	require.NoError(t, err)
	require.NotNil(t, pkg)
	assert.Equal(t, "SUSE Linux Enterprise Server 15 SP7", pkg.GetName().Data)
}
