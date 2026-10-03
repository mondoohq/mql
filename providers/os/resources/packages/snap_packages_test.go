// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type snapCommandResult struct {
	stdout     string
	stderr     string
	exitStatus int
	err        error
}

type snapTestConnection struct {
	fs           afero.Fs
	capabilities shared.Capabilities
	asset        *inventory.Asset
	commands     map[string]snapCommandResult
}

func (c *snapTestConnection) ID() uint32 {
	return 0
}

func (c *snapTestConnection) ParentID() uint32 {
	return 0
}

func (c *snapTestConnection) RunCommand(command string) (*shared.Command, error) {
	result, ok := c.commands[command]
	if !ok {
		return &shared.Command{
			Command:    command,
			Stdout:     bytes.NewBuffer(nil),
			Stderr:     bytes.NewBufferString("command not found"),
			ExitStatus: 1,
		}, nil
	}

	if result.err != nil {
		return nil, result.err
	}

	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(result.stdout),
		Stderr:     bytes.NewBufferString(result.stderr),
		ExitStatus: result.exitStatus,
	}, nil
}

func (c *snapTestConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, os.ErrNotExist
}

func (c *snapTestConnection) FileSystem() afero.Fs {
	return c.fs
}

func (c *snapTestConnection) Name() string {
	return "snap-test"
}

func (c *snapTestConnection) Type() shared.ConnectionType {
	if c.capabilities.Has(shared.Capability_RunCommand) {
		return shared.Type_SSH
	}

	return shared.Type_FileSystem
}

func (c *snapTestConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *snapTestConnection) UpdateAsset(asset *inventory.Asset) {
	c.asset = asset
}

func (c *snapTestConnection) Capabilities() shared.Capabilities {
	return c.capabilities
}

type recordingFs struct {
	afero.Fs
	accesses []string
}

func (fs *recordingFs) Open(name string) (afero.File, error) {
	fs.accesses = append(fs.accesses, "open:"+name)
	return fs.Fs.Open(name)
}

func (fs *recordingFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	fs.accesses = append(fs.accesses, "openfile:"+name)
	return fs.Fs.OpenFile(name, flag, perm)
}

func (fs *recordingFs) Stat(name string) (os.FileInfo, error) {
	fs.accesses = append(fs.accesses, "stat:"+name)
	return fs.Fs.Stat(name)
}

func newSnapPkgManagerForTest(fs afero.Fs, capabilities shared.Capabilities, commands map[string]snapCommandResult) *SnapPkgManager {
	platform := &inventory.Platform{
		Name:    "ubuntu",
		Version: "22.04",
		Arch:    "amd64",
		Family:  []string{"debian", "linux", "unix", "os"},
	}

	asset := &inventory.Asset{Platform: platform}

	return &SnapPkgManager{
		conn: &snapTestConnection{
			fs:           fs,
			capabilities: capabilities,
			asset:        asset,
			commands:     commands,
		},
		platform: platform,
	}
}

func newSnapBasePathFs(t *testing.T) (afero.Fs, string) {
	t.Helper()

	root := t.TempDir()
	return afero.NewBasePathFs(afero.NewOsFs(), root), root
}

func hostPath(root string, logicalPath string) string {
	return filepath.Join(root, strings.TrimPrefix(logicalPath, "/"))
}

func writeTestFile(t *testing.T, root string, logicalPath string, content string) {
	t.Helper()

	fullPath := hostPath(root, logicalPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o755))
	require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
}

func writeSnapManifest(t *testing.T, root string, logicalPath string, name string, version string, description string, arch string) {
	t.Helper()

	content := fmt.Sprintf("name: %s\nversion: %s\ndescription: %s\narchitectures:\n  - %s\n", name, version, description, arch)
	writeTestFile(t, root, logicalPath, content)
}

func TestParseSnapMeta(t *testing.T) {
	spm := newSnapPkgManagerForTest(afero.NewMemMapFs(), shared.Capability_None, nil)

	manifestFile, err := os.Open("testdata/snap.yaml")
	require.NoError(t, err)
	defer manifestFile.Close()

	pkg, err := spm.parseSnapManifest(manifestFile)
	require.NoError(t, err)

	assert.Equal(t, "dbgate", pkg.Name)
	assert.Equal(t, "6.1.0", pkg.Version)
	assert.Equal(t, SnapPkgFormat, pkg.Format)
	assert.Contains(t, pkg.Description, "database")
	assert.Equal(t, "pkg:snap/ubuntu/dbgate@6.1.0?arch=amd64", pkg.PUrl)
}

func TestParseSnapListOutput(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected []snapListEntry
	}{
		{
			name:     "header only returns empty list",
			output:   "Name Version Rev Tracking Publisher Notes\n",
			expected: []snapListEntry{},
		},
		{
			name:     "empty output returns empty list",
			output:   "",
			expected: []snapListEntry{},
		},
		{
			name: "parses rows and ignores multi-word notes",
			output: strings.Join([]string{
				"Name Version Rev Tracking Publisher Notes",
				"firefox 121.0 42 latest/stable canonical** -",
				"snap-store 1.2 7 latest/stable canonical** classic disabled",
			}, "\n"),
			expected: []snapListEntry{
				{name: "firefox", version: "121.0", rev: "42"},
				{name: "snap-store", version: "1.2", rev: "7"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := parseSnapListOutput(strings.NewReader(tt.output))
			require.NoError(t, err)
			assert.Equal(t, tt.expected, entries)
		})
	}
}

func TestSnapPkgManagerList_NoSnapDirectoryReturnsEmpty(t *testing.T) {
	fs, _ := newSnapBasePathFs(t)
	spm := newSnapPkgManagerForTest(fs, shared.Capability_None, nil)

	pkgs, err := spm.List()
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func TestSnapPkgManagerList_UsesCLIManifestEnrichment(t *testing.T) {
	fs, root := newSnapBasePathFs(t)
	writeSnapManifest(t, root, "/snap/firefox/42/meta/snap.yaml", "firefox", "121.0", "Firefox browser", "amd64")
	writeSnapManifest(t, root, "/snap/firefox/99/meta/snap.yaml", "firefox", "999.0", "Disabled revision", "amd64")
	writeSnapManifest(t, root, "/snap/snap-store/7/meta/snap.yaml", "snap-store", "1.2", "Snap Store", "amd64")

	spm := newSnapPkgManagerForTest(fs, shared.Capability_RunCommand, map[string]snapCommandResult{
		"snap list": {
			stdout: strings.Join([]string{
				"Name Version Rev Tracking Publisher Notes",
				"firefox 121.0 42 latest/stable canonical** -",
				"snap-store 1.2 7 latest/stable canonical** classic disabled",
			}, "\n"),
		},
	})

	pkgs, err := spm.List()
	require.NoError(t, err)
	require.Len(t, pkgs, 2)

	firefox := findPkg(pkgs, "firefox")
	assert.Equal(t, "121.0", firefox.Version)
	assert.Equal(t, "Firefox browser", firefox.Description)
	assert.Equal(t, "amd64", firefox.Arch)
	assert.Equal(t, "pkg:snap/ubuntu/firefox@121.0?arch=amd64", firefox.PUrl)

	store := findPkg(pkgs, "snap-store")
	assert.Equal(t, "Snap Store", store.Description)
	assert.Equal(t, "1.2", store.Version)
}

func TestSnapPkgManagerList_FallsBackToFilesystemWhenCLIFails(t *testing.T) {
	fs, root := newSnapBasePathFs(t)
	writeSnapManifest(t, root, "/snap/firefox/42/meta/snap.yaml", "firefox", "121.0", "Firefox browser", "amd64")

	spm := newSnapPkgManagerForTest(fs, shared.Capability_RunCommand, map[string]snapCommandResult{
		"snap list": {stderr: "snap not installed", exitStatus: 1},
	})

	pkgs, err := spm.List()
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "firefox", pkgs[0].Name)
	assert.Equal(t, "121.0", pkgs[0].Version)
}

func TestSnapPkgManagerListFromFS_PrefersCurrentSymlink(t *testing.T) {
	fs, root := newSnapBasePathFs(t)
	writeSnapManifest(t, root, "/snap/firefox/10/meta/snap.yaml", "firefox", "10.0", "Current Firefox", "amd64")
	writeSnapManifest(t, root, "/snap/firefox/11/meta/snap.yaml", "firefox", "11.0", "Stale Firefox", "amd64")
	require.NoError(t, os.Symlink("10", hostPath(root, "/snap/firefox/current")))

	spm := newSnapPkgManagerForTest(fs, shared.Capability_None, nil)

	pkgs, err := spm.List()
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "10.0", pkgs[0].Version)
	assert.Equal(t, "Current Firefox", pkgs[0].Description)
}

func TestSnapPkgManagerListFromFS_FallsBackToHighestValidRevision(t *testing.T) {
	fs, root := newSnapBasePathFs(t)
	writeSnapManifest(t, root, "/snap/firefox/9/meta/snap.yaml", "firefox", "9.0", "Firefox", "amd64")
	writeTestFile(t, root, "/snap/firefox/10/meta/snap.yaml", "invalid: [\n")

	spm := newSnapPkgManagerForTest(fs, shared.Capability_None, nil)

	pkgs, err := spm.List()
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "9.0", pkgs[0].Version)
}

func TestSnapPkgManagerList_SkipsMalformedManifest(t *testing.T) {
	fs, root := newSnapBasePathFs(t)
	writeSnapManifest(t, root, "/snap/firefox/42/meta/snap.yaml", "firefox", "121.0", "Firefox browser", "amd64")
	writeTestFile(t, root, "/snap/broken/7/meta/snap.yaml", "not: [valid")

	spm := newSnapPkgManagerForTest(fs, shared.Capability_RunCommand, map[string]snapCommandResult{
		"snap list": {
			stdout: strings.Join([]string{
				"Name Version Rev Tracking Publisher Notes",
				"firefox 121.0 42 latest/stable canonical** -",
				"broken 1.0 7 latest/stable canonical** broken install",
			}, "\n"),
		},
	})

	pkgs, err := spm.List()
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "firefox", pkgs[0].Name)
}

func TestSnapPkgManagerListFromFS_OnlyTouchesBoundedPaths(t *testing.T) {
	baseFs, root := newSnapBasePathFs(t)
	writeSnapManifest(t, root, "/snap/firefox/123/meta/snap.yaml", "firefox", "123.0", "Firefox browser", "amd64")
	writeTestFile(t, root, "/snap/firefox/123/usr/lib/locale/en_US.UTF-8/LC_MESSAGES/ignored", "ignore me")

	recording := &recordingFs{Fs: baseFs}
	spm := newSnapPkgManagerForTest(recording, shared.Capability_None, nil)

	pkgs, err := spm.List()
	require.NoError(t, err)
	require.Len(t, pkgs, 1)

	for _, access := range recording.accesses {
		assert.NotContains(t, access, "/usr/lib/locale")
	}
}

// `snap refresh --list` on Ubuntu 20.04 with five snaps behind the store.
const snapRefreshListUbuntu2004 = `Name              Version         Rev    Size  Publisher    Notes
amazon-ssm-agent  3.3.4793.0      13349  29MB  aws**        classic
core20            20260901        2922   66MB  canonical**  base
core22            20260824        2955   77MB  canonical**  base
lxd               4.0.14-b6e6806  40953  96MB  canonical**  -
snapd             2.77.1          28254  46MB  canonical**  snapd
`

func TestParseSnapRefreshList(t *testing.T) {
	updates, err := ParseSnapRefreshList(strings.NewReader(snapRefreshListUbuntu2004))
	require.NoError(t, err)
	assert.Equal(t, map[string]PackageUpdate{
		"amazon-ssm-agent": {Name: "amazon-ssm-agent", Available: "3.3.4793.0"},
		"core20":           {Name: "core20", Available: "20260901"},
		"core22":           {Name: "core22", Available: "20260824"},
		"lxd":              {Name: "lxd", Available: "4.0.14-b6e6806"},
		"snapd":            {Name: "snapd", Available: "2.77.1"},
	}, updates)

	// nothing to refresh: "All snaps up to date." goes to stderr
	updates, err = ParseSnapRefreshList(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, updates)
}

func TestSnapPkgManagerAvailable(t *testing.T) {
	fs, root := newSnapBasePathFs(t)
	writeSnapManifest(t, root, "/snap/snapd/current/meta/snap.yaml", "snapd", "2.68.4.1", "snapd", "amd64")

	t.Run("updates", func(t *testing.T) {
		spm := newSnapPkgManagerForTest(fs, shared.Capability_RunCommand, map[string]snapCommandResult{
			snapRefreshListCmd: {stdout: snapRefreshListUbuntu2004},
		})
		updates, err := spm.Available()
		require.NoError(t, err)
		assert.Len(t, updates, 5)
		// packages match an update by name and arch, so the update carries
		// the installed snap's arch
		assert.Equal(t, PackageUpdate{Name: "snapd", Arch: "amd64", Available: "2.77.1"}, updates["snapd"])
		assert.Equal(t, "", updates["lxd"].Arch, "no manifest to read the arch from")
	})

	t.Run("all up to date", func(t *testing.T) {
		spm := newSnapPkgManagerForTest(fs, shared.Capability_RunCommand, map[string]snapCommandResult{
			snapRefreshListCmd: {stderr: "All snaps up to date.\n"},
		})
		updates, err := spm.Available()
		require.NoError(t, err)
		assert.NotNil(t, updates)
		assert.Empty(t, updates)
	})

	// stderr captured on Ubuntu 24.04 with snapd stopped, and with the store
	// address blocked
	for name, stderr := range map[string]string{
		"snapd down":        `error: cannot list snaps: cannot communicate with server: Get "http://localhost/v2/find?select=refresh": dial unix /run/snapd.socket: connect: connection refused`,
		"store unreachable": "error: cannot list updates: Post \"https://api.snapcraft.io/v2/snaps/refresh\":\n       dial tcp 127.0.0.1:443: connect: connection refused",
	} {
		t.Run(name, func(t *testing.T) {
			spm := newSnapPkgManagerForTest(fs, shared.Capability_RunCommand, map[string]snapCommandResult{
				snapRefreshListCmd: {stderr: stderr, exitStatus: 1},
			})
			_, err := spm.Available()
			require.ErrorIs(t, err, ErrUpdateCheckFailed)
			assert.Contains(t, err.Error(), "connection refused")
		})
	}

	t.Run("snap not installed", func(t *testing.T) {
		spm := newSnapPkgManagerForTest(fs, shared.Capability_RunCommand, map[string]snapCommandResult{
			snapRefreshListCmd: {stderr: "sh: 1: snap: not found", exitStatus: 127},
		})
		updates, err := spm.Available()
		require.NoError(t, err)
		assert.Nil(t, updates)
	})

	t.Run("no command execution", func(t *testing.T) {
		spm := newSnapPkgManagerForTest(fs, shared.Capability_None, nil)
		updates, err := spm.Available()
		require.NoError(t, err)
		assert.Nil(t, updates)
	})
}
