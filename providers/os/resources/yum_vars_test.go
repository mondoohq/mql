// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/yum"
	"go.mondoo.com/mql/utils/syncx"
)

func yumVarsFs(t *testing.T, files map[string]string) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for p, content := range files {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	return afs
}

func TestReadYumVarsDirs(t *testing.T) {
	afs := yumVarsFs(t, map[string]string{
		// amazonlinux:2023 ships these in /etc/dnf/vars
		"/etc/dnf/vars/awsregion":  "us-west-2\n",
		"/etc/dnf/vars/awsdomain":  "amazonaws.com\n",
		"/etc/dnf/vars/dualstack":  ".dualstack\n",
		"/etc/dnf/vars/mirrorlist": "mirror.list\n",
		// rockylinux:9 ships an empty rltype
		"/etc/dnf/vars/rltype": "",
		// only the first line is the value
		"/etc/dnf/vars/multiline": "first\nsecond\n",
		// /etc/dnf/vars is read after /etc/yum/vars and wins
		"/etc/yum/vars/awsregion": "eu-central-1\n",
		"/etc/yum/vars/yumonly":   "legacy\n",
		// a subdirectory is not a variable
		"/etc/dnf/vars/sub/nested": "ignored\n",
	})

	got, err := readYumVarsDirs(afs, dnf4VarsDirs)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"awsregion":  "us-west-2",
		"awsdomain":  "amazonaws.com",
		"dualstack":  ".dualstack",
		"mirrorlist": "mirror.list",
		"rltype":     "",
		"multiline":  "first",
		"yumonly":    "legacy",
	}, got)
}

func TestReadYumVarsDirsDnf5(t *testing.T) {
	// dnf5 reads /usr/share/dnf5/vars.d and /etc/dnf/vars, not /etc/yum/vars.
	afs := yumVarsFs(t, map[string]string{
		"/usr/share/dnf5/vars.d/awsregion": "us-east-1\n",
		"/usr/share/dnf5/vars.d/vendor":    "shipped\n",
		"/etc/dnf/vars/awsregion":          "us-west-2\n",
		"/etc/yum/vars/yumonly":            "legacy\n",
	})

	got, err := readYumVarsDirs(afs, dnf5VarsDirs)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"awsregion": "us-west-2", "vendor": "shipped"}, got)
}

// wrappedNotExistYumFs reports a missing path the way a remote connection's
// filesystem can: fs.ErrNotExist wrapped in its own error, not *os.PathError.
type wrappedNotExistYumFs struct{ afero.Fs }

func (w wrappedNotExistYumFs) Open(name string) (afero.File, error) {
	f, err := w.Fs.Open(name)
	if err != nil && os.IsNotExist(err) {
		return nil, fmt.Errorf("remote: %w", fs.ErrNotExist)
	}
	return f, err
}

func TestReadYumVarsDirsMissing(t *testing.T) {
	afs := &afero.Afero{Fs: wrappedNotExistYumFs{afero.NewMemMapFs()}}
	got, err := readYumVarsDirs(afs, dnf4VarsDirs)
	require.NoError(t, err, "missing var directories are not an error")
	assert.Empty(t, got)
}

func newYumRuntime(t *testing.T, files map[string]string, commands map[string]*mock.Command) *plugin.Runtime {
	t.Helper()
	fileData := map[string]*mock.MockFileData{}
	for p, content := range files {
		fileData[p] = &mock.MockFileData{Path: p, Content: content}
		dir := path.Dir(p)
		fileData[dir] = &mock.MockFileData{Path: dir, StatData: mock.FileInfo{Mode: os.ModeDir | 0o755}}
	}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "amazonlinux", Version: "2023", Family: []string{"linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{Files: fileData, Commands: commands}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestYumVarsMergesCustomVarsOverBuiltins(t *testing.T) {
	rt := newYumRuntime(t, map[string]string{
		"/etc/dnf/vars/awsregion":  "us-west-2\n",
		"/etc/dnf/vars/releasever": "2023.override\n",
	}, map[string]*mock.Command{
		fmt.Sprintf(yum.DnfVarsCommand, yum.Python3): {
			Stdout: `{"arch": "aarch64", "basearch": "aarch64", "releasever": "2023.12.20260831"}`,
		},
	})

	y := &mqlYum{MqlRuntime: rt}
	got, err := y.vars()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"arch":       "aarch64",
		"basearch":   "aarch64",
		"releasever": "2023.override",
		"awsregion":  "us-west-2",
	}, got, "custom variables are added and override the built-in ones")
}

func TestYumVarsWithoutPython(t *testing.T) {
	// amazonlinux:2027 has no python3 and no dnf Python module; the command
	// fails, but the variables on disk are still reported.
	rt := newYumRuntime(t, map[string]string{
		"/usr/bin/dnf5":           "",
		"/etc/dnf/vars/awsregion": "us-west-2\n",
		"/etc/dnf/vars/awsdomain": "amazonaws.com\n",
		"/etc/yum/vars/yumonly":   "legacy\n",
	}, map[string]*mock.Command{
		fmt.Sprintf(yum.DnfVarsCommand, yum.Python3): {ExitStatus: 127, Stderr: "python3: command not found"},
	})

	y := &mqlYum{MqlRuntime: rt}
	got, err := y.vars()
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"awsregion": "us-west-2",
		"awsdomain": "amazonaws.com",
	}, got, "dnf5 does not read /etc/yum/vars")
}
