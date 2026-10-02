// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// Debian 13 installs sudo-rs next to the C sudo: /usr/bin/sudo-rs and
// /usr/bin/visudo-rs link to /usr/lib/cargo/bin/{sudo,visudo}, while
// /usr/bin/sudo and /usr/sbin/visudo stay the C implementation.
var debian13SudoFiles = []string{
	"/usr/bin/sudo",
	"/usr/sbin/visudo",
	"/usr/bin/sudo-rs",
	"/usr/bin/visudo-rs",
	"/usr/lib/cargo/bin/sudo",
	"/usr/lib/cargo/bin/visudo",
}

func TestVisudoForSudo(t *testing.T) {
	fs := afero.NewMemMapFs()
	for _, p := range append(debian13SudoFiles, "/usr/local/bin/sudo", "/usr/local/sbin/visudo", "/opt/sudo/mysudo") {
		require.NoError(t, afero.WriteFile(fs, p, []byte{}, 0o755))
	}
	afs := &afero.Afero{Fs: fs}

	tests := map[string]string{
		"/usr/bin/sudo-rs":        "/usr/bin/visudo-rs",
		"/usr/bin/sudo":           "/usr/sbin/visudo",
		"/usr/lib/cargo/bin/sudo": "/usr/lib/cargo/bin/visudo",
		"/usr/local/bin/sudo":     "/usr/local/sbin/visudo",
		"/opt/sudo/mysudo":        "",
		"/usr/sbin/sudo":          "/usr/sbin/visudo",
	}
	for sudoPath, want := range tests {
		t.Run(sudoPath, func(t *testing.T) {
			assert.Equal(t, want, visudoForSudo(afs, sudoPath))
		})
	}
}

// `visudo-rs -c` on Debian 13 (sudo-rs 0.2.5) for a sudoers.d file that the
// C visudo accepts
const visudoRsStderr = `/etc/sudoers.d/mqltest:7:21: syntax error: 'requiretty' cannot be used in a boolean context
Defaults:mqlt_bash !requiretty
                    ^~~~~~~~~~
/etc/sudoers.d/mqltest:8:20: syntax error: unknown setting: 'logfile'
Defaults@localhost logfile=/var/log/sudo-mql.log
                   ^~~~~~~
visudo: invalid sudoers file
`

const visudoCOK = `/etc/sudoers: parsed OK
/etc/sudoers.d/mqltest: parsed OK
`

func sudoValidateRuntime(t *testing.T, files []string) *plugin.Runtime {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{}
	for _, p := range files {
		mockFiles[p] = &mock.MockFileData{Path: p, Content: "binary"}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{
		Name:   "debian",
		Family: []string{"debian", "linux", "unix", "os"},
	}}, mock.WithData(&mock.TomlData{
		Files: mockFiles,
		Commands: map[string]*mock.Command{
			"/usr/sbin/visudo -c":   {Command: "/usr/sbin/visudo -c", Stdout: visudoCOK},
			"/usr/bin/visudo-rs -c": {Command: "/usr/bin/visudo-rs -c", Stderr: visudoRsStderr, ExitStatus: 1},
		},
	}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestSudoValidateUsesTheImplementationsVisudo(t *testing.T) {
	runtime := sudoValidateRuntime(t, debian13SudoFiles)

	cSudo, err := NewResource(runtime, "sudo", map[string]*llx.RawData{})
	require.NoError(t, err)
	rsSudo, err := NewResource(runtime, "sudo", map[string]*llx.RawData{
		"path": llx.StringData("/usr/bin/sudo-rs"),
	})
	require.NoError(t, err)

	cValidate := cSudo.(*mqlSudo).GetValidate()
	require.NoError(t, cValidate.Error)
	require.NotNil(t, cValidate.Data)
	assert.True(t, cValidate.Data.Valid.Data)

	rsValidate := rsSudo.(*mqlSudo).GetValidate()
	require.NoError(t, rsValidate.Error)
	require.NotNil(t, rsValidate.Data)
	assert.False(t, rsValidate.Data.Valid.Data)
	assert.NotEmpty(t, rsValidate.Data.Errors.Data)
}

func TestSudoValidateNullWhenNotInstalled(t *testing.T) {
	runtime := sudoValidateRuntime(t, debian13SudoFiles)

	res, err := NewResource(runtime, "sudo", map[string]*llx.RawData{
		"path": llx.StringData("/usr/local/bin/nosuchsudo"),
	})
	require.NoError(t, err)
	validate := res.(*mqlSudo).GetValidate()
	require.NoError(t, validate.Error)
	assert.Nil(t, validate.Data)
	assert.True(t, validate.IsNull())
}

// A sudo outside the conventional locations without its own visudo has no
// validator: some other visudo on the system may belong to another
// implementation.
func TestSudoValidateNullWithoutSiblingVisudo(t *testing.T) {
	runtime := sudoValidateRuntime(t, append(debian13SudoFiles, "/opt/sudo/bin/sudo"))

	res, err := NewResource(runtime, "sudo", map[string]*llx.RawData{
		"path": llx.StringData("/opt/sudo/bin/sudo"),
	})
	require.NoError(t, err)
	validate := res.(*mqlSudo).GetValidate()
	require.NoError(t, validate.Error)
	assert.True(t, validate.IsNull())
}

func TestSudoIDIncludesExplicitPath(t *testing.T) {
	runtime := sudoValidateRuntime(t, debian13SudoFiles)

	auto, err := NewResource(runtime, "sudo", map[string]*llx.RawData{})
	require.NoError(t, err)
	rs, err := NewResource(runtime, "sudo", map[string]*llx.RawData{
		"path": llx.StringData("/usr/bin/sudo-rs"),
	})
	require.NoError(t, err)

	assert.Equal(t, "sudo", auto.MqlID())
	assert.Equal(t, "sudo//usr/bin/sudo-rs", rs.MqlID())
	assert.Equal(t, "/usr/bin/sudo", auto.(*mqlSudo).GetPath().Data)
	assert.Equal(t, "/usr/bin/sudo-rs", rs.(*mqlSudo).GetPath().Data)
}
