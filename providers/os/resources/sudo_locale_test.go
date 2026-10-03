// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

// Output of sudo 1.9.15p5 on Ubuntu 24.04, run as a non-root user, in the C
// locale and with LANG/LC_ALL=de_DE.UTF-8.
const (
	sudoVOutputC = `Sudo version 1.9.15p5
Sudoers policy plugin version 1.9.15p5
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.15p5
Sudoers audit plugin version 1.9.15p5
`
	sudoVOutputDE = `Sudo-Version 1.9.15p5
Sudoers-Policy-Plugin Version 1.9.15p5
sudoers-Dateigrammatik Version 50
Sudoers I/O plugin version 1.9.15p5
Sudoers audit plugin version 1.9.15p5
`
	visudoNonRootC  = "visudo: unable to open /etc/sudoers: Permission denied\n"
	visudoNonRootDE = "visudo: Die Datei »/etc/sudoers« kann nicht geöffnet werden: Keine Berechtigung\n"
)

// germanLocaleConn answers like a host whose environment sets a German
// locale: a command prints English only when it runs under LC_ALL=C.
type germanLocaleConn struct {
	sudoTestConn
}

func (c *germanLocaleConn) RunCommand(command string) (*shared.Command, error) {
	res := &shared.Command{Command: command, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	cLocale := strings.HasPrefix(command, "env LC_ALL=C ")
	switch {
	case strings.HasSuffix(command, "/usr/bin/sudo -V"):
		out := sudoVOutputDE
		if cLocale {
			out = sudoVOutputC
		}
		res.Stdout = bytes.NewBufferString(out)
	case strings.HasSuffix(command, "/usr/sbin/visudo -c"):
		out := visudoNonRootDE
		if cLocale {
			out = visudoNonRootC
		}
		res.Stderr = bytes.NewBufferString(out)
		res.ExitStatus = 1
	default:
		res.ExitStatus = 127
	}
	return res, nil
}

func newGermanLocaleSudo(t *testing.T) *mqlSudo {
	t.Helper()
	fs := afero.NewMemMapFs()
	for _, p := range []string{"/usr/bin/sudo", "/usr/sbin/visudo"} {
		require.NoError(t, afero.WriteFile(fs, p, []byte("binary"), 0o755))
	}
	runtime := &plugin.Runtime{
		Connection: &germanLocaleConn{sudoTestConn{fs: fs}},
		Resources:  &syncx.Map[plugin.Resource]{},
	}
	res, err := NewResource(runtime, "sudo", map[string]*llx.RawData{})
	require.NoError(t, err)
	return res.(*mqlSudo)
}

func TestSudoVersionUnderGermanLocale(t *testing.T) {
	s := newGermanLocaleSudo(t)

	version := s.GetVersion()
	require.NoError(t, version.Error)
	assert.Equal(t, "1.9.15p5", version.Data)

	impl := s.GetImplementation()
	require.NoError(t, impl.Error)
	assert.Equal(t, "sudo", impl.Data)

	policy := s.GetPolicyPlugin()
	require.NoError(t, policy.Error)
	require.NotNil(t, policy.Data)
	assert.Equal(t, "sudoers_policy", policy.Data.Name.Data)
}

// visudo -c as a non-root user cannot read /etc/sudoers. That is "could not
// check", not "sudoers is invalid".
func TestSudoValidateUnderGermanLocaleNonRoot(t *testing.T) {
	s := newGermanLocaleSudo(t)

	validate := s.GetValidate()
	require.NoError(t, validate.Error)
	assert.True(t, validate.IsNull())
	assert.Nil(t, validate.Data)
}
