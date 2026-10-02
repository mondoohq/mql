// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	sudopkg "go.mondoo.com/mql/providers/os/resources/sudo"
	"go.mondoo.com/mql/types"
)

// sudoCommonPaths lists where sudo binaries are typically installed.
// Order matters — we return the first hit, so prefer the more conventional
// path when sudo is installed in multiple places.
var sudoCommonPaths = []string{
	"/usr/bin/sudo",
	"/usr/local/bin/sudo",
	"/usr/sbin/sudo",
	"/opt/freeware/bin/sudo", // AIX (packaged via Bull / RPM)
	"/opt/csw/bin/sudo",      // Solaris CSW
}

// visudoCommonPaths mirrors sudoCommonPaths for visudo, which conventionally
// lives in the sbin sibling of sudo's bin directory.
var visudoCommonPaths = []string{
	"/usr/sbin/visudo",
	"/usr/local/sbin/visudo",
	"/sbin/visudo",
	"/opt/freeware/sbin/visudo", // AIX
	"/opt/csw/sbin/visudo",      // Solaris CSW
}

// buildSudoVCommand returns a shell-safe `<path> -V` invocation. The path
// may originate from `init(path: ...)`, so it must be quoted to prevent
// shell-metacharacter injection (e.g., `init(path: "/tmp/evil; cat /etc/shadow")`).
func buildSudoVCommand(path string) string {
	return shared.ShellEscape(path) + " -V"
}

// mqlSudoInternal caches the parsed `sudo -V` result so the binary is
// invoked at most once per resource instance, regardless of how many
// dependent fields fan out.
type mqlSudoInternal struct {
	once    sync.Once
	parsed  sudopkg.VersionInfo
	parseOK bool
	parseEr error
}

func (s *mqlSudo) id() (string, error) {
	return "sudo", nil
}

// path locates the sudo binary on the asset. Filesystem probing is
// preferred because it works regardless of the remote shell's $PATH.
func (s *mqlSudo) path() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	for _, p := range sudoCommonPaths {
		ok, err := afs.Exists(p)
		if err == nil && ok {
			return p, nil
		}
	}

	// Fall back to `command -v` when the binary lives somewhere
	// non-standard and a shell is available.
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		if p := lookupSudoViaCommand(conn); p != "" {
			return p, nil
		}
	}

	// Not installed. Mark the field resolved-but-null so callers don't
	// retry the lookup.
	s.Path = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	return "", nil
}

func lookupSudoViaCommand(conn shared.Connection) string {
	return lookupViaCommand(conn, "sudo")
}

// lookupViaCommand asks the remote shell to resolve a binary on $PATH.
// `command` is a shell builtin, which sudo cannot run ("sudo: command:
// command not found"), so the lookup runs in its own shell.
func lookupViaCommand(conn shared.Connection, name string) string {
	cmd, err := conn.RunCommand(lookupViaCommandLine(name))
	if err != nil || cmd.ExitStatus != 0 || cmd.Stdout == nil {
		return ""
	}
	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func lookupViaCommandLine(name string) string {
	return "sh -c " + shared.ShellEscape("command -v "+shared.ShellEscape(name))
}

// resolveVisudoPath locates the visudo binary on the asset. Filesystem
// probing is preferred so non-standard installs (AIX /opt/freeware,
// Solaris /opt/csw) work without relying on $PATH.
func resolveVisudoPath(conn shared.Connection) string {
	afs := &afero.Afero{Fs: conn.FileSystem()}
	for _, p := range visudoCommonPaths {
		ok, err := afs.Exists(p)
		if err == nil && ok {
			return p
		}
	}
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		if p := lookupViaCommand(conn, "visudo"); p != "" {
			return p
		}
	}
	return ""
}

// installed reports whether a sudo binary is present on disk at `path`.
// Note: a non-empty Path is not sufficient — init(path: ...) can
// pre-populate Path with a string that doesn't resolve to a file on
// the asset. Verify existence so policies asserting `sudo.installed`
// get a truthful answer regardless of how the resource was constructed.
func (s *mqlSudo) installed() (bool, error) {
	p := s.GetPath()
	if p.Error != nil {
		return false, p.Error
	}
	if p.Data == "" {
		return false, nil
	}
	conn := s.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}
	exists, err := afs.Exists(p.Data)
	if err != nil {
		// afero.Exists returns a non-nil error only for genuine FS faults
		// (permission denied, broken mount) — plain absence yields (false, nil).
		// Surface the fault rather than silently reporting sudo as missing.
		return false, err
	}
	return exists, nil
}

// versionInfo runs `sudo -V` once and caches the parsed result. All
// version/plugin/python-support fields share the same parse.
func (s *mqlSudo) versionInfo() (sudopkg.VersionInfo, error) {
	s.once.Do(func() {
		s.parsed, s.parseOK, s.parseEr = runSudoVersion(s)
	})
	if s.parseEr != nil {
		return sudopkg.VersionInfo{}, s.parseEr
	}
	return s.parsed, nil
}

func runSudoVersion(s *mqlSudo) (sudopkg.VersionInfo, bool, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return sudopkg.VersionInfo{}, false, nil
	}

	p := s.GetPath()
	if p.Error != nil {
		return sudopkg.VersionInfo{}, false, p.Error
	}
	if p.Data == "" {
		return sudopkg.VersionInfo{}, false, nil
	}

	// The path may have been supplied by the user via `init(path: ...)`.
	// Verify it actually exists before running it — otherwise an
	// attacker-controlled MQL query could execute arbitrary binaries.
	afs := &afero.Afero{Fs: conn.FileSystem()}
	if exists, err := afs.Exists(p.Data); err != nil || !exists {
		return sudopkg.VersionInfo{}, false, nil
	}

	cmd, err := conn.RunCommand(buildSudoVCommand(p.Data))
	if err != nil {
		return sudopkg.VersionInfo{}, false, err
	}

	// `sudo -V` writes to stdout, but a few hardened sudoers configs
	// emit the banner to stderr — concatenate both streams before
	// parsing so we don't lose the version line.
	var sb strings.Builder
	if cmd.Stdout != nil {
		b, _ := io.ReadAll(cmd.Stdout)
		sb.Write(b)
	}
	if cmd.Stderr != nil {
		b, _ := io.ReadAll(cmd.Stderr)
		sb.WriteString("\n")
		sb.Write(b)
	}

	return sudopkg.ParseVersionOutput(sb.String()), true, nil
}

func (s *mqlSudo) version() (string, error) {
	info, err := s.versionInfo()
	if err != nil {
		return "", err
	}
	if info.Version == "" {
		s.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return info.Version, nil
}

func (s *mqlSudo) implementation() (string, error) {
	info, err := s.versionInfo()
	if err != nil {
		return "", err
	}
	if info.Implementation == "" {
		s.Implementation = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return info.Implementation, nil
}

func (s *mqlSudo) plugins() ([]any, error) {
	info, err := s.versionInfo()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(info.Plugins))
	for _, p := range info.Plugins {
		res, err := CreateResource(s.MqlRuntime, "sudo.plugin", map[string]*llx.RawData{
			"name":    llx.StringData(p.Name),
			"version": llx.StringData(p.Version),
			"path":    llx.StringData(p.Path),
			"type":    llx.StringData(p.Type),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res.(*mqlSudoPlugin))
	}
	return out, nil
}

func (s *mqlSudo) policyPlugin(plugins []any) (*mqlSudoPlugin, error) {
	for _, raw := range plugins {
		p := raw.(*mqlSudoPlugin)
		if p.Type.Data == "policy" {
			return p, nil
		}
	}
	s.PolicyPlugin = plugin.TValue[*mqlSudoPlugin]{State: plugin.StateIsSet | plugin.StateIsNull}
	return nil, nil
}

func (s *mqlSudo) ioPlugins(plugins []any) ([]any, error) {
	return pluginsOfType(plugins, "io"), nil
}

func (s *mqlSudo) auditPlugins(plugins []any) ([]any, error) {
	return pluginsOfType(plugins, "audit"), nil
}

func (s *mqlSudo) approvalPlugins(plugins []any) ([]any, error) {
	return pluginsOfType(plugins, "approval"), nil
}

func pluginsOfType(plugins []any, t string) []any {
	out := make([]any, 0)
	for _, raw := range plugins {
		p := raw.(*mqlSudoPlugin)
		if p.Type.Data == t {
			out = append(out, p)
		}
	}
	return out
}

func (s *mqlSudo) pythonSupport() (bool, error) {
	info, err := s.versionInfo()
	if err != nil {
		return false, err
	}
	return info.PythonSupport, nil
}

// sudoers returns the existing `sudoers` resource for this asset, so
// policies can write `sudo.sudoers.defaults.contains(...)` without
// importing both resources explicitly.
func (s *mqlSudo) sudoers() (*mqlSudoers, error) {
	res, err := CreateResource(s.MqlRuntime, "sudoers", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlSudoers), nil
}

// validate runs `visudo -c` and reports parse errors. Returns null when
// sudoers files can't be read (typical for unprivileged sessions —
// /etc/sudoers is mode 0440 root:root) or when visudo cannot be located.
func (s *mqlSudo) validate() (*mqlSudoValidation, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		s.Validate = plugin.TValue[*mqlSudoValidation]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	visudo := resolveVisudoPath(conn)
	if visudo == "" {
		s.Validate = plugin.TValue[*mqlSudoValidation]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	cmd, err := conn.RunCommand(shared.ShellEscape(visudo) + " -c")
	if err != nil {
		s.Validate = plugin.TValue[*mqlSudoValidation]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	var sb strings.Builder
	if cmd.Stdout != nil {
		b, _ := io.ReadAll(cmd.Stdout)
		sb.Write(b)
	}
	if cmd.Stderr != nil {
		b, _ := io.ReadAll(cmd.Stderr)
		sb.WriteString("\n")
		sb.Write(b)
	}
	out := sb.String()

	// `visudo -c` requires read access to /etc/sudoers. Treat permission
	// errors as "validation unavailable" rather than "validation failed".
	lower := strings.ToLower(out)
	if strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "operation not permitted") ||
		strings.Contains(lower, "command not found") {
		s.Validate = plugin.TValue[*mqlSudoValidation]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	// `visudo -c` exits non-zero on any syntax error, so the exit status is
	// the authoritative pass/fail signal. When it exits 0 every file parsed
	// OK, so any colon-format lines that slipped past reVisudoOK (e.g. a
	// future visudo emitting `/etc/sudoers: 5 entries`) are informational,
	// not errors — discard them rather than reporting a false failure.
	var parseErrors []sudopkg.ValidationError
	if cmd.ExitStatus != 0 {
		parseErrors = sudopkg.ParseVisudoErrors(out)
	}

	// If visudo exited non-zero but we recognized no error lines (an
	// unknown error format), surface the raw output as one synthetic
	// error so the operator isn't left staring at `valid=false, errors=[]`.
	if cmd.ExitStatus != 0 && len(parseErrors) == 0 {
		trimmed := strings.TrimSpace(out)
		if trimmed != "" {
			parseErrors = append(parseErrors, sudopkg.ValidationError{Message: trimmed})
		}
	}

	errsResources := make([]any, 0, len(parseErrors))
	for _, e := range parseErrors {
		res, err := CreateResource(s.MqlRuntime, "sudo.validation.error", map[string]*llx.RawData{
			"file":    llx.StringData(e.File),
			"line":    llx.IntData(int64(e.Line)),
			"message": llx.StringData(e.Message),
		})
		if err != nil {
			return nil, err
		}
		errsResources = append(errsResources, res.(*mqlSudoValidationError))
	}

	valid := cmd.ExitStatus == 0 && len(parseErrors) == 0
	res, err := CreateResource(s.MqlRuntime, "sudo.validation", map[string]*llx.RawData{
		"valid":  llx.BoolData(valid),
		"errors": llx.ArrayData(errsResources, types.Resource("sudo.validation.error")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlSudoValidation), nil
}

// id methods for the private sub-resources.

func (p *mqlSudoPlugin) id() (string, error) {
	return "sudo.plugin/" + p.Name.Data + ":" + p.Version.Data, nil
}

func (v *mqlSudoValidation) id() (string, error) {
	if v.Valid.Data {
		return "sudo.validation/valid", nil
	}
	return "sudo.validation/invalid", nil
}

func (e *mqlSudoValidationError) id() (string, error) {
	return "sudo.validation.error/" + e.File.Data + ":" + strconv.FormatInt(e.Line.Data, 10) + ":" + e.Message.Data, nil
}
