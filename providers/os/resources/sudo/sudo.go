// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sudo parses output from the `sudo -V` and `visudo -c` binaries.
package sudo

import (
	"regexp"
	"strconv"
	"strings"
)

// VersionInfo is the structured result of parsing `sudo -V` output.
type VersionInfo struct {
	// Which sudo implementation produced the output: ImplementationSudo or
	// ImplementationSudoRs. Empty when the output matches neither banner.
	Implementation string
	// Upstream version of that implementation (e.g., "1.9.5p3" for sudo,
	// "0.2.13" for sudo-rs)
	Version string
	// Plugins discovered in the output
	Plugins []Plugin
	// Whether the build supports Python-based plugins.
	// True when configure options contain --enable-python or any plugin
	// has a python_* name.
	PythonSupport bool
}

// Implementation names reported in VersionInfo.Implementation.
const (
	// ImplementationSudo is the C sudo maintained at sudo.ws.
	ImplementationSudo = "sudo"
	// ImplementationSudoRs is the Rust reimplementation, which recent Ubuntu
	// releases install as `sudo`.
	ImplementationSudoRs = "sudo-rs"
)

// Plugin describes a single sudo plugin reported by `sudo -V`.
type Plugin struct {
	// Canonical plugin name (e.g., "sudoers_policy", "python_io")
	Name string
	// Plugin version
	Version string
	// Plugin type: "policy", "io", "audit", or "approval"
	Type string
	// Full path to the .so file, when reported (often empty as non-root)
	Path string
}

// ValidationError is a single parse error reported by `visudo -c`.
type ValidationError struct {
	File    string
	Line    int
	Message string
}

// Plugin family prefixes that `sudo -V` uses. Order matters when matching:
// "Sudoers I/O" must be tried before "Sudoers" (the broader prefix would
// otherwise win), so list specific subtypes first within each family.
var (
	// "Sudoers policy plugin version 1.9.5p2"
	// "Sudoers I/O plugin version 1.9.5p2"
	// "Sudoers audit plugin version 1.9.5p2"
	// "Sudoers approval plugin version 1.9.5p2"
	// Python-backed variants ("Python policy plugin version ...") use
	// the same shape and signal that the sudo build supports Python plugins.
	rePluginLine = regexp.MustCompile(`^(Sudoers|Python)\s+(I/O|policy|audit|approval)\s+plugin\s+(?:version\s+)?(\S+)`)

	// "Sudo version 1.9.5p2"
	reVersionLine = regexp.MustCompile(`^Sudo\s+version\s+(\S+)`)

	// "sudo-rs 0.2.13-0ubuntu1.2" (sudo-rs answers -V with one line and
	// has no plugin architecture). Distribution builds append the package
	// revision after a hyphen; upstream versions have none, so everything
	// from the first hyphen on is dropped to keep the version comparable.
	reSudoRsVersionLine = regexp.MustCompile(`^sudo-rs\s+([^\s-]+)`)

	// "Configure options: ... --enable-python ..."
	reConfigureLine = regexp.MustCompile(`^Configure options:\s*(.*)$`)

	// `visudo -c` emits two error formats:
	//   ">>> /etc/sudoers: syntax error near line 42 <<<"  (positional)
	//   "/etc/sudoers: Invalid Defaults entry: badparam"   (defaults / include errors)
	// The positional form carries a line number; the colon form does not.
	reVisudoErrorPositional = regexp.MustCompile(`^>>>\s+(\S+?):\s+(.*?)\s+near\s+line\s+(\d+)\s+<<<`)
	reVisudoErrorColon      = regexp.MustCompile(`^(/\S+):\s+(.+?)$`)
	// `parsed OK` lines (and their localized forms) are emitted by
	// visudo on success and must not be treated as errors.
	reVisudoOK = regexp.MustCompile(`:\s+parsed OK\s*$`)
)

// ParseVersionOutput parses the textual output of `sudo -V` (or `sudo -VV`).
// Empty output returns an empty VersionInfo without error so callers can
// distinguish "sudo not found" (returned earlier by the resolver) from
// "sudo printed nothing useful".
func ParseVersionOutput(output string) VersionInfo {
	info := VersionInfo{}

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		if info.Version == "" {
			if m := reVersionLine.FindStringSubmatch(line); m != nil {
				info.Implementation = ImplementationSudo
				info.Version = m[1]
				continue
			}
			if m := reSudoRsVersionLine.FindStringSubmatch(line); m != nil {
				info.Implementation = ImplementationSudoRs
				info.Version = m[1]
				continue
			}
		}

		if m := reConfigureLine.FindStringSubmatch(line); m != nil {
			if strings.Contains(m[1], "--enable-python") {
				info.PythonSupport = true
			}
			continue
		}

		if m := rePluginLine.FindStringSubmatch(line); m != nil {
			family := strings.ToLower(m[1]) // "sudoers" | "python" | "group"
			rawType := m[2]                 // "I/O" | "policy" | "audit" | "approval"
			pluginType := normalizePluginType(rawType)

			plugin := Plugin{
				Name:    family + "_" + pluginType,
				Type:    pluginType,
				Version: m[3],
			}
			info.Plugins = append(info.Plugins, plugin)

			if family == "python" {
				info.PythonSupport = true
			}
		}
	}

	return info
}

// normalizePluginType maps the raw label in `sudo -V` output to the
// canonical plugin type names exposed in MQL.
func normalizePluginType(raw string) string {
	switch raw {
	case "I/O":
		return "io"
	default:
		// "policy", "audit", "approval" — already canonical
		return raw
	}
}

// PluginsByType returns plugins matching the given type ("policy", "io",
// "audit", or "approval"). Returns nil (not empty slice) when none match,
// which matters because MQL distinguishes empty arrays from null.
func PluginsByType(plugins []Plugin, pluginType string) []Plugin {
	var out []Plugin
	for _, p := range plugins {
		if p.Type == pluginType {
			out = append(out, p)
		}
	}
	return out
}

// FirstPluginByType returns the first plugin matching pluginType, or nil
// when none exists. Useful for `policyPlugin` which is a singleton field.
func FirstPluginByType(plugins []Plugin, pluginType string) *Plugin {
	for i := range plugins {
		if plugins[i].Type == pluginType {
			return &plugins[i]
		}
	}
	return nil
}

// ParseVisudoErrors parses the stderr/stdout of `visudo -c`. Two error
// shapes are recognized:
//
//   - Positional:  ">>> /etc/sudoers: syntax error near line 42 <<<"
//     → File, Line, Message all populated.
//   - Colon:       "/etc/sudoers: Invalid Defaults entry: badparam"
//     → File and Message populated; Line is 0.
//
// Lines matching the `<file>: parsed OK` success marker are dropped.
// Anything else is ignored here — callers that have access to the
// command's exit status should construct a fallback error from the
// raw output when this returns nil but visudo exited non-zero.
//
// Returns nil when there are no recognized error lines.
func ParseVisudoErrors(output string) []ValidationError {
	var errs []ValidationError
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if reVisudoOK.MatchString(line) {
			continue
		}
		if m := reVisudoErrorPositional.FindStringSubmatch(line); m != nil {
			lineNum, _ := strconv.Atoi(m[3])
			errs = append(errs, ValidationError{
				File:    m[1],
				Line:    lineNum,
				Message: m[2],
			})
			continue
		}
		if m := reVisudoErrorColon.FindStringSubmatch(line); m != nil {
			errs = append(errs, ValidationError{
				File:    m[1],
				Message: m[2],
			})
			continue
		}
	}
	return errs
}
