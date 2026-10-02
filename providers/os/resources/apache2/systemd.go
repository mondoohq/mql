// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"strings"
)

// ServiceUnit holds what a systemd service unit hands the httpd process:
// the Environment= assignments, the EnvironmentFile= paths in order, and the
// ExecStart= command line.
type ServiceUnit struct {
	Environment map[string]string
	// EnvironmentFiles are the files to read, without systemd's leading '-'
	// (which only makes a missing file non-fatal).
	EnvironmentFiles []string
	ExecStart        string
}

// ParseServiceUnit reads the [Service] section of a systemd unit file
// followed by its drop-ins, in the order systemd applies them. RHEL 7's
// httpd.service, for example, has
//
//	EnvironmentFile=/etc/sysconfig/httpd
//	ExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND
//
// and on RHEL 8 and later `systemctl edit httpd` adds a drop-in with
// `Environment=OPTIONS=-DMY_DEFINE`. An empty assignment resets the list, as
// systemd does.
func ParseServiceUnit(contents ...string) ServiceUnit {
	unit := ServiceUnit{Environment: map[string]string{}}
	for _, content := range contents {
		unit.apply(content)
	}
	return unit
}

func (unit *ServiceUnit) apply(content string) {
	inService := false
	for _, raw := range joinUnitContinuations(content) {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			inService = line == "[Service]"
			continue
		}
		if !inService {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "Environment":
			if value == "" {
				unit.Environment = map[string]string{}
				continue
			}
			for _, word := range splitUnitWords(value) {
				if k, v, ok := strings.Cut(word, "="); ok && isValidEnvKey(k) {
					unit.Environment[k] = v
				}
			}
		case "EnvironmentFile":
			if value == "" {
				unit.EnvironmentFiles = nil
				continue
			}
			unit.EnvironmentFiles = append(unit.EnvironmentFiles, strings.TrimPrefix(value, "-"))
		case "ExecStart":
			// a drop-in clears ExecStart= before setting a new one
			unit.ExecStart = value
		}
	}
}

// ParseEnvironmentFile reads a systemd EnvironmentFile: KEY=VALUE lines,
// '#' and ';' comment lines, optional surrounding quotes. Unlike a shell,
// systemd expands no variable references in these values.
func ParseEnvironmentFile(content string) map[string]string {
	vars := map[string]string{}
	for _, raw := range joinUnitContinuations(content) {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !isValidEnvKey(key) {
			continue
		}
		vars[key] = unquoteShellValue(strings.TrimSpace(value))
	}
	return vars
}

// UnitDefines returns the -D parameters httpd is started with, after
// systemd substitutes $VAR and ${VAR} in the ExecStart command line.
func UnitDefines(execStart string, env map[string]string) []string {
	return DefinesFromArguments(expandShellVars(execStart, env))
}

// joinUnitContinuations joins lines ending in a backslash with the next one.
func joinUnitContinuations(content string) []string {
	var lines []string
	var buf strings.Builder
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasSuffix(line, "\\") {
			buf.WriteString(strings.TrimSuffix(line, "\\"))
			buf.WriteByte(' ')
			continue
		}
		buf.WriteString(line)
		lines = append(lines, buf.String())
		buf.Reset()
	}
	if buf.Len() > 0 {
		lines = append(lines, buf.String())
	}
	return lines
}

// splitUnitWords splits an Environment= value into its assignments, which
// are separated by whitespace and may be wrapped in double or single quotes.
func splitUnitWords(s string) []string {
	var words []string
	var cur strings.Builder
	var quote byte
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				continue
			}
			if c == '\\' && i+1 < len(s) {
				i++
				c = s[i]
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
			inWord = true
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}
