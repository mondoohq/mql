// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"strings"
)

// ParseEnvvars parses a Debian-style Apache envvars file (/etc/apache2/envvars).
// It extracts simple `export KEY=value` and `KEY=value` assignments and expands
// `$VAR` / `${VAR}` references within values. Shell control flow (if/for/fi)
// is ignored — we only need the final exported values that Apache reads at
// startup.
func ParseEnvvars(content string) map[string]string {
	vars := map[string]string{}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}

		// Strip a trailing inline comment (outside of quotes)
		line = stripInlineComment(line)
		if line == "" {
			continue
		}

		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)

		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}

		key := strings.TrimSpace(line[:eq])
		if !isValidEnvKey(key) {
			continue
		}

		value := strings.TrimSpace(line[eq+1:])
		value = unquoteShellValue(value)
		vars[key] = value
	}

	// Expand $VAR / ${VAR} references using the collected map. Iterate to a
	// fixed point so chained references (A=$B, B=$C) fully resolve regardless
	// of map iteration order. Bounded by len(vars) to guard against cycles.
	for i := 0; i <= len(vars); i++ {
		changed := false
		for k, v := range vars {
			expanded := expandShellVars(v, vars)
			if expanded != v {
				vars[k] = expanded
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return vars
}

// isValidEnvKey reports whether s is a valid shell environment variable name
// (letters, digits, underscores; cannot start with a digit).
func isValidEnvKey(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			continue
		}
		if i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

// unquoteShellValue strips a single pair of surrounding single or double
// quotes from a shell value.
func unquoteShellValue(v string) string {
	if len(v) < 2 {
		return v
	}
	first, last := v[0], v[len(v)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}

// expandShellVars expands $VAR and ${VAR} references in s using vars. Unknown
// variables are replaced with the empty string, matching shell behavior.
func expandShellVars(s string, vars map[string]string) string {
	return expandVarsWith(s, func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}, true)
}

// expandApacheVars expands only `${VAR}` references (Apache does not honor
// bare `$VAR`). Unresolved references are left as-is so the original text is
// preserved when we can't resolve it.
func expandApacheVars(s string, vars map[string]string) string {
	if !strings.Contains(s, "${") || len(vars) == 0 {
		return s
	}
	return expandVarsWith(s, func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}, false)
}

// expandVarsWith walks s and replaces variable references. When allowBare is
// true, bare `$VAR` forms are also expanded (shell-style). Unresolved
// `${VAR}` references are left literal so downstream tools can still see the
// original text.
func expandVarsWith(s string, lookup func(string) (string, bool), allowBare bool) string {
	if !strings.ContainsRune(s, '$') {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		c := s[i]
		if c != '$' || i+1 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}

		// ${VAR}
		if s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				b.WriteByte(c)
				i++
				continue
			}
			name := s[i+2 : i+2+end]
			if v, ok := lookup(name); ok {
				b.WriteString(v)
			} else {
				// Keep the original reference so users can still see it.
				b.WriteString(s[i : i+2+end+1])
			}
			i += 2 + end + 1
			continue
		}

		// $VAR (bash-style, only when allowed)
		if allowBare && isEnvNameStart(s[i+1]) {
			j := i + 1
			for j < len(s) && isEnvNameChar(s[j]) {
				j++
			}
			name := s[i+1 : j]
			if v, ok := lookup(name); ok {
				b.WriteString(v)
			}
			// shell replaces unknown $VAR with empty string
			i = j
			continue
		}

		b.WriteByte(c)
		i++
	}
	return b.String()
}

func isEnvNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isEnvNameChar(c byte) bool {
	return isEnvNameStart(c) || (c >= '0' && c <= '9')
}

// stripInlineComment removes a shell # comment that isn't inside double
// quotes. It applies to the shell-syntax envvars file only; Apache's own
// configuration has no inline comments.
func stripInlineComment(line string) string {
	inQuote := false
	for i, c := range line {
		switch c {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return line
}
