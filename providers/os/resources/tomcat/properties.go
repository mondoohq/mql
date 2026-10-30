// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseProperties reads a java.util.Properties file — catalina.properties,
// logging.properties, and an application's WEB-INF/classes/logging.properties
// are all in this format.
//
// It follows the java.util.Properties rules that matter in practice: `#` and
// `!` comments, `=`, `:` or whitespace as the key/value separator, a trailing
// backslash continuing the value on the next line, and the `\t`, `\n`, `\r`,
// `\f` and `\uXXXX` escapes. Values are passed through Paths.Expand so that
// ${catalina.base} in a log handler's directory resolves to a real path.
func ParseProperties(content string, paths Paths) map[string]string {
	res := map[string]string{}

	var logical strings.Builder
	continued := false

	for raw := range strings.SplitSeq(content, "\n") {
		line := strings.TrimRight(raw, "\r")

		if !continued {
			trimmed := strings.TrimLeft(line, " \t\f")
			if trimmed == "" || trimmed[0] == '#' || trimmed[0] == '!' {
				continue
			}
			line = trimmed
		} else {
			// Leading whitespace on a continuation line is discarded.
			line = strings.TrimLeft(line, " \t\f")
		}

		if hasTrailingEscape(line) {
			logical.WriteString(line[:len(line)-1])
			continued = true
			continue
		}

		logical.WriteString(line)
		continued = false

		key, value := splitProperty(logical.String())
		logical.Reset()
		if key == "" {
			continue
		}
		res[key] = paths.Expand(value)
	}

	// A file ending on a continuation line still carries a usable entry.
	if logical.Len() > 0 {
		if key, value := splitProperty(logical.String()); key != "" {
			res[key] = paths.Expand(value)
		}
	}

	return res
}

// hasTrailingEscape reports whether the line ends in an odd number of
// backslashes, which is what makes the value continue on the next line. An
// even number is an escaped backslash and ends the value.
func hasTrailingEscape(line string) bool {
	count := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		count++
	}
	return count%2 == 1
}

// splitProperty separates a logical line into its key and value at the first
// unescaped `=`, `:` or run of whitespace.
func splitProperty(line string) (string, string) {
	var key strings.Builder
	i := 0
	escaped := false

	for ; i < len(line); i++ {
		c := line[i]
		if escaped {
			key.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			key.WriteByte(c)
			escaped = true
			continue
		}
		if c == '=' || c == ':' || c == ' ' || c == '\t' || c == '\f' {
			break
		}
		key.WriteByte(c)
	}

	// Skip the separator and any whitespace padding around it.
	for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\f') {
		i++
	}
	if i < len(line) && (line[i] == '=' || line[i] == ':') {
		i++
		for i < len(line) && (line[i] == ' ' || line[i] == '\t' || line[i] == '\f') {
			i++
		}
	}

	return unescapeProperty(key.String()), unescapeProperty(line[i:])
}

func unescapeProperty(value string) string {
	if !strings.Contains(value, "\\") {
		return value
	}

	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			out.WriteByte(value[i])
			continue
		}
		i++
		switch value[i] {
		case 't':
			out.WriteByte('\t')
		case 'n':
			out.WriteByte('\n')
		case 'r':
			out.WriteByte('\r')
		case 'f':
			out.WriteByte('\f')
		case 'u':
			// A \uXXXX escape is four hex digits, so it cannot exceed 0xFFFF,
			// but the bound is checked rather than assumed: converting an
			// out-of-range value to a rune would silently wrap it into a
			// different character instead of failing.
			if i+4 < len(value) {
				if code, err := strconv.ParseUint(value[i+1:i+5], 16, 32); err == nil && code <= utf8.MaxRune {
					out.WriteRune(rune(code))
					i += 4
					continue
				}
			}
			out.WriteByte('u')
		default:
			out.WriteByte(value[i])
		}
	}
	return out.String()
}
