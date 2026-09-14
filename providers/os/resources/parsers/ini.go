// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package parsers

import "strings"

// Ini contains the parsed contents of an ini-style file
type Ini struct {
	Fields map[string]any
}

// unquotedHashIndex returns the offset of the first "#" that starts a comment,
// or -1 when the line carries none.
//
// A "#" inside a quoted value is part of the value in every ini dialect, so
// cutting the line there truncated values such as
//
//	proxy_password = "p@ss#word"
//
// down to an unterminated `"p@ss`. Inline comments on unquoted values are
// still honoured, which is what the callers of this parser have always relied
// on.
func unquotedHashIndex(line string) int {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#':
			return i
		}
	}
	return -1
}

// ParseIni parses the raw text contents of an ini-style file
func ParseIni(raw string, delimiter string) *Ini {
	res := Ini{
		Fields: map[string]any{},
	}

	curGroup := ""
	res.Fields[curGroup] = map[string]any{}

	lines := strings.Split(raw, "\n")
	for i := range lines {
		line := lines[i]
		line = strings.TrimSpace(line)
		if idx := unquotedHashIndex(line); idx >= 0 {
			line = line[0:idx]
		}

		if len(line) == 0 {
			continue
		}

		if line[0] == '[' {
			gEnd := strings.Index(line, "]")
			if gEnd > 0 {
				curGroup = line[1:gEnd]
				res.Fields[curGroup] = map[string]any{}
			}
			continue
		}

		// this is a common occurrence on space-separated files
		// we pre-process tabs to make things easier on the tester and allow for
		// space-split mechanisms to still work
		if delimiter != "\t" {
			line = strings.ReplaceAll(line, "\t", "    ")
		}

		kv := strings.SplitN(line, delimiter, 2)
		k := strings.Trim(kv[0], " \t\r")
		if k == "" {
			continue
		}

		var v string
		if len(kv) == 2 {
			v = strings.Trim(kv[1], " \t\r")
		}

		res.Fields[curGroup].(map[string]any)[k] = v
	}

	// check if group "" really contains entries
	defaultGroup := res.Fields[""].(map[string]any)
	if len(defaultGroup) == 0 {
		delete(res.Fields, "")
	}

	return &res
}
