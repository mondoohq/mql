// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logrotate

import (
	"strings"
)

// Entry represents a single logrotate block for one log path.
// If a block specifies multiple paths, each path gets its own Entry
// with the same config values.
type Entry struct {
	File       string
	LineNumber int
	Path       string
	Config     map[string]string
}

// ParseContent parses the content of a logrotate configuration file and
// returns the global directives and per-path entries.
func ParseContent(filePath string, content string) (globalConfig map[string]string, entries []Entry) {
	globalConfig = make(map[string]string)
	lines := strings.Split(content, "\n")

	var (
		inBlock    bool
		inScript   bool
		blockPaths []string
		blockLine  int
		blockConf  map[string]string
	)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Handle endscript inside a script block
		if inScript {
			if trimmed == "endscript" {
				inScript = false
			}
			continue
		}

		if inBlock {
			// Check for closing brace
			if trimmed == "}" {
				// Emit one entry per path in this block
				for _, p := range blockPaths {
					entries = append(entries, Entry{
						File:       filePath,
						LineNumber: blockLine,
						Path:       p,
						Config:     copyMap(blockConf),
					})
				}
				inBlock = false
				blockPaths = nil
				blockConf = nil
				continue
			}

			// Check for script block start
			if isScriptDirective(trimmed) {
				inScript = true
				continue
			}

			// Parse directive inside block
			key, value := parseDirective(trimmed)
			if key != "" {
				blockConf[key] = value
			}
			continue
		}

		// Outside any block

		// Check for lone opening brace (paths on previous line(s), { on its own)
		if trimmed == "{" {
			blockPaths, blockLine = findPathsBackward(lines, i)
			if len(blockPaths) > 0 {
				blockConf = make(map[string]string)
				inBlock = true
			}
			continue
		}

		// Check for block opening: paths followed by { on the same line
		if strings.HasSuffix(trimmed, "{") {
			pathsPart := strings.TrimSuffix(trimmed, "{")
			pathsPart = strings.TrimSpace(pathsPart)
			if pathsPart != "" {
				blockPaths = splitPaths(pathsPart)
				blockLine = lineNum
				blockConf = make(map[string]string)
				inBlock = true
			}
			continue
		}

		// Skip include directives at global level (file discovery handles these)
		if strings.HasPrefix(trimmed, "include ") || strings.HasPrefix(trimmed, "include\t") {
			continue
		}

		// Skip tabooext directives
		if strings.HasPrefix(trimmed, "tabooext ") || strings.HasPrefix(trimmed, "tabooext\t") {
			continue
		}

		// A path line belonging to a lone-brace block ("paths" on one line,
		// "{" on the next) is claimed by the brace handler on a later
		// iteration. Without this it is also recorded here, leaving the log
		// path in globalConfig as a directive nobody wrote.
		if nextSignificantIsLoneBrace(lines, i) {
			continue
		}

		// Global directive
		key, value := parseDirective(trimmed)
		if key != "" {
			globalConfig[key] = value
		}
	}

	return globalConfig, entries
}

// parseDirective splits a logrotate directive into key and value.
// Boolean directives (like "compress") return key with empty value.
// Value directives (like "rotate 4") return key and value.
func parseDirective(line string) (string, string) {
	// Strip inline comments
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return "", ""
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", ""
	}

	key := parts[0]
	if len(parts) == 1 {
		return key, ""
	}
	return key, strings.Join(parts[1:], " ")
}

// splitPaths splits a space-separated list of log file paths/globs.
func splitPaths(s string) []string {
	fields := strings.Fields(s)
	paths := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			paths = append(paths, f)
		}
	}
	return paths
}

// nextSignificantIsLoneBrace reports whether the next line that is neither
// blank nor a comment is a lone "{", which makes the current line the path
// list of the block that brace opens.
func nextSignificantIsLoneBrace(lines []string, idx int) bool {
	for j := idx + 1; j < len(lines); j++ {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return trimmed == "{"
	}
	return false
}

// findPathsBackward scans backward from a lone "{" to find the log path(s).
func findPathsBackward(lines []string, braceIdx int) ([]string, int) {
	for j := braceIdx - 1; j >= 0; j-- {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return splitPaths(trimmed), j + 1
	}
	return nil, 0
}

// isScriptDirective returns true if the line starts a script block.
func isScriptDirective(line string) bool {
	for _, prefix := range []string{"prerotate", "postrotate", "firstaction", "lastaction", "preremove"} {
		if line == prefix || strings.HasPrefix(line, prefix+" ") {
			return true
		}
	}
	return false
}

func copyMap(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
