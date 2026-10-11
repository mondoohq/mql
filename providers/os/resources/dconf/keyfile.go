// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package dconf reads dconf's system configuration as dconf itself does:
// profiles, the keyfiles `dconf update` compiles, and the compiled databases
// GSettings reads.
package dconf

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

// KeyfileError reports a keyfile `dconf update` rejects. It then writes no
// database for the directory, so the previous database stays in place.
type KeyfileError struct {
	File string
	Line int
	Err  string
}

func (e *KeyfileError) Error() string {
	if e.Line == 0 {
		return fmt.Sprintf("%s: %s", e.File, e.Err)
	}
	return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Err)
}

// KeyfileEntry is one key of a keyfile, as a dconf path and its value.
type KeyfileEntry struct {
	Path string
	// Text is the value as written, in GVariant text format.
	Text string
}

// ParseKeyfile reads a keyfile as GKeyFile does: # starts a comment line,
// [group] starts a group, and key=value lines belong to the group before
// them, with whitespace around = ignored. A key set twice keeps the last
// value; a group written twice is one group. Each key becomes the dconf path
// /group/key (/key for the group "/"). The entries are in the order the
// groups and keys first appear.
func ParseKeyfile(name string, r io.Reader) ([]KeyfileEntry, error) {
	type group struct {
		keys   []string
		values map[string]string
	}
	var order []string
	groups := map[string]*group{}
	var cur *group

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		line = strings.TrimLeft(line, " \t\n\v\f\r")
		switch {
		case line == "" || line[0] == '#':
			continue
		case line[0] == '[':
			end := strings.IndexByte(line, ']')
			if end < 0 || strings.Trim(line[end+1:], " \t") != "" {
				return nil, &KeyfileError{File: name, Line: lineNo, Err: "invalid group line"}
			}
			g := line[1:end]
			if g == "" || strings.ContainsAny(g, "[]") {
				return nil, &KeyfileError{File: name, Line: lineNo, Err: "invalid group name"}
			}
			cur = groups[g]
			if cur == nil {
				cur = &group{values: map[string]string{}}
				groups[g] = cur
				order = append(order, g)
			}
		default:
			eq := strings.IndexByte(line, '=')
			if eq <= 0 {
				return nil, &KeyfileError{File: name, Line: lineNo, Err: "line is not a key-value pair, group, or comment"}
			}
			if cur == nil {
				return nil, &KeyfileError{File: name, Line: lineNo, Err: "key file does not start with a group"}
			}
			key := strings.TrimRight(line[:eq], " \t")
			if key == "" {
				return nil, &KeyfileError{File: name, Line: lineNo, Err: "empty key"}
			}
			value := strings.TrimLeft(line[eq+1:], " \t")
			if _, ok := cur.values[key]; !ok {
				cur.keys = append(cur.keys, key)
			}
			cur.values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var res []KeyfileEntry
	for _, g := range order {
		for _, k := range groups[g].keys {
			p := "/" + k
			if g != "/" {
				p = "/" + g + "/" + k
			}
			if !IsKey(p) {
				return nil, &KeyfileError{File: name, Err: fmt.Sprintf("[%s]: %s: invalid path: %s", g, k, p)}
			}
			res = append(res, KeyfileEntry{Path: p, Text: groups[g].values[k]})
		}
	}
	return res, nil
}

// IsKey reports whether p is a valid dconf key: absolute, not a directory
// (no trailing slash) and without empty path segments.
func IsKey(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasSuffix(p, "/") && !strings.Contains(p, "//")
}

// IsKeyfile reports whether `dconf update` reads a file of this name in a
// keyfile directory: every regular file whose name does not start with a dot.
func IsKeyfile(name string) bool {
	return name != "" && name[0] != '.'
}

// ParseLocks reads a lock file: each line that starts with / locks that key,
// taken as written. Other lines, including indented ones, are ignored.
func ParseLocks(r io.Reader) ([]string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var res []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "/") {
			res = append(res, line)
		}
	}
	return res, nil
}

// Keyfile is one parsed keyfile of a keyfile directory.
type Keyfile struct {
	Name    string
	Entries []KeyfileEntry
}

// Compile merges the keyfiles of a directory as `dconf update` does: a key
// set in several files takes the value of the file whose name sorts last. It
// returns the values by key, with the text of each value; a value that is not
// valid GVariant text is an error, as for dconf update.
func Compile(files []Keyfile, locks []string) (*Database, map[string]string, error) {
	sorted := append([]Keyfile{}, files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	text := map[string]string{}
	from := map[string]string{}
	for _, f := range sorted {
		for _, e := range f.Entries {
			text[e.Path] = e.Text
			from[e.Path] = f.Name
		}
	}

	db := &Database{Values: make(map[string]any, len(text))}
	for p, t := range text {
		v, err := ParseText(t)
		if err != nil {
			return nil, nil, &KeyfileError{File: from[p], Err: fmt.Sprintf("%s: invalid value: %s: %v", p, t, err)}
		}
		db.Values[p] = v
	}

	seen := map[string]bool{}
	for _, l := range locks {
		if !seen[l] {
			seen[l] = true
			db.Locks = append(db.Locks, l)
		}
	}
	sort.Strings(db.Locks)
	return db, text, nil
}
