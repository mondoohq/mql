// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package bind9 parses the configuration language of BIND 9's named.conf.
//
// The grammar is small: a statement is a name, zero or more arguments, an
// optional brace-delimited block of further statements, and a terminating
// semicolon. Comments come in three spellings (`//`, `#`, and `/* */`), values
// may be quoted, and `include` pulls in another file wherever a statement is
// allowed — which is why a regular expression over named.conf answers questions
// about a fraction of the running configuration on most distributions, where
// the interesting parts live in named.conf.options and named.conf.local.
package bind9

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Statement is one declaration of the configuration language: a name, its
// arguments, and the block it opens, if any.
//
//	dnssec-validation auto;          -> Name: "dnssec-validation", Args: ["auto"]
//	zone "example.com" IN { ... };   -> Name: "zone", Args: ["example.com", "IN"], Block: [...]
type Statement struct {
	Name  string
	Args  []string
	Block []Statement
	// File the statement was read from, after include expansion, and the line
	// it starts on. Both are what makes a finding actionable: the answer to
	// "where is recursion enabled" is a file and a line, not just "yes".
	File string
	Line int
}

// IsBlock reports whether the statement opened a block. A block that is
// present but empty is still a block: `acl trusted { };` declares an empty
// ACL, which is not the same as not declaring one.
func (s *Statement) IsBlock() bool { return s.Block != nil }

// Arg returns the argument at i, or the empty string when there is none, so
// callers can read optional arguments without bounds checks.
func (s *Statement) Arg(i int) string {
	if i < 0 || i >= len(s.Args) {
		return ""
	}
	return s.Args[i]
}

// ArgValue returns the argument that follows key, which is how the grammar
// attaches modifiers to a statement:
//
//	listen-on port 53 { 127.0.0.1; };   -> ArgValue("port")     == "53"
//	file "audit.log" versions 3 size 5m -> ArgValue("versions") == "3"
//
// The empty string means the modifier is absent, which is not the same as a
// modifier set to zero.
func (s *Statement) ArgValue(key string) string {
	for i := 0; i < len(s.Args)-1; i++ {
		if strings.EqualFold(s.Args[i], key) {
			return s.Args[i+1]
		}
	}
	return ""
}

// Unlimited is what a size or a count reports when the configuration says
// `unlimited`, which is a real setting and not an absent one.
const Unlimited = -1

// ParseSize reads a BIND size specification: a number with an optional k, m or
// g suffix, or the words `unlimited` and `default`. It returns the size in
// bytes, Unlimited for `unlimited`, and 0 when the value is absent or
// unreadable, so a caller can tell "no cap" from "no setting".
func ParseSize(v string) int64 {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "":
		return 0
	case "unlimited":
		return Unlimited
	case "default":
		return 0
	}

	multiplier := int64(1)
	switch v[len(v)-1] {
	case 'k':
		multiplier = 1024
		v = v[:len(v)-1]
	case 'm':
		multiplier = 1024 * 1024
		v = v[:len(v)-1]
	case 'g':
		multiplier = 1024 * 1024 * 1024
		v = v[:len(v)-1]
	}

	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0
	}
	return n * multiplier
}

// ParseCount reads a count that may also be the word `unlimited`, as the
// versions modifier of a log channel is. 0 means absent.
func ParseCount(v string) int64 {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "unlimited" {
		return Unlimited
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// Config is a parsed named.conf together with every file that contributed to
// it and every problem found along the way.
type Config struct {
	Statements []Statement
	// Files in the order they were first read, starting with the root config.
	Files []string
	// Errors collected rather than returned: a config with one unreadable
	// include still answers questions about everything else, and reporting
	// nothing at all would read as "nothing configured".
	Errors []error
}

// OpenFunc reads a configuration file. The resource passes one backed by the
// connection's filesystem so this works against an image or a remote host, not
// only the local disk.
type OpenFunc func(path string) (io.ReadCloser, error)

// maxIncludeDepth bounds recursion for a config that includes itself through a
// chain the visited-set cannot catch on its own.
const maxIncludeDepth = 32

// Parse reads a single configuration text. Includes are left as ordinary
// statements; use ParseFiles to expand them.
func Parse(content string) ([]Statement, error) {
	stmts, errs := parseStatements(tokenize(content, ""), "")
	if len(errs) > 0 {
		return stmts, errs[0]
	}
	return stmts, nil
}

// ParseFiles reads the configuration rooted at path and expands every include
// it reaches, depth first, so the returned statements are the configuration
// named would run with.
func ParseFiles(path string, open OpenFunc) *Config {
	cfg := &Config{}
	seen := map[string]bool{}
	cfg.Statements = parseFile(path, open, cfg, seen, 0)
	return cfg
}

func parseFile(path string, open OpenFunc, cfg *Config, seen map[string]bool, depth int) []Statement {
	if depth > maxIncludeDepth {
		cfg.Errors = append(cfg.Errors, fmt.Errorf("include nesting deeper than %d levels at %q", maxIncludeDepth, path))
		return nil
	}
	// An include cycle is a configuration error, not a reason to hang.
	if seen[path] {
		cfg.Errors = append(cfg.Errors, fmt.Errorf("%q is included more than once, skipping the repeat", path))
		return nil
	}
	seen[path] = true

	f, err := open(path)
	if err != nil {
		cfg.Errors = append(cfg.Errors, fmt.Errorf("could not read %q: %w", path, err))
		return nil
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		cfg.Errors = append(cfg.Errors, fmt.Errorf("could not read %q: %w", path, err))
		return nil
	}
	cfg.Files = append(cfg.Files, path)

	stmts, errs := parseStatements(tokenize(string(raw), path), path)
	cfg.Errors = append(cfg.Errors, errs...)
	return expandIncludes(stmts, path, open, cfg, seen, depth)
}

// expandIncludes replaces every include statement with the statements of the
// file it names, at any depth, so a `zone` inside an included file inside a
// `view` ends up where named would put it.
func expandIncludes(stmts []Statement, from string, open OpenFunc, cfg *Config, seen map[string]bool, depth int) []Statement {
	out := make([]Statement, 0, len(stmts))
	for i := range stmts {
		s := stmts[i]
		if strings.EqualFold(s.Name, "include") && !s.IsBlock() {
			target := s.Arg(0)
			if target == "" {
				cfg.Errors = append(cfg.Errors, fmt.Errorf("%s:%d: include without a path", s.File, s.Line))
				continue
			}
			out = append(out, parseFile(resolveInclude(target, from), open, cfg, seen, depth+1)...)
			continue
		}
		if s.IsBlock() {
			s.Block = expandIncludes(s.Block, from, open, cfg, seen, depth)
		}
		out = append(out, s)
	}
	return out
}

// resolveInclude makes a relative include absolute against the directory of the
// file that named it. named resolves relative includes against its working
// directory, which is the `directory` option; reading them next to the
// including file matches how distributions actually lay these files out, and is
// the only interpretation available before the options block has been parsed.
func resolveInclude(target, from string) string {
	if filepath.IsAbs(target) || from == "" {
		return target
	}
	return filepath.Join(filepath.Dir(from), target)
}

// Find returns the top-level statements with the given name, case-insensitively
// as named treats them.
func Find(stmts []Statement, name string) []Statement {
	var out []Statement
	for i := range stmts {
		if strings.EqualFold(stmts[i].Name, name) {
			out = append(out, stmts[i])
		}
	}
	return out
}

// First returns the first statement with the given name, or nil.
//
// named takes the first occurrence of a repeated option and warns about the
// rest, so reading the first is what the running server does.
func First(stmts []Statement, name string) *Statement {
	for i := range stmts {
		if strings.EqualFold(stmts[i].Name, name) {
			return &stmts[i]
		}
	}
	return nil
}

// Value returns the single argument of a named statement, e.g. "auto" for
// `dnssec-validation auto;`. Absent statements and blocks yield "".
func Value(stmts []Statement, name string) string {
	s := First(stmts, name)
	if s == nil {
		return ""
	}
	return strings.Join(s.Args, " ")
}

// List returns the entries of an address-match list, the shape BIND uses for
// allow-transfer, allow-query, listen-on and friends:
//
//	allow-transfer { none; };
//	allow-recursion { localhost; 10.0.0.0/8; };
//
// The optional leading arguments of the statement (`listen-on port 53 { ... }`)
// are not entries and are dropped; read them from the statement itself.
func List(stmts []Statement, name string) []string {
	s := First(stmts, name)
	if s == nil || !s.IsBlock() {
		return nil
	}
	out := make([]string, 0, len(s.Block))
	for i := range s.Block {
		entry := s.Block[i].Name
		if args := s.Block[i].Args; len(args) > 0 {
			entry = entry + " " + strings.Join(args, " ")
		}
		out = append(out, entry)
	}
	return out
}

// Params flattens the non-block statements of a block into name/value pairs, so
// settings without a typed field of their own stay queryable. Block statements
// are left out: their shape is a list or a nested block, and flattening them to
// a string would invent a value that is not in the file.
func Params(stmts []Statement) map[string]string {
	out := map[string]string{}
	for i := range stmts {
		s := stmts[i]
		if s.IsBlock() {
			continue
		}
		if strings.EqualFold(s.Name, "include") {
			continue
		}
		out[strings.ToLower(s.Name)] = strings.Join(s.Args, " ")
	}
	return out
}

// SortedFiles returns the contributing files, deduplicated and ordered, for a
// stable answer across runs.
func SortedFiles(files []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(files))
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
