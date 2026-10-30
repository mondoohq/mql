// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package haproxy parses HAProxy configuration files.
//
// The grammar is line-oriented:
//
//   - A section starts when a line begins (column 0, no indentation) with one
//     of the recognized section keywords: global, defaults, frontend, backend,
//     listen, resolvers, userlist, peers, mailers, cache, program, ring,
//     http-errors, fcgi-app, crt-store, ruleset.
//   - All subsequent lines until the next section header belong to that
//     section as directives. By convention they are indented, but indentation
//     is not enforced — HAProxy itself does not require it.
//   - `#` starts a comment that extends to end-of-line. A `#` inside a quoted
//     string is treated as part of the string.
//   - A trailing `\` continues the line to the next physical line, joining
//     them with a single space.
//   - `"..."` and `'...'` quote arguments. Backslash escapes are honored
//     inside double quotes.
//   - `!include <path>` and `!includeglob <pattern>` (HAProxy 2.4+) pull in
//     additional config files. Include paths are resolved relative to the
//     directory of the file containing the directive when not absolute.
//
// The parser is lenient: it collects non-fatal issues (unknown section
// keywords, unbalanced quotes, missing include targets) in Config.Errors
// rather than aborting, so callers can extract as much structure as
// possible from imperfect configs.
package haproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// maxConfigBytes caps the bytes read from a single config file to guard
// against pathological inputs (e.g. a runaway symlink). 10 MiB is well
// above any realistic HAProxy config.
const maxConfigBytes = 10 << 20

// knownSections is the set of section keywords recognized as starting a
// new section. Anything else appearing in column 0 is reported as a parse
// error but kept as a directive of the previous section so audits can
// still see it.
var knownSections = map[string]bool{
	"global":      true,
	"defaults":    true,
	"frontend":    true,
	"backend":     true,
	"listen":      true,
	"resolvers":   true,
	"userlist":    true,
	"peers":       true,
	"mailers":     true,
	"cache":       true,
	"program":     true,
	"ring":        true,
	"http-errors": true,
	"fcgi-app":    true,
	"crt-store":   true,
	"ruleset":     true,
	"traces":      true,
}

// Section is a parsed top-level block in an HAProxy config.
type Section struct {
	// Type is the section keyword (global, defaults, frontend, backend, ...).
	Type string
	// Name is the section's identifier (e.g. backend name). Empty for the
	// global section, and may be empty for unnamed defaults blocks.
	Name string
	// Inherits is the value of a `from <other>` argument on the section
	// header (HAProxy 2.4+ named-defaults inheritance). Empty if absent.
	Inherits string
	// File is the path of the source file the section was parsed from.
	File string
	// StartLine is the 1-based source line of the section header.
	StartLine int
	// EndLine is the 1-based source line of the last directive in the
	// section (equals StartLine for an empty section).
	EndLine int
	// Directives lists every non-blank, non-comment line inside the section.
	Directives []Directive
	// Raw is the raw text of the section including its header line.
	Raw string
}

// Directive is one parsed line inside a section.
type Directive struct {
	// Name is the first token of the line (e.g. "bind", "server", "option").
	Name string
	// Args are the remaining tokens with quotes unwrapped.
	Args []string
	// Line is the 1-based source line where the directive starts. For
	// directives that span multiple physical lines via trailing `\`, this
	// is the line of the first segment.
	Line int
	// File is the path of the source file containing the directive.
	File string
	// Raw is the raw text of the directive (line continuations resolved).
	Raw string
}

// ParseError describes a non-fatal error encountered while parsing.
type ParseError struct {
	File string
	Line int
	Msg  string
}

func (e ParseError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

// Config is the result of parsing one or more HAProxy config files.
type Config struct {
	// Sections holds every section in source order, with `!include`d files
	// expanded in place where the include directive appeared.
	Sections []Section
	// Files lists every file visited (root first, then includes in the
	// order they were expanded).
	Files []string
	// Errors collects non-fatal parse errors from every visited file.
	Errors []ParseError
}

// OpenFunc reads the content of a config file for ParseFiles.
type OpenFunc func(path string) (io.ReadCloser, error)

// GlobFunc expands an `!includeglob` pattern into absolute file paths.
// If nil, ParseFiles falls back to filepath.Glob (which only works
// against the real filesystem).
type GlobFunc func(pattern string) ([]string, error)

// Parse parses a single config file's content. The filename is used for
// error reporting and stored on each section/directive; it does not have
// to exist on disk. The returned error wraps any collected ParseErrors;
// the *Config is returned even on error so lenient callers can inspect it.
func Parse(filename string, r io.Reader) (*Config, error) {
	cfg := &Config{}
	if err := parseOne(filename, r, cfg); err != nil {
		return cfg, err
	}
	if len(cfg.Errors) > 0 {
		return cfg, errorList(cfg.Errors)
	}
	return cfg, nil
}

// ParseFiles reads rootPath, parses it, and recursively expands every
// `!include` and `!includeglob` directive encountered.
//
// Include paths that are relative resolve against the directory of the
// file containing the include directive (matching HAProxy's behavior).
// A missing or unreadable root file returns an error; errors in
// transitively included files are collected in Config.Errors but do not
// stop parsing.
func ParseFiles(rootPath string, open OpenFunc, glob GlobFunc) (*Config, error) {
	if open == nil {
		return nil, errors.New("haproxy.ParseFiles: open function is required")
	}
	cfg := &Config{}
	visited := map[string]bool{}
	if err := parseFileRecursive(rootPath, open, glob, cfg, visited); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseFileRecursive(path string, open OpenFunc, glob GlobFunc, cfg *Config, visited map[string]bool) error {
	if visited[path] {
		// Avoid cycles from configs that include themselves.
		return nil
	}
	visited[path] = true
	cfg.Files = append(cfg.Files, path)

	r, err := open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer r.Close()

	// We can't expand includes after the fact because they must appear in
	// section order. Walk lines, build sections, and recurse on includes
	// as we encounter them at the top level.
	return parseStreamWithIncludes(path, r, open, glob, cfg, visited)
}

func parseOne(filename string, r io.Reader, cfg *Config) error {
	// No include expansion — used by the public Parse for single-file callers.
	return parseStreamWithIncludes(filename, r, nil, nil, cfg, nil)
}

func parseStreamWithIncludes(filename string, r io.Reader, open OpenFunc, glob GlobFunc, cfg *Config, visited map[string]bool) error {
	lines, errs := readLogicalLines(r)
	for _, e := range errs {
		e.File = filename
		cfg.Errors = append(cfg.Errors, e)
	}

	var cur *Section
	flush := func() {
		if cur != nil {
			cfg.Sections = append(cfg.Sections, *cur)
			cur = nil
		}
	}

	prefix := filepath.Dir(filename)

	for _, ln := range lines {
		// Detect column-0 directives. Indented lines (any leading whitespace)
		// belong to the current section regardless of the keyword.
		head, rest := firstToken(ln.text)
		if head == "" {
			continue
		}

		// `!include` / `!includeglob` work at the top level. They behave
		// like a section-flushing operation: complete the current section,
		// recurse, then continue collecting into a fresh section after the
		// include returns.
		if !ln.indented && (head == "!include" || head == "!includeglob") {
			if open == nil {
				cfg.Errors = append(cfg.Errors, ParseError{
					File: filename,
					Line: ln.line,
					Msg:  fmt.Sprintf("%s is only supported with ParseFiles", head),
				})
				continue
			}
			args, _, perr := splitArgs(rest)
			if perr != "" {
				cfg.Errors = append(cfg.Errors, ParseError{File: filename, Line: ln.line, Msg: perr})
			}
			if len(args) != 1 {
				cfg.Errors = append(cfg.Errors, ParseError{
					File: filename, Line: ln.line,
					Msg: fmt.Sprintf("%s expects exactly one argument, got %d", head, len(args)),
				})
				continue
			}
			pattern := args[0]
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(prefix, pattern)
			}
			flush()
			var paths []string
			if head == "!includeglob" {
				expanded, err := expandGlob(pattern, glob)
				if err != nil {
					cfg.Errors = append(cfg.Errors, ParseError{File: filename, Line: ln.line, Msg: fmt.Sprintf("glob %q: %v", pattern, err)})
					continue
				}
				paths = expanded
			} else {
				paths = []string{pattern}
			}
			for _, p := range paths {
				if err := parseFileRecursive(p, open, glob, cfg, visited); err != nil {
					cfg.Errors = append(cfg.Errors, ParseError{File: filename, Line: ln.line, Msg: err.Error()})
				}
			}
			continue
		}

		// A column-0 known-section keyword opens a new section.
		if !ln.indented && knownSections[head] {
			flush()
			args, _, perr := splitArgs(rest)
			if perr != "" {
				cfg.Errors = append(cfg.Errors, ParseError{File: filename, Line: ln.line, Msg: perr})
			}
			s := Section{
				Type:      head,
				File:      filename,
				StartLine: ln.line,
				EndLine:   ln.line,
				Raw:       ln.raw,
			}
			// Pull out the section name and `from <name>` inheritance if
			// present. The grammar is: <type> [<name>] [from <other>].
			i := 0
			if i < len(args) && args[i] != "from" {
				s.Name = args[i]
				i++
			}
			if i+1 < len(args) && args[i] == "from" {
				s.Inherits = args[i+1]
			}
			// Anything past the recognized header tokens stays in the
			// section's raw text but isn't otherwise modeled.
			cur = &s
			continue
		}

		// Anything else is a directive of the current section. If we don't
		// have a current section (text before any header), drop it but
		// record an error so the user can find their mistake.
		if cur == nil {
			cfg.Errors = append(cfg.Errors, ParseError{
				File: filename, Line: ln.line,
				Msg: fmt.Sprintf("directive %q outside any section", head),
			})
			continue
		}

		args, _, perr := splitArgs(rest)
		if perr != "" {
			cfg.Errors = append(cfg.Errors, ParseError{File: filename, Line: ln.line, Msg: perr})
		}
		cur.Directives = append(cur.Directives, Directive{
			Name: head,
			Args: args,
			Line: ln.line,
			File: filename,
			Raw:  ln.raw,
		})
		cur.EndLine = ln.line
		cur.Raw += "\n" + ln.raw
	}
	flush()
	return nil
}

// logicalLine is one source line after comment-stripping and trailing-`\`
// continuation handling.
type logicalLine struct {
	text     string // content with leading whitespace preserved, comments removed
	raw      string // raw source text (with continuations joined by a space)
	line     int    // 1-based line number of the first physical line
	indented bool   // true when the first character of text is whitespace
}

// readLogicalLines reads r into logical lines. Trailing `\` continues a
// line, joining the next physical line to it with a single space.
// Comments (`#` outside quotes) are stripped after continuation handling
// so a `#` on a continuation line is still recognized.
func readLogicalLines(r io.Reader) ([]logicalLine, []ParseError) {
	scanner := bufio.NewScanner(io.LimitReader(r, maxConfigBytes))
	// Allow long lines — HAProxy ACL lists can be lengthy.
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	var lines []logicalLine
	var errs []ParseError

	physical := 0
	var pending string
	var pendingStart int

	for scanner.Scan() {
		physical++
		raw := scanner.Text()

		// Continuation: a single trailing backslash (not inside quotes)
		// joins this line with the next. We use a simple heuristic — strip
		// trailing whitespace, then check for `\` — which is what HAProxy
		// itself does.
		trimmedRight := strings.TrimRight(raw, " \t")
		if strings.HasSuffix(trimmedRight, `\`) && !endsWithEscapedBackslash(trimmedRight) {
			seg := strings.TrimSuffix(trimmedRight, `\`)
			if pending == "" {
				pendingStart = physical
				pending = seg
			} else {
				pending += " " + strings.TrimSpace(seg)
			}
			continue
		}

		var lineText string
		var lineNum int
		if pending != "" {
			lineText = pending + " " + strings.TrimSpace(raw)
			lineNum = pendingStart
			pending = ""
		} else {
			lineText = raw
			lineNum = physical
		}

		// Strip comments. `#` outside quotes ends the line.
		stripped, perr := stripComment(lineText)
		if perr != "" {
			errs = append(errs, ParseError{Line: lineNum, Msg: perr})
		}

		// Skip blank lines (after comment strip).
		if strings.TrimSpace(stripped) == "" {
			continue
		}

		indented := len(stripped) > 0 && (stripped[0] == ' ' || stripped[0] == '\t')
		lines = append(lines, logicalLine{
			text:     stripped,
			raw:      lineText,
			line:     lineNum,
			indented: indented,
		})
	}

	// A trailing continuation with no following line is treated as the
	// final logical line so it isn't silently dropped.
	if pending != "" {
		stripped, perr := stripComment(pending)
		if perr != "" {
			errs = append(errs, ParseError{Line: pendingStart, Msg: perr})
		}
		if strings.TrimSpace(stripped) != "" {
			lines = append(lines, logicalLine{
				text:     stripped,
				raw:      pending,
				line:     pendingStart,
				indented: len(stripped) > 0 && (stripped[0] == ' ' || stripped[0] == '\t'),
			})
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, ParseError{Line: physical, Msg: err.Error()})
	}

	return lines, errs
}

// endsWithEscapedBackslash reports whether s ends with an even-length run
// of backslashes — i.e. the trailing `\` is itself escaped and should
// NOT be treated as a line continuation.
func endsWithEscapedBackslash(s string) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 0
}

// stripComment removes a `#`-introduced comment from a line, taking
// quotes into account. Returns the trimmed text and an error string if
// the line ended with an unterminated quote.
func stripComment(s string) (string, string) {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote != 0 && c == '\\' && quote == '"' && i+1 < len(s):
			// Skip the escaped char inside double quotes.
			i++
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && c == '#':
			return s[:i], ""
		}
	}
	if quote != 0 {
		return s, fmt.Sprintf("unterminated %c quote", quote)
	}
	return s, ""
}

// firstToken splits a directive line into its first token and the rest.
// The split respects quoting — a quoted first token is unwrapped — but
// preserves the rest of the line verbatim so splitArgs can re-tokenize
// it consistently. Leading whitespace is dropped.
func firstToken(s string) (string, string) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", ""
	}
	// Quoted first token.
	if s[0] == '"' || s[0] == '\'' {
		q := s[0]
		var buf strings.Builder
		i := 1
		for i < len(s) {
			c := s[i]
			if c == '\\' && q == '"' && i+1 < len(s) {
				buf.WriteByte(s[i+1])
				i += 2
				continue
			}
			if c == q {
				return buf.String(), strings.TrimLeft(s[i+1:], " \t")
			}
			buf.WriteByte(c)
			i++
		}
		return buf.String(), ""
	}
	// Unquoted: token ends at first whitespace.
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return s[:i], strings.TrimLeft(s[i+1:], " \t")
		}
	}
	return s, ""
}

// splitArgs splits the argument portion of a directive into a slice,
// honoring `"..."` and `'...'` quotes. Returns the args, the number of
// physical characters consumed, and an error string if a quote was
// unterminated.
func splitArgs(s string) ([]string, int, string) {
	var args []string
	i := 0
	n := len(s)
	for i < n {
		// Skip leading whitespace.
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			i++
			var buf strings.Builder
			closed := false
			for i < n {
				c := s[i]
				if c == '\\' && q == '"' && i+1 < n {
					buf.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == q {
					closed = true
					i++
					break
				}
				buf.WriteByte(c)
				i++
			}
			if !closed {
				return args, i, fmt.Sprintf("unterminated %c quote", q)
			}
			args = append(args, buf.String())
			continue
		}
		start := i
		for i < n && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		args = append(args, s[start:i])
	}
	return args, i, ""
}

func expandGlob(pattern string, glob GlobFunc) ([]string, error) {
	if glob != nil {
		return glob(pattern)
	}
	// A literal path with no glob meta-characters is returned verbatim so
	// callers see a missing-file error at the open step rather than a
	// silent skip.
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}, nil
	}
	return filepath.Glob(pattern)
}

// errorList aggregates multiple ParseError values into a single error.
type errorList []ParseError

func (l errorList) Error() string {
	switch len(l) {
	case 0:
		return "no errors"
	case 1:
		return l[0].Error()
	}
	return fmt.Sprintf("%d parse errors; first: %s", len(l), l[0])
}

func (l errorList) Errors() []ParseError { return l }
