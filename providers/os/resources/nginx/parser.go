// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package nginx parses nginx configuration files. It supports the full
// nginx config grammar:
//
//   - simple directives terminated by ';'
//   - block directives enclosed in '{' ... '}', including nested blocks
//   - double- and single-quoted string arguments with backslash escapes
//   - '#' line comments (at whitespace boundaries)
//   - 'include' directives with filesystem glob expansion
//
// The parser is lenient: it collects non-fatal issues (mismatched braces,
// missing semicolons) in its error slice rather than aborting. This mirrors
// how nginx itself reports config problems.
package nginx

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// maxConfigBytes caps the bytes read from a single config file to guard
// against pathological inputs (e.g. a runaway symlink). 10 MiB is well
// above any realistic nginx config.
const maxConfigBytes = 10 << 20

// Directive is a single parsed nginx directive.
type Directive struct {
	// Name is the directive keyword (e.g. "server_name", "server", "http").
	Name string
	// Args holds positional arguments in source order. Quoted arguments are
	// unescaped — the outer quotes are not included.
	Args []string
	// Block holds child directives when this directive is a block. A nil
	// Block means a simple directive (terminated by ';'). A non-nil but
	// empty Block means an empty block (e.g. "events {}").
	Block []Directive
	// Line is the 1-based source line of the directive name.
	Line int
}

// IsBlock reports whether this directive has a '{ ... }' body.
func (d *Directive) IsBlock() bool { return d.Block != nil }

// ParseError describes a non-fatal error encountered while parsing a
// config file. Parse and ParseFiles continue past these errors so that
// callers can extract as much structure as possible.
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

// Config is the result of parsing one or more nginx config files.
type Config struct {
	// Directives is the top-level directive tree with 'include' directives
	// expanded in place.
	Directives []Directive
	// Files lists every file visited (root first, then includes in the
	// order they were expanded). Useful for building a file list for the
	// resource.
	Files []string
	// Errors collects non-fatal parse and lookup errors from all files.
	Errors []ParseError
}

// OpenFunc reads the content of a config file for ParseFiles.
type OpenFunc func(path string) (io.ReadCloser, error)

// GlobFunc expands an include pattern into absolute file paths. If nil,
// ParseFiles falls back to filepath.Glob.
type GlobFunc func(pattern string) ([]string, error)

// Parse parses nginx config content without following include directives.
// The returned error, if any, wraps all collected ParseError values; the
// directive tree is returned even on error so lenient callers can inspect it.
func Parse(content string) ([]Directive, error) {
	tokens, tokErrs := tokenize(content)
	directives, parseErrs, _ := parseBlock(tokens, 0, false)

	all := append([]ParseError(nil), tokErrs...)
	all = append(all, parseErrs...)
	if len(all) == 0 {
		return directives, nil
	}
	return directives, errorList(all)
}

// ParseFiles reads rootPath, parses it, and recursively expands every
// 'include' directive encountered using open to read files and glob to
// expand patterns. Include paths that are relative resolve against the
// directory containing the root file (matching nginx's default "-p prefix"
// behavior when the prefix is the config directory).
//
// A missing or unreadable root file returns an error; errors in included
// files are collected in Config.Errors but do not stop parsing.
func ParseFiles(rootPath string, open OpenFunc, glob GlobFunc) (*Config, error) {
	if open == nil {
		return nil, errors.New("nginx.ParseFiles: open function is required")
	}
	cfg := &Config{}
	st := &includeState{
		active: map[string]bool{},
		seen:   map[string]bool{},
	}
	prefix := filepath.Dir(rootPath)
	dirs, err := parseFileRecursive(rootPath, prefix, open, glob, cfg, st)
	if err != nil {
		return cfg, err
	}
	cfg.Directives = dirs
	return cfg, nil
}

// includeState tracks include expansion across one ParseFiles run.
//
// `active` is the chain of files currently being expanded, not every file
// ever seen. Cycle protection needs the chain: a file that (transitively)
// includes itself is on it. Using an ever-growing set instead would also
// drop legitimate repeats — the canonical nginx layout has several server
// blocks `include` the same TLS snippet, and only the first would have
// received it.
//
// `seen` deduplicates Config.Files so a snippet included by five servers is
// still listed once.
type includeState struct {
	active map[string]bool
	seen   map[string]bool
	depth  int
}

// maxIncludeDepth bounds include nesting so a pathological config cannot
// exhaust the stack. nginx itself has no documented limit; real configs
// nest a handful deep.
const maxIncludeDepth = 64

// parseFileRecursive reads a file, parses it, then recursively expands
// include directives found inside it (using `prefix` for relative paths).
func parseFileRecursive(path, prefix string, open OpenFunc, glob GlobFunc, cfg *Config, st *includeState) ([]Directive, error) {
	if st.active[path] {
		// This file is already being expanded further up the chain, so
		// including it again is a cycle.
		return nil, nil
	}
	if st.depth >= maxIncludeDepth {
		return nil, fmt.Errorf("include nesting deeper than %d at %s", maxIncludeDepth, path)
	}

	st.active[path] = true
	st.depth++
	defer func() {
		delete(st.active, path)
		st.depth--
	}()

	if !st.seen[path] {
		st.seen[path] = true
		cfg.Files = append(cfg.Files, path)
	}

	r, err := open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, maxConfigBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	tokens, tokErrs := tokenize(string(raw))
	for _, e := range tokErrs {
		e.File = path
		cfg.Errors = append(cfg.Errors, e)
	}

	directives, parseErrs, _ := parseBlock(tokens, 0, false)
	for _, e := range parseErrs {
		e.File = path
		cfg.Errors = append(cfg.Errors, e)
	}

	directives = expandIncludes(directives, prefix, open, glob, cfg, st, path)
	return directives, nil
}

// expandIncludes walks the tree and replaces every simple 'include'
// directive with the parsed directives from the included file(s).
func expandIncludes(directives []Directive, prefix string, open OpenFunc, glob GlobFunc, cfg *Config, st *includeState, sourceFile string) []Directive {
	result := make([]Directive, 0, len(directives))
	for _, d := range directives {
		if d.Name == "include" && !d.IsBlock() {
			if len(d.Args) != 1 {
				cfg.Errors = append(cfg.Errors, ParseError{
					File: sourceFile,
					Line: d.Line,
					Msg:  fmt.Sprintf("'include' expects exactly one argument, got %d", len(d.Args)),
				})
				continue
			}
			pattern := d.Args[0]
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(prefix, pattern)
			}
			paths, err := expandGlob(pattern, glob)
			if err != nil {
				cfg.Errors = append(cfg.Errors, ParseError{
					File: sourceFile,
					Line: d.Line,
					Msg:  fmt.Sprintf("glob %q: %v", pattern, err),
				})
				continue
			}
			for _, p := range paths {
				sub, err := parseFileRecursive(p, prefix, open, glob, cfg, st)
				if err != nil {
					cfg.Errors = append(cfg.Errors, ParseError{
						File: sourceFile,
						Line: d.Line,
						Msg:  err.Error(),
					})
					continue
				}
				result = append(result, sub...)
			}
			continue
		}
		if d.IsBlock() {
			d.Block = expandIncludes(d.Block, prefix, open, glob, cfg, st, sourceFile)
		}
		result = append(result, d)
	}
	return result
}

func expandGlob(pattern string, glob GlobFunc) ([]string, error) {
	if glob != nil {
		return glob(pattern)
	}
	// A literal path without glob meta-characters is returned verbatim so
	// callers see a missing-file error at the open step rather than a
	// silent skip. filepath.Glob would otherwise drop the path when the
	// file doesn't exist.
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

// Errors exposes the underlying slice so callers that care can iterate.
func (l errorList) Errors() []ParseError { return l }

// ====================================================================
// Tokenizer
// ====================================================================

type token struct {
	text     string
	line     int
	isQuoted bool
}

// tokenize converts the input string into a stream of tokens. It emits
// three kinds of tokens:
//
//  1. word tokens (unquoted or quoted argument/directive text)
//  2. single-character delimiter tokens: ';', '{', '}'
//
// Quoted tokens have isQuoted=true; their text has the surrounding quotes
// stripped and backslash escapes applied. Delimiter tokens always carry
// isQuoted=false so a literal "'{'" in the source does not mis-open a block.
//
// Comments starting with '#' extend to end-of-line and are discarded.
func tokenize(input string) ([]token, []ParseError) {
	var tokens []token
	var errs []ParseError
	line := 1
	i := 0
	n := len(input)

	for i < n {
		ch := input[i]

		switch ch {
		case ' ', '\t', '\r':
			i++
		case '\n':
			line++
			i++
		case '#':
			for i < n && input[i] != '\n' {
				i++
			}
		case ';', '{', '}':
			tokens = append(tokens, token{text: string(ch), line: line})
			i++
		case '"', '\'':
			startLine := line
			quote := ch
			var buf strings.Builder
			i++ // consume opening quote
			closed := false
			for i < n {
				c := input[i]
				if c == '\\' && i+1 < n {
					// Backslash escapes the next character literally. This
					// is the minimum needed to let configs embed a closing
					// quote via \" inside the matching quote type.
					nextC := input[i+1]
					if nextC == '\n' {
						line++
					}
					buf.WriteByte(nextC)
					i += 2
					continue
				}
				if c == quote {
					i++ // consume closing quote
					closed = true
					break
				}
				if c == '\n' {
					line++
				}
				buf.WriteByte(c)
				i++
			}
			if !closed {
				errs = append(errs, ParseError{
					Line: startLine,
					Msg:  fmt.Sprintf("unterminated %c-quoted string", quote),
				})
			}
			tokens = append(tokens, token{text: buf.String(), line: startLine, isQuoted: true})
		default:
			startLine := line
			var buf strings.Builder
			for i < n {
				c := input[i]
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
					c == ';' || c == '{' || c == '}' || c == '#' ||
					c == '"' || c == '\'' {
					break
				}
				// A trailing '\' before a delimiter escapes it (rare, but
				// nginx does honor this in unquoted arguments like regex
				// patterns). In all other positions the backslash is kept
				// literally so regexes like `\.php$` survive intact.
				if c == '\\' && i+1 < n {
					nextC := input[i+1]
					switch nextC {
					case ' ', '\t', ';', '{', '}', '"', '\'', '\\', '#':
						buf.WriteByte(nextC)
						i += 2
						continue
					}
				}
				buf.WriteByte(c)
				i++
			}
			if buf.Len() > 0 {
				tokens = append(tokens, token{text: buf.String(), line: startLine})
			}
		}
	}
	return tokens, errs
}

// ====================================================================
// Parser
// ====================================================================

// parseBlock parses directives starting at tokens[pos]. When expectClose
// is true it stops at the first '}' (block body); otherwise it stops at
// EOF (top level). Returns the parsed directives, any errors, and the
// index of the token following the block (or len(tokens) at EOF).
func parseBlock(tokens []token, pos int, expectClose bool) ([]Directive, []ParseError, int) {
	var directives []Directive
	var errs []ParseError
	i := pos

	for i < len(tokens) {
		tok := tokens[i]

		if !tok.isQuoted && tok.text == "}" {
			if !expectClose {
				errs = append(errs, ParseError{Line: tok.line, Msg: "unexpected '}'"})
				i++
				continue
			}
			return directives, errs, i + 1
		}
		if !tok.isQuoted && (tok.text == ";" || tok.text == "{") {
			errs = append(errs, ParseError{
				Line: tok.line,
				Msg:  fmt.Sprintf("unexpected %q (expected a directive name)", tok.text),
			})
			i++
			continue
		}

		name := tok.text
		line := tok.line
		i++

		var args []string
		var block []Directive
		terminated := false

	argsLoop:
		for i < len(tokens) {
			t := tokens[i]
			switch {
			case !t.isQuoted && t.text == ";":
				i++
				terminated = true
				break argsLoop
			case !t.isQuoted && t.text == "{":
				i++
				inner, innerErrs, next := parseBlock(tokens, i, true)
				errs = append(errs, innerErrs...)
				if inner == nil {
					// Ensure a non-nil slice so IsBlock reports true for
					// empty blocks like "events {}".
					inner = []Directive{}
				}
				block = inner
				i = next
				terminated = true
				break argsLoop
			case !t.isQuoted && t.text == "}":
				// Close of the enclosing block; leave it for the caller.
				errs = append(errs, ParseError{
					Line: line,
					Msg:  fmt.Sprintf("directive %q missing ';' before '}'", name),
				})
				break argsLoop
			default:
				args = append(args, t.text)
				i++
			}
		}

		if !terminated && i >= len(tokens) {
			errs = append(errs, ParseError{
				Line: line,
				Msg:  fmt.Sprintf("directive %q missing terminator (';' or block)", name),
			})
		}

		directives = append(directives, Directive{
			Name:  name,
			Args:  args,
			Block: block,
			Line:  line,
		})
	}

	if expectClose {
		// Ran off the end of the token stream without finding '}'.
		errs = append(errs, ParseError{Line: 0, Msg: "unclosed block (missing '}')"})
	}
	return directives, errs, i
}
