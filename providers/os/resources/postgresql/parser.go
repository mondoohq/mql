// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package postgresql contains parsers for PostgreSQL on-disk configuration
// files: postgresql.conf, pg_hba.conf, and pg_ident.conf. The parsers operate
// on already-read file content so they don't depend on a particular
// filesystem implementation — that lets them be unit-tested against
// inlined fixtures and re-used over different transports (local, SSH,
// container snapshot, ...).
package postgresql

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Conf is the flattened result of parsing postgresql.conf (and its include
// fragments). Last-write-wins semantics match PostgreSQL's own behaviour.
type Conf struct {
	// Params is the effective key->value map across the main file and all
	// included fragments. Keys are normalised to lowercase to match
	// PostgreSQL's case-insensitive parameter names.
	Params map[string]string
	// Files lists every file that contributed (main + includes, in load
	// order, deduplicated).
	Files []string
}

// Overlay applies another parse over this one, as the server applies
// postgresql.auto.conf after postgresql.conf: each of its settings wins, and
// its files are read after this one's.
func (c *Conf) Overlay(other *Conf) {
	if other == nil {
		return
	}
	for k, v := range other.Params {
		c.Params[k] = v
	}
	for _, f := range other.Files {
		if !slices.Contains(c.Files, f) {
			c.Files = append(c.Files, f)
		}
	}
}

// FileReader returns the textual content of `path`. A missing file must be
// reported with an error that wraps fs.ErrNotExist: `include_if_exists` and
// `include_dir` skip those, the way PostgreSQL does. Any other error (a
// permission refusal, a transport failure) aborts the parse, since the
// fragment it could not read may hold the setting being audited.
type FileReader func(path string) (string, error)

// DirLister returns the paths of the regular files directly inside dir. A
// missing directory must be reported with an error that wraps fs.ErrNotExist.
// The parser applies PostgreSQL's include_dir filter (`*.conf`, no dotfiles)
// and ordering itself, so the lister may return every entry in any order.
type DirLister func(dir string) ([]string, error)

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// includeDirFiles returns the files PostgreSQL loads for `include_dir dir`:
// names ending in `.conf` that do not start with a dot, in byte order. A
// missing directory yields nothing.
func includeDirFiles(dir string, dirLister DirLister) ([]string, error) {
	if dirLister == nil {
		return nil, nil
	}
	entries, err := dirLister(dir)
	if err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		base := filepath.Base(entry)
		if strings.HasPrefix(base, ".") || !strings.HasSuffix(base, ".conf") {
			continue
		}
		out = append(out, entry)
	}
	sort.Strings(out)
	return out, nil
}

// GlobExpander expands a single shell-style glob pattern into a list of file
// paths. PostgreSQL itself does not glob include directives — but providing
// this hook lets the caller resolve `include_dir 'conf.d'` by reading the
// directory listing. The default behaviour (when this is nil) treats
// include_dir's argument as a literal path with no globbing.
type GlobExpander func(pattern string) ([]string, error)

// ParseConf parses postgresql.conf at `path`, following any include /
// include_if_exists / include_dir directives encountered. `fileReader` is
// used for both the root file and includes. `dirLister` (optional) expands
// `include_dir` arguments into a sorted list of files; pass nil when the
// caller doesn't have a way to enumerate a directory.
func ParseConf(path string, fileReader FileReader, dirLister DirLister) (*Conf, error) {
	c := &Conf{Params: map[string]string{}}
	visited := map[string]bool{}
	err := parseConfRec(c, path, false, fileReader, dirLister, visited)
	return c, err
}

// parseConfRec reads one file and the files it includes. With optional set
// (an include_if_exists target), a missing path is skipped; a missing file
// further down, named by a plain include inside it, is still an error.
func parseConfRec(c *Conf, path string, optional bool, fileReader FileReader, dirLister DirLister, visited map[string]bool) error {
	// Canonicalise the path before checking the cycle guard so equivalent
	// spellings (`./foo.conf` vs `conf.d/../foo.conf` vs `foo.conf`) collapse
	// to the same key. Without this the recursive include detection would
	// miss self-referential loops that walk through `..` segments.
	key := filepath.Clean(path)
	if visited[key] {
		return nil
	}
	visited[key] = true

	content, err := fileReader(path)
	if err != nil {
		if optional && isNotExist(err) {
			return nil
		}
		return err
	}
	c.Files = append(c.Files, path)

	baseDir := filepath.Dir(path)

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		// Trim inline comments. PostgreSQL does NOT support inline comments
		// inside quoted strings, so we walk respecting quoting.
		line = trimInlineComment(line)
		if line == "" {
			continue
		}

		key, value, ok := splitConfKV(line)
		if !ok {
			continue
		}
		key = strings.ToLower(key)

		switch key {
		case "include":
			next := resolveInclude(baseDir, value)
			if err := parseConfRec(c, next, false, fileReader, dirLister, visited); err != nil {
				return err
			}
		case "include_if_exists":
			next := resolveInclude(baseDir, value)
			if err := parseConfRec(c, next, true, fileReader, dirLister, visited); err != nil {
				return err
			}
		case "include_dir":
			entries, err := includeDirFiles(resolveInclude(baseDir, value), dirLister)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if err := parseConfRec(c, entry, false, fileReader, dirLister, visited); err != nil {
					return err
				}
			}
		default:
			c.Params[key] = value
		}
	}
	return nil
}

// splitConfKV parses a single non-comment, non-blank postgresql.conf line
// into a key and a value. PostgreSQL accepts either `key = value` or
// `key value` (the `=` is optional). The value may be a bare token, a
// number with a unit suffix, or a single-quoted string that uses two
// consecutive single quotes to represent an embedded single quote.
func splitConfKV(line string) (string, string, bool) {
	// Find the end of the key — first whitespace or '='
	i := 0
	for i < len(line) && line[i] != ' ' && line[i] != '\t' && line[i] != '=' {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	key := line[:i]
	rest := strings.TrimSpace(line[i:])
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimSpace(rest[1:])
	}
	value := unquoteConfValue(rest)
	return key, value, true
}

// unquoteConfValue strips surrounding single quotes from a postgresql.conf
// value and resolves the doubled single-quote escape (two consecutive
// single quotes) inside the string.
// Returned unchanged when the value isn't quoted.
func unquoteConfValue(s string) string {
	if len(s) < 2 || s[0] != '\'' {
		return s
	}
	// Find the matching closing quote, treating "''" as an escaped single quote.
	var b strings.Builder
	b.Grow(len(s))
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\'' {
			if i+1 < len(s) && s[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			return b.String()
		}
		b.WriteByte(c)
	}
	// Unterminated quote — return what we have.
	return b.String()
}

// trimInlineComment removes a trailing `# comment` while respecting single-
// quoted strings (where a `#` is literal). Returns the trimmed line.
func trimInlineComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'':
			if i+1 < len(line) && line[i+1] == '\'' {
				i++
				continue
			}
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

func resolveInclude(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// SplitListParam splits a postgresql.conf parameter value that holds a
// comma- or whitespace-separated list (e.g. `listen_addresses`,
// `shared_preload_libraries`). Individual elements are trimmed of
// whitespace and surrounding double quotes.
func SplitListParam(value string) []string {
	if value == "" {
		return nil
	}
	// Replace commas with spaces and split on whitespace — this matches
	// PostgreSQL's `SplitGUCList()` for the most common cases without
	// pulling in its full string-list grammar.
	value = strings.ReplaceAll(value, ",", " ")
	fields := strings.Fields(value)
	for i, f := range fields {
		if len(f) >= 2 && f[0] == '"' && f[len(f)-1] == '"' {
			fields[i] = f[1 : len(f)-1]
		}
	}
	return fields
}

// ParseBool reads a boolean parameter value the way PostgreSQL's parse_bool
// does: case-insensitive, and any unique prefix of true, false, yes, no, on
// or off is accepted, so `t`, `ye` and `of` are valid. `o` alone is
// ambiguous and rejected. ok is false for a value PostgreSQL would refuse.
func ParseBool(value string) (val bool, ok bool) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return false, false
	}
	switch v[0] {
	case 't':
		return true, strings.HasPrefix("true", v)
	case 'f':
		return false, strings.HasPrefix("false", v)
	case 'y':
		return true, strings.HasPrefix("yes", v)
	case 'n':
		return false, strings.HasPrefix("no", v)
	case 'o':
		if len(v) < 2 {
			return false, false
		}
		if strings.HasPrefix("on", v) {
			return true, true
		}
		return false, strings.HasPrefix("off", v)
	case '1':
		return true, v == "1"
	case '0':
		return false, v == "0"
	}
	return false, false
}

// IsTruthy returns whether a postgresql.conf value is a boolean PostgreSQL
// reads as true (see ParseBool).
func IsTruthy(value string) bool {
	val, ok := ParseBool(value)
	return ok && val
}

// LogConnectionsEnabled reports whether a log_connections value logs what
// `on` logs. Up to PostgreSQL 17 the parameter is a boolean. PostgreSQL 18
// also accepts a list of the aspects to log (receipt, authentication,
// authorization, setup_durations) or `all`, where `on` stands for receipt,
// authentication and authorization; a list counts as enabled when it covers
// those three. PostgreSQL 18 no longer takes a boolean prefix such as `t`
// here; the server refuses to start with one, so reading it as the boolean
// it abbreviates misreports nothing that runs.
func LogConnectionsEnabled(value string) bool {
	if val, ok := ParseBool(value); ok {
		return val
	}
	need := map[string]bool{"receipt": false, "authentication": false, "authorization": false}
	for _, aspect := range SplitListParam(strings.ToLower(value)) {
		if aspect == "all" {
			return true
		}
		if _, ok := need[aspect]; ok {
			need[aspect] = true
		}
	}
	for _, seen := range need {
		if !seen {
			return false
		}
	}
	return true
}

// HbaRule is one parsed entry from pg_hba.conf. Fields preserve the file's
// token order so the consumer can faithfully audit the original line.
type HbaRule struct {
	// File is the file the rule was read from: pg_hba.conf itself or a file
	// it includes. Empty when the rule was parsed from bare content.
	File       string
	LineNumber int
	Type       string
	Database   string
	User       string
	Address    string
	AuthMethod string
	Options    map[string]string
}

// record is a single logical line from pg_hba.conf or pg_ident.conf after
// inline comments have been stripped and backslash continuations joined. num
// is the 1-based line number where the record starts in the source file.
type record struct {
	num  int
	text string
}

// preprocessRecords turns raw pg_hba.conf / pg_ident.conf content into logical
// records. It strips inline comments (unquoted `#` to end of line) and joins
// physical lines that a trailing unquoted backslash marks as continued, both
// features PostgreSQL's own tokenizer supports. Blank and comment-only lines
// collapse to an empty record so callers can skip them. Double-quoted spans
// are respected: a `#` or `\` inside quotes is treated literally.
func preprocessRecords(content string) []record {
	var out []record
	var buf strings.Builder
	start := 0
	continuing := false

	for i, raw := range strings.Split(content, "\n") {
		body, cont := stripCommentAndContinuation(strings.TrimRight(raw, "\r"))
		if !continuing {
			start = i + 1
			buf.Reset()
		}
		buf.WriteString(body)
		if cont {
			// Insert a separator so tokens on either side of the join don't
			// merge into one when the backslash directly abutted a token.
			buf.WriteByte(' ')
			continuing = true
			continue
		}
		out = append(out, record{num: start, text: strings.TrimSpace(buf.String())})
		continuing = false
	}
	// A trailing backslash on the final line has nothing to continue onto;
	// flush whatever was accumulated rather than dropping it.
	if continuing {
		out = append(out, record{num: start, text: strings.TrimSpace(buf.String())})
	}
	return out
}

// stripCommentAndContinuation removes an unquoted trailing `# comment` from a
// physical line and reports whether the line ends with an unquoted backslash
// continuation marker. When it does, the returned body has that backslash
// removed. A `#` inside a double-quoted span is literal (not a comment), and a
// backslash inside an unterminated quote is not treated as a continuation.
func stripCommentAndContinuation(line string) (string, bool) {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				// The comment consumes the rest of the line, including any
				// trailing backslash, so this record cannot continue.
				return strings.TrimRight(line[:i], " \t"), false
			}
		}
	}
	trimmed := strings.TrimRight(line, " \t")
	if !inQuote && strings.HasSuffix(trimmed, `\`) {
		return trimmed[:len(trimmed)-1], true
	}
	return line, false
}

// ParseHba parses the textual content of a pg_hba.conf file into a list of
// rules in file order. Inline comments (an unquoted `#` to the end of the
// line) are stripped, physical lines joined by a trailing unquoted backslash
// are merged into a single record, and double-quoted tokens are honored so a
// `#`, backslash, or whitespace inside quotes stays literal. Lines that don't
// form a well-formed rule (too few fields, or a leading token that isn't a
// known connection type) are silently skipped, and so are `include`
// directives: use ParseHbaFile to follow them. Each rule's LineNumber is the
// 1-based line where its record begins.
func ParseHba(content string) []HbaRule {
	var rules []HbaRule
	for _, rec := range preprocessRecords(content) {
		if rule, ok := hbaRule(rec); ok {
			rules = append(rules, rule)
		}
	}
	return rules
}

// ParseHbaFile parses pg_hba.conf at path and every file it pulls in with
// `include`, `include_if_exists` and `include_dir` (PostgreSQL 16 and later).
// Rules come back in the order the server evaluates them, an included file's
// rules in place of its directive, each tagged with the file it came from.
func ParseHbaFile(path string, fileReader FileReader, dirLister DirLister) ([]HbaRule, error) {
	var rules []HbaRule
	err := walkAuthFile(path, false, fileReader, dirLister, map[string]bool{}, func(file string, rec record) {
		if rule, ok := hbaRule(rec); ok {
			rule.File = file
			rules = append(rules, rule)
		}
	})
	return rules, err
}

// walkAuthFile reads an authentication file (pg_hba.conf or pg_ident.conf),
// hands each record to fn, and follows the inclusion directives PostgreSQL 16
// added to both files: a record of exactly two tokens whose first is
// `include`, `include_if_exists` or `include_dir`. A relative target is
// resolved against the directory of the file that names it. A missing
// `include` target is an error (the server refuses to load the file); a
// missing `include_if_exists` target (optional set) or include_dir directory
// contributes nothing, while a missing file named by a plain include inside
// that target is still an error.
func walkAuthFile(path string, optional bool, fileReader FileReader, dirLister DirLister, visited map[string]bool, fn func(file string, rec record)) error {
	key := filepath.Clean(path)
	if visited[key] {
		return nil
	}
	visited[key] = true

	content, err := fileReader(path)
	if err != nil {
		if optional && isNotExist(err) {
			return nil
		}
		return err
	}
	baseDir := filepath.Dir(path)

	for _, rec := range preprocessRecords(content) {
		if rec.text == "" {
			continue
		}
		tokens := tokenizeHba(rec.text)
		if len(tokens) != 2 {
			fn(path, rec)
			continue
		}
		switch tokens[0] {
		case "include":
			if err := walkAuthFile(resolveInclude(baseDir, tokens[1]), false, fileReader, dirLister, visited, fn); err != nil {
				return err
			}
		case "include_if_exists":
			if err := walkAuthFile(resolveInclude(baseDir, tokens[1]), true, fileReader, dirLister, visited, fn); err != nil {
				return err
			}
		case "include_dir":
			entries, err := includeDirFiles(resolveInclude(baseDir, tokens[1]), dirLister)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if err := walkAuthFile(entry, false, fileReader, dirLister, visited, fn); err != nil {
					return err
				}
			}
		default:
			fn(path, rec)
		}
	}
	return nil
}

// hbaRule builds a rule from one record, or reports false when the record is
// blank or not a well-formed rule.
func hbaRule(rec record) (HbaRule, bool) {
	if rec.text == "" {
		return HbaRule{}, false
	}
	tokens := tokenizeHba(rec.text)
	if len(tokens) < 4 {
		return HbaRule{}, false
	}
	rule := HbaRule{LineNumber: rec.num, Type: tokens[0]}
	switch tokens[0] {
	case "local":
		// type database user auth-method [options...]
		rule.Database = tokens[1]
		rule.User = tokens[2]
		rule.AuthMethod = tokens[3]
		rule.Options = parseHbaOptions(tokens[4:])
	case "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc":
		// type database user address auth-method [options...]
		// Address may be `IP/CIDR`, `hostname`, `samehost`, `samenet`,
		// `all`, or an `IP NETMASK` pair (two tokens).
		if len(tokens) < 5 {
			return HbaRule{}, false
		}
		rule.Database = tokens[1]
		rule.User = tokens[2]
		rule.Address = tokens[3]
		authIdx := 4
		// Detect the netmask form: `IP NETMASK` (two tokens). The next
		// token is a netmask when it looks like an IP/CIDR-ish value and
		// the token after it would be the auth method.
		if len(tokens) >= 6 && looksLikeNetmask(tokens[4]) {
			rule.Address = tokens[3] + " " + tokens[4]
			authIdx = 5
		}
		rule.AuthMethod = tokens[authIdx]
		rule.Options = parseHbaOptions(tokens[authIdx+1:])
	default:
		return HbaRule{}, false
	}
	return rule, true
}

// tokenizeHba splits a pg_hba.conf line into whitespace-separated tokens,
// honoring double-quoted tokens (`"my user"`).
func tokenizeHba(line string) []string {
	var tokens []string
	var cur strings.Builder
	quoted := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			quoted = !quoted
		case (c == ' ' || c == '\t') && !quoted:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func parseHbaOptions(tokens []string) map[string]string {
	if len(tokens) == 0 {
		return nil
	}
	out := make(map[string]string, len(tokens))
	for _, t := range tokens {
		if eq := strings.IndexByte(t, '='); eq >= 0 {
			out[t[:eq]] = strings.Trim(t[eq+1:], `"`)
		} else {
			out[t] = ""
		}
	}
	return out
}

// looksLikeNetmask returns true when the token looks like a netmask in
// dotted-quad form (255.255.255.0) or an IPv6 mask (ffff:ffff::). It is
// deliberately permissive — the parser only needs to distinguish a netmask
// from an auth method like `md5`.
func looksLikeNetmask(token string) bool {
	if token == "" {
		return false
	}
	// IPv4 dotted-quad
	if strings.Count(token, ".") == 3 {
		for _, part := range strings.Split(token, ".") {
			if _, err := strconv.Atoi(part); err != nil {
				return false
			}
		}
		return true
	}
	// IPv6 mask (contains ":" and hex digits/colons only)
	if strings.ContainsRune(token, ':') {
		for _, r := range token {
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == ':' {
				continue
			}
			return false
		}
		return true
	}
	return false
}

// IdentMapping is one parsed entry from pg_ident.conf.
type IdentMapping struct {
	// File is the file the mapping was read from: pg_ident.conf itself or a
	// file it includes. Empty when the mapping was parsed from bare content.
	File           string
	LineNumber     int
	MapName        string
	SystemUsername string
	PgUsername     string
}

// ParseIdent parses the textual content of a pg_ident.conf file into a list
// of mappings in file order. It shares pg_hba.conf's preprocessing: inline
// comments are stripped, backslash-continued physical lines are joined, and
// double-quoted tokens (used for regular-expression system-username patterns)
// are honored. Lines that don't have at least three tokens are silently
// skipped, and so are `include` directives: use ParseIdentFile to follow
// them. Each mapping's LineNumber is the 1-based line where its record
// begins.
func ParseIdent(content string) []IdentMapping {
	var out []IdentMapping
	for _, rec := range preprocessRecords(content) {
		if m, ok := identMapping(rec); ok {
			out = append(out, m)
		}
	}
	return out
}

// ParseIdentFile parses pg_ident.conf at path and every file it pulls in with
// `include`, `include_if_exists` and `include_dir` (PostgreSQL 16 and later),
// each mapping tagged with the file it came from.
func ParseIdentFile(path string, fileReader FileReader, dirLister DirLister) ([]IdentMapping, error) {
	var out []IdentMapping
	err := walkAuthFile(path, false, fileReader, dirLister, map[string]bool{}, func(file string, rec record) {
		if m, ok := identMapping(rec); ok {
			m.File = file
			out = append(out, m)
		}
	})
	return out, err
}

// identMapping builds a mapping from one record, or reports false when the
// record has fewer than three tokens.
func identMapping(rec record) (IdentMapping, bool) {
	if rec.text == "" {
		return IdentMapping{}, false
	}
	tokens := tokenizeHba(rec.text) // same quoting rules
	if len(tokens) < 3 {
		return IdentMapping{}, false
	}
	return IdentMapping{
		LineNumber:     rec.num,
		MapName:        tokens[0],
		SystemUsername: tokens[1],
		PgUsername:     tokens[2],
	}, true
}
