// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package mycnf contains a parser for the MySQL option file format (my.cnf,
// mariadb.cnf and the fragments they pull in). The format is shared by MySQL,
// Percona Server and MariaDB, so the package is named for the file format
// rather than for one product.
//
// The parser operates on already-read file content so it doesn't depend on a
// particular filesystem implementation. That lets it be unit-tested against
// inlined fixtures and re-used over different transports (local, SSH,
// container snapshot, ...).
package mycnf

import (
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Option is a single option assignment from an option file, recorded with the
// file and line it came from so callers can report provenance.
type Option struct {
	// Section is the name of the group the option was declared under, as
	// written in the file (for example "mysqld" or "mariadb-11.4").
	Section string
	// Name is the option name after normalization: lowercased, with "-"
	// folded to "_", any leading "--" removed and any "loose" prefix
	// stripped. See NormalizeName.
	Name string
	// Value is the assigned value after unquoting and escape resolution.
	// Empty for an option written with no value.
	Value string
	// Bare reports an option written with no "=" at all. MySQL treats such
	// an option as enabled, so Bare distinguishes `skip_name_resolve` (in
	// effect) from `skip_name_resolve=` (assigned the empty string).
	Bare bool
	// Loose reports an option written with the "loose" prefix, which tells
	// the server to ignore the option when it isn't recognized instead of
	// refusing to start.
	Loose bool
	// File is the path of the option file that declared the option.
	File string
	// Line is the 1-based line number within File.
	Line int
}

// Section is one option group, with the options declared under it across
// every file that contributed to it.
type Section struct {
	// Name is the group name as written, without the surrounding brackets.
	Name string
	// Options are the group's options in read order, duplicates preserved.
	Options []Option
	// Files lists the option files that declared this group, in read order.
	Files []string
}

// Conf is the result of parsing an option file and everything it includes.
type Conf struct {
	// Options holds every option across every file in true read order. The
	// flat shape is deliberate: last-write-wins resolution has to respect
	// the order options were actually read, which a per-group grouping
	// cannot express once a group is reopened in a later file.
	Options []Option
	// Files lists every file that contributed, in read order, deduplicated.
	Files []string
	// Includes holds the raw argument of every !includedir directive, in
	// read order. Flavor detection reads these because the directory a
	// distribution includes names the product more reliably than the root
	// file's own contents do.
	Includes []string
	// groups lists every group header seen, in read order, deduplicated.
	// It is kept separately from Options because a group that declares no
	// options still matters: MariaDB's packaged fragments announce the
	// product with bare [mariadb] and [galera] headers whose bodies are
	// entirely commented out, and a [galera] group present but empty is a
	// different finding from no [galera] group at all.
	groups []string
	// groupFiles maps a group name to the files that declared it, so an
	// empty group still reports where it came from.
	groupFiles map[string][]string
}

// FileReader returns the textual content of path. A non-nil error aborts the
// include currently being followed; the parser does not interpret the error.
type FileReader func(path string) (string, error)

// DirLister returns the file paths directly inside dir, excluding
// subdirectories. Pass nil when the caller has no way to enumerate a
// directory, in which case !includedir directives are recorded but not
// followed.
type DirLister func(dir string) ([]string, error)

// cumulativeOptions lists the options whose occurrences accumulate rather
// than overwrite. Everything else in an option file is last-write-wins.
//
// plugin_load_add is the case that matters in practice: distributions ship
// one fragment per pluggable component (Debian's MariaDB packages install
// five separate provider_*.cnf files, each adding a single compression
// provider), so collapsing them last-write-wins would report one loaded
// plugin where five are in effect. Note that plugin_load, without the
// _add suffix, deliberately does replace any earlier value.
var cumulativeOptions = map[string]bool{
	"plugin_load_add": true,
}

// Parse reads the option file at path and follows every !include and
// !includedir directive it encounters, returning the options in read order.
//
// Includes that cannot be read are skipped rather than failing the parse: a
// dangling !include is a normal state on a host where an optional package was
// removed, and it should not blind the caller to the rest of the
// configuration. An unreadable root file does return an error.
func Parse(path string, reader FileReader, dirLister DirLister) (*Conf, error) {
	c := &Conf{}
	visited := map[string]bool{}
	if err := c.parseFile(path, reader, dirLister, visited, true); err != nil {
		return c, err
	}
	return c, nil
}

func (c *Conf) parseFile(path string, reader FileReader, dirLister DirLister, visited map[string]bool, root bool) error {
	// Canonicalize before the cycle check so equivalent spellings of one
	// path ("conf.d/../my.cnf" and "my.cnf") collapse to the same key and a
	// self-referential include chain terminates.
	key := filepath.Clean(path)
	if visited[key] {
		return nil
	}
	visited[key] = true

	content, err := reader(path)
	if err != nil {
		if root {
			return err
		}
		return nil
	}
	c.Files = append(c.Files, path)

	baseDir := filepath.Dir(path)
	section := ""

	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		// A line comment starts with "#" or ";". Only "#" also works
		// mid-line, which trimInlineComment handles for option values.
		if line[0] == '#' || line[0] == ';' {
			continue
		}

		if line[0] == '!' {
			c.parseDirective(line, baseDir, reader, dirLister, visited)
			continue
		}

		if line[0] == '[' {
			if name, ok := parseGroupHeader(line); ok {
				section = name
				if !contains(c.groups, name) {
					c.groups = append(c.groups, name)
				}
				if c.groupFiles == nil {
					c.groupFiles = map[string][]string{}
				}
				if !contains(c.groupFiles[name], path) {
					c.groupFiles[name] = append(c.groupFiles[name], path)
				}
			}
			continue
		}

		// MySQL rejects options that appear before any group header. Skip
		// them rather than attributing them to an arbitrary group.
		if section == "" {
			continue
		}

		opt, ok := parseOption(line)
		if !ok {
			continue
		}
		opt.Section = section
		opt.File = path
		opt.Line = i + 1
		c.Options = append(c.Options, opt)
	}
	return nil
}

func (c *Conf) parseDirective(line, baseDir string, reader FileReader, dirLister DirLister, visited map[string]bool) {
	// Strip a trailing comment before splitting so `!include foo.cnf # note`
	// resolves to "foo.cnf".
	line = trimInlineComment(line)
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	arg := strings.Join(fields[1:], " ")

	switch strings.ToLower(fields[0]) {
	case "!include":
		_ = c.parseFile(resolvePath(baseDir, arg), reader, dirLister, visited, false)
	case "!includedir":
		dir := resolvePath(baseDir, arg)
		c.Includes = append(c.Includes, dir)
		if dirLister == nil {
			return
		}
		entries, err := dirLister(dir)
		if err != nil {
			return
		}
		// MySQL does not define the order in which a directory's files are
		// read. Sort so a scan is reproducible across hosts and transports.
		sort.Strings(entries)
		for _, entry := range entries {
			if !isIncludableFile(entry) {
				continue
			}
			_ = c.parseFile(entry, reader, dirLister, visited, false)
		}
	}
}

// isIncludableFile reports whether !includedir should read the entry. MySQL
// reads only files ending in ".cnf" on Unix, plus ".ini" on Windows. Other
// suffixes are skipped, which matters because distributions park templates
// next to live fragments (MariaDB ships an "enable_encryption.preset" and a
// "99-enable-encryption.cnf.preset" directory inside its fragment directory).
func isIncludableFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".cnf" || ext == ".ini"
}

// parseGroupHeader extracts the group name from a "[name]" line, tolerating
// whitespace inside the brackets and a trailing comment after them.
func parseGroupHeader(line string) (string, bool) {
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return "", false
	}
	name := strings.TrimSpace(line[1:end])
	if name == "" {
		return "", false
	}
	return name, true
}

// parseOption splits an option line into a normalized name and its resolved
// value. Both "name=value" and a bare "name" are accepted.
func parseOption(line string) (Option, bool) {
	rawName, rawValue, hasValue := strings.Cut(line, "=")
	if !hasValue {
		// Bare option. A mid-line "#" still starts a comment.
		name := strings.TrimSpace(trimInlineComment(line))
		if name == "" {
			return Option{}, false
		}
		normalized, loose := NormalizeName(name)
		if normalized == "" {
			return Option{}, false
		}
		return Option{Name: normalized, Bare: true, Loose: loose}, true
	}

	normalized, loose := NormalizeName(rawName)
	if normalized == "" {
		return Option{}, false
	}
	return Option{
		Name:  normalized,
		Value: unquoteValue(strings.TrimSpace(rawValue)),
		Loose: loose,
	}, true
}

// NormalizeName canonicalizes an option name and reports whether it carried
// the "loose" prefix. MySQL treats "-" and "_" as interchangeable in option
// names, so `bind-address` and `bind_address` are one option and have to
// collapse to a single map key. Any leading "--" is tolerated even though
// option files don't use it.
//
// The "skip", "disable" and "enable" prefixes are deliberately left alone:
// `skip_name_resolve` and `skip_networking` are documented options in their
// own right, so rewriting them into an assignment on some shorter name would
// invent options that do not exist.
func NormalizeName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "--")
	name = strings.ReplaceAll(name, "-", "_")

	loose := false
	if rest, ok := strings.CutPrefix(name, "loose_"); ok && rest != "" {
		name = rest
		loose = true
	}
	return name, loose
}

// unquoteValue resolves an option value: it drops a trailing comment, strips
// one layer of single or double quotes, and resolves the backslash escapes
// MySQL recognizes.
func unquoteValue(value string) string {
	if value == "" {
		return ""
	}

	quote := value[0]
	if quote == '\'' || quote == '"' {
		// Find the closing quote, skipping one escaped by a backslash.
		for i := 1; i < len(value); i++ {
			if value[i] == '\\' {
				i++
				continue
			}
			if value[i] == quote {
				return unescape(value[1:i])
			}
		}
		// Unterminated quote. Take the rest of the line as the value.
		return unescape(value[1:])
	}

	return unescape(strings.TrimSpace(trimInlineComment(value)))
}

// unescape resolves the backslash escapes MySQL recognizes inside an option
// value. A backslash before any other character is left in place, matching
// the server's own behavior.
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'b':
			b.WriteByte('\b')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 's':
			b.WriteByte(' ')
		case '\\', '"', '\'':
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// trimInlineComment drops a trailing "#" comment from an unquoted span. A ";"
// only starts a comment at the beginning of a line, so it is left alone here.
func trimInlineComment(s string) string {
	if before, _, found := strings.Cut(s, "#"); found {
		return strings.TrimRight(before, " \t")
	}
	return s
}

func resolvePath(baseDir, path string) string {
	path = strings.Trim(strings.TrimSpace(path), `"'`)
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(baseDir, path)
}

// Sections groups the parsed options by the group that declared them,
// preserving the order in which each group was first seen.
//
// A group that was declared but set nothing is still reported, with an empty
// option list. Distributions ship such groups routinely (MariaDB's packaged
// [galera] and [mariadb] fragments have every line commented out), and a group
// present but empty is a different finding from a group that is absent.
func (c *Conf) Sections() []Section {
	options := map[string][]Option{}
	optionFiles := map[string][]string{}
	for _, opt := range c.Options {
		options[opt.Section] = append(options[opt.Section], opt)
		if !contains(optionFiles[opt.Section], opt.File) {
			optionFiles[opt.Section] = append(optionFiles[opt.Section], opt.File)
		}
	}

	out := make([]Section, 0, len(c.groups))
	for _, name := range c.groups {
		files := optionFiles[name]
		// A group with no options still came from somewhere.
		if len(files) == 0 {
			files = c.groupFiles[name]
		}
		out = append(out, Section{
			Name:    name,
			Options: options[name],
			Files:   files,
		})
	}
	return out
}

// SectionNames lists every group name seen while parsing, in read order,
// including groups that declared no options. Rebuilding this from Options
// alone would miss the empty groups, which is why the parser records header
// names as it goes.
func (c *Conf) SectionNames() []string {
	return c.groups
}

// Merge resolves the named groups into a single option map using MySQL's
// last-write-wins semantics, walking options in true read order. Options in
// cumulativeOptions accumulate into a comma-separated list instead.
//
// An option written bare, with no value at all, resolves to "ON". The server
// treats such an option as enabled, so "ON" is its effective value; carrying
// the empty string through instead would make every consumer of this map
// re-derive the distinction from Flags, and any that forgot would report an
// option that is in effect as disabled. Flags still reports which options
// were written that way.
//
// Group names match exactly or by version suffix, so passing "mysqld" also
// picks up "[mysqld-8.0]". See MatchesGroup.
func Merge(c *Conf, groups ...string) map[string]string {
	out := map[string]string{}
	for _, opt := range c.Options {
		if !matchesAny(opt.Section, groups) {
			continue
		}
		value := opt.Value
		if opt.Bare {
			value = "ON"
		}
		if cumulativeOptions[opt.Name] {
			if prev, ok := out[opt.Name]; ok && prev != "" && value != "" {
				out[opt.Name] = prev + "," + value
				continue
			}
		}
		out[opt.Name] = value
	}
	return out
}

// Flags lists the options in the named groups that were written bare, with no
// value at all. MySQL treats a bare option as enabled, so these are in effect
// while carrying an empty string in the map Merge returns.
func Flags(c *Conf, groups ...string) []string {
	var out []string
	for _, opt := range c.Options {
		if opt.Bare && matchesAny(opt.Section, groups) && !contains(out, opt.Name) {
			out = append(out, opt.Name)
		}
	}
	return out
}

// LooseOptions lists the options in the named groups written with the "loose"
// prefix, which the server ignores rather than rejecting when unrecognized.
func LooseOptions(c *Conf, groups ...string) []string {
	var out []string
	for _, opt := range c.Options {
		if opt.Loose && matchesAny(opt.Section, groups) && !contains(out, opt.Name) {
			out = append(out, opt.Name)
		}
	}
	return out
}

func matchesAny(sectionName string, groups []string) bool {
	for _, g := range groups {
		if MatchesGroup(sectionName, g) {
			return true
		}
	}
	return false
}

// MatchesGroup reports whether an option group named sectionName is read by a
// program that reads group. A group matches exactly, or when it is the same
// name with a version suffix: a server running 8.0 reads both [mysqld] and
// [mysqld-8.0].
//
// The version suffix must actually look like a version. Matching on the
// prefix alone would be wrong in both directions and in ways that change
// audit results: [mysqld_safe] and [mysqldump] would fold into server scope
// even though the server never reads them, and MariaDB's [mariadb-client],
// [mariadb-dump] and [mariadb-admin] groups would fold into [mariadb].
func MatchesGroup(sectionName, group string) bool {
	if sectionName == group {
		return true
	}
	rest, ok := strings.CutPrefix(sectionName, group+"-")
	if !ok || rest == "" {
		return false
	}
	// A version suffix is digits and dots, with at least one digit.
	digits := false
	for _, r := range rest {
		switch {
		case r >= '0' && r <= '9':
			digits = true
		case r == '.':
		default:
			return false
		}
	}
	return digits
}

// IsTruthy reports whether an option value means enabled. MySQL accepts ON,
// TRUE, YES and 1, and treats an option written with no value at all as
// enabled, which is what bare covers.
func IsTruthy(value string, bare bool) bool {
	if bare {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "yes", "1":
		return true
	}
	return false
}

// SplitPathList splits an option value holding a list of directories, which
// MySQL and MariaDB separate differently from their comma lists: with ":" on
// Unix and ";" on Windows. tmpdir is the option that uses this form.
//
// A Windows drive letter carries its own colon ("C:\\tmp"), so a colon in the
// second character position followed by a path separator is part of the path,
// not a delimiter.
func SplitPathList(value string) []string {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}

	// A semicolon anywhere means the value uses the Windows separator, where a
	// bare colon is always part of a drive letter.
	if strings.ContainsRune(v, ';') {
		return cleanPathElems(strings.Split(v, ";"))
	}

	var elems []string
	start := 0
	for i := 0; i < len(v); i++ {
		if v[i] != ':' {
			continue
		}
		if isDriveColon(v, i) {
			continue
		}
		elems = append(elems, v[start:i])
		start = i + 1
	}
	elems = append(elems, v[start:])
	return cleanPathElems(elems)
}

// isDriveColon reports whether the colon at i separates a Windows drive letter
// from its path, as in "C:\\tmp", rather than delimiting two directories.
func isDriveColon(v string, i int) bool {
	if i != 1 {
		return false
	}
	c := v[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	return i+1 < len(v) && (v[i+1] == '\\' || v[i+1] == '/')
}

func cleanPathElems(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.Trim(strings.TrimSpace(e), `"'`)
		if e != "" {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SplitList splits an option value holding a comma- or space-separated list
// (tls_version, sql_mode, ...). Elements are trimmed of whitespace and
// surrounding quotes; empty elements are dropped.
//
// Path lists are not this shape: use SplitPathList for those.
func SplitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(strings.TrimSpace(f), `"'`)
		if f != "" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func contains(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}
