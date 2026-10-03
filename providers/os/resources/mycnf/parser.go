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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Option is a single option assignment from an option file, recorded with the
// file and line it came from so callers can report provenance.
type Option struct {
	// Section is the name of the group the option was declared under,
	// lowercased (for example "mysqld" or "mariadb-11.4"). See
	// parseGroupHeader.
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
	// Name is the group name without the surrounding brackets, lowercased.
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
	// errs holds the include files and directories that exist but could not
	// be read. See Parse.
	errs []error
}

// FileReader returns the textual content of path. An error wrapping
// fs.ErrNotExist marks a dangling include, which is skipped. Any other error
// means the file is there but could not be read, and Parse reports it.
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

// RedactedValue stands in for the value of an option that holds a credential.
// See IsSecretOption.
const RedactedValue = "<redacted>"

// secretOptions lists the options whose value is a credential, after
// NormalizeName. password1 through password3 (the multifactor client
// passwords) are matched by IsSecretOption rather than listed.
//
// The password policy options (password_history, validate_password.length,
// default_password_lifetime, ...) are deliberately not here: they are
// settings an audit reads, not secrets.
var secretOptions = map[string]bool{
	// The client password, read from [client], [mysql] and the other
	// client groups, most often in a per-user ~/.my.cnf.
	"password": true,
	// Replication credentials, accepted in option files by old servers.
	"master_password": true,
	// Galera state snapshot transfer credentials, written as user:password.
	"wsrep_sst_auth": true,
	// Bind passwords of MySQL Enterprise's LDAP authentication plugins.
	"authentication_ldap_sasl_bind_root_pwd":   true,
	"authentication_ldap_simple_bind_root_pwd": true,
	// Vault token of MariaDB's HashiCorp key management plugin.
	"hashicorp_key_management_token": true,
}

// IsSecretOption reports whether an option's value is a credential. Parse
// replaces such a value with RedactedValue, so a credential written into an
// option file never reaches a caller: the option is still reported, which is
// the finding (a password stored in a file), but not what it is set to.
func IsSecretOption(name string) bool {
	if secretOptions[name] {
		return true
	}
	rest, ok := strings.CutPrefix(name, "password")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Parse reads the option file at path and follows every !include and
// !includedir directive it encounters, returning the options in read order.
//
// An include that does not exist is skipped: a dangling !include is a normal
// state on a host where an optional package was removed. An include that
// exists but cannot be read is different. The server reads it, so the options
// it holds are in effect, and leaving it out would report the remaining files
// as if they were the whole configuration. Parse still reads everything else,
// so the returned Conf is usable for product detection, but the error names
// every file it could not read. An unreadable root file is an error as well.
func Parse(path string, reader FileReader, dirLister DirLister) (*Conf, error) {
	c := &Conf{}
	visited := map[string]bool{}
	if err := c.parseFile(path, reader, dirLister, visited, true); err != nil {
		return c, err
	}
	return c, errors.Join(c.errs...)
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
		if !errors.Is(err, fs.ErrNotExist) {
			c.errs = append(c.errs, fmt.Errorf("cannot read included option file %s: %w", path, err))
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
				if name == "" {
					// "[ ]" opens a group no program reads. The options
					// under it are dropped like those before any header.
					continue
				}
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
		if opt.Value != "" && IsSecretOption(opt.Name) {
			opt.Value = RedactedValue
		}
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
			if !errors.Is(err, fs.ErrNotExist) {
				c.errs = append(c.errs, fmt.Errorf("cannot list included option directory %s: %w", dir, err))
			}
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

// isIncludableFile reports whether !includedir should read the entry. Both
// servers read only files ending in ".cnf" on Unix, plus ".ini" on Windows,
// so an ".ini" file in a Unix fragment directory is not part of the
// configuration however much it looks like one. Other suffixes are skipped
// too, which matters because distributions park templates next to live
// fragments (MariaDB ships an "enable_encryption.preset" and a
// "99-enable-encryption.cnf.preset" directory inside its fragment directory).
//
// On Unix the extension is compared exactly, as the server compares it with
// strcmp, so a fragment named "zz.CNF" is not read. Only Windows paths, whose
// file system ignores case, are compared case-insensitively.
func isIncludableFile(path string) bool {
	if !isWindowsPath(path) {
		return filepath.Ext(path) == ".cnf"
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".cnf" || ext == ".ini"
}

// isWindowsPath reports whether path is written the Windows way, with a drive
// letter or a backslash separator. The parser does not know which platform
// the target runs, but the paths it is handed are the target's own.
func isWindowsPath(path string) bool {
	if strings.Contains(path, `\`) {
		return true
	}
	return len(path) >= 2 && path[1] == ':' &&
		((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z'))
}

// parseGroupHeader extracts the group name from a "[name]" line, tolerating a
// trailing comment after the brackets. It reports an empty name for "[ ]".
//
// The name is lowercased because the servers look groups up with find_type,
// which ignores case: a fragment headed [MYSQLD] configures the server like
// one headed [mysqld]. Only trailing whitespace inside the brackets is
// dropped, as my_default.c does, so [ mysqld ] names a group " mysqld" that
// no program reads.
func parseGroupHeader(line string) (string, bool) {
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return "", false
	}
	name := strings.TrimRight(line[1:end], " \t\v\f\r")
	return strings.ToLower(name), true
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
		if target, value, ok := resolveBooleanPrefix(normalized, "", false); ok {
			return Option{Name: target, Value: value, Loose: loose}, true
		}
		return Option{Name: normalized, Bare: true, Loose: loose}, true
	}

	normalized, loose := NormalizeName(rawName)
	if normalized == "" {
		return Option{}, false
	}
	value := unquoteValue(strings.TrimSpace(rawValue))
	if target, resolved, ok := resolveBooleanPrefix(normalized, value, true); ok {
		return Option{Name: target, Value: resolved, Loose: loose}, true
	}
	return Option{
		Name:  normalized,
		Value: value,
		Loose: loose,
	}, true
}

// booleanOptions lists the boolean server options that the enable, disable
// and skip prefixes are resolved for. The server applies those prefixes to
// any boolean option it knows; this parser has no copy of the server's option
// registry, so it resolves them only for the options the mysql.conf and
// mariadb.conf resources report. Other prefixed names are kept as written.
// A new boolean field on either resource needs its option added here.
var booleanOptions = map[string]bool{
	"allow_suspicious_udfs":             true,
	"automatic_sp_privileges":           true,
	"binlog_encryption":                 true,
	"default_table_encryption":          true,
	"encrypt_binlog":                    true,
	"encrypt_tmp_disk_tables":           true,
	"general_log":                       true,
	"gtid_strict_mode":                  true,
	"innodb_encrypt_log":                true,
	"innodb_redo_log_encrypt":           true,
	"innodb_undo_log_encrypt":           true,
	"local_infile":                      true,
	"log_bin_trust_function_creators":   true,
	"password_require_current":          true,
	"read_only":                         true,
	"require_secure_transport":          true,
	"server_audit_logging":              true,
	"skip_grant_tables":                 true,
	"skip_name_resolve":                 true,
	"skip_networking":                   true,
	"skip_show_database":                true,
	"slow_query_log":                    true,
	"super_read_only":                   true,
	"symbolic_links":                    true,
	"table_encryption_privilege_check":  true,
	"validate_password.check_user_name": true,
	"wsrep_on":                          true,
}

// resolveBooleanPrefix rewrites `enable-X`, `disable-X` and `skip-X` into an
// assignment on X when X is a known boolean option, following the server's
// option parser: `enable-X` turns X on unless its value is exactly "0", and
// `disable-X` and `skip-X` turn it off unless their value is exactly "0". Any
// other value is ignored, so `enable-general-log=OFF` still enables the general
// log, which is what the server does with it.
//
// A name that is itself an option keeps its meaning: `skip_name_resolve` is
// not a prefix on some "name_resolve" option, so it is never rewritten, while
// `disable-skip-name-resolve` turns skip_name_resolve off.
func resolveBooleanPrefix(name, value string, hasValue bool) (string, string, bool) {
	for _, prefix := range []string{"enable_", "disable_", "skip_"} {
		target, ok := strings.CutPrefix(name, prefix)
		if !ok || !booleanOptions[target] {
			continue
		}
		on := prefix == "enable_"
		if hasValue && value == "0" {
			on = !on
		}
		if on {
			return target, "ON", true
		}
		return target, "OFF", true
	}
	return "", "", false
}

// NormalizeName canonicalizes an option name and reports whether it carried
// the "loose" prefix. MySQL treats "-" and "_" as interchangeable in option
// names, so `bind-address` and `bind_address` are one option and have to
// collapse to a single map key. Any leading "--" is tolerated even though
// option files don't use it.
//
// The "skip", "disable" and "enable" prefixes are left alone here:
// `skip_name_resolve` and `skip_networking` are documented options in their
// own right, so rewriting every such name into an assignment on some shorter
// name would invent options that do not exist. parseOption resolves the
// prefixes for the boolean options it knows, see resolveBooleanPrefix.
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
// cumulativeOptions accumulate into a ";"-separated list instead, the
// separator the plugin load options use (see SplitPluginList).
//
// An option written bare, with no value at all, resolves to "ON". The server
// treats such an option as enabled, so "ON" is its effective value; carrying
// the empty string through instead would make every consumer of this map
// re-derive the distinction from Flags, and any that forgot would report an
// option that is in effect as disabled. Flags still reports which options
// were written that way.
//
// Group names match exactly, and the parser has already lowercased them. A
// version-suffixed group such as [mysqld-8.0] is read only by a server of
// that version, so a caller that wants it names it;
// ServerGroups does that for the server version it is given.
func Merge(c *Conf, groups ...string) map[string]string {
	out := map[string]string{}
	for _, opt := range c.Options {
		if !slices.Contains(groups, opt.Section) {
			continue
		}
		value := opt.Value
		if opt.Bare {
			value = "ON"
		}
		if cumulativeOptions[opt.Name] {
			if prev, ok := out[opt.Name]; ok && prev != "" && value != "" {
				out[opt.Name] = prev + ";" + value
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
		if opt.Bare && slices.Contains(groups, opt.Section) && !contains(out, opt.Name) {
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
		if opt.Loose && slices.Contains(groups, opt.Section) && !contains(out, opt.Name) {
			out = append(out, opt.Name)
		}
	}
	return out
}

// MatchesGroup reports whether an option group named sectionName is group
// itself or group with a version suffix, as in [mysqld] and [mysqld-8.0]. It
// identifies the product a group belongs to; it does not say whether a given
// server reads the group, because a server reads only the suffix for its own
// version (ServerGroups).
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

// SplitPluginList splits the value of plugin_load, plugin_load_add or
// early_plugin_load into its entries ("name=library" or "library"). The server
// splits these on ";" and, on Unix, on ":" as well (plugin_load_list in
// sql_plugin.cc); a Windows path keeps its drive-letter colon. A comma is not
// a separator.
func SplitPluginList(value string) []string {
	v := strings.Trim(strings.TrimSpace(value), `"'`)
	if v == "" {
		return nil
	}
	// The server picks its separators by platform, never per entry, so a
	// Windows path anywhere in the value means no entry is split on ":".
	windows := isWindowsPath(v)
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == ';' || (r == ':' && !windows)
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
