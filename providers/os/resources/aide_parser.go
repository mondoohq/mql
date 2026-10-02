// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// aide selection rule kinds, named after what the line does to coverage rather
// than after the punctuation that introduces it.
const (
	aideSelectionRecursive = "recursive"
	aideSelectionEquals    = "equals"
	aideSelectionNegative  = "negative"
	// a "-" rule (AIDE 0.19+) excludes the path without descending into it
	aideSelectionNonRecursiveNegative = "nonRecursiveNegative"
)

// aideMaxGroupDepth bounds group resolution so a configuration defining a group
// in terms of itself cannot spin.
const aideMaxGroupDepth = 16

// aideMaxIncludeDepth bounds include recursion so a configuration including
// itself cannot spin.
const aideMaxIncludeDepth = 8

// aideSelectionRule is one selection line from an AIDE configuration.
type aideSelectionRule struct {
	Path        string
	Selection   string
	Restriction string
	Expression  string
	Attributes  []string
	LineNumber  int
	File        string
}

// aideHost answers the questions an @@if expression asks about the system.
// A nil Exists, or an empty Hostname, means the answer is not known.
type aideHost struct {
	// Hostname is the short host name AIDE compares against (without the
	// domain), or "" when unknown.
	Hostname string
	// Exists reports whether a path exists, and whether that could be found out.
	Exists func(path string) (exists bool, known bool)
}

// aideConfig accumulates the state of an AIDE configuration as it is parsed.
// Includes are parsed into the same value, because a macro or group defined in
// one file is visible to every file parsed after it.
type aideConfig struct {
	Macros map[string]string
	Groups map[string]string
	Params map[string]string
	Rules  []aideSelectionRule
	// Builtins are the compound groups the installed AIDE defines itself
	// (R, L, >, H, X, E), or nil when its release is unknown.
	Builtins map[string]string
	// Version is the installed AIDE release, such as "0.19.1", or "" when it is
	// not known.
	Version string
	// Host evaluates the host-dependent @@if predicates.
	Host aideHost
	// XEnv holds the @@x_include_setenv variables, in the order they were set,
	// for the scripts an @@x_include runs.
	XEnv []aideEnvVar
}

// aideEnvVar is one variable set by @@x_include_setenv.
type aideEnvVar struct {
	Name  string
	Value string
}

// aideConfigOptions are the settings AIDE recognizes as configuration rather
// than as attribute group definitions. A `key = value` line whose key is absent
// here is treated as a group definition, which is how AIDE itself distinguishes
// the two.
var aideConfigOptions = map[string]struct{}{
	"acl_no_symlink_follow":                {},
	"config_check_warn_unrestricted_rules": {},
	"config_version":                       {},
	"database":                             {},
	"database_add_metadata":                {},
	"database_attrs":                       {},
	"database_gzip":                        {},
	"database_in":                          {},
	"database_new":                         {},
	"database_out":                         {},
	"grouped":                              {},
	"gzip_dbout":                           {},
	"ignore_list":                          {},
	"log_level":                            {},
	"num_workers":                          {},
	"report_append":                        {},
	"report_base16":                        {},
	"report_attributes":                    {},
	"report_detailed_init":                 {},
	"report_force_attrs":                   {},
	"report_format":                        {},
	"report_grouped":                       {},
	"report_ignore_added_attrs":            {},
	"report_ignore_changed_attrs":          {},
	"report_ignore_e2fsattrs":              {},
	"report_ignore_removed_attrs":          {},
	"report_level":                         {},
	"report_quiet":                         {},
	"report_summarize_changes":             {},
	"report_url":                           {},
	"root_prefix":                          {},
	"summarize_changes":                    {},
	"syslog_format":                        {},
	"verbose":                              {},
	"warn_dead_symlinks":                   {},
	"warn_unrestricted_rules":              {},
}

var (
	aideMacroRefRegex = regexp.MustCompile(`@@\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	aideDirectiveArgs = regexp.MustCompile(`\s+`)
)

func newAideConfig() *aideConfig {
	return &aideConfig{
		Macros: map[string]string{},
		Groups: map[string]string{},
		Params: map[string]string{},
		Rules:  []aideSelectionRule{},
	}
}

// defineBuiltinMacros defines the macros AIDE itself provides before it reads
// the configuration: HOSTNAME (the host name without its domain) and, from
// 0.19 on, AIDE_VERSION. Version and Host must be set first.
func (cfg *aideConfig) defineBuiltinMacros() {
	if cfg.Host.Hostname != "" {
		cfg.Macros["HOSTNAME"] = cfg.Host.Hostname
	}
	if cfg.Version != "" && aideVersionAtLeast(cfg.Version, 0, 19) {
		cfg.Macros["AIDE_VERSION"] = cfg.Version
	}
}

// unescapesRules reports whether the AIDE release reads backslash escapes in
// rule lines ('\\', '\ ', '\@'), which 0.17 and later do. An unknown release is
// treated as a current one.
func (cfg *aideConfig) unescapesRules() bool {
	if cfg.Version == "" {
		return true
	}
	if _, _, ok := aideReleaseNumbers(cfg.Version); !ok {
		return true
	}
	return aideVersionAtLeast(cfg.Version, 0, 17)
}

// aideIncludeFile is one file an include target expanded to.
type aideIncludeFile struct {
	Path    string
	Content string
}

// aideInclude is one @@include or @@x_include directive.
type aideInclude struct {
	// Target is the file or directory named by the directive.
	Target string
	// Regex, for a directory, selects the file names to read (AIDE 0.17+).
	// Empty means every file.
	Regex string
	// Execute is set for @@x_include: an executable file is run and its output
	// read as configuration, rather than reading the file itself.
	Execute bool
	// Env is the environment @@x_include_setenv set up for the scripts.
	Env []aideEnvVar
}

// aideIncludeResolver reads an include target, returning the files it expands to
// in the order AIDE would read them. A target naming a directory expands to its
// entries; one naming a file expands to just that file.
type aideIncludeResolver func(include aideInclude) []aideIncludeFile

// aideBranch is the state of one conditional block.
type aideBranch int8

const (
	// aideBranchSkip: the condition is false, the lines are not read
	aideBranchSkip aideBranch = iota
	// aideBranchKeep: the condition is true, the lines are read
	aideBranchKeep
	// aideBranchUnknown: the condition cannot be evaluated here. Both the
	// branch and its @@else are read, on the basis that reporting a rule that
	// may not apply is safer than hiding one that does.
	aideBranchUnknown
)

func (b aideBranch) not() aideBranch {
	switch b {
	case aideBranchKeep:
		return aideBranchSkip
	case aideBranchSkip:
		return aideBranchKeep
	}
	return aideBranchUnknown
}

func aideBranchOf(value bool) aideBranch {
	if value {
		return aideBranchKeep
	}
	return aideBranchSkip
}

// parseAideConfig folds one configuration file into cfg, following @@include
// directives through resolve at the point they appear. Reading files stays with
// the caller through resolve, which keeps the parser pure and lets a test drive
// the include graph without a filesystem.
//
// The recursion is positional rather than batched at the end of the file,
// because a macro or group is only visible to the lines parsed after it, so
// where an include sits changes what it sees.
//
// @@if, @@ifdef, @@ifndef, @@ifhost, @@ifnhost, @@else and @@endif are
// evaluated against the macros defined so far and cfg.Host. A condition that
// cannot be evaluated (an unknown host name, a path whose existence cannot be
// checked, an unrecognized predicate) reads both of its branches.
func parseAideConfig(cfg *aideConfig, filePath string, content string, depth int, resolve aideIncludeResolver) {
	parseAideConfigPrefixed(cfg, filePath, content, depth, "", resolve)
}

// parseAideConfigPrefixed is parseAideConfig with the RULE_PREFIX (AIDE 0.18+)
// of the include statements the file was reached through.
func parseAideConfigPrefixed(cfg *aideConfig, filePath string, content string, depth int, prefix string, resolve aideIncludeResolver) {
	branches := []aideBranch{}

	for i, rawLine := range strings.Split(content, "\n") {
		lineNumber := i + 1

		line := strings.TrimSpace(stripAideComment(rawLine))
		if line == "" {
			continue
		}

		// "@@{NAME}" opens a macro reference, not a directive, and a selection
		// line commonly starts with one
		if strings.HasPrefix(line, "@@") && !strings.HasPrefix(line, "@@{") {
			include, ok := parseAideDirective(cfg, line, &branches)
			if !ok || resolve == nil || depth >= aideMaxIncludeDepth {
				continue
			}
			for _, included := range resolve(include.aideInclude) {
				parseAideConfigPrefixed(cfg, included.Path, included.Content, depth+1, prefix+include.prefix, resolve)
			}
			continue
		}

		if !aideBranchActive(branches) {
			continue
		}

		line = expandAideMacros(cfg, line)

		if rule, ok := parseAideSelectionLine(cfg, line, prefix, filePath, lineNumber); ok {
			cfg.Rules = append(cfg.Rules, rule)
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}

		if _, isOption := aideConfigOptions[strings.ToLower(key)]; isOption {
			cfg.Params[strings.ToLower(key)] = value
			continue
		}
		cfg.Groups[key] = value
	}
}

// aideIncludeDirective is an include the parser asks the resolver for, with
// the RULE_PREFIX it applies to the included rules.
type aideIncludeDirective struct {
	aideInclude
	prefix string
}

// parseAideDirective handles an @@ line, returning the include to read when the
// directive names one in an active branch.
func parseAideDirective(cfg *aideConfig, line string, branches *[]aideBranch) (aideIncludeDirective, bool) {
	fields := aideDirectiveArgs.Split(line, 2)
	directive := strings.ToLower(fields[0])
	args := ""
	if len(fields) > 1 {
		args = strings.TrimSpace(fields[1])
	}

	// inside a branch that is not read, only the nesting of conditionals
	// matters; a nested condition is not evaluated, since a macro it names
	// may not be defined the way the skipped lines would have left it
	if !aideBranchActive(*branches) {
		switch directive {
		case "@@if", "@@ifdef", "@@ifndef", "@@ifhost", "@@ifnhost":
			*branches = append(*branches, aideBranchSkip)
		case "@@else":
			aideFlipBranch(*branches)
		case "@@endif":
			aidePopBranch(branches)
		}
		return aideIncludeDirective{}, false
	}

	arg, rest := args, ""
	if parts := aideDirectiveArgs.Split(args, 2); len(parts) == 2 {
		arg, rest = parts[0], strings.TrimSpace(parts[1])
	}

	switch directive {
	case "@@define":
		if arg != "" {
			cfg.Macros[arg] = expandAideMacros(cfg, rest)
		}

	case "@@undef":
		delete(cfg.Macros, arg)

	case "@@x_include_setenv":
		if arg != "" {
			cfg.XEnv = append(cfg.XEnv, aideEnvVar{Name: arg, Value: expandAideMacros(cfg, rest)})
		}

	case "@@include", "@@x_include":
		// @@include FILE, or @@include DIRECTORY REGEX [RULE_PREFIX]; the path
		// and the rest may be built from macros
		parts := strings.Fields(expandAideMacros(cfg, args))
		if len(parts) == 0 {
			return aideIncludeDirective{}, false
		}
		include := aideIncludeDirective{aideInclude: aideInclude{
			Target:  parts[0],
			Execute: directive == "@@x_include",
		}}
		if len(parts) > 1 {
			include.Regex = parts[1]
		}
		if len(parts) > 2 {
			include.prefix = parts[2]
		}
		if include.Execute {
			include.Env = append([]aideEnvVar{}, cfg.XEnv...)
		}
		return include, true

	case "@@if":
		*branches = append(*branches, evalAideCondition(cfg, args))

	case "@@ifdef":
		*branches = append(*branches, evalAideCondition(cfg, "defined "+arg))

	case "@@ifndef":
		*branches = append(*branches, evalAideCondition(cfg, "not defined "+arg))

	case "@@ifhost":
		*branches = append(*branches, evalAideCondition(cfg, "hostname "+arg))

	case "@@ifnhost":
		*branches = append(*branches, evalAideCondition(cfg, "not hostname "+arg))

	case "@@else":
		aideFlipBranch(*branches)

	case "@@endif":
		aidePopBranch(branches)
	}

	return aideIncludeDirective{}, false
}

func aideFlipBranch(branches []aideBranch) {
	if len(branches) > 0 {
		branches[len(branches)-1] = branches[len(branches)-1].not()
	}
}

func aidePopBranch(branches *[]aideBranch) {
	if len(*branches) > 0 {
		*branches = (*branches)[:len(*branches)-1]
	}
}

// evalAideCondition evaluates the boolean expression of an @@if line:
//
//	not EXPR
//	defined VARIABLE
//	hostname HOSTNAME
//	exists PATH
//	VERSION1 version_ge VERSION2 (AIDE 0.19+)
//
// An expression it cannot decide, including one it does not recognize, is
// unknown, and both of its branches are read.
func evalAideCondition(cfg *aideConfig, expression string) aideBranch {
	fields := strings.Fields(expression)
	if len(fields) == 0 {
		return aideBranchUnknown
	}

	if fields[0] == "not" {
		return evalAideCondition(cfg, strings.Join(fields[1:], " ")).not()
	}

	if len(fields) == 3 && fields[1] == "version_ge" {
		left := expandAideMacros(cfg, fields[0])
		right := expandAideMacros(cfg, fields[2])
		cmp, ok := compareAideVersions(left, right)
		if !ok {
			return aideBranchUnknown
		}
		return aideBranchOf(cmp >= 0)
	}

	if len(fields) != 2 {
		return aideBranchUnknown
	}
	arg := expandAideMacros(cfg, fields[1])

	switch fields[0] {
	case "defined":
		if _, ok := cfg.Macros[arg]; ok {
			return aideBranchKeep
		}
		// AIDE defines these itself; when the value was not learned here the
		// macro is still defined for AIDE
		if arg == "HOSTNAME" && cfg.Host.Hostname == "" {
			return aideBranchUnknown
		}
		if arg == "AIDE_VERSION" && cfg.Version == "" {
			return aideBranchUnknown
		}
		return aideBranchSkip

	case "hostname":
		if cfg.Host.Hostname == "" {
			return aideBranchUnknown
		}
		return aideBranchOf(arg == cfg.Host.Hostname)

	case "exists":
		if cfg.Host.Exists == nil {
			return aideBranchUnknown
		}
		exists, known := cfg.Host.Exists(arg)
		if !known {
			return aideBranchUnknown
		}
		return aideBranchOf(exists)
	}

	return aideBranchUnknown
}

// compareAideVersions compares two MAJOR[.MINOR[.PATCH]] versions the way
// AIDE's version_ge does, ignoring a suffix such as "-rc1". It reports false
// when either is not a version.
func compareAideVersions(a, b string) (int, bool) {
	av, ok := aideVersionParts(a)
	if !ok {
		return 0, false
	}
	bv, ok := aideVersionParts(b)
	if !ok {
		return 0, false
	}
	for i := range av {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func aideVersionParts(version string) ([3]int, bool) {
	res := [3]int{}
	version = strings.TrimSpace(version)
	if version == "" {
		return res, false
	}
	for i, part := range strings.SplitN(version, ".", 3) {
		digits := part
		if idx := strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }); idx >= 0 {
			digits = part[:idx]
		}
		if digits == "" {
			if i == 0 {
				return res, false
			}
			break
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return res, false
		}
		res[i] = n
		if len(digits) != len(part) {
			// a suffix ends the version
			break
		}
	}
	return res, true
}

// aideVersionAtLeast reports whether version is major.minor or later.
func aideVersionAtLeast(version string, major, minor int) bool {
	cmp, ok := compareAideVersions(version, strconv.Itoa(major)+"."+strconv.Itoa(minor))
	return ok && cmp >= 0
}

// aideBranchActive reports whether the lines at this point are read: every
// enclosing conditional is true or cannot be decided.
func aideBranchActive(branches []aideBranch) bool {
	for _, branch := range branches {
		if branch == aideBranchSkip {
			return false
		}
	}
	return true
}

// stripAideComment drops a trailing comment. A '#' inside a macro reference or a
// path is not a comment introducer in practice, but AIDE treats any unescaped
// '#' as one, so this follows AIDE.
func stripAideComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] != '#' {
			continue
		}
		if i > 0 && line[i-1] == '\\' {
			continue
		}
		return line[:i]
	}
	return line
}

// expandAideMacros substitutes @@{NAME} references with the macro's value. An
// undefined reference expands to nothing, as it does for AIDE: Debian's
// `/@@{BINDCHROOT}run/named$` is the rule `/run/named$` on a host without a
// bind chroot.
func expandAideMacros(cfg *aideConfig, line string) string {
	if !strings.Contains(line, "@@{") {
		return line
	}

	return aideMacroRefRegex.ReplaceAllStringFunc(line, func(match string) string {
		name := aideMacroRefRegex.FindStringSubmatch(match)[1]
		return cfg.Macros[name]
	})
}

// splitAideFields splits a line on whitespace that is not escaped with a
// backslash, keeping the escapes in the fields.
func splitAideFields(line string) []string {
	res := []string{}
	current := strings.Builder{}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) {
			current.WriteByte(c)
			current.WriteByte(line[i+1])
			i++
			continue
		}
		if c == ' ' || c == '\t' {
			if current.Len() > 0 {
				res = append(res, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteByte(c)
	}
	if current.Len() > 0 {
		res = append(res, current.String())
	}
	return res
}

// unescapeAide removes the escapes AIDE 0.17+ reads in a configuration line:
// '\\' for a backslash, '\ ' for a space and '\@' for an at sign. Any other
// backslash is kept, since it belongs to the regular expression.
func unescapeAide(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	res := strings.Builder{}
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\', ' ', '@':
				res.WriteByte(s[i+1])
				i++
				continue
			}
		}
		res.WriteByte(s[i])
	}
	return res.String()
}

// parseAideSelectionLine parses a selection line, reporting false when the line
// is not one.
//
// A rule is `PATH [RESTRICTION] EXPRESSION`; a negative rule is
// `!PATH [RESTRICTION]` or, from AIDE 0.19, `-PATH [RESTRICTION]`. The
// restriction limits the rule to file types (f, d, l, c, b, p, s, D, P, comma
// separated) and, from 0.19, a file system (`=tmpfs`, `d=vfat`). `0` stands
// for no restriction (0.18+) and is reported as empty.
func parseAideSelectionLine(cfg *aideConfig, line string, prefix string, filePath string, lineNumber int) (aideSelectionRule, bool) {
	selection := aideSelectionRecursive

	switch {
	case strings.HasPrefix(line, "!"):
		selection = aideSelectionNegative
		line = strings.TrimSpace(line[1:])
	case strings.HasPrefix(line, "-"):
		selection = aideSelectionNonRecursiveNegative
		line = strings.TrimSpace(line[1:])
	case strings.HasPrefix(line, "="):
		selection = aideSelectionEquals
		line = strings.TrimSpace(line[1:])
	}

	line = prefix + line

	// a selection line always names an absolute path
	if !strings.HasPrefix(line, "/") {
		return aideSelectionRule{}, false
	}

	fields := splitAideFields(line)
	path := fields[0]
	if cfg.unescapesRules() {
		path = unescapeAide(path)
	}

	restriction := ""
	expression := ""
	switch selection {
	case aideSelectionNegative, aideSelectionNonRecursiveNegative:
		// a negative rule takes no attributes, only a restriction
		restriction = strings.Join(fields[1:], " ")
	default:
		switch len(fields) {
		case 1:
		case 2:
			expression = fields[1]
		default:
			restriction = fields[1]
			expression = strings.Join(fields[2:], " ")
		}
	}
	if restriction == "0" {
		restriction = ""
	}

	return aideSelectionRule{
		Path:        path,
		Selection:   selection,
		Restriction: restriction,
		Expression:  expression,
		Attributes:  resolveAideAttributes(cfg, expression),
		LineNumber:  lineNumber,
		File:        filePath,
	}, true
}

// aideIncludeEntries returns the names in a directory an include reads: those
// matching the include's regular expression (all of them when there is none),
// in lexical order. AIDE reads nothing from a directory whose expression does
// not compile.
func aideIncludeEntries(names []string, expression string) []string {
	var re *regexp.Regexp
	if expression != "" {
		var err error
		if re, err = regexp.Compile(expression); err != nil {
			return []string{}
		}
	}

	res := []string{}
	for _, name := range names {
		if re == nil || re.MatchString(name) {
			res = append(res, name)
		}
	}
	sort.Strings(res)
	return res
}

// aideConfigHasInclude reports whether a configuration includes other files.
func aideConfigHasInclude(content string) bool {
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.ToLower(strings.TrimSpace(rawLine))
		if strings.HasPrefix(line, "@@include") || strings.HasPrefix(line, "@@x_include ") || strings.HasPrefix(line, "@@x_include\t") {
			return true
		}
	}
	return false
}

// aideBuiltinGroupNames are the compound groups AIDE defines itself. Their
// members depend on the release and on what the binary was compiled with.
var aideBuiltinGroupNames = map[string]struct{}{
	"R": {}, "L": {}, ">": {}, "H": {}, "X": {}, "E": {},
}

// resolveAideAttributes expands an attribute expression into the attributes it
// stands for. Group names defined in the configuration are substituted
// recursively, then the compound groups AIDE defines itself (cfg.Builtins). A
// '-' term removes what it names from the result. When a built-in group cannot
// be expanded because the AIDE release is unknown, it is kept as written and a
// removal that may apply to it is kept as "-name", so `R+sha512-m-c` reads
// [-c, -m, R, sha512] rather than losing the removals.
func resolveAideAttributes(cfg *aideConfig, expression string) []string {
	if strings.TrimSpace(expression) == "" {
		return []string{}
	}

	included := map[string]struct{}{}
	excluded := map[string]struct{}{}

	unexpanded := collectAideAttributes(cfg, expression, false, 0, included, excluded)

	res := []string{}
	for token := range excluded {
		if _, ok := included[token]; ok {
			delete(included, token)
			continue
		}
		if unexpanded {
			res = append(res, "-"+token)
		}
	}

	for token := range included {
		res = append(res, token)
	}
	sort.Strings(res)
	return res
}

// collectAideAttributes adds the terms of expression to included or excluded.
// It reports whether a built-in group was left unexpanded.
func collectAideAttributes(cfg *aideConfig, expression string, negated bool, depth int, included, excluded map[string]struct{}) bool {
	if depth > aideMaxGroupDepth {
		return false
	}

	unexpanded := false
	for _, token := range splitAideExpression(expression) {
		remove := negated != token.remove

		definition, ok := cfg.Groups[token.name]
		if !ok {
			definition, ok = cfg.Builtins[token.name]
		}
		if ok {
			if collectAideAttributes(cfg, definition, remove, depth+1, included, excluded) {
				unexpanded = true
			}
			continue
		}
		if _, builtin := aideBuiltinGroupNames[token.name]; builtin && !remove {
			unexpanded = true
		}

		if remove {
			excluded[token.name] = struct{}{}
			continue
		}
		included[token.name] = struct{}{}
	}
	return unexpanded
}

// aideBuiltinGroups returns the compound groups the installed AIDE defines,
// read from its `aide --version` output, or nil when the output does not tell.
//
// AIDE 0.17 and later list them under "Default compound groups:" (E, the empty
// group, is not listed). 0.15 and 0.16 do not, and define them in code: R, L
// and > from the base attributes plus acl, selinux, xattrs and e2fsattrs for
// the features the binary was compiled with (its WITH_* options), R adding md5
// when built with a hash library. 0.16 also names that feature set X.
func aideBuiltinGroups(versionOutput string) map[string]string {
	if groups := parseAideDefaultGroups(versionOutput); groups != nil {
		groups["E"] = ""
		return groups
	}

	major, minor, ok := aideReleaseNumbers(parseAideVersion(versionOutput))
	if !ok || major != 0 || minor < 15 || minor > 16 {
		return nil
	}

	options := map[string]bool{}
	for _, line := range strings.Split(versionOutput, "\n") {
		if option := strings.TrimSpace(line); strings.HasPrefix(option, "WITH_") {
			options[option] = true
		}
	}

	extra := []string{}
	if options["WITH_POSIX_ACL"] || options["WITH_ACL"] {
		extra = append(extra, "acl")
	}
	if options["WITH_SELINUX"] {
		extra = append(extra, "selinux")
	}
	if options["WITH_XATTR"] {
		extra = append(extra, "xattrs")
	}
	if options["WITH_E2FSATTRS"] {
		extra = append(extra, "e2fsattrs")
	}
	hashes := []string{}
	if options["WITH_MHASH"] || options["WITH_GCRYPT"] {
		hashes = append(hashes, "md5")
	}

	join := func(parts ...[]string) string {
		all := []string{}
		for _, p := range parts {
			all = append(all, p...)
		}
		return strings.Join(all, "+")
	}
	groups := map[string]string{
		"R": join([]string{"p", "ftype", "i", "n", "u", "g", "s", "l", "m", "c"}, hashes, extra),
		"L": join([]string{"p", "ftype", "i", "n", "u", "g", "l"}, extra),
		">": join([]string{"p", "ftype", "i", "n", "u", "g", "S", "l"}, extra),
		"E": "",
	}
	if minor == 16 {
		groups["X"] = join(extra)
	}
	return groups
}

// parseAideDefaultGroups reads the "Default compound groups:" section of
// `aide --version` output, lines like "R: l+p+u+g+s+c+m+i+n+sha3_256".
func parseAideDefaultGroups(out string) map[string]string {
	var groups map[string]string
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if groups == nil {
			if line == "Default compound groups:" {
				groups = map[string]string{}
			}
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found || strings.ContainsAny(name, " \t") || name == "" {
			break
		}
		groups[name] = strings.TrimSpace(value)
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}

// aideReleaseNumbers splits a release such as "0.16" or "0.15.1" into its
// major and minor numbers.
func aideReleaseNumbers(version string) (int, int, bool) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(strings.TrimRightFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

type aideExpressionToken struct {
	name   string
	remove bool
}

// splitAideExpression breaks an attribute expression into its terms, carrying
// whether each was introduced by '-' rather than '+'.
func splitAideExpression(expression string) []aideExpressionToken {
	res := []aideExpressionToken{}

	current := strings.Builder{}
	remove := false

	flush := func() {
		name := strings.TrimSpace(current.String())
		current.Reset()
		if name == "" {
			return
		}
		res = append(res, aideExpressionToken{name: name, remove: remove})
	}

	for _, char := range expression {
		switch char {
		case '+':
			flush()
			remove = false
		case '-':
			flush()
			remove = true
		case ' ', '\t':
			// a restriction such as "f" may be separated by whitespace; treat it
			// as its own term rather than joining it to the next one
			flush()
		default:
			current.WriteRune(char)
		}
	}
	flush()

	return res
}

// aideDatabasePath turns a database setting into a filesystem path. AIDE accepts
// a URL, and the only form naming a local file is "file:".
func aideDatabasePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "file://"):
		return value[len("file://"):]
	case strings.HasPrefix(lower, "file:"):
		return value[len("file:"):]
	case strings.HasPrefix(value, "/"):
		return value
	}

	// stdout, stderr, fd:, url: and the like name no local file
	return ""
}

// parseAideVersion pulls the release out of "aide --version" output, whose first
// line reads like "Aide 0.17.4".
func parseAideVersion(out string) string {
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		for _, field := range fields {
			if field == "" {
				continue
			}
			if field[0] >= '0' && field[0] <= '9' {
				return field
			}
		}
		// only the first non-empty line carries the version
		return ""
	}
	return ""
}
