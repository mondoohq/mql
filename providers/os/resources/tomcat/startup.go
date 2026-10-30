// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"path"
	"regexp"
	"strings"

	"github.com/spf13/afero"
)

// BootstrapClass is the main class every Catalina JVM is started with. The
// arguments before it on the command line belong to the JVM, the ones after it
// to Catalina.
const BootstrapClass = "org.apache.catalina.startup.Bootstrap"

// JVMOptionsFromArgs returns the JVM options of a Catalina command line: the
// arguments between the java executable and the Bootstrap main class. The
// second return value is false when argv is not a Catalina JVM, for example
// the catalina.sh shell that is about to start one.
func JVMOptionsFromArgs(argv []string) ([]string, bool) {
	for i := 1; i < len(argv); i++ {
		if argv[i] == BootstrapClass {
			return append([]string{}, argv[1:i]...), true
		}
	}
	return nil, false
}

// SystemProperties collects the -D system properties of a list of JVM options.
// A bare -Dname is a property with an empty value. A property given more than
// once keeps its last value, which is the one the JVM uses.
func SystemProperties(opts []string) map[string]string {
	res := map[string]string{}
	for _, opt := range opts {
		if !strings.HasPrefix(opt, "-D") || len(opt) == 2 {
			continue
		}
		key, value, _ := strings.Cut(opt[2:], "=")
		res[key] = value
	}
	return res
}

// Startup is the configuration Catalina would start with, gathered from the
// places a distribution and an administrator set it.
type Startup struct {
	// Env holds the variables after every source has been applied
	Env map[string]string
	// Files lists the files that were read, in the order they were applied
	Files []string
}

// JVMOptions returns JAVA_OPTS followed by CATALINA_OPTS, split into the
// individual options, in the order catalina.sh passes them to the JVM.
func (s Startup) JVMOptions() []string {
	res := SplitOptions(s.Env["JAVA_OPTS"])
	return append(res, SplitOptions(s.Env["CATALINA_OPTS"])...)
}

// TmpDir returns CATALINA_TMPDIR, or catalina.sh's default of
// CATALINA_BASE/temp when it is not set.
func (s Startup) TmpDir(base string) string {
	if dir := s.Env["CATALINA_TMPDIR"]; dir != "" {
		return dir
	}
	if base == "" {
		return ""
	}
	return path.Join(base, "temp")
}

// StartupConfig gathers the environment Catalina is started with, in the
// order the sources apply:
//
//  1. Environment= of the systemd unit that starts this installation
//  2. the unit's EnvironmentFile= targets, which override Environment=
//  3. the distribution's environment files (EnvConfigGlobs) the unit does not
//     name itself; the distributions' start scripts source them as shell
//  4. bin/setenv.sh of CATALINA_BASE, or of CATALINA_HOME when the instance
//     has none, which catalina.sh sources last
//
// CATALINA_HOME and CATALINA_BASE are seeded from the installation's paths,
// so that setenv.sh can refer to them.
func StartupConfig(fs afero.Fs, p Paths) Startup {
	afs := &afero.Afero{Fs: fs}
	res := Startup{
		Env:   map[string]string{},
		Files: []string{},
	}
	if p.Home != "" {
		res.Env["CATALINA_HOME"] = p.Home
	}
	if p.Base != "" {
		res.Env["CATALINA_BASE"] = p.Base
	}

	read := map[string]bool{}

	if unit, ok := unitFor(fs, p); ok {
		res.Files = append(res.Files, unit.Path)
		UnitEnvironment(unit.Content, res.Env)
		for _, envFile := range unit.EnvFiles {
			read[envFile] = true
			content, err := afs.ReadFile(envFile)
			if err != nil {
				continue
			}
			res.Files = append(res.Files, envFile)
			EnvironmentFileAssignments(string(content), res.Env)
		}
	}

	for _, pattern := range EnvConfigGlobs {
		matches, err := afero.Glob(afs, pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if read[match] {
				continue
			}
			read[match] = true
			content, err := afs.ReadFile(match)
			if err != nil {
				continue
			}
			// A file that declares the paths of another installation (a second
			// instance's configuration) does not apply to this one.
			fileHome, fileBase := PathsFromEnvFile(string(content))
			if !samePath(fileBase, p.Base) || !samePath(fileHome, p.Home) {
				continue
			}
			res.Files = append(res.Files, match)
			ShellAssignments(string(content), res.Env)
		}
	}

	for _, dir := range []string{p.Base, p.Home} {
		if dir == "" {
			continue
		}
		setenv := path.Join(dir, "bin", "setenv.sh")
		content, err := afs.ReadFile(setenv)
		if err != nil {
			continue
		}
		res.Files = append(res.Files, setenv)
		ShellAssignments(string(content), res.Env)
		break
	}

	return res
}

// unitFor returns the systemd unit that starts the installation at p. A unit
// that declares a CATALINA_BASE belongs to that instance only; a unit that
// declares only CATALINA_HOME belongs to the instances of that installation
// that have no unit of their own.
func unitFor(fs afero.Fs, p Paths) (CatalinaUnit, bool) {
	units := catalinaUnits(fs)
	for _, unit := range units {
		if unit.Base != "" && p.Base != "" && samePath(unit.Base, p.Base) {
			return unit, true
		}
	}
	for _, unit := range units {
		if unit.Base == "" && unit.Home != "" && p.Home != "" && samePath(unit.Home, p.Home) {
			return unit, true
		}
	}
	return CatalinaUnit{}, false
}

// samePath reports whether two paths name the same directory. An empty path
// declares nothing and matches anything.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	return path.Clean(a) == path.Clean(b)
}

// UnitEnvironment applies the Environment= assignments of a systemd unit to
// env. systemd does not expand variables in them, so values are taken as
// written, with the quotes around each assignment removed.
func UnitEnvironment(content string, env map[string]string) {
	for line := range strings.SplitSeq(content, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found || strings.TrimSpace(key) != "Environment" {
			continue
		}
		for _, assignment := range splitUnitEnvironment(strings.TrimSpace(value)) {
			if name, v, ok := strings.Cut(assignment, "="); ok && isShellName(name) {
				env[name] = v
			}
		}
	}
}

// EnvironmentFileAssignments applies a systemd EnvironmentFile= to env. Each
// line is one assignment whose value runs to the end of the line, with one pair
// of enclosing quotes removed; systemd does not expand variables in it.
func EnvironmentFileAssignments(content string, env map[string]string) {
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		name, value, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || !isShellName(name) {
			continue
		}
		env[name] = unquote(strings.TrimSpace(value))
	}
}

var reShellName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func isShellName(s string) bool {
	return reShellName.MatchString(s)
}

// ShellAssignments applies the variable assignments of a shell script, such as
// bin/setenv.sh or /etc/default/tomcat9, to env.
//
// This is not a shell. It evaluates assignments (`NAME=value`, `export
// NAME=value`, several per line, separated by `;`, `&&` or `||`) with the
// quoting rules of sh, and expands `$NAME`, `${NAME}`, `${NAME:-word}` and
// `${NAME-word}` from the variables assigned so far, so the common
// `CATALINA_OPTS="$CATALINA_OPTS -Dname=value"` append works. Conditions are not
// evaluated: an assignment inside an `if` block or after `[ ... ] &&` always
// applies. Command substitutions and other parameter expansions are kept as
// written. Commands are not run, and an assignment that only prefixes a command
// (`NAME=value cmd`) does not change env, as in sh.
func ShellAssignments(content string, env map[string]string) {
	for _, words := range shellStatements(content) {
		applyShellStatement(words, env)
	}
}

// shellKeywords may precede an assignment in a compound command.
var shellKeywords = map[string]bool{
	"then": true,
	"else": true,
	"do":   true,
	"{":    true,
	"!":    true,
}

func applyShellStatement(words []string, env map[string]string) {
	for len(words) > 0 && shellKeywords[words[0]] {
		words = words[1:]
	}
	if len(words) == 0 {
		return
	}

	if words[0] == "export" || words[0] == "readonly" {
		for _, word := range words[1:] {
			if name, raw, ok := shellAssignment(word); ok {
				env[name] = expandShellWord(raw, env)
			}
		}
		return
	}

	type assignment struct{ name, raw string }
	assignments := []assignment{}
	for _, word := range words {
		name, raw, ok := shellAssignment(word)
		if !ok {
			// NAME=value cmd: the assignments are the command's environment
			return
		}
		assignments = append(assignments, assignment{name, raw})
	}
	for _, a := range assignments {
		env[a.name] = expandShellWord(a.raw, env)
	}
}

// shellAssignment splits a raw word of the form NAME=value.
func shellAssignment(word string) (string, string, bool) {
	name, raw, found := strings.Cut(word, "=")
	if !found || !isShellName(name) {
		return "", "", false
	}
	return name, raw, true
}

// shellStatements splits a shell script into simple commands, each a list of
// raw words that still carry their quotes.
func shellStatements(content string) [][]string {
	res := [][]string{}
	words := []string{}
	var cur strings.Builder
	inWord := false

	endWord := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	endStatement := func() {
		endWord()
		if len(words) > 0 {
			res = append(res, words)
			words = []string{}
		}
	}

	for i := 0; i < len(content); i++ {
		c := content[i]
		switch {
		case c == '\\' && i+1 < len(content):
			if content[i+1] == '\n' {
				// line continuation
				i++
				continue
			}
			cur.WriteByte(c)
			cur.WriteByte(content[i+1])
			inWord = true
			i++
		case c == '#' && !inWord:
			for i < len(content) && content[i] != '\n' {
				i++
			}
			endStatement()
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		case c == '\n' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			endStatement()
		case c == '\'' || c == '`':
			// a single-quoted string or a command substitution, up to its end
			j := closingQuote(content, i)
			cur.WriteString(content[i : j+1])
			inWord = true
			i = j
		case c == '"':
			j := i + 1
			for j < len(content) && content[j] != '"' {
				if content[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(content) {
				j = len(content) - 1
			}
			cur.WriteString(content[i : j+1])
			inWord = true
			i = j
		case c == '$' && i+1 < len(content) && (content[i+1] == '(' || content[i+1] == '{'):
			j := matchingClose(content, i+1)
			cur.WriteString(content[i : j+1])
			inWord = true
			i = j
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	endStatement()
	return res
}

// closingQuote returns the index of the quote that closes the one at
// content[open], or the last index when it is never closed.
func closingQuote(content string, open int) int {
	if end := strings.IndexByte(content[open+1:], content[open]); end >= 0 {
		return open + 1 + end
	}
	return len(content) - 1
}

// matchingClose returns the index of the bracket that closes the one at
// content[open], or the last index when it is never closed.
func matchingClose(content string, open int) int {
	opening := content[open]
	closing := byte(')')
	if opening == '{' {
		closing = '}'
	}
	depth := 0
	for j := open; j < len(content); j++ {
		switch content[j] {
		case '\\':
			j++
		case '\'':
			if end := strings.IndexByte(content[j+1:], '\''); end >= 0 {
				j += end + 1
			}
		case opening:
			depth++
		case closing:
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return len(content) - 1
}

// expandShellWord removes the quotes of a raw word and expands its variable
// references the way sh does for the right-hand side of an assignment, which
// is not split into fields.
func expandShellWord(raw string, env map[string]string) string {
	var res strings.Builder
	inDouble := false

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\'' && !inDouble:
			end := strings.IndexByte(raw[i+1:], '\'')
			if end < 0 {
				res.WriteString(raw[i+1:])
				return res.String()
			}
			res.WriteString(raw[i+1 : i+1+end])
			i += end + 1
		case c == '"':
			inDouble = !inDouble
		case c == '\\' && i+1 < len(raw):
			next := raw[i+1]
			if inDouble && !strings.ContainsRune("$`\"\\\n", rune(next)) {
				// inside double quotes a backslash only escapes these
				res.WriteByte(c)
				continue
			}
			if next != '\n' {
				res.WriteByte(next)
			}
			i++
		case c == '`':
			// command substitution, kept as written
			j := closingQuote(raw, i)
			res.WriteString(raw[i : j+1])
			i = j
		case c == '$' && i+1 < len(raw):
			n := expandShellParameter(raw[i:], env, &res)
			i += n - 1
		default:
			res.WriteByte(c)
		}
	}
	return res.String()
}

var (
	reShellParam       = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)`)
	reShellBracedParam = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([^}]*))?\}`)
)

// expandShellParameter expands the reference at the start of s into res and
// returns how many bytes of s it consumed. A reference it does not evaluate,
// such as a command substitution or a positional parameter, is copied as
// written.
func expandShellParameter(s string, env map[string]string, res *strings.Builder) int {
	if m := reShellParam.FindStringSubmatch(s); m != nil {
		res.WriteString(env[m[1]])
		return len(m[0])
	}
	if m := reShellBracedParam.FindStringSubmatch(s); m != nil {
		value, set := env[m[1]]
		switch m[2] {
		case ":-":
			if value == "" {
				value = m[3]
			}
		case "-":
			if !set {
				value = m[3]
			}
		}
		res.WriteString(value)
		return len(m[0])
	}
	if s[1] == '(' || s[1] == '{' {
		end := matchingClose(s, 1)
		res.WriteString(s[:end+1])
		return end + 1
	}
	res.WriteByte('$')
	return 1
}

// SplitOptions splits an option variable such as JAVA_OPTS into the options it
// holds. catalina.sh passes the variable through eval, so quotes inside the
// value group an option that contains spaces, and are removed.
func SplitOptions(value string) []string {
	res := []string{}
	var cur strings.Builder
	inWord := false
	var quote byte

	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
				continue
			}
			cur.WriteByte(c)
		case quote == '"':
			if c == '\\' && i+1 < len(value) && strings.ContainsRune("$`\"\\", rune(value[i+1])) {
				i++
				cur.WriteByte(value[i])
				continue
			}
			if c == '"' {
				quote = 0
				continue
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == '\\' && i+1 < len(value):
			i++
			cur.WriteByte(value[i])
			inWord = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				res = append(res, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		res = append(res, cur.String())
	}
	return res
}
