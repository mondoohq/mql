// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cassandraconf

import (
	"regexp"
	"strconv"
	"strings"
)

// Env is the result of parsing a cassandra-env.sh.
type Env struct {
	// Variables holds the shell variable assignments that survive the file,
	// with LOCAL_JMX resolved to the value the launch script would use.
	Variables map[string]string
	// Properties holds the JVM system properties the file appends to
	// JVM_OPTS, keyed without the -D prefix and with $VAR references
	// expanded.
	Properties map[string]string
}

// JMX property names the security posture is read from.
const (
	PropJMXLocalPort     = "cassandra.jmx.local.port"
	PropJMXRemotePort    = "cassandra.jmx.remote.port"
	PropJMXAuthenticate  = "com.sun.management.jmxremote.authenticate"
	PropJMXSSL           = "com.sun.management.jmxremote.ssl"
	PropJMXSSLClientAuth = "com.sun.management.jmxremote.ssl.need.client.auth"
	PropJMXPasswordFile  = "com.sun.management.jmxremote.password.file"
	PropJMXAccessFile    = "com.sun.management.jmxremote.access.file"
	PropJMXLoginConfig   = "cassandra.jmx.remote.login.config"
	PropJMXAuthorizer    = "cassandra.jmx.authorizer"
)

var (
	// reAssign matches a shell variable assignment, with or without the
	// export keyword.
	reAssign = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

	// reSysProp matches a JVM system property as written on a JVM_OPTS line.
	// The value is optional because a bare -Dflag is legal.
	reSysProp = regexp.MustCompile(`-D([A-Za-z0-9_.]+)(?:=([^\s"']*))?`)

	// reVarRef matches a $VAR or ${VAR} reference inside a value.
	reVarRef = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

	// reLocalJMXGuard matches the `if [ "x$LOCAL_JMX" = "x" ]` block the
	// shipped file uses to default LOCAL_JMX when it is not already set.
	reLocalJMXGuard = regexp.MustCompile(`^if\s+\[\s*"x\$\{?LOCAL_JMX\}?"\s*=\s*"x"\s*\]`)

	// reLocalJMXTest matches the `if [ "$LOCAL_JMX" = "yes" ]` block that
	// selects between the localhost-only and remote JMX property sets.
	reLocalJMXTest = regexp.MustCompile(`^if\s+\[\s*"?\$\{?LOCAL_JMX\}?"?\s*(=|==|!=)\s*"?([A-Za-z]*)"?\s*\]`)
)

// ParseEnv parses the content of a cassandra-env.sh.
//
// The file is a shell script rather than a configuration file, so this is a
// reader for the shape Cassandra ships rather than a shell interpreter. It
// resolves the one conditional that matters, `if [ "$LOCAL_JMX" = "yes" ]`,
// and treats any other conditional as taken.
//
// Resolving that conditional is not optional. The shipped file sets
// com.sun.management.jmxremote.authenticate to false in its then-branch and
// to true in its else-branch, so collecting every -D in the file reports
// whichever is written last and gives a localhost-only host and a hardened
// remote-JMX host the same answer.
func ParseEnv(content string) *Env {
	lines := activeLines(content)
	localJMX := resolveLocalJMX(lines)

	env := &Env{
		Variables:  map[string]string{},
		Properties: map[string]string{},
	}

	// stack holds one frame per open conditional. known records whether the
	// condition could be evaluated; active records whether the branch
	// currently being read runs.
	type frame struct{ known, active bool }
	var stack []frame

	live := func() bool {
		for _, f := range stack {
			if !f.active {
				return false
			}
		}
		return true
	}

	for _, text := range lines {
		switch {
		case strings.HasPrefix(text, "if "), strings.HasPrefix(text, "if\t"):
			f := frame{known: false, active: true}
			if m := reLocalJMXTest.FindStringSubmatch(text); m != nil {
				equal := localJMX == m[2]
				if m[1] == "!=" {
					equal = !equal
				}
				f = frame{known: true, active: equal}
			}
			stack = append(stack, f)
			continue

		case text == "else", strings.HasPrefix(text, "else "), strings.HasPrefix(text, "else;"):
			if n := len(stack); n > 0 && stack[n-1].known {
				stack[n-1].active = !stack[n-1].active
			}
			continue

		case strings.HasPrefix(text, "elif "):
			// An elif condition is not one this reader evaluates, so the
			// branch is treated as taken rather than guessed at.
			if n := len(stack); n > 0 {
				stack[n-1] = frame{known: false, active: true}
			}
			continue

		case text == "fi", strings.HasPrefix(text, "fi "), strings.HasPrefix(text, "fi;"):
			if n := len(stack); n > 0 {
				stack = stack[:n-1]
			}
			continue
		}

		if !live() {
			continue
		}

		if m := reAssign.FindStringSubmatch(text); m != nil {
			name, value := m[1], expand(unquote(m[2]), env.Variables)
			// JVM_OPTS is an accumulator rather than a setting; its
			// contents are reported through Properties.
			if name != "JVM_OPTS" {
				env.Variables[name] = value
			}
		}

		// Scan for properties past the inline comment, so a line that ends
		// in a note mentioning another -D flag does not contribute it.
		for _, m := range reSysProp.FindAllStringSubmatch(cutUnquoted(text), -1) {
			env.Properties[m[1]] = expand(m[2], env.Variables)
		}
	}

	// The guard block assigns LOCAL_JMX only when it is not already set, so
	// the assignment collected above is the default rather than necessarily
	// the effective value. resolveLocalJMX applies the precedence.
	env.Variables["LOCAL_JMX"] = localJMX

	return env
}

// activeLines strips comments and blank lines, and trims the indentation that
// the conditional prefix checks would otherwise trip over.
func activeLines(content string) []string {
	out := []string{}
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// resolveLocalJMX reports the LOCAL_JMX value the launch script ends up with,
// which decides whether JMX listens on localhost only.
//
// An assignment outside the `if [ "x$LOCAL_JMX" = "x" ]` guard wins, because
// the guard only fires when the variable is unset. An assignment inside the
// guard is the default and applies when there is no outside one. With
// neither, Cassandra's own default of yes applies.
func resolveLocalJMX(lines []string) string {
	var outside, inside string
	depth, guardDepth := 0, -1

	for _, text := range lines {
		switch {
		case strings.HasPrefix(text, "if "), strings.HasPrefix(text, "if\t"):
			depth++
			if guardDepth < 0 && reLocalJMXGuard.MatchString(text) {
				guardDepth = depth
			}
			continue
		case text == "fi", strings.HasPrefix(text, "fi "), strings.HasPrefix(text, "fi;"):
			if guardDepth == depth {
				guardDepth = -1
			}
			depth--
			continue
		}

		m := reAssign.FindStringSubmatch(text)
		if m == nil || m[1] != "LOCAL_JMX" {
			continue
		}
		if guardDepth >= 0 {
			inside = unquote(m[2])
		} else {
			outside = unquote(m[2])
		}
	}

	if outside != "" {
		return outside
	}
	if inside != "" {
		return inside
	}
	return "yes"
}

// unquote strips any trailing inline comment or statement separator, then one
// layer of surrounding quotes.
//
// The trailing part has to go first and has to be quote-aware, because the
// two orderings disagree on `LOCAL_JMX="yes" # local mode`: cutting the
// comment first leaves a value the quote strip recognizes, while checking the
// quotes first sees a value that ends in `e` and hands back the comment as
// part of it. On LOCAL_JMX that reads as remote JMX on a host that has none.
func unquote(v string) string {
	v = strings.TrimSpace(cutUnquoted(strings.TrimSpace(v)))
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// cutUnquoted trims a shell fragment at the first statement separator or
// inline comment that falls outside quotes.
//
// A `#` only opens a comment at the start of a word, which is why it counts
// only at the start of the fragment or after whitespace: `a#b` is the literal
// value a#b, while `a #b` is the value a.
func cutUnquoted(v string) string {
	var quote byte
	for i := 0; i < len(v); i++ {
		c := v[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch {
		case c == '"' || c == '\'':
			quote = c
		case c == ';':
			return v[:i]
		case c == '#' && (i == 0 || v[i-1] == ' ' || v[i-1] == '\t'):
			return v[:i]
		}
	}
	return v
}

// expand substitutes $VAR references from the variables read so far. A
// reference to something not assigned in the file resolves to empty, which is
// what the shell does for an unset variable.
func expand(v string, vars map[string]string) string {
	if !strings.Contains(v, "$") {
		return v
	}
	return reVarRef.ReplaceAllStringFunc(v, func(ref string) string {
		m := reVarRef.FindStringSubmatch(ref)
		if m == nil {
			return ""
		}
		return vars[m[1]]
	})
}

// ---------------------------------------------------------------------------
// JMX posture
// ---------------------------------------------------------------------------

// LocalJMX reports whether JMX is reachable from localhost only.
//
// Cassandra ships this way, and turning it off is what exposes the JMX port
// to the network. It is the single most consequential setting in the file,
// and it exists nowhere in cassandra.yaml or in the settings virtual table.
func (e *Env) LocalJMX() bool {
	return strings.EqualFold(e.Variables["LOCAL_JMX"], "yes")
}

// JMXPort reports the port JMX binds to, 7199 when the file does not say.
func (e *Env) JMXPort() int64 {
	for _, key := range []string{PropJMXLocalPort, PropJMXRemotePort} {
		if p, err := strconv.ParseInt(strings.TrimSpace(e.Properties[key]), 10, 64); err == nil && p > 0 {
			return p
		}
	}
	if p, err := strconv.ParseInt(strings.TrimSpace(e.Variables["JMX_PORT"]), 10, 64); err == nil && p > 0 {
		return p
	}
	return 7199
}

// Bool reports a JVM system property as a boolean, falling back to def when
// the property is not set on the live branch.
func (e *Env) Bool(key string, def bool) bool {
	raw, ok := e.Properties[key]
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	return b
}

// String reports a JVM system property, empty when it is not set on the live
// branch.
func (e *Env) String(key string) string {
	return e.Properties[key]
}
