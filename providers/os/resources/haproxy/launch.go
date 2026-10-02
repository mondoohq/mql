// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package haproxy

import (
	"bufio"
	"strings"
)

// LaunchArgs is what the haproxy command line says about configuration:
// the `-f` paths (files or directories, in order) and the `-p` pid file.
type LaunchArgs struct {
	Configs []string
	PidFile string
}

// ParseLaunchArgs extracts the configuration paths and the pid file from
// an haproxy command line (argv[0] included or not). Every `-f <path>`
// adds a path, and every argument after `--` is a configuration path too,
// as haproxy(1) documents. Other flags are ignored.
func ParseLaunchArgs(argv []string) LaunchArgs {
	var res LaunchArgs
	for i := 0; i < len(argv); i++ {
		switch argv[i] {
		case "-f":
			if i+1 < len(argv) {
				res.Configs = append(res.Configs, argv[i+1])
				i++
			}
		case "-p":
			if i+1 < len(argv) {
				res.PidFile = argv[i+1]
				i++
			}
		case "--":
			res.Configs = append(res.Configs, argv[i+1:]...)
			return res
		}
	}
	return res
}

// SplitProcCmdline splits the NUL-separated content of /proc/<pid>/cmdline.
func SplitProcCmdline(data []byte) []string {
	s := strings.TrimRight(string(data), "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

// ParseEnvironmentFile parses a systemd EnvironmentFile (and the Debian
// /etc/default/haproxy, which is written in the same KEY=value form).
// Comment lines and lines without `=` are skipped; one level of matching
// single or double quotes around the value is removed.
func ParseEnvironmentFile(content string) map[string]string {
	env := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		env[k] = unquote(strings.TrimSpace(v))
	}
	return env
}

// SystemdService is the subset of a systemd service unit needed to work
// out the haproxy command line.
type SystemdService struct {
	// Environment holds the Environment= assignments in order of appearance.
	Environment map[string]string
	// EnvironmentFiles lists the EnvironmentFile= paths. A leading `-`
	// (ignore when missing) is stripped.
	EnvironmentFiles []string
	// ExecStart is the last effective ExecStart= command line, with
	// systemd's `-@:+!` prefixes removed.
	ExecStart string
}

// ParseSystemdService merges a unit file and its drop-ins (in the order
// given) into the settings that determine the haproxy command line. An
// empty `ExecStart=` resets the command, as in systemd.
func ParseSystemdService(contents ...string) SystemdService {
	svc := SystemdService{Environment: map[string]string{}}
	for _, content := range contents {
		inService := false
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			if strings.HasPrefix(line, "[") {
				inService = line == "[Service]"
				continue
			}
			if !inService {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "Environment":
				for _, word := range splitSystemdWords(v) {
					if ek, ev, ok := strings.Cut(word, "="); ok {
						svc.Environment[ek] = ev
					}
				}
			case "EnvironmentFile":
				if v == "" {
					svc.EnvironmentFiles = nil
					continue
				}
				svc.EnvironmentFiles = append(svc.EnvironmentFiles, strings.TrimPrefix(v, "-"))
			case "ExecStart":
				svc.ExecStart = strings.TrimLeft(v, "-@:+!")
			}
		}
	}
	return svc
}

// ExpandSystemdCommand splits a systemd ExecStart= command line into
// arguments and substitutes environment variables the way systemd does:
// `${VAR}` becomes exactly one argument, while an unquoted `$VAR` standing
// alone is split on whitespace into zero or more arguments.
func ExpandSystemdCommand(cmd string, env map[string]string) []string {
	var out []string
	for _, word := range splitSystemdWords(cmd) {
		if name, ok := wholeWordVar(word); ok {
			out = append(out, strings.Fields(env[name])...)
			continue
		}
		out = append(out, expandBraced(word, env))
	}
	return out
}

// wholeWordVar reports whether word is exactly `$NAME` (no braces).
func wholeWordVar(word string) (string, bool) {
	if len(word) < 2 || word[0] != '$' || word[1] == '{' {
		return "", false
	}
	name := word[1:]
	for _, r := range name {
		if !isEnvNameRune(r) {
			return "", false
		}
	}
	return name, true
}

func isEnvNameRune(r rune) bool {
	return r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

func expandBraced(word string, env map[string]string) string {
	var b strings.Builder
	for {
		start := strings.Index(word, "${")
		if start < 0 {
			b.WriteString(word)
			return b.String()
		}
		end := strings.IndexByte(word[start:], '}')
		if end < 0 {
			b.WriteString(word)
			return b.String()
		}
		b.WriteString(word[:start])
		b.WriteString(env[word[start+2:start+end]])
		word = word[start+end+1:]
	}
}

// splitSystemdWords splits on whitespace, honoring single and double
// quotes (which are removed) the way systemd splits Environment= and
// ExecStart= values.
func splitSystemdWords(s string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			inWord = true
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inWord = true
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// LaunchFromService resolves the haproxy command line a systemd service
// runs. envFiles holds the content of the service's EnvironmentFile=
// entries that exist, in order. As in systemd, variables from environment
// files override Environment= assignments regardless of their position.
func LaunchFromService(svc SystemdService, envFiles []string) LaunchArgs {
	env := make(map[string]string, len(svc.Environment))
	for k, v := range svc.Environment {
		env[k] = v
	}
	for _, content := range envFiles {
		for k, v := range ParseEnvironmentFile(content) {
			env[k] = v
		}
	}
	argv := ExpandSystemdCommand(svc.ExecStart, env)
	if len(argv) == 0 {
		return LaunchArgs{}
	}
	return ParseLaunchArgs(argv[1:])
}
