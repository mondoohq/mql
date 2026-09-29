// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"strings"

	"github.com/kballard/go-shellquote"
)

// Flagset is derived from Go's internal flagset, licensed MIT
type FlagSet struct {
	parsed bool
	// actual maps flag names to their values. Operands are stored too, keyed
	// by the word itself with an empty value: positional arguments, a lone
	// "-", and words that look like flags but have no usable name ("---x",
	// "-=x").
	actual map[string]string
	args   []string // arguments after flags
}

// ParseCommand parses a POSIX command line, as ps and /proc report it. A
// process without a command line (an empty string) has no flags.
func (f *FlagSet) ParseCommand(cmd string) error {
	if strings.TrimSpace(cmd) == "" {
		return f.Parse(nil)
	}
	// ps prints argv joined by spaces without re-quoting, so an argument with
	// an apostrophe leaves an unbalanced quote. Fall back to whitespace
	// splitting rather than failing the whole flag map for it.
	words, err := shellquote.Split(cmd)
	if err != nil {
		words = strings.Fields(cmd)
	}
	if len(words) == 0 {
		return f.Parse(nil)
	}
	return f.parseArgs(words[1:])
}

// ParseWindowsCommand parses a Windows command line. Windows passes a process
// one unsplit string, so it is split the way CommandLineToArgvW does it:
// backslashes are literal unless they precede a double quote, and double
// quotes group. argv[0] is the program and never a flag. executable is the
// process image name ("amazon-ssm-agent"); it may be empty. A process without
// a command line has no flags.
func (f *FlagSet) ParseWindowsCommand(cmd string, executable string) error {
	_, rest := splitWindowsArgv0(cmd, executable)
	return f.parseArgs(windowsCommandLineToArgv(rest))
}

func (f *FlagSet) parseArgs(args []string) error {
	// NOTE: it is impossible to do flag parsing correct without having the context of the binary
	// - `--name=x` is pretty clear where name is the key and x is the value
	//  `--name x` here name is the key, but x could be the value or an arg, if name is a boolean flag x will not be the value
	//
	// Therefore we work with the assumption that if `--arg` is followed by a flag without `-` prefix, we count this as a value
	preparedArgs := []string{}
	n := len(args)
	for i := 0; i < n; i++ {
		key := args[i]
		if key == "--" {
			break
		}
		// A lone "-" is an operand (stdin, or the end of options for
		// `#!/bin/sh -` scripts such as FreeBSD's periodic), never a flag
		// that takes the next word as its value.
		if key != "-" && strings.HasPrefix(key, "-") {
			if i+1 < n && !strings.HasPrefix(args[i+1], "-") {
				preparedArgs = append(preparedArgs, key+"="+args[i+1])
				i++
				continue
			}
		}
		preparedArgs = append(preparedArgs, key)
	}

	return f.Parse(preparedArgs)
}

func (f *FlagSet) Parse(args []string) error {
	f.parsed = true
	f.args = args

	if f.actual == nil {
		f.actual = make(map[string]string)
	}

	for {
		seen, err := f.parseOneArg()
		if seen {
			continue
		}
		if err == nil {
			break
		}
		return err
	}
	return nil
}

func (f *FlagSet) parseOneArg() (bool, error) {
	if len(f.args) == 0 {
		return false, nil
	}
	s := f.args[0]

	if len(s) < 2 || s[0] != '-' {
		f.args = f.args[1:]
		f.actual[s] = ""
		return true, nil
	}
	numMinuses := 1
	if s[1] == '-' {
		numMinuses++
		if len(s) == 2 { // "--" terminates the flags
			f.args = f.args[1:]
			return false, nil
		}
	}
	name := s[numMinuses:]
	if len(name) == 0 || name[0] == '-' || name[0] == '=' {
		// Not a flag the parser can name ("---x", "-=x"). Keep it as an
		// operand: one odd argument must not cost the process its flag map.
		f.args = f.args[1:]
		f.actual[s] = ""
		return true, nil
	}

	// it's a flag. does it have an argument?
	f.args = f.args[1:]
	value := ""
	for i := 1; i < len(name); i++ { // equals cannot be first
		if name[i] == '=' {
			value = name[i+1:]
			name = name[0:i]
			break
		}
	}
	name = strings.ToLower(name)
	f.actual[name] = value
	return true, nil
}

func (f *FlagSet) Map() map[string]string {
	return f.actual
}

// splitWindowsArgv0 returns the program part of a Windows command line and the
// remaining arguments.
//
// CommandLineToArgvW takes argv[0] up to the closing quote when it starts with
// one, and otherwise up to the first space or tab. An unquoted path with a
// space in it, "C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe", is still a
// runnable command line: CreateProcess tries each space-delimited prefix in
// turn. Splitting it at the first space would report the rest of the path as
// an argument, so the program ends at the first space-delimited prefix that
// matches, trying in order:
//
//  1. the process image with its extension ("...\ping.exe" for ping), which
//     is exact whenever the command line starts with the executable's path
//  2. the process image without an extension ("...\agent" for agent)
//  3. any .exe or .com, when the image name is unknown or not in the line
//  4. the first space
//
// Checking the image with its extension first keeps a folder named like the
// program, "C:\Tools\ping 1\ping.exe", from ending the path at "C:\Tools\ping".
// Checking the bare image before any .exe keeps an argument that ends in .exe
// from being read as part of the program.
func splitWindowsArgv0(cmd string, executable string) (string, string) {
	cmd = strings.TrimLeft(cmd, " \t")
	if cmd == "" {
		return "", ""
	}
	if cmd[0] == '"' {
		if end := strings.IndexByte(cmd[1:], '"'); end >= 0 {
			return cmd[1 : end+1], cmd[end+2:]
		}
		return cmd[1:], ""
	}

	// candidate ends of argv[0]: every space or tab, and the end of the line
	var ends []int
	for i := 0; i < len(cmd); i++ {
		if cmd[i] == ' ' || cmd[i] == '\t' {
			ends = append(ends, i)
		}
	}
	ends = append(ends, len(cmd))

	executable = strings.ToLower(executable)
	program := func(prefix string) bool {
		ext := strings.ToLower(filepathExt(prefix))
		return ext == ".exe" || ext == ".com"
	}
	image := func(prefix string) bool {
		return executable != "" && windowsImageName(prefix) == executable
	}
	rules := []func(string) bool{
		func(prefix string) bool { return image(prefix) && program(prefix) },
		func(prefix string) bool { return image(prefix) && filepathExt(prefix) == "" },
		program,
	}
	for _, rule := range rules {
		for _, end := range ends {
			if rule(cmd[:end]) {
				return cmd[:end], cmd[end:]
			}
		}
	}
	return cmd[:ends[0]], cmd[ends[0]:]
}

// windowsImageName returns the lowercase file name of a Windows path without
// its extension, the form Get-Process reports as the process name.
func windowsImageName(path string) string {
	name := path[strings.LastIndexAny(path, `\/`)+1:]
	name = strings.TrimSuffix(name, filepathExt(name))
	return strings.ToLower(name)
}

func filepathExt(path string) string {
	name := path[strings.LastIndexAny(path, `\/`)+1:]
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i:]
	}
	return ""
}

// windowsCommandLineToArgv splits the arguments that follow argv[0] with the
// rules of CommandLineToArgvW:
//   - space and tab separate arguments outside double quotes
//   - 2n backslashes before a double quote become n backslashes, and the quote
//     opens or closes a quoted section
//   - 2n+1 backslashes before a double quote become n backslashes and a
//     literal double quote
//   - backslashes anywhere else are literal
//   - "" inside a quoted section is a literal double quote, and closes the
//     section
func windowsCommandLineToArgv(cmd string) []string {
	var args []string
	for len(cmd) > 0 {
		if cmd[0] == ' ' || cmd[0] == '\t' {
			cmd = cmd[1:]
			continue
		}
		var arg string
		arg, cmd = readWindowsArg(cmd)
		args = append(args, arg)
	}
	return args
}

// readWindowsArg follows readNextArg in Go's os package (BSD-3-Clause), which
// Go tests against the CommandLineToArgvW API.
func readWindowsArg(cmd string) (string, string) {
	var b strings.Builder
	inQuote := false
	nSlash := 0
	for ; len(cmd) > 0; cmd = cmd[1:] {
		c := cmd[0]
		switch c {
		case ' ', '\t':
			if !inQuote {
				b.WriteString(strings.Repeat(`\`, nSlash))
				return b.String(), cmd[1:]
			}
		case '"':
			b.WriteString(strings.Repeat(`\`, nSlash/2))
			if nSlash%2 == 0 {
				if inQuote && len(cmd) > 1 && cmd[1] == '"' {
					b.WriteByte('"')
					cmd = cmd[1:]
				}
				inQuote = !inQuote
			} else {
				b.WriteByte('"')
			}
			nSlash = 0
			continue
		case '\\':
			nSlash++
			continue
		}
		b.WriteString(strings.Repeat(`\`, nSlash))
		nSlash = 0
		b.WriteByte(c)
	}
	b.WriteString(strings.Repeat(`\`, nSlash))
	return b.String(), ""
}
