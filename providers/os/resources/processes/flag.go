// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"errors"
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

func (f *FlagSet) ParseCommand(cmd string) error {
	if cmd == "" {
		return errors.New("no command provided")
	}
	// ps prints argv joined by spaces without re-quoting, so an argument with
	// an apostrophe leaves an unbalanced quote. Fall back to whitespace
	// splitting rather than failing the whole flag map for it.
	words, err := shellquote.Split(cmd)
	if err != nil {
		words = strings.Fields(cmd)
	}
	if len(words) == 0 {
		return errors.New("no command provided")
	}
	args := words[1:]

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
