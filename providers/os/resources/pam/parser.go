// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pam

import (
	"fmt"
	"strings"
)

type PamLine struct {
	PamType string
	Control string
	Module  string
	Options []any
	// IgnoreMissing is set by a leading '-' on the type (`-session optional
	// pam_systemd.so`): PAM skips the line without logging an error when the
	// module cannot be loaded. The '-' is not part of PamType.
	IgnoreMissing bool
}

// IsType reports whether token is a PAM module type (auth, account,
// password, session), optionally prefixed with '-'. PAM compares types
// case-insensitively.
func IsType(token string) bool {
	switch strings.ToLower(strings.TrimPrefix(token, "-")) {
	case "auth", "account", "password", "session":
		return true
	}
	return false
}

func ParseLine(line string) (*PamLine, error) {
	line = StripComments(line)

	if line == "" {
		return nil, nil
	}

	fields := strings.Fields(line)

	options := []any{}

	// check if we have @include
	if len(fields) == 2 && fields[0] == "@include" {
		return &PamLine{
			PamType: fields[0],
			Control: fields[1],
			Module:  "",
			Options: options,
		}, nil
	}

	if len(fields) < 3 {
		return &PamLine{}, fmt.Errorf("invalid pam entry: %s", line)
	}

	// parse modules

	pamType, ignoreMissing := splitType(fields[0])
	control := fields[1]
	// Control can either be one word or several contained in [] brackets
	if control[0] == '[' && control[len(control)-1] != ']' {
		return complicatedParse(fields)
	}
	module := fields[2]

	if len(fields) >= 3 {
		for _, f := range fields[3:] {
			options = append(options, f)
		}
	} else {
		options = nil
	}

	pl := &PamLine{
		PamType:       pamType,
		Control:       control,
		Module:        module,
		Options:       options,
		IgnoreMissing: ignoreMissing,
	}
	return pl, nil
}

// splitType strips the leading '-' PAM accepts on a type and reports whether
// it was there.
func splitType(token string) (string, bool) {
	if len(token) > 1 && token[0] == '-' {
		return token[1:], true
	}
	return token, false
}

func complicatedParse(fields []string) (*PamLine, error) {
	pamType, ignoreMissing := splitType(fields[0])
	control := fields[1]
	i := 2
	closed := false
	// Accumulate fields into the bracketed control until the closing `]`.
	// The loop must be able to inspect the final field as well, otherwise a
	// control that runs to the end of the line is never recognized as closed.
	for ; i < len(fields); i++ {
		str := fields[i]
		control += " " + str
		if strings.HasSuffix(str, "]") {
			closed = true
			break
		}
	}
	// The module is the token after the closing bracket. If the bracket was
	// never closed, or there is no field after it, the line is malformed —
	// return an error rather than indexing out of range.
	if !closed || i+1 >= len(fields) {
		return &PamLine{}, fmt.Errorf("invalid pam entry: %s", strings.Join(fields, " "))
	}
	module := fields[i+1]
	options := []any{}
	if i+2 < len(fields) {
		for _, f := range fields[i+2:] {
			options = append(options, f)
		}
	}
	pl := &PamLine{
		PamType:       pamType,
		Control:       control,
		Module:        module,
		Options:       options,
		IgnoreMissing: ignoreMissing,
	}
	return pl, nil
}

func StripComments(line string) string {
	// A '#' starts a comment only when it begins a token (start of line or
	// preceded by whitespace). A '#' embedded in a module option is part of
	// the option value and must be preserved.
	for idx := 0; idx < len(line); idx++ {
		if line[idx] == '#' && (idx == 0 || line[idx-1] == ' ' || line[idx-1] == '\t') {
			line = line[0:idx]
			break
		}
	}
	line = strings.Trim(line, " \t\r")
	return line
}
