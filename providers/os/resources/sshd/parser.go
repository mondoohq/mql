// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshd

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type SshdLine struct {
	key  string
	args string
}

// sshd_config keywords are case-insensitive, and ParseLine sees the raw
// keyword before it is canonicalized to its mixed-case form, so the lookup
// keys are stored lowercased and compared against the lowercased keyword.
var keysWithTimeValue = map[string]int{
	"clientaliveinterval": 1,
	"logingracetime":      1,
}

// ParseLine parses a single line of the sshd_config file
// A valid line contains a key. If the entire line is a
// comment, key will be empty. If the line could not be
// parsed, an error is returned.
//
// Note: The caller must provide only a single line.
func ParseLine(s []rune) (SshdLine, error) {
	l := SshdLine{}
	if len(s) == 0 {
		return l, nil
	}

	l.key, s = parseKeyword(s)

	var err error
	l.args, _, err = parseArgs(s)
	if err != nil {
		return l, err
	}

	if _, ok := keysWithTimeValue[strings.ToLower(l.key)]; ok {
		duration, err := time.ParseDuration(l.args)
		if err == nil {
			l.args = fmt.Sprintf("%.0f", duration.Seconds())
		}
	}

	return l, nil
}

func parseKeyword(s []rune) (string, []rune) {
	s = consumeWhitespace(s)

	i := 0
LOOP:
	for i < len(s) {
		switch s[i] {
		case '#':
			break LOOP
		case ' ', '\t', '\r', '\n', '=':
			break LOOP
		}
		i++
	}

	return string(s[0:i]), consumeEqualOrWhitespace(s[i:])
}

func parseArgs(s []rune) (string, []rune, error) {
	args := []string{}
LOOP:
	for len(s) > 0 {
		var arg string

		switch s[0] {
		case '#':
			break LOOP
		case '"':
			var err error
			arg, s, err = parseQuotedArg(s)
			if err != nil {
				return "", nil, err
			}
			args = append(args, arg)
		default:
			arg, s = parseArg(s)
			args = append(args, arg)
		}
	}

	return strings.Join(args, " "), s, nil
}

func parseArg(s []rune) (string, []rune) {
	i := 0
LOOP:
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
			break LOOP
		}
		i++
	}
	return string(s[0:i]), consumeWhitespace(s[i:])
}

var errUnexpectedEOF = errors.New("unexpected EOF")

func parseQuotedArg(s []rune) (string, []rune, error) {
	i := 1
LOOP:
	for {
		if i >= len(s) {
			return "", nil, errUnexpectedEOF
		}

		switch s[i] {
		case '\\':
			i++
			if i < len(s) && s[i] == '"' {
				i++
			}
		case '\r', '\n':
			return "", nil, errUnexpectedEOF
		case '"':
			i++
			break LOOP
		}
		i++
	}
	return string(s[0:i]), consumeWhitespace(s[i:]), nil
}

func consumeWhitespace(s []rune) []rune {
	for i := range s {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		default:
			return s[i:]
		}
	}
	return []rune{}
}

func consumeEqualOrWhitespace(s []rune) []rune {
	s = consumeWhitespace(s)
	if len(s) > 0 && s[0] == '=' {
		s = consumeWhitespace(s[1:])
	}
	return s
}
