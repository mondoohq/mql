// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logindefs

import (
	"bufio"
	"io"
	"math"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

// ignore line if it starts with a comment, allow trailing comments though.
// Compiled once: matched against every line of login.defs.
var logindefEntry = regexp.MustCompile(`^\s*([^#]\S+)\s+(\S+)\s*(?:#.*)?$`)

// Entry is one setting line of login.defs.
type Entry struct {
	// Line is the line number, counted from 1.
	Line int
	Key  string
	// Value is the first word after the key.
	Value string
}

// Parse reads login.defs settings into a map; a later line of the same key
// replaces an earlier one.
func Parse(r io.Reader) map[string]string {
	res := map[string]string{}
	for _, e := range Entries(r) {
		res[e.Key] = e.Value
	}
	return res
}

// Entries reads the setting lines of login.defs in file order.
func Entries(r io.Reader) []Entry {
	var res []Entry

	scanner := bufio.NewScanner(r)
	// shadow reads login.defs with getline(3) and has no line limit; read
	// whole lines so a long value does not drop every key after it. With no
	// token limit the scanner can only fail on a read error; both callers pass
	// file content already held in memory, which cannot fail to read.
	scanner.Buffer(make([]byte, 0, 64*1024), math.MaxInt)
	line := 0
	for scanner.Scan() {
		line++
		noWhitespace := strings.TrimSpace(scanner.Text())

		m := logindefEntry.FindStringSubmatch(noWhitespace)
		if len(m) == 3 {
			res = append(res, Entry{Line: line, Key: m[1], Value: m[2]})
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn().Err(err).Msg("login.defs could not be read to the end, settings after the failure are missing")
	}

	return res
}
