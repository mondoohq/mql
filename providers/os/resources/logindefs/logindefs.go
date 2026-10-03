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

func Parse(r io.Reader) map[string]string {
	res := map[string]string{}

	scanner := bufio.NewScanner(r)
	// shadow reads login.defs with getline(3) and has no line limit; read
	// whole lines so a long value does not drop every key after it. With no
	// token limit the scanner can only fail on a read error; both callers pass
	// file content already held in memory, which cannot fail to read.
	scanner.Buffer(make([]byte, 0, 64*1024), math.MaxInt)
	for scanner.Scan() {
		line := scanner.Text()
		noWhitespace := strings.TrimSpace(line)

		m := logindefEntry.FindStringSubmatch(noWhitespace)
		if len(m) == 3 {
			res[m[1]] = m[2]
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn().Err(err).Msg("login.defs could not be read to the end, settings after the failure are missing")
	}

	return res
}
