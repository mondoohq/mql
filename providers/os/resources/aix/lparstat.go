// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"bufio"
	"strconv"
	"strings"
)

// LparstatCommand prints the configuration of the logical partition. It
// needs no special privileges.
const LparstatCommand = "lparstat -i"

// ParseLparstat reads `lparstat -i`: one "Key : value" line per attribute,
// the key padded with spaces to align the colons. Values lparstat cannot
// report, such as the shared pool of a dedicated partition, are printed as
// "-" and left out of the result.
func ParseLparstat(out string) map[string]string {
	res := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		key = strings.Join(strings.Fields(key), " ")
		value = strings.TrimSpace(value)
		if key == "" || value == "" || value == "-" {
			continue
		}
		res[key] = value
	}
	return res
}

// LparSmtThreads returns the hardware threads per processor that the
// partition Type encodes as [Shared | Dedicated][-SMT][-#]: no SMT suffix
// is one thread, "-SMT" alone is two, and "-SMT-#" is #.
func LparSmtThreads(typ string) (int64, bool) {
	parts := strings.Split(strings.TrimSpace(typ), "-")
	switch parts[0] {
	case "Shared", "Dedicated":
	default:
		return 0, false
	}
	switch {
	case len(parts) == 1:
		return 1, true
	case len(parts) == 2 && parts[1] == "SMT":
		return 2, true
	case len(parts) == 3 && parts[1] == "SMT":
		n, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || n < 1 {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// LparMemoryBytes converts a memory size as lparstat prints it, a number
// and a unit such as "8192 MB", into bytes.
func LparMemoryBytes(v string) (int64, bool) {
	f := strings.Fields(v)
	if len(f) != 2 {
		return 0, false
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	var unit int64
	switch strings.ToUpper(f[1]) {
	case "KB":
		unit = 1 << 10
	case "MB":
		unit = 1 << 20
	case "GB":
		unit = 1 << 30
	default:
		return 0, false
	}
	return n * unit, true
}
