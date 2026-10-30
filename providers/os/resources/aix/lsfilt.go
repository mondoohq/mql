// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"bufio"
	"strconv"
	"strings"
)

// Filter is one IP security filter rule as lsfilt prints it.
type Filter struct {
	Version int
	ID      int
	Attrs   map[string]string
}

// ParseLsfilt reads `lsfilt -v4` or `lsfilt -v6`:
//
//	Rule 1:
//	Rule action         : permit
//	Source Address      : 0.0.0.0
//	...
//
//	Rule 2:
//	*** Dynamic filter placement rule for IKE tunnels ***
//	Logging control     : no
//
// A rule is a "Rule N:" line followed by "Key : value" lines. The dynamic
// placement rule, a marker for where IKE adds its rules, carries no action
// and is left out.
func ParseLsfilt(out string, version int) []Filter {
	var res []Filter
	var cur *Filter
	flush := func() {
		if cur != nil && cur.Attrs["Rule action"] != "" {
			res = append(res, *cur)
		}
		cur = nil
	}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Rule ") && strings.HasSuffix(line, ":") {
			flush()
			id, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(line, "Rule "), ":"))
			if err != nil {
				continue
			}
			cur = &Filter{Version: version, ID: id, Attrs: map[string]string{}}
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		cur.Attrs[strings.TrimSpace(key)] = strings.Join(strings.Fields(value), " ")
	}
	flush()
	return res
}
