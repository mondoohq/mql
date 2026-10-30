// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"bufio"
	"strings"
)

// ParseLsattr reads `lsattr -El <device> -F "attribute value"`: one
// attribute per line, its name and then its value, which may be empty or
// hold spaces.
func ParseLsattr(out string) map[string]string {
	res := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		name, value, _ := strings.Cut(line, " ")
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		res[name] = strings.TrimSpace(value)
	}
	return res
}
