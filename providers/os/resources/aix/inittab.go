// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"bufio"
	"io"
	"strings"
)

// InittabEntry is one line of /etc/inittab: identifier, run levels, action
// and command.
type InittabEntry struct {
	ID        string
	RunLevels string
	Action    string
	Command   string
}

// ParseInittab reads /etc/inittab. A line starting with a colon is a
// comment, and so is everything after a # in the command.
func ParseInittab(r io.Reader) ([]InittabEntry, error) {
	var entries []InittabEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == ':' {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) != 4 {
			continue
		}
		command, _, _ := strings.Cut(parts[3], "#")
		entries = append(entries, InittabEntry{
			ID:        parts[0],
			RunLevels: parts[1],
			Action:    parts[2],
			Command:   strings.TrimSpace(command),
		})
	}
	return entries, scanner.Err()
}
