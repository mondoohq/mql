// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package crontab

import (
	"bufio"
	"io"
	"strings"
)

// Entry represents a single crontab entry
type Entry struct {
	LineNumber int
	Minute     string
	Hour       string
	DayOfMonth string
	Month      string
	DayOfWeek  string
	User       string
	Command    string
}

// ParseCrontab parses a crontab file content and returns the entries.
// If hasUserField is true, it expects the user field after the time fields
// (system crontab format). Otherwise, it parses user crontab format.
func ParseCrontab(r io.Reader, hasUserField bool) ([]Entry, error) {
	return parseCrontab(r, hasUserField, noLogPrefixNone)
}

// ParseCronieCrontab parses a crontab the way cronie reads it. cronie lets a
// privileged crontab (a system crontab, or root's own) start an entry with
// "-", which only stops cron from logging the command to syslog: SUSE's
// /etc/crontab runs run-crons as `-*/15 * * * *`. An unprivileged user's
// crontab may not, and cronie refuses such a line.
func ParseCronieCrontab(r io.Reader, hasUserField bool, privileged bool) ([]Entry, error) {
	if privileged {
		return parseCrontab(r, hasUserField, noLogPrefixStrip)
	}
	return parseCrontab(r, hasUserField, noLogPrefixRefuse)
}

// noLogPrefix says what a leading "-" on an entry means.
type noLogPrefix int

const (
	// noLogPrefixNone reads the "-" as part of the minute field
	noLogPrefixNone noLogPrefix = iota
	// noLogPrefixStrip drops the "-" and reads the entry after it
	noLogPrefixStrip
	// noLogPrefixRefuse leaves out an entry that starts with "-"
	noLogPrefixRefuse
)

func parseCrontab(r io.Reader, hasUserField bool, dash noLogPrefix) ([]Entry, error) {
	var entries []Entry

	scanner := bufio.NewScanner(r)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip environment variable assignments (e.g., SHELL=/bin/bash)
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "@") {
			// Check if this looks like a variable assignment (key=value without spaces before =)
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 && !strings.ContainsAny(parts[0], " \t") {
				continue
			}
		}

		if strings.HasPrefix(line, "-") {
			switch dash {
			case noLogPrefixStrip:
				line = line[1:]
			case noLogPrefixRefuse:
				continue
			}
		}

		entry, ok := parseLine(line, lineNumber, hasUserField)
		if ok {
			entries = append(entries, entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// parseLine parses a single crontab line and returns an Entry
func parseLine(line string, lineNumber int, hasUserField bool) (Entry, bool) {
	entry := Entry{LineNumber: lineNumber}

	// Handle special time strings (@reboot, @hourly, etc.)
	if strings.HasPrefix(line, "@") {
		return parseSpecialLine(line, lineNumber, hasUserField)
	}

	// Standard crontab format: min hour dom mon dow [user] command
	// We need to parse fields but preserve original whitespace in the command
	numFieldsBeforeCommand := 5 // min hour dom mon dow
	if hasUserField {
		numFieldsBeforeCommand = 6 // min hour dom mon dow user
	}

	// Extract the schedule fields and optionally the user field
	remaining := line
	var fields []string
	for i := 0; i < numFieldsBeforeCommand; i++ {
		remaining = strings.TrimLeft(remaining, " \t")
		if remaining == "" {
			return entry, false
		}
		idx := strings.IndexAny(remaining, " \t")
		if idx == -1 {
			// No more whitespace, but we need more fields
			return entry, false
		}
		fields = append(fields, remaining[:idx])
		remaining = remaining[idx:]
	}

	// The command is everything remaining after trimming leading whitespace
	command := strings.TrimLeft(remaining, " \t")
	if command == "" {
		return entry, false
	}

	entry.Minute = fields[0]
	entry.Hour = fields[1]
	entry.DayOfMonth = fields[2]
	entry.Month = fields[3]
	entry.DayOfWeek = fields[4]

	if hasUserField {
		entry.User = fields[5]
	}
	entry.Command = command

	return entry, true
}

// parseSpecialLine parses lines with special time strings like @reboot, @hourly, etc.
func parseSpecialLine(line string, lineNumber int, hasUserField bool) (Entry, bool) {
	entry := Entry{LineNumber: lineNumber}

	// Parse fields while preserving command whitespace
	numFieldsBeforeCommand := 1 // @special
	if hasUserField {
		numFieldsBeforeCommand = 2 // @special user
	}

	remaining := line
	var fields []string
	for i := 0; i < numFieldsBeforeCommand; i++ {
		remaining = strings.TrimLeft(remaining, " \t")
		if remaining == "" {
			return entry, false
		}
		idx := strings.IndexAny(remaining, " \t")
		if idx == -1 {
			// No more whitespace, but we need more fields
			return entry, false
		}
		fields = append(fields, remaining[:idx])
		remaining = remaining[idx:]
	}

	command := strings.TrimLeft(remaining, " \t")
	if command == "" {
		return entry, false
	}

	// Map special strings to their crontab equivalents for display
	special := fields[0]
	switch special {
	case "@reboot":
		entry.Minute = "@reboot"
		entry.Hour = ""
		entry.DayOfMonth = ""
		entry.Month = ""
		entry.DayOfWeek = ""
	case "@yearly", "@annually":
		entry.Minute = "0"
		entry.Hour = "0"
		entry.DayOfMonth = "1"
		entry.Month = "1"
		entry.DayOfWeek = "*"
	case "@monthly":
		entry.Minute = "0"
		entry.Hour = "0"
		entry.DayOfMonth = "1"
		entry.Month = "*"
		entry.DayOfWeek = "*"
	case "@weekly":
		entry.Minute = "0"
		entry.Hour = "0"
		entry.DayOfMonth = "*"
		entry.Month = "*"
		entry.DayOfWeek = "0"
	case "@daily", "@midnight":
		entry.Minute = "0"
		entry.Hour = "0"
		entry.DayOfMonth = "*"
		entry.Month = "*"
		entry.DayOfWeek = "*"
	case "@hourly":
		entry.Minute = "0"
		entry.Hour = "*"
		entry.DayOfMonth = "*"
		entry.Month = "*"
		entry.DayOfWeek = "*"
	default:
		// Unknown special string, store as-is
		entry.Minute = special
		entry.Hour = ""
		entry.DayOfMonth = ""
		entry.Month = ""
		entry.DayOfWeek = ""
	}

	if hasUserField {
		entry.User = fields[1]
	}
	entry.Command = command

	return entry, true
}
