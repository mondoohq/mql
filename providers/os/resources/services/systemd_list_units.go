// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"strings"
	"unicode/utf8"
)

// systemdListUnitsJobColumn returns where the JOB column starts in
// `systemctl list-units` output, counted in characters from the start of the
// line, or -1 when there is none. systemctl adds the column between SUB and
// DESCRIPTION only while some unit has a queued job (a unit that is
// activating or stopping):
//
//	UNIT                LOAD      ACTIVE     SUB     JOB   DESCRIPTION
//	g04-slow.service    loaded    activating start   start g04 slow start job
func systemdListUnitsJobColumn(content string) int {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "UNIT" || fields[1] != "LOAD" {
			continue
		}
		idx := strings.Index(line, " JOB ")
		if idx < 0 {
			return -1
		}
		return utf8.RuneCountInString(line[:idx+1])
	}
	return -1
}

// systemdListUnitsDescription returns the description of a list-units row
// matched by SYSTEMD_LIST_UNITS_REGEX, leaving out the row's job when the
// output has a JOB column (see systemdListUnitsJobColumn). The regex takes
// everything after SUB as the description, job included.
func systemdListUnitsDescription(match []string, jobCol int) string {
	desc := strings.TrimSpace(match[5])
	if jobCol < 0 {
		return desc
	}
	// the "●" that marks a failed unit takes the place of the header's
	// leading spaces, so counting characters keeps the columns aligned
	row := []rune(match[0])
	if jobCol >= len(row) || row[jobCol] == ' ' {
		return desc
	}
	_, rest, _ := strings.Cut(desc, " ")
	return strings.TrimSpace(rest)
}
