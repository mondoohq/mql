// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package masterpasswd parses the BSD password database source
// /etc/master.passwd, as described in master.passwd(5) on FreeBSD,
// DragonFly, OpenBSD and NetBSD.
package masterpasswd

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// fieldCount is the number of colon-separated fields in a master.passwd
// entry: name:password:uid:gid:class:change:expire:gecos:home_dir:shell.
const fieldCount = 10

// LockedPrefix is what `pw lock` (FreeBSD, DragonFly) puts in front of the
// password hash. The hash stays intact behind it, so unlocking restores it.
const LockedPrefix = "*LOCKED*"

// Entry is one account from master.passwd.
type Entry struct {
	// Line is the 1-indexed line number the entry was read from.
	Line     int
	User     string
	Password string
	UID      int64
	GID      int64
	Class    string
	// Change is the time by which the password must be changed. Nil when the
	// field is 0 or empty, which means never.
	Change *time.Time
	// Expire is the time the account expires. Nil when the field is 0 or
	// empty, which means never.
	Expire *time.Time
	Gecos  string
	Home   string
	Shell  string
}

// Locked reports whether the account is locked with `pw lock`.
func (e Entry) Locked() bool {
	return strings.HasPrefix(e.Password, LockedPrefix)
}

// HasPassword reports whether the password field holds a usable hash: not
// empty (no password), not starting with `*` (no password login, which also
// covers `*LOCKED*`) and not `!`.
func (e Entry) HasPassword() bool {
	p := e.Password
	if p == "" || strings.HasPrefix(p, "*") || strings.HasPrefix(p, "!") {
		return false
	}
	return true
}

// LineError describes a line that could not be parsed.
type LineError struct {
	Line   int
	Reason string
}

func (e LineError) Error() string {
	return fmt.Sprintf("master.passwd line %d: %s", e.Line, e.Reason)
}

// Parse reads master.passwd content. Comments (lines starting with `#`) and
// blank lines are skipped. A line that does not have exactly ten fields, or
// whose uid, gid, change or expire is not a number, is skipped and returned
// in the second result instead of being guessed at: a bad uid must never
// read as 0, which is root.
func Parse(r io.Reader) ([]Entry, []LineError, error) {
	var entries []Entry
	var invalid []LineError

	scanner := bufio.NewScanner(r)
	// GECOS fields and hashes are short, but do not fail on a long line.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) != fieldCount {
			invalid = append(invalid, LineError{Line: lineNo, Reason: fmt.Sprintf("expected %d fields, got %d", fieldCount, len(fields))})
			continue
		}
		if fields[0] == "" {
			invalid = append(invalid, LineError{Line: lineNo, Reason: "empty user name"})
			continue
		}

		uid, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			invalid = append(invalid, LineError{Line: lineNo, Reason: fmt.Sprintf("invalid uid %q", fields[2])})
			continue
		}
		gid, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			invalid = append(invalid, LineError{Line: lineNo, Reason: fmt.Sprintf("invalid gid %q", fields[3])})
			continue
		}
		change, err := parseEpoch(fields[5])
		if err != nil {
			invalid = append(invalid, LineError{Line: lineNo, Reason: fmt.Sprintf("invalid change %q", fields[5])})
			continue
		}
		expire, err := parseEpoch(fields[6])
		if err != nil {
			invalid = append(invalid, LineError{Line: lineNo, Reason: fmt.Sprintf("invalid expire %q", fields[6])})
			continue
		}

		entries = append(entries, Entry{
			Line:     lineNo,
			User:     fields[0],
			Password: fields[1],
			UID:      uid,
			GID:      gid,
			Class:    fields[4],
			Change:   change,
			Expire:   expire,
			Gecos:    fields[7],
			Home:     fields[8],
			Shell:    fields[9],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return entries, invalid, nil
}

// parseEpoch reads a change or expire field: seconds since the epoch, where
// empty and 0 mean never.
func parseEpoch(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	t := time.Unix(n, 0).UTC()
	return &t, nil
}
