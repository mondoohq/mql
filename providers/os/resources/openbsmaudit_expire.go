// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"math"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// The expire-after grammar is the one libbsm's getacexpire(3) reads, and the
// helpers below mirror it rather than the man page, which describes less than
// the parser accepts:
//
//	sscanf(str, "%lu%c%[ \tadnorADNOR]%lu%c", &val1, &mult1, andor, &val2, &mult2)
//
// One term is a number plus the character right after it (no character means
// bytes). Two terms need the joining run of spaces, tabs and the letters of
// AND/OR, a second number and its suffix. Anything after the parsed terms is
// ignored. An upper-case suffix or a space is a size, anything else an age;
// an unknown suffix makes the whole value invalid, and auditd then expires
// nothing. A second term of the same kind overwrites the first, and a zero
// threshold is skipped when trails are expired.

// auditExpireAfter is expire-after as auditd holds it after getacexpire.
type auditExpireAfter struct {
	// ageSeconds is the age threshold, nil when no term set one
	ageSeconds *int64
	// bytes is the size threshold, nil when no term set one
	bytes *int64
	// operator is "AND" or "OR" for two terms, "" for one
	operator string
}

const (
	secondsPerDay       = int64(24 * 60 * 60)
	auditExpireAfterKey = "expire-after"
)

// auditControlValue returns the value of the first line whose key is name,
// the way libbsm's getstrfromtype_locked finds it. Only the first matching
// line counts. A line is a comment only when `#` is its first character, and
// the key must match exactly, so a key with leading whitespace does not match.
//
// Upstream OpenBSM (FreeBSD) strips trailing spaces and tabs from the line and
// returns everything after the first colon. Apple's fork strips only the
// newline and returns the next colon-delimited token, failing when there is
// none. ok is false when the key is absent or its line cannot be read.
func auditControlValue(content string, name string, apple bool) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !apple {
			line = strings.TrimRight(line, " \t")
		}

		// strtok_r(line, ":") skips leading delimiters, and a line of only
		// delimiters yields no token
		rest := strings.TrimLeft(line, ":")
		if rest == "" {
			continue
		}
		key, value, _ := strings.Cut(rest, ":")
		if key != name {
			continue
		}

		if !apple {
			return value, true
		}
		value = strings.TrimLeft(value, ":")
		if value == "" {
			return "", false
		}
		value, _, _ = strings.Cut(value, ":")
		return value, true
	}
	return "", false
}

// isCSpace reports whether c is whitespace in the C locale, which is what
// %lu skips before a number.
func isCSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// scanAuditUlong reads a %lu conversion starting at i. It returns the index
// after the digits. A minus sign is rejected rather than wrapped around as
// strtoul would, since the resulting threshold means nothing, and so is a
// number too large for int64.
func scanAuditUlong(s string, i int) (int64, int, bool) {
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	if i < len(s) && s[i] == '-' {
		return 0, i, false
	}
	if i < len(s) && s[i] == '+' {
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0, i, false
	}
	v, err := strconv.ParseInt(s[start:i], 10, 64)
	if err != nil {
		return 0, i, false
	}
	return v, i, true
}

// checkedMul multiplies two non-negative values, reporting overflow.
func checkedMul(a int64, b int64) (int64, bool) {
	if a != 0 && b > math.MaxInt64/a {
		return 0, false
	}
	return a * b, true
}

// auditAgeSeconds mirrors libbsm's au_timetosec. A year is 364 days, plus one
// day for every fourth year.
func auditAgeSeconds(value int64, unit byte) (int64, bool) {
	switch unit {
	case 's':
		return value, true
	case 'h':
		return checkedMul(value, 60*60)
	case 'd':
		return checkedMul(value, secondsPerDay)
	case 'y':
		days, ok := checkedMul(value, 364)
		if !ok || days > math.MaxInt64-value/4 {
			return 0, false
		}
		return checkedMul(days+value/4, secondsPerDay)
	}
	return 0, false
}

// auditSizeBytes mirrors libbsm's au_spacetobytes. A space means bytes.
func auditSizeBytes(value int64, unit byte) (int64, bool) {
	switch unit {
	case 'B', ' ':
		return value, true
	case 'K':
		return checkedMul(value, 1024)
	case 'M':
		return checkedMul(value, 1024*1024)
	case 'G':
		return checkedMul(value, 1024*1024*1024)
	}
	return 0, false
}

// set mirrors libbsm's setexpirecond: an upper-case suffix or a space is a
// size, anything else an age. A later term of the same kind overwrites an
// earlier one.
func (e *auditExpireAfter) set(value int64, unit byte) bool {
	if (unit >= 'A' && unit <= 'Z') || unit == ' ' {
		b, ok := auditSizeBytes(value, unit)
		if !ok {
			return false
		}
		e.bytes = &b
		return true
	}
	secs, ok := auditAgeSeconds(value, unit)
	if !ok {
		return false
	}
	e.ageSeconds = &secs
	return true
}

// parseAuditExpireAfter parses an expire-after value the way getacexpire
// does. It returns nil for any value auditd rejects.
func parseAuditExpireAfter(value string) *auditExpireAfter {
	s := strings.TrimLeft(value, " \t")
	res := &auditExpireAfter{}

	v1, i, ok := scanAuditUlong(s, 0)
	if !ok {
		return nil
	}
	if i == len(s) {
		// a number alone is bytes
		if !res.set(v1, 'B') {
			return nil
		}
		return res
	}
	unit1 := s[i]
	i++

	j := i
	for j < len(s) && strings.IndexByte(" \tadnorADNOR", s[j]) >= 0 {
		j++
	}
	if j == i {
		// one term, anything after it is ignored
		if !res.set(v1, unit1) {
			return nil
		}
		return res
	}
	joiner := s[i:j]

	v2, k, ok := scanAuditUlong(s, j)
	if !ok || k == len(s) {
		// a joiner with no second term, or a second number with no suffix
		return nil
	}
	unit2 := s[k]

	if !res.set(v1, unit1) || !res.set(v2, unit2) {
		return nil
	}

	joiner = strings.ToLower(joiner)
	switch {
	case strings.Contains(joiner, "and"):
		res.operator = "AND"
	case strings.Contains(joiner, "or"):
		res.operator = "OR"
	default:
		return nil
	}
	return res
}

// activeAge is the age threshold auditd applies, nil when none or zero.
func (e *auditExpireAfter) activeAge() *int64 {
	if e.ageSeconds == nil || *e.ageSeconds == 0 {
		return nil
	}
	return e.ageSeconds
}

// activeBytes is the size threshold auditd applies, nil when none or zero.
func (e *auditExpireAfter) activeBytes() *int64 {
	if e.bytes == nil || *e.bytes == 0 {
		return nil
	}
	return e.bytes
}

// retention returns the age and aggregate size auditd is guaranteed to keep
// trail files for, following auditd_expire_trails. With AND a file goes only
// once both active thresholds are exceeded, so each one is a floor on its own.
// With OR, or a single threshold, a file goes as soon as any active threshold
// is exceeded, so a floor exists only for a dimension no other threshold can
// undercut. A nil result means no floor in that dimension.
func (e *auditExpireAfter) retention() (*int64, *int64) {
	age := e.activeAge()
	size := e.activeBytes()
	if age != nil && size != nil && e.operator != "AND" {
		return nil, nil
	}
	return age, size
}

func (s *mqlOpenBSMAudit) isAppleAuditd() bool {
	if s.MqlRuntime == nil {
		return false
	}
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return false
	}
	return conn.Asset().Platform.IsFamily("darwin")
}

func (s *mqlOpenBSMAudit) expireAfterSetting(content string) *auditExpireAfter {
	value, ok := auditControlValue(content, auditExpireAfterKey, s.isAppleAuditd())
	if !ok {
		return nil
	}
	return parseAuditExpireAfter(value)
}

func auditDuration(seconds int64) *time.Time {
	return MqlTime(llx.DurationToTime(seconds))
}

func (s *mqlOpenBSMAudit) expireAfterAge(content string) (*time.Time, error) {
	e := s.expireAfterSetting(content)
	if e == nil || e.ageSeconds == nil {
		s.ExpireAfterAge.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return auditDuration(*e.ageSeconds), nil
}

func (s *mqlOpenBSMAudit) expireAfterBytes(content string) (int64, error) {
	e := s.expireAfterSetting(content)
	if e == nil || e.bytes == nil {
		s.ExpireAfterBytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *e.bytes, nil
}

func (s *mqlOpenBSMAudit) expireAfterOperator(content string) (string, error) {
	e := s.expireAfterSetting(content)
	if e == nil || e.operator == "" {
		s.ExpireAfterOperator.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return e.operator, nil
}

func (s *mqlOpenBSMAudit) minRetentionAge(content string) (*time.Time, error) {
	e := s.expireAfterSetting(content)
	if e != nil {
		if age, _ := e.retention(); age != nil {
			return auditDuration(*age), nil
		}
	}
	s.MinRetentionAge.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (s *mqlOpenBSMAudit) minRetentionBytes(content string) (int64, error) {
	e := s.expireAfterSetting(content)
	if e != nil {
		if _, size := e.retention(); size != nil {
			return *size, nil
		}
	}
	s.MinRetentionBytes.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}
