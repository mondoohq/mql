// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jboss

import "strings"

// User is an entry of a realm's users properties file.
//
// The stored password hash is deliberately not carried. Nothing a
// configuration review asks needs the credential itself, and a resource that
// returned it would copy every management password hash on the host into a
// report.
type User struct {
	Username    string
	HasPassword bool
	Roles       []string
}

// ParseUsers reads a mgmt-users.properties or application-users.properties
// file and joins it with the matching roles or groups file.
//
// The format is a Java properties file, but a JBoss user name is allowed to
// contain characters the properties format escapes — a backslash before an
// equals sign, a space or a colon — because add-user.sh writes it that way.
// The escapes are undone so that the name reads as the administrator typed it.
//
// The realm the file belongs to is written into the header as
// `$REALM_NAME=ManagementRealm$`, which is a comment line, so the realm is
// taken from the caller rather than guessed here.
func ParseUsers(usersContent string, rolesContent string) []User {
	roles := parseRoleAssignments(rolesContent)

	res := []User{}
	for _, entry := range parseProperties(usersContent) {
		user := User{
			Username:    entry.key,
			HasPassword: entry.value != "",
			Roles:       []string{},
		}
		if assigned, ok := roles[entry.key]; ok {
			user.Roles = assigned
		}
		res = append(res, user)
	}
	return res
}

func parseRoleAssignments(content string) map[string][]string {
	res := map[string][]string{}
	for _, entry := range parseProperties(content) {
		roles := []string{}
		for role := range strings.SplitSeq(entry.value, ",") {
			role = strings.TrimSpace(role)
			if role != "" {
				roles = append(roles, role)
			}
		}
		res[entry.key] = roles
	}
	return res
}

type propertyEntry struct {
	key   string
	value string
}

// parseProperties reads a Java properties file into key/value pairs.
//
// Only the parts of the format JBoss actually writes are handled: comments
// introduced by # or !, the three separators (= : whitespace), backslash
// escapes in the key, and a backslash at the end of a line continuing it.
func parseProperties(content string) []propertyEntry {
	res := []propertyEntry{}

	var pending strings.Builder
	for raw := range strings.SplitSeq(content, "\n") {
		line := strings.TrimRight(raw, "\r")

		if pending.Len() == 0 {
			trimmed := strings.TrimLeft(line, " \t\f")
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
				continue
			}
			line = trimmed
		}

		// A line ending in an odd number of backslashes continues on the next
		// one. An even number is an escaped backslash and ends the line.
		if trailingBackslashes(line)%2 == 1 {
			pending.WriteString(line[:len(line)-1])
			continue
		}
		pending.WriteString(line)

		key, value := splitProperty(pending.String())
		pending.Reset()
		if key == "" {
			continue
		}
		res = append(res, propertyEntry{key: key, value: value})
	}

	if pending.Len() > 0 {
		if key, value := splitProperty(pending.String()); key != "" {
			res = append(res, propertyEntry{key: key, value: value})
		}
	}

	return res
}

func trailingBackslashes(line string) int {
	n := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		n++
	}
	return n
}

// splitProperty cuts a properties line at its first unescaped separator and
// unescapes the key.
func splitProperty(line string) (string, string) {
	var key strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) {
			i++
			key.WriteByte(unescapeProperty(line[i]))
			continue
		}
		if c == '=' || c == ':' || c == ' ' || c == '\t' {
			value := strings.TrimLeft(line[i:], " \t")
			value = strings.TrimLeft(value, "=:")
			return strings.TrimSpace(key.String()), strings.TrimSpace(value)
		}
		key.WriteByte(c)
	}
	return strings.TrimSpace(key.String()), ""
}

func unescapeProperty(c byte) byte {
	switch c {
	case 't':
		return '\t'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 'f':
		return '\f'
	default:
		return c
	}
}
