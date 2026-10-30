// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudoers

import "strings"

// StripComment removes a sudoers comment from line and returns the rest with
// surrounding whitespace trimmed, or "" for a line that is all comment.
//
// As in sudo's lexer, a '#' starts a comment anywhere on the line unless it
// is escaped with a backslash, sits inside double quotes, or is followed by a
// digit (or by '-' and a digit), which makes it a numeric uid or gid such as
// `#1000` or `%#1000`. The #include and #includedir directives are not
// comments and are returned unchanged.
//
// Stock SUSE sudoers files end the rule granting every user full sudo access
// with a comment (`ALL ALL=(ALL) ALL # WARNING! ...`), so keeping the comment
// would put it inside the parsed command.
func StripComment(line string) string {
	line = strings.TrimSpace(line)
	if IncludeRegex.MatchString(line) || IncludedirRegex.MatchString(line) {
		return line
	}

	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++ // the escaped character is literal
		case '"':
			inQuote = !inQuote
		case '#':
			if inQuote || isNumericID(line[i+1:]) {
				continue
			}
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

// isNumericID reports whether the text after a '#' makes it a numeric id:
// a digit, or '-' followed by a digit.
func isNumericID(rest string) bool {
	if rest != "" && rest[0] == '-' {
		rest = rest[1:]
	}
	return rest != "" && rest[0] >= '0' && rest[0] <= '9'
}
