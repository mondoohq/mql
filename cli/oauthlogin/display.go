// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// maxDisplayLen caps a server-provided string shown in the terminal.
const maxDisplayLen = 512

// DisplayText prepares a string received from the server for printing in the
// terminal: control characters (including escape sequences' ESC) and
// bidirectional formatting characters are removed, and the length is capped.
func DisplayText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || isBidiControl(r) {
			return -1
		}
		return r
	}, s)
	return truncateUTF8(strings.TrimSpace(s), maxDisplayLen)
}

// isBidiControl reports whether r changes the direction of the text that
// follows it.
func isBidiControl(r rune) bool {
	switch {
	case r == '؜', r == '‎', r == '‏':
		return true
	case r >= '‪' && r <= '‮':
		return true
	case r >= '⁦' && r <= '⁩':
		return true
	}
	return false
}

// CheckServerURL checks a URL the server returned for the CLI to show, open
// or use: it must be an absolute https URL, or http to a loopback host.
// insecure also allows http to other hosts, as for the server endpoint.
func CheckServerURL(raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", DisplayText(raw), err)
	}
	if !u.IsAbs() || u.Host == "" || u.User != nil {
		return fmt.Errorf("%q is not an absolute URL without user info", DisplayText(raw))
	}
	if strings.IndexFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) || isBidiControl(r) }) >= 0 {
		return fmt.Errorf("%q contains characters that are not allowed in a URL", DisplayText(raw))
	}
	return checkTransport(raw, insecure, false)
}
