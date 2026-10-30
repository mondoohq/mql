// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"strings"
)

// Banners holds the login and message-of-the-day banner text.
//
// EOS renders banners in running-config as a header line followed by the
// literal banner body and an `EOF` terminator:
//
//	banner login
//	Authorized users only. All activity is monitored.
//	EOF
//	banner motd
//	   ****************************
//	   *  Restricted system       *
//	   ****************************
//	EOF
//
// The login banner is shown before authentication and is what notice-and-
// consent requirements are checked against; the MOTD banner is shown after.
// An empty string means no banner text is configured.
type Banners struct {
	Login string
	Motd  string
}

// ParseBanners extracts the login and MOTD banner bodies from running-config.
//
// Banner bodies are captured verbatim, including leading whitespace, because
// the indentation is part of the displayed text rather than config nesting.
// That also means the body must be read from the raw lines: the indentation
// heuristics the section parsers use do not apply inside a banner.
func ParseBanners(runningConfig string) *Banners {
	b := &Banners{}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := scanner.Text()
		var target *string
		switch strings.TrimSpace(line) {
		case "banner login":
			target = &b.Login
		case "banner motd":
			target = &b.Motd
		case "no banner login":
			b.Login = ""
			continue
		case "no banner motd":
			b.Motd = ""
			continue
		default:
			continue
		}

		// Collect the body verbatim until the EOF terminator. A config that
		// ends mid-banner (truncated capture) simply yields what was read.
		body := []string{}
		for scanner.Scan() {
			bodyLine := scanner.Text()
			if strings.TrimSpace(bodyLine) == "EOF" {
				break
			}
			body = append(body, bodyLine)
		}
		*target = strings.Join(body, "\n")
	}

	return b
}

// StripBanners replaces every banner body with blank lines, leaving the rest
// of the running-config and its line numbering untouched.
//
// A banner body is arbitrary operator-authored text sitting at column 0 in the
// same namespace every command parser scans, and operational banners routinely
// quote configuration ("do not run: no aaa root"). Scanned as config it cuts
// both ways: a quoted line can invent a setting the device does not have, and
// because several parsers are last-write-wins, one appearing after the real
// line can overwrite the device's true value. Neither shows up as an error.
//
// ParseBanners itself reads the raw text; everything else should read this.
func StripBanners(runningConfig string) string {
	var out strings.Builder

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := scanner.Text()
		out.WriteString(line)
		out.WriteByte('\n')

		switch strings.TrimSpace(line) {
		case "banner login", "banner motd":
		default:
			continue
		}

		// Blank out the body up to and including the EOF terminator, so the
		// stripped config keeps the same number of lines as the original.
		for scanner.Scan() {
			body := scanner.Text()
			if strings.TrimSpace(body) == "EOF" {
				out.WriteString(body)
				out.WriteByte('\n')
				break
			}
			out.WriteByte('\n')
		}
	}

	return out.String()
}
