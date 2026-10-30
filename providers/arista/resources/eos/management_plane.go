// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"strconv"
	"strings"
)

// SectionBody returns the body of a top-level running-config block with its
// indentation intact, so callers can tell a line in the block itself from a
// line in a nested sub-block.
//
// GetSection flattens every descendant onto one level, which loses exactly
// that distinction: in
//
//	management ssh
//	   shutdown
//	   vrf MGMT
//	      no shutdown
//
// the nested `no shutdown` governs the MGMT routing instance, not the
// default one, and a flattened read cannot separate the two.
//
// The body runs from the line after the header to the next line at column 0.
// Comment lines and the trailing `end` marker are dropped. An absent header
// yields an empty string.
func SectionBody(runningConfig, header string) string {
	var body strings.Builder
	inSection := false

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") || line == "end" {
			continue
		}

		if CountLeadingSpace(raw) == 0 {
			if inSection {
				break
			}
			if line == header {
				inSection = true
			}
			continue
		}
		if inSection {
			body.WriteString(raw)
			body.WriteByte('\n')
		}
	}
	return body.String()
}

// eachSubBlock walks an indented section body produced by SectionBody and
// invokes fn once per line that sits at the body's own outermost level,
// passing that line and the block indented beneath it. A line with nothing
// nested under it is reported with an empty block.
//
// The outermost level is taken from the first line rather than assumed to be
// three spaces, since EOS renders `show running-config` with three-space
// indentation but a configuration captured by other means may not.
func eachSubBlock(body string, fn func(line, block string)) {
	lines := strings.Split(body, "\n")

	baseIndent := -1
	for _, raw := range lines {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		baseIndent = CountLeadingSpace(raw)
		break
	}
	if baseIndent < 0 {
		return
	}

	current := ""
	var block strings.Builder
	flush := func() {
		if current != "" {
			fn(current, block.String())
		}
		current = ""
		block.Reset()
	}

	for _, raw := range lines {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if CountLeadingSpace(raw) <= baseIndent {
			flush()
			current = strings.TrimSpace(raw)
			continue
		}
		if current != "" {
			block.WriteString(strings.TrimSpace(raw))
			block.WriteByte('\n')
		}
	}
	flush()
}

// EnableSecretState reports the enable-mode password used for privilege
// escalation.
//
//	enable secret sha512 $6$salt$hash   <- escalation requires a password
//	enable secret 5 $1$salt$hash        <- MD5-crypt, a weak encoding
//	enable password 5 $1$salt$hash      <- the same command, current spelling
//	no enable secret                    <- no escalation password at all
//
// EOS documents `enable secret` and `enable password` as one command under
// two names, so both spellings are read.
//
// The password itself is never kept: only whether one is configured and how
// it is encoded, which is what the encoding-strength question needs and all
// it needs. Guarding that is the reason the encoding selector is matched
// against a closed set rather than taken positionally, since the selector is
// optional and the token in its place is otherwise the password.
type EnableSecretState struct {
	// Configured is true when an enable password is set and not negated.
	// When it is false, EOS does not prompt at all on `enable`, so any
	// authenticated account reaches privileged mode unchallenged.
	Configured bool
	// Format is the encoding selector: "0" for cleartext, "5" for
	// MD5-crypt, or "sha512". Empty when no password is configured. A line
	// written without a selector is cleartext, which EOS documents as
	// equivalent to "0", and is reported as "0".
	Format string
}

// passwordSecretSelectors is the closed set of encoding selectors EOS accepts
// on a password secret, shared by the `enable secret` and `aaa root secret`
// lines. The selector is optional on both, so a token outside this set is the
// password itself and must never be read as a format: doing so publishes the
// credential in a field every consumer treats as safe metadata.
//
// The set matches the one Arista's own eAPI library applies to the sibling
// `username <name> secret <selector> <value>` line. It is deliberately not
// keyEncryptionTypes: that covers the reversible encodings a shared secret
// can use, and a TACACS+ key cannot be stored as a hash.
var passwordSecretSelectors = map[string]bool{
	"0":      true,
	"5":      true,
	"7":      true,
	"sha512": true,
}

// ParseEnableSecret reports whether an enable-mode password is configured
// and how it is encoded.
func ParseEnableSecret(runningConfig string) *EnableSecretState {
	state := &EnableSecretState{}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		raw := scanner.Text()
		if CountLeadingSpace(raw) > 0 {
			continue
		}
		line := strings.TrimSpace(raw)

		negated := false
		if cut, ok := strings.CutPrefix(line, "no "); ok {
			negated = true
			line = cut
		}

		rest, ok := strings.CutPrefix(line, "enable secret")
		if !ok {
			rest, ok = strings.CutPrefix(line, "enable password")
		}
		if !ok {
			continue
		}
		// Guard against matching a longer command that merely starts the
		// same way.
		if rest != "" && !strings.HasPrefix(rest, " ") {
			continue
		}

		// A negation clears whatever an earlier line set.
		if negated {
			state.Configured = false
			state.Format = ""
			continue
		}

		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}

		state.Configured = true
		if passwordSecretSelectors[fields[0]] {
			state.Format = fields[0]
		} else {
			// No selector: the token is the password, and EOS documents the
			// bare form as equivalent to cleartext.
			state.Format = "0"
		}
	}

	return state
}

// ConsoleSettings captures the `management console` block, which governs the
// physically attached serial console.
//
//	management console
//	   idle-timeout 15
//
// The console is authorized separately from remote sessions, and an idle
// timeout is the only thing that ends a privileged session someone walked
// away from. EOS leaves the console idle-timeout unset by default, so an
// absent block means sessions never time out.
type ConsoleSettings struct {
	// Configured is true when a `management console` block exists in the
	// running-config.
	Configured bool
	// IdleTimeout is the console idle timeout in minutes. 0 means no
	// timeout, which is both the EOS default and the explicit
	// `idle-timeout 0` setting.
	IdleTimeout int
	// SessionTimeout is the absolute session timeout in minutes from
	// `timeout <minutes> warning <minutes>`, which ends a session whether or
	// not it is idle. 0 when unset.
	SessionTimeout int
	// SessionTimeoutWarning is the warning issued that many minutes before
	// the absolute timeout. 0 when unset.
	SessionTimeoutWarning int
}

// ParseConsoleSettings reads the `management console` block.
func ParseConsoleSettings(runningConfig string) *ConsoleSettings {
	c := &ConsoleSettings{}

	body := SectionBody(runningConfig, "management console")
	if body == "" {
		return c
	}
	c.Configured = true

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "idle-timeout "):
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "idle-timeout "))); err == nil {
				c.IdleTimeout = n
			}
		case strings.HasPrefix(line, "timeout "):
			// `timeout <minutes> warning <minutes>`
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					c.SessionTimeout = n
				}
			}
			if len(fields) >= 4 && fields[2] == "warning" {
				if n, err := strconv.Atoi(fields[3]); err == nil {
					c.SessionTimeoutWarning = n
				}
			}
		}
	}
	return c
}

// EapiContainment is the part of `management api http-commands` that decides
// who can reach eAPI, as opposed to which transports it speaks.
//
//	management api http-commands
//	   protocol https
//	   no shutdown
//	   session timeout 60 minutes
//	   !
//	   vrf MGMT
//	      no shutdown
//	      ip access-group ACL-API
//
// The transport state is already reported by `show management api
// http-commands`. What that command does not say is which routing instances
// the listener is reachable in, and eAPI in the default instance is reachable
// from the data plane.
type EapiContainment struct {
	// Configured is true when a `management api http-commands` block exists
	// in the running-config.
	Configured bool
	// Vrfs are the routing instances the block explicitly enables eAPI in,
	// via a nested `vrf <name>` sub-block that is not shut down. Empty when
	// the block names none.
	Vrfs []string
	// SessionTimeout is the `session timeout <n> minutes` value, after
	// which an authenticated eAPI session stops being usable. 0 when unset;
	// EOS ships 1440.
	SessionTimeout int
}

// ParseEapiContainment reads the containment settings of the eAPI block.
func ParseEapiContainment(runningConfig string) *EapiContainment {
	e := &EapiContainment{Vrfs: []string{}}

	body := SectionBody(runningConfig, "management api http-commands")
	if body == "" {
		return e
	}
	e.Configured = true

	eachSubBlock(body, func(line, block string) {
		if name, ok := strings.CutPrefix(line, "vrf "); ok {
			name = strings.TrimSpace(name)
			if name == "" {
				return
			}
			// A sub-block exists to enable eAPI in that instance, so it
			// counts unless it explicitly shuts it down.
			enabled := true
			for sub := range strings.SplitSeq(block, "\n") {
				switch strings.TrimSpace(sub) {
				case "shutdown", "default shutdown":
					enabled = false
				case "no shutdown":
					enabled = true
				}
			}
			if enabled {
				e.Vrfs = append(e.Vrfs, name)
			}
			return
		}

		// `session timeout <n> minutes`
		if rest, ok := strings.CutPrefix(line, "session timeout "); ok {
			fields := strings.Fields(rest)
			if len(fields) >= 1 {
				if n, err := strconv.Atoi(fields[0]); err == nil {
					e.SessionTimeout = n
				}
			}
		}
	})

	return e
}
