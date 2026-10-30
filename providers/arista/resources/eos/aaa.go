// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"regexp"
	"strings"
)

// TacacsServer is a single TACACS+ server the device authenticates against.
//
//	tacacs-server host 10.0.0.1 key 7 042B0F1C
//	tacacs-server host 10.0.0.2 vrf MGMT port 4949 timeout 10 single-connection
//	tacacs-server key 0 plaintextsecret
//	tacacs-server timeout 5
//
// Timeout and the key fields report the value in effect for the server: an
// option omitted from the host line falls back to the global
// `tacacs-server <option>` setting, which is how EOS resolves it. Reporting
// only what appears on the host line would call a globally keyed server
// unkeyed.
//
// The shared secret itself is deliberately not captured. KeyConfigured says
// whether one exists and KeyEncryptionType says how it is stored, which is
// what an audit needs; the secret's value is not something to move off the
// device.
type TacacsServer struct {
	Host string
	// VRF is the routing instance used to reach the server. Empty means the
	// default VRF.
	VRF string
	// Port is the TACACS+ port (49 when unset).
	Port int
	// Timeout is the per-server timeout in seconds (0 = unset with no global
	// default configured).
	Timeout int
	// SingleConnection multiplexes sessions over one TCP connection.
	SingleConnection bool
	// KeyConfigured reports whether a shared secret is configured for this
	// server, either on its own line or globally.
	KeyConfigured bool
	// KeyEncryptionType is how the shared secret is stored: "0" is
	// cleartext in the running-config, "7" is the reversible type-7
	// obfuscation, and "8a" is a stronger hash. Empty when no key is
	// configured. This is a string because "8a" is not a number.
	KeyEncryptionType string
}

// RadiusServer is a single RADIUS server the device authenticates against.
//
//	radius-server host 10.0.0.5 key 7 042B0F1C
//	radius-server host 10.0.0.6 vrf MGMT auth-port 1645 acct-port 1646 retransmit 5
//
// The same effective-value and secret-handling rules as TacacsServer apply.
type RadiusServer struct {
	Host string
	// VRF is the routing instance used to reach the server. Empty means the
	// default VRF.
	VRF string
	// AuthPort is the authentication port (1812 when unset).
	AuthPort int
	// AcctPort is the accounting port (1813 when unset).
	AcctPort int
	// Timeout is the per-server timeout in seconds (0 = unset with no global
	// default configured).
	Timeout int
	// Retransmit is the retry count (0 = unset).
	Retransmit int
	// KeyConfigured reports whether a shared secret is configured for this
	// server, either on its own line or globally.
	KeyConfigured bool
	// KeyEncryptionType is how the shared secret is stored. See
	// TacacsServer.KeyEncryptionType.
	KeyEncryptionType string
}

// AaaServerGroup is a named set of AAA servers referenced by method lists.
//
//	aaa group server tacacs+ TACACS-GROUP
//	   server 10.0.0.1
//	   server 10.0.0.2 vrf MGMT
//
// Method lists name groups rather than hosts (`aaa authentication login
// default group TACACS-GROUP local`), so without the group membership a
// method list cannot be traced to the servers it actually reaches.
type AaaServerGroup struct {
	Name string
	// Protocol is "tacacs+" or "radius".
	Protocol string
	// Servers are the member server hosts, in configured order.
	Servers []string
}

var (
	aaaGroupServerRe = regexp.MustCompile(`^aaa group server\s+(\S+)\s+(\S+)$`)
	aaaGroupMemberRe = regexp.MustCompile(`^server\s+(\S+)`)
)

// keyEncryptionTypes are the encoding selectors EOS accepts after the `key`
// keyword. Anything else in that position is the secret itself, written
// without an explicit type.
var keyEncryptionTypes = map[string]bool{"0": true, "7": true, "8a": true}

// ParseTacacsServers extracts the TACACS+ servers from running-config,
// folding the global `tacacs-server key` and `tacacs-server timeout` defaults
// into each server so the fields report the value actually in effect.
func ParseTacacsServers(runningConfig string) []TacacsServer {
	servers := []TacacsServer{}
	globalTimeout := 0
	globalKeyConfigured := false
	globalKeyType := ""

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, "tacacs-server ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "timeout":
			if len(fields) > 1 {
				globalTimeout = atoiOrZero(fields[1])
			}
		case "key":
			globalKeyConfigured, globalKeyType = parseKeyClause(fields[1:])
		case "host":
			if len(fields) < 2 {
				continue
			}
			servers = append(servers, parseTacacsHostLine(fields[1:]))
		}
	}

	for i := range servers {
		if servers[i].Timeout == 0 {
			servers[i].Timeout = globalTimeout
		}
		if !servers[i].KeyConfigured && globalKeyConfigured {
			servers[i].KeyConfigured = true
			servers[i].KeyEncryptionType = globalKeyType
		}
	}
	return servers
}

// parseTacacsHostLine reads the tokens after `tacacs-server host`.
func parseTacacsHostLine(fields []string) TacacsServer {
	s := TacacsServer{
		Host: fields[0],
		// EOS falls back to the well-known TACACS+ port when the line omits it.
		Port: 49,
	}
	for i := 1; i < len(fields); i++ {
		next := ""
		if i+1 < len(fields) {
			next = fields[i+1]
		}
		switch fields[i] {
		case "vrf":
			s.VRF = next
			i++
		case "port":
			s.Port = atoiOrZero(next)
			i++
		case "timeout":
			s.Timeout = atoiOrZero(next)
			i++
		case "single-connection":
			s.SingleConnection = true
		case "key":
			s.KeyConfigured, s.KeyEncryptionType = parseKeyClause(fields[i+1:])
			// The secret is the last thing on the line; nothing after it is
			// config we should read.
			return s
		}
	}
	return s
}

// ParseRadiusServers extracts the RADIUS servers from running-config, folding
// in the global `radius-server key` and `radius-server timeout` defaults.
func ParseRadiusServers(runningConfig string) []RadiusServer {
	servers := []RadiusServer{}
	globalTimeout := 0
	globalKeyConfigured := false
	globalKeyType := ""

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, "radius-server ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "timeout":
			if len(fields) > 1 {
				globalTimeout = atoiOrZero(fields[1])
			}
		case "key":
			globalKeyConfigured, globalKeyType = parseKeyClause(fields[1:])
		case "host":
			if len(fields) < 2 {
				continue
			}
			servers = append(servers, parseRadiusHostLine(fields[1:]))
		}
	}

	for i := range servers {
		if servers[i].Timeout == 0 {
			servers[i].Timeout = globalTimeout
		}
		if !servers[i].KeyConfigured && globalKeyConfigured {
			servers[i].KeyConfigured = true
			servers[i].KeyEncryptionType = globalKeyType
		}
	}
	return servers
}

// parseRadiusHostLine reads the tokens after `radius-server host`.
func parseRadiusHostLine(fields []string) RadiusServer {
	s := RadiusServer{
		Host: fields[0],
		// EOS falls back to the well-known RADIUS ports when the line omits them.
		AuthPort: 1812,
		AcctPort: 1813,
	}
	for i := 1; i < len(fields); i++ {
		next := ""
		if i+1 < len(fields) {
			next = fields[i+1]
		}
		switch fields[i] {
		case "vrf":
			s.VRF = next
			i++
		case "auth-port":
			s.AuthPort = atoiOrZero(next)
			i++
		case "acct-port":
			s.AcctPort = atoiOrZero(next)
			i++
		case "timeout":
			s.Timeout = atoiOrZero(next)
			i++
		case "retransmit":
			s.Retransmit = atoiOrZero(next)
			i++
		case "key":
			s.KeyConfigured, s.KeyEncryptionType = parseKeyClause(fields[i+1:])
			return s
		}
	}
	return s
}

// parseKeyClause reads the tokens following a `key` keyword and reports
// whether a secret is present and how it is encoded. The secret itself is
// never returned.
func parseKeyClause(fields []string) (bool, string) {
	if len(fields) == 0 {
		return false, ""
	}
	if keyEncryptionTypes[fields[0]] {
		// An encoding selector with no secret after it is not a usable key.
		if len(fields) < 2 {
			return false, ""
		}
		return true, fields[0]
	}
	// A secret written without an explicit selector is stored in the clear.
	return true, "0"
}

// ParseAaaServerGroups extracts the named AAA server groups and their members.
func ParseAaaServerGroups(runningConfig string) []AaaServerGroup {
	groups := []AaaServerGroup{}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	var current *AaaServerGroup
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}

		// Group headers are top-level; members are the indented lines that
		// follow. Any other top-level line closes the group being read.
		if CountLeadingSpace(raw) == 0 {
			if current != nil {
				groups = append(groups, *current)
				current = nil
			}
			if m := aaaGroupServerRe.FindStringSubmatch(line); m != nil {
				current = &AaaServerGroup{
					Protocol: m[1],
					Name:     m[2],
					Servers:  []string{},
				}
			}
			continue
		}

		if current == nil {
			continue
		}
		if m := aaaGroupMemberRe.FindStringSubmatch(line); m != nil {
			current.Servers = append(current.Servers, m[1])
		}
	}
	if current != nil {
		groups = append(groups, *current)
	}

	return groups
}

// RootAccountState describes the `aaa root` account, the escape hatch that
// grants shell access to the underlying Linux system.
//
//	aaa root secret 5 $1$salt$hash    <- root has a password
//	aaa root nopassword               <- root logs in with no password
//	no aaa root                       <- root is disabled
//
// An absent `aaa root` line means the account is disabled, which is the
// shipped default and the posture most hardening guidance requires.
type RootAccountState struct {
	// Enabled is true when the root account can be logged into at all.
	Enabled bool
	// NoPassword is true when root authenticates with no password, the worst
	// of the three states.
	NoPassword bool
	// SecretFormat is the encoding selector on the secret, for example "5"
	// or "sha512". Empty when root has no secret configured. A line written
	// without a selector is cleartext, which EOS documents as equivalent to
	// "0", and is reported as "0". The secret itself is never captured.
	SecretFormat string
}

// aaaRootSecretRe captures only the first token after `secret`, which is what
// keeps the credential out of the result in both spellings of the line. With a
// selector (`aaa root secret sha512 <hash>`) the hash sits in the next token
// and is never captured at all; without one (`aaa root secret <password>`) the
// password lands in the capture group and is discarded by the selector check
// below rather than stored. Widening this regex would break that guarantee.
var aaaRootSecretRe = regexp.MustCompile(`^aaa root secret\s+(\S+)`)

// ParseRootAccount reports the state of the `aaa root` account.
func ParseRootAccount(runningConfig string) *RootAccountState {
	state := &RootAccountState{}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "no aaa root":
			state.Enabled = false
			state.NoPassword = false
			state.SecretFormat = ""
		case line == "aaa root nopassword":
			state.Enabled = true
			state.NoPassword = true
			state.SecretFormat = ""
		case strings.HasPrefix(line, "aaa root secret "):
			if m := aaaRootSecretRe.FindStringSubmatch(line); m != nil {
				state.Enabled = true
				state.NoPassword = false
				// The selector is optional. Taking the first token
				// positionally publishes the root password itself when the
				// line is written without one, so a token that is not a
				// known selector is the secret: report the line as cleartext
				// and let the captured value go.
				if passwordSecretSelectors[m[1]] {
					state.SecretFormat = m[1]
				} else {
					state.SecretFormat = "0"
				}
			}
		}
	}

	return state
}
