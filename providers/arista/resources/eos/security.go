// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

// AaaConfig captures Authentication, Authorization, and Accounting settings
// extracted from running-config.
//
// Arista EOS configures AAA via lines like:
//
//	aaa authentication login default group tacacs+ local
//	aaa authorization commands all default group tacacs+ local
//	aaa accounting exec default start-stop group tacacs+
//	tacacs-server host 10.0.0.1
//	radius-server host 10.0.0.2
//
// The methods slice for each block is the ordered list of authentication
// sources (e.g. ["group", "tacacs+", "local"]). The "local" method as a
// terminal fallback indicates control-plane access can succeed using the
// switch's local account database alone — usually an audit finding when
// remote AAA is required by policy.
type AaaConfig struct {
	// AuthenticationLogin holds method lists for "aaa authentication login"
	// keyed by list name (typically "default").
	AuthenticationLogin map[string][]string
	// AuthenticationEnable holds method lists for "aaa authentication enable".
	AuthenticationEnable map[string][]string
	// AuthorizationCommands holds method lists for "aaa authorization commands"
	// keyed by privilege level (or "all"+listName).
	AuthorizationCommands map[string][]string
	// AuthorizationConsoleCommands holds method lists for
	// "aaa authorization console commands", keyed the same way. The console is
	// authorized separately from remote sessions, so a device can require
	// TACACS+ command authorization over SSH while leaving the console
	// unauthorized.
	AuthorizationConsoleCommands map[string][]string
	// SerialConsoleAuthorization reflects `aaa authorization serial-console`,
	// which extends exec authorization to the serial console.
	SerialConsoleAuthorization bool
	// AuthorizationExec holds method lists for "aaa authorization exec".
	AuthorizationExec map[string][]string
	// AccountingCommands holds method lists for "aaa accounting commands".
	AccountingCommands map[string][]string
	// AccountingExec holds method lists for "aaa accounting exec".
	AccountingExec map[string][]string
	// DefaultLoginPermitsLocalOnly is true when the default authentication
	// list contains "local" with no `group` token preceding it — i.e. the
	// local user database is the only authentication source for the default
	// login list (control-plane could be reached without contacting remote
	// AAA).
	DefaultLoginPermitsLocalOnly bool
}

var (
	aaaAuthLoginRe = regexp.MustCompile(
		`^aaa authentication login\s+(\S+)\s+(.+)$`)
	aaaAuthEnableRe = regexp.MustCompile(
		`^aaa authentication enable\s+(\S+)\s+(.+)$`)
	aaaAuthzCommandsRe = regexp.MustCompile(
		`^aaa authorization commands\s+(\S+)\s+(\S+)\s+(.+)$`)
	aaaAuthzConsoleCommandsRe = regexp.MustCompile(
		`^aaa authorization console commands\s+(\S+)\s+(\S+)\s+(.+)$`)
	aaaAuthzExecRe = regexp.MustCompile(
		`^aaa authorization exec\s+(\S+)\s+(.+)$`)
	// Accounting lines have an action token (start-stop, stop-only, wait-start,
	// none) between the list name and the methods. When action is "none" there
	// are no method tokens, so the trailing methods group is optional.
	aaaAcctCommandsRe = regexp.MustCompile(
		`^aaa accounting commands\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.+))?$`)
	aaaAcctExecRe = regexp.MustCompile(
		`^aaa accounting exec\s+(\S+)\s+(\S+)(?:\s+(.+))?$`)
)

// ParseAaaConfig extracts AAA configuration from running-config.
// Comments (lines starting with "!") are ignored.
func ParseAaaConfig(runningConfig string) *AaaConfig {
	cfg := &AaaConfig{
		AuthenticationLogin:          map[string][]string{},
		AuthenticationEnable:         map[string][]string{},
		AuthorizationCommands:        map[string][]string{},
		AuthorizationConsoleCommands: map[string][]string{},
		AuthorizationExec:            map[string][]string{},
		AccountingCommands:           map[string][]string{},
		AccountingExec:               map[string][]string{},
	}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}

		if m := aaaAuthLoginRe.FindStringSubmatch(line); m != nil {
			cfg.AuthenticationLogin[m[1]] = strings.Fields(m[2])
			continue
		}
		if m := aaaAuthEnableRe.FindStringSubmatch(line); m != nil {
			cfg.AuthenticationEnable[m[1]] = strings.Fields(m[2])
			continue
		}
		if m := aaaAuthzConsoleCommandsRe.FindStringSubmatch(line); m != nil {
			cfg.AuthorizationConsoleCommands[m[1]+"/"+m[2]] = strings.Fields(m[3])
			continue
		}
		if m := aaaAuthzCommandsRe.FindStringSubmatch(line); m != nil {
			cfg.AuthorizationCommands[m[1]+"/"+m[2]] = strings.Fields(m[3])
			continue
		}
		if line == "aaa authorization serial-console" {
			cfg.SerialConsoleAuthorization = true
			continue
		}
		if m := aaaAuthzExecRe.FindStringSubmatch(line); m != nil {
			cfg.AuthorizationExec[m[1]] = strings.Fields(m[2])
			continue
		}
		if m := aaaAcctCommandsRe.FindStringSubmatch(line); m != nil {
			cfg.AccountingCommands[m[1]+"/"+m[2]] = strings.Fields(m[4])
			continue
		}
		if m := aaaAcctExecRe.FindStringSubmatch(line); m != nil {
			cfg.AccountingExec[m[1]] = strings.Fields(m[3])
			continue
		}
	}

	// DefaultLoginPermitsLocalOnly: methods in the "default" login list are
	// tried in order, so local authentication is reachable without a working
	// remote source whenever "local" appears before the first "group" (remote
	// AAA) method, or when there is no remote group at all. A "group" that
	// precedes "local" makes local a fallback, not the primary source, so it
	// does not count.
	if methods, ok := cfg.AuthenticationLogin["default"]; ok {
		for _, m := range methods {
			if m == "group" {
				break
			}
			if m == "local" {
				cfg.DefaultLoginPermitsLocalOnly = true
				break
			}
		}
	}

	return cfg
}

// SshSettings captures SSH server settings from `management ssh`.
//
// Real-world EOS output looks like:
//
//	management ssh
//	   ip access-group MGMT in
//	   idle-timeout 30
//	   server-port 22
//	   no shutdown
//	   authentication mode keyboard-interactive
//	   protocol version 2
//	   cipher aes256-gcm@openssh.com aes256-ctr
//	   key-exchange curve25519-sha256 ecdh-sha2-nistp521
//	   mac hmac-sha2-512-etm@openssh.com
//	   hostkey rsa key-size 4096
//
// Lines that aren't recognized are ignored.
type SshSettings struct {
	Enabled            bool
	ProtocolVersion    string
	IdleTimeout        int
	ServerPort         int
	AuthenticationMode string
	Ciphers            []string
	KeyExchange        []string
	Macs               []string
	HostkeyAlgorithms  []string
	FipsRestrictions   bool

	// The fields below are the containment controls: who may reach the
	// service, from which routing instances, and how hard it may be
	// hammered. The crypto suite above says nothing about any of them.

	// Vrfs are the routing instances the block explicitly enables SSH in,
	// via a nested `vrf <name>` sub-block that is not shut down. Empty when
	// the block names none, in which case SSH is reachable in the default
	// instance only.
	Vrfs []string
	// LoginTimeout is the `login timeout` value, the window a connection has
	// to complete authentication before it is dropped. 0 when unset; EOS
	// ships 120.
	LoginTimeout int
	// ConnectionLimit is the ceiling on concurrent SSH sessions
	// (`connection limit`). 0 means no configured ceiling.
	ConnectionLimit int
	// ConnectionPerHostLimit is the per-source-host session ceiling
	// (`connection per-host`), the bound that stops one host consuming the
	// whole allowance. 0 means no configured ceiling.
	ConnectionPerHostLimit int
	// EmptyPasswords reflects `authentication empty-passwords`, one of
	// "auto", "permit", or "deny". EOS defaults to "auto", which is what
	// this reports when the block does not set it.
	EmptyPasswords string
	// LogLevel is the SSH daemon log level (`log-level`). Empty when unset;
	// EOS ships "info".
	LogLevel string
	// ClientAliveInterval is the `client-alive interval` in seconds, and
	// ClientAliveCountMax the `client-alive count-max`. Together they end a
	// session whose peer has gone away. 0 when unset.
	ClientAliveInterval int
	ClientAliveCountMax int
}

func ParseSshSettings(runningConfig string) *SshSettings {
	s := &SshSettings{
		// EOS default: SSH enabled unless an explicit "shutdown" is present
		Enabled: true,
		// EOS default for `authentication empty-passwords`.
		EmptyPasswords: "auto",
		Vrfs:           []string{},
	}

	// SectionBody keeps the block's indentation so a nested `vrf` sub-block
	// stays distinguishable. A `no shutdown` inside one governs that routing
	// instance, not the service as a whole, and flattening the two together
	// would report a shut-down service as running.
	body := SectionBody(runningConfig, "management ssh")
	if body == "" {
		// No explicit `management ssh` section in the diffed running-config; can
		// still be on by default — leave Enabled=true and other fields empty.
		return s
	}

	eachSubBlock(body, func(line, block string) {
		if name, ok := strings.CutPrefix(line, "vrf "); ok {
			name = strings.TrimSpace(name)
			if name == "" {
				return
			}
			// A sub-block exists to enable the service in that instance, so
			// it counts unless it explicitly shuts it down.
			enabled := true
			for sub := range strings.SplitSeq(block, "\n") {
				switch strings.TrimSpace(sub) {
				case "shutdown":
					enabled = false
				case "no shutdown":
					enabled = true
				}
			}
			if enabled {
				s.Vrfs = append(s.Vrfs, name)
			}
			return
		}

		switch {
		case line == "shutdown":
			s.Enabled = false
		case line == "no shutdown":
			s.Enabled = true
		case strings.HasPrefix(line, "protocol version "):
			s.ProtocolVersion = strings.TrimSpace(strings.TrimPrefix(line, "protocol version "))
		case strings.HasPrefix(line, "idle-timeout "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "idle-timeout ")))
			if err == nil {
				s.IdleTimeout = n
			}
		case strings.HasPrefix(line, "server-port "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "server-port ")))
			if err == nil {
				s.ServerPort = n
			}
		case strings.HasPrefix(line, "login timeout "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "login timeout ")))
			if err == nil {
				s.LoginTimeout = n
			}
		case strings.HasPrefix(line, "connection limit "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "connection limit ")))
			if err == nil {
				s.ConnectionLimit = n
			}
		case strings.HasPrefix(line, "connection per-host "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "connection per-host ")))
			if err == nil {
				s.ConnectionPerHostLimit = n
			}
		case strings.HasPrefix(line, "client-alive interval "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "client-alive interval ")))
			if err == nil {
				s.ClientAliveInterval = n
			}
		case strings.HasPrefix(line, "client-alive count-max "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "client-alive count-max ")))
			if err == nil {
				s.ClientAliveCountMax = n
			}
		case strings.HasPrefix(line, "authentication empty-passwords "):
			s.EmptyPasswords = strings.TrimSpace(strings.TrimPrefix(line, "authentication empty-passwords "))
		case strings.HasPrefix(line, "log-level "):
			s.LogLevel = strings.TrimSpace(strings.TrimPrefix(line, "log-level "))
		case strings.HasPrefix(line, "authentication mode "):
			s.AuthenticationMode = strings.TrimSpace(strings.TrimPrefix(line, "authentication mode "))
		case strings.HasPrefix(line, "cipher "):
			s.Ciphers = strings.Fields(strings.TrimPrefix(line, "cipher "))
		case strings.HasPrefix(line, "key-exchange "):
			s.KeyExchange = strings.Fields(strings.TrimPrefix(line, "key-exchange "))
		case strings.HasPrefix(line, "mac "):
			s.Macs = strings.Fields(strings.TrimPrefix(line, "mac "))
		case strings.HasPrefix(line, "hostkey "):
			s.HostkeyAlgorithms = append(s.HostkeyAlgorithms, strings.TrimSpace(strings.TrimPrefix(line, "hostkey ")))
		case line == "fips restrictions":
			s.FipsRestrictions = true
		}
	})
	return s
}

// SnmpCommunity represents a single `snmp-server community` line.
//
// Examples:
//
//	snmp-server community public ro
//	snmp-server community ops ro IPV4-MGMT
//	snmp-server community admin rw
//
// The `name` is the community string itself — treat as plaintext shared secret.
// `access` is "ro" or "rw" (omitted defaults to "ro" in EOS). `acl` is the
// optional ACL name applied to the community.
type SnmpCommunity struct {
	Name   string
	Access string
	// ACL is the optional access-list name applied to the community. When
	// IPv6 is true the ACL is an IPv6 access-list (per the
	// `snmp-server community <name> ro ipv6 <acl6>` form); otherwise it
	// is an IPv4 ACL.
	ACL string
	// IPv6 is true when the community line declares an IPv6 ACL via the
	// `ipv6` keyword.
	IPv6 bool
}

// ParseSnmpCommunities extracts SNMPv1/v2c community strings from
// running-config. SNMPv3 (`snmp-server user`/`snmp-server group`) is
// intentionally excluded since v3 uses authPriv/authNoPriv per-user, not
// communities.
//
// The full EOS form is:
//
//	snmp-server community <name> [view <view-name>] [ro|rw] [ipv6] [<acl>]
//
// The optional `view` clause and the optional `ipv6` keyword (for IPv6
// ACLs) are recognized so that the access mode and ACL are captured
// correctly regardless of the extra tokens.
func ParseSnmpCommunities(runningConfig string) []SnmpCommunity {
	res := []SnmpCommunity{}
	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "snmp-server community ") {
			continue
		}
		toks := strings.Fields(line)
		// toks[0]="snmp-server", toks[1]="community", toks[2]=name
		if len(toks) < 3 {
			continue
		}
		c := SnmpCommunity{Name: toks[2], Access: "ro"}
		i := 3
		// Optional `view <view-name>` clause.
		if i+1 < len(toks) && toks[i] == "view" {
			i += 2
		}
		// Optional access mode.
		if i < len(toks) && (toks[i] == "ro" || toks[i] == "rw") {
			c.Access = toks[i]
			i++
		}
		// Optional `ipv6` keyword for IPv6 ACLs.
		if i < len(toks) && toks[i] == "ipv6" {
			c.IPv6 = true
			i++
		}
		// Optional trailing ACL name.
		if i < len(toks) {
			c.ACL = toks[i]
		}
		res = append(res, c)
	}
	return res
}

// TelnetService represents the `management telnet` configuration block.
//
//	management telnet
//	   shutdown            <- service disabled (good)
//	   no shutdown         <- service enabled (insecure)
//	   idle-timeout 0
//	   session-limit 20
//
// On a stock EOS device the telnet service is shut down by default. If the
// `management telnet` block is absent entirely, the service is considered
// disabled.
type TelnetService struct {
	// Configured indicates whether a `management telnet` block exists in the
	// running-config (vs. being completely absent).
	Configured bool
	// Enabled is true only when the block is present AND not shutdown. We
	// treat absent block as disabled.
	Enabled       bool
	IdleTimeout   int
	SessionLimit  int
	PerHostLimit  int
	IPAccessGroup string
}

func ParseTelnetService(runningConfig string) *TelnetService {
	block := GetSection(strings.NewReader(runningConfig), "management telnet")
	t := &TelnetService{}
	if block == "" {
		return t
	}
	t.Configured = true

	// Default: when the block exists, EOS treats telnet as enabled unless
	// `shutdown` appears. Most production configs explicitly include
	// `shutdown` for safety.
	t.Enabled = true

	scanner := bufio.NewScanner(strings.NewReader(block))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "shutdown":
			t.Enabled = false
		case line == "no shutdown":
			t.Enabled = true
		case strings.HasPrefix(line, "idle-timeout "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "idle-timeout ")))
			if err == nil {
				t.IdleTimeout = n
			}
		case strings.HasPrefix(line, "session-limit per-host "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "session-limit per-host ")))
			if err == nil {
				t.PerHostLimit = n
			}
		case strings.HasPrefix(line, "session-limit "):
			n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "session-limit ")))
			if err == nil {
				t.SessionLimit = n
			}
		case strings.HasPrefix(line, "ip access-group "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				t.IPAccessGroup = parts[2]
			}
		}
	}
	return t
}

// PasswordPolicy describes password policy attributes derived from
// running-config. EOS exposes password policy via:
//
//	aaa authentication policy lockout failure 5 window 60 duration 300
//	aaa authentication policy local allow-nopassword-remote-login
//	aaa authentication policy on-failure log
//	aaa authentication policy on-success log
//	password policy <name>
//	   minimum length 12
//	   minimum digits 1
//	   minimum upper 1
//	   minimum lower 1
//	   minimum special 1
//	   maximum repetitive 2
//	   maximum sequential 2
//
// When the `password policy` block is absent, all minimum/maximum fields
// are zero, indicating no enforced complexity.
type PasswordPolicy struct {
	// LockoutFailure is the number of failed login attempts before lockout.
	// 0 means lockout is not configured.
	LockoutFailure int
	// LockoutWindowSeconds is the rolling window during which failures count.
	LockoutWindowSeconds int
	// LockoutDurationSeconds is how long an account stays locked.
	LockoutDurationSeconds int
	// AllowNopasswordRemoteLogin permits remote login for users with no
	// password configured (insecure when true).
	AllowNopasswordRemoteLogin bool
	// LogOnFailure / LogOnSuccess: whether auth events are logged.
	LogOnFailure bool
	LogOnSuccess bool
	// PolicyName is the configured `password policy <name>`.
	PolicyName string
	// MinimumLength etc. are 0 when unset.
	MinimumLength     int
	MinimumDigits     int
	MinimumUppercase  int
	MinimumLowercase  int
	MinimumSpecial    int
	MaximumRepetitive int
	MaximumSequential int
}

var (
	// EOS does not enforce token order on the lockout clauses (failure /
	// window / duration), so each clause is matched independently.
	pwLockoutFailureRe     = regexp.MustCompile(`failure\s+(\d+)`)
	pwLockoutWindowRe      = regexp.MustCompile(`window\s+(\d+)`)
	pwLockoutDurationRe    = regexp.MustCompile(`duration\s+(\d+)`)
	passwordPolicyHeaderRe = regexp.MustCompile(`(?m)^password policy\s+(\S+)\s*$`)
)

func ParsePasswordPolicy(runningConfig string) *PasswordPolicy {
	p := &PasswordPolicy{}

	// Top-level policy lines.
	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "aaa authentication policy lockout"):
			if m := pwLockoutFailureRe.FindStringSubmatch(line); m != nil {
				p.LockoutFailure, _ = strconv.Atoi(m[1])
			}
			if m := pwLockoutWindowRe.FindStringSubmatch(line); m != nil {
				p.LockoutWindowSeconds, _ = strconv.Atoi(m[1])
			}
			if m := pwLockoutDurationRe.FindStringSubmatch(line); m != nil {
				p.LockoutDurationSeconds, _ = strconv.Atoi(m[1])
			}
		case line == "aaa authentication policy local allow-nopassword-remote-login":
			p.AllowNopasswordRemoteLogin = true
		case line == "aaa authentication policy on-failure log":
			p.LogOnFailure = true
		case line == "aaa authentication policy on-success log":
			p.LogOnSuccess = true
		}
	}

	// Find a `password policy <name>` block. EOS allows multiple named
	// policies; if multiple exist we prefer the one named "default" (the
	// most common case), otherwise the first declared block. The single
	// `passwordPolicy` field can only represent one policy.
	policyName, block := findPolicyBlock(runningConfig)
	if policyName != "" {
		p.PolicyName = policyName
		s := bufio.NewScanner(strings.NewReader(block))
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			parts := strings.Fields(line)
			if len(parts) < 3 {
				continue
			}
			n, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				continue
			}
			switch {
			case strings.HasPrefix(line, "minimum length "):
				p.MinimumLength = n
			case strings.HasPrefix(line, "minimum digits "):
				p.MinimumDigits = n
			case strings.HasPrefix(line, "minimum upper "):
				p.MinimumUppercase = n
			case strings.HasPrefix(line, "minimum lower "):
				p.MinimumLowercase = n
			case strings.HasPrefix(line, "minimum special "):
				p.MinimumSpecial = n
			case strings.HasPrefix(line, "maximum repetitive "):
				p.MaximumRepetitive = n
			case strings.HasPrefix(line, "maximum sequential "):
				p.MaximumSequential = n
			}
		}
	}

	return p
}

// findPolicyBlock returns the name and inner body of a `password policy
// <name>` section. EOS allows multiple named policies in running-config; we
// prefer the policy named "default" if present, otherwise the first one
// declared.
func findPolicyBlock(runningConfig string) (string, string) {
	locs := passwordPolicyHeaderRe.FindAllStringSubmatchIndex(runningConfig, -1)
	if len(locs) == 0 {
		return "", ""
	}

	// Prefer the "default" policy if it exists; otherwise take the first.
	chosen := locs[0]
	for _, loc := range locs {
		if runningConfig[loc[2]:loc[3]] == "default" {
			chosen = loc
			break
		}
	}

	name := runningConfig[chosen[2]:chosen[3]]
	rest := runningConfig[chosen[1]:]

	// Walk lines until we hit the next non-indented, non-comment line.
	var b strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(rest))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "!") {
			continue
		}
		// Stop when we hit a line at column 0 that isn't a comment — this
		// belongs to the next config block.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		b.WriteString(trimmed)
		b.WriteByte('\n')
	}
	return name, b.String()
}

// NtpAuthKey represents an `ntp authentication-key <id> <hash> ...` line.
//
//	ntp authentication-key 1 sha1 7 0123456789ABCDEF
//	ntp authentication-key 2 md5 7 0123456789ABCDEF
//
// The hash field is one of md5, sha1, sha256, sha384, sha512. md5 is
// considered weak.
type NtpAuthKey struct {
	ID       int
	HashAlgo string
	// Trusted indicates whether the key ID appears in
	// `ntp trusted-key <id>` and is therefore actually used for
	// authenticating servers.
	Trusted bool
}

// NtpAuthState aggregates NTP authentication settings.
type NtpAuthState struct {
	// AuthenticationEnabled indicates whether `ntp authenticate` was issued.
	AuthenticationEnabled bool
	Keys                  []NtpAuthKey
	TrustedKeyIDs         []int
}

var (
	ntpKeyRe        = regexp.MustCompile(`^ntp authentication-key\s+(\d+)\s+(\S+)`)
	ntpTrustedKeyRe = regexp.MustCompile(`^ntp trusted-key\s+(.+)$`)
)

func ParseNtpAuth(runningConfig string) *NtpAuthState {
	state := &NtpAuthState{}
	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "ntp authenticate":
			state.AuthenticationEnabled = true
		case strings.HasPrefix(line, "ntp authentication-key"):
			if m := ntpKeyRe.FindStringSubmatch(line); m != nil {
				id, _ := strconv.Atoi(m[1])
				state.Keys = append(state.Keys, NtpAuthKey{
					ID:       id,
					HashAlgo: m[2],
				})
			}
		case strings.HasPrefix(line, "ntp trusted-key"):
			if m := ntpTrustedKeyRe.FindStringSubmatch(line); m != nil {
				for tok := range strings.FieldsSeq(m[1]) {
					id, err := strconv.Atoi(tok)
					if err == nil {
						state.TrustedKeyIDs = append(state.TrustedKeyIDs, id)
					}
				}
			}
		}
	}

	// Mark trusted keys.
	trusted := map[int]bool{}
	for _, id := range state.TrustedKeyIDs {
		trusted[id] = true
	}
	for i := range state.Keys {
		if trusted[state.Keys[i].ID] {
			state.Keys[i].Trusted = true
		}
	}
	return state
}

// ControlPlanePolicer describes Control-Plane Policing (CoPP) coverage from
// the `control-plane` section of running-config.
//
//	control-plane
//	   no service-policy input copp-system-policy
//
// Or, configured:
//
//	control-plane
//	   ip access-group COPP-IN in
//	   service-policy input copp-system-policy
//
// Without a service policy applied, the device has no CoPP protection
// against control-plane DoS — a high-impact misconfiguration.
type ControlPlanePolicer struct {
	// Configured indicates whether a `control-plane` block exists.
	Configured bool
	// PolicyApplied is true if a `service-policy input <name>` line is
	// present (and not negated).
	PolicyApplied  bool
	PolicyName     string
	IPAccessGroup  string
	IP6AccessGroup string
}

func ParseControlPlanePolicer(runningConfig string) *ControlPlanePolicer {
	block := GetSection(strings.NewReader(runningConfig), "control-plane")
	c := &ControlPlanePolicer{}
	if block == "" {
		return c
	}
	c.Configured = true

	scanner := bufio.NewScanner(strings.NewReader(block))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// The negated ("no ...") cases must be matched before their positive
		// counterparts so a later `no` line clears state set by an earlier
		// positive line.
		switch {
		case strings.HasPrefix(line, "no service-policy input "):
			c.PolicyApplied = false
			c.PolicyName = ""
		case strings.HasPrefix(line, "service-policy input "):
			c.PolicyApplied = true
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				c.PolicyName = parts[2]
			}
		case strings.HasPrefix(line, "no ip access-group "):
			c.IPAccessGroup = ""
		case strings.HasPrefix(line, "ip access-group "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				c.IPAccessGroup = parts[2]
			}
		case strings.HasPrefix(line, "no ipv6 access-group "):
			c.IP6AccessGroup = ""
		case strings.HasPrefix(line, "ipv6 access-group "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				c.IP6AccessGroup = parts[2]
			}
		}
	}
	return c
}

// PortSecurityConfig captures `switchport port-security` settings on an
// interface block.
//
//	interface Ethernet1
//	   switchport port-security
//	   switchport port-security maximum 2
//	   switchport port-security violation protect
//	   switchport port-security mac-address sticky
//
// Without `switchport port-security` (the bare command), the feature is
// disabled on the interface — which is the EOS default.
type PortSecurityConfig struct {
	// Interface is the parent interface name (e.g. "Ethernet1").
	Interface string
	Enabled   bool
	// MaximumMacAddresses is the configured limit. 0 means default (1).
	MaximumMacAddresses int
	// ViolationAction: "protect", "restrict", or "shutdown".
	ViolationAction string
	// StickyLearning is true when sticky MAC learning is configured.
	StickyLearning bool
}

var ifaceHeaderRe = regexp.MustCompile(`(?m)^interface (\S+)\s*$`)

// ParsePortSecurity walks every `interface <name>` block and returns one
// PortSecurityConfig per interface that has at least one
// `switchport port-security ...` line. Interfaces without port-security are
// excluded — caller decides the policy default.
func ParsePortSecurity(runningConfig string) []PortSecurityConfig {
	res := []PortSecurityConfig{}

	eachInterfaceBlock(runningConfig, func(ifaceName, block string) {
		ps := PortSecurityConfig{Interface: ifaceName}
		hasAny := false
		scanner := bufio.NewScanner(strings.NewReader(block))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// Stop reading at end-of-block markers within the block too.
			if line == "!" || line == "end" {
				break
			}
			if line == "switchport port-security" {
				ps.Enabled = true
				hasAny = true
				continue
			}
			if !strings.HasPrefix(line, "switchport port-security") {
				continue
			}
			hasAny = true
			rest := strings.TrimSpace(strings.TrimPrefix(line, "switchport port-security"))
			switch {
			case strings.HasPrefix(rest, "maximum "):
				parts := strings.Fields(rest)
				if len(parts) >= 2 {
					if n, err := strconv.Atoi(parts[1]); err == nil {
						ps.MaximumMacAddresses = n
					}
				}
			case strings.HasPrefix(rest, "violation "):
				parts := strings.Fields(rest)
				if len(parts) >= 2 {
					ps.ViolationAction = parts[1]
				}
			case rest == "mac-address sticky" || strings.HasPrefix(rest, "mac-address sticky "):
				ps.StickyLearning = true
			}
		}
		if hasAny {
			res = append(res, ps)
		}
	})
	return res
}
