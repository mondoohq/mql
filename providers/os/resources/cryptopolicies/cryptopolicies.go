// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package cryptopolicies reads the system-wide crypto policy of
// crypto-policies (RHEL 8 and later, Fedora, Amazon Linux 2023, SLES 16): the
// configured policy as update-crypto-policies parses it, and the resolved
// policy it dumps to /etc/crypto-policies/state/CURRENT.pol.
package cryptopolicies

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const (
	// ConfigFile holds the configured policy.
	ConfigFile = "/etc/crypto-policies/config"
	// DefaultConfigFile is used when ConfigFile cannot be read and the kernel
	// is not in FIPS mode.
	DefaultConfigFile = "/usr/share/crypto-policies/default-config"
	// CurrentFile names the policy the back ends were last generated for.
	CurrentFile = "/etc/crypto-policies/state/current"
	// PolicyDumpFile is the resolved policy update-crypto-policies dumped
	// when it generated the back ends.
	PolicyDumpFile = "/etc/crypto-policies/state/CURRENT.pol"
	// FipsFile is the kernel's FIPS mode flag.
	FipsFile = "/proc/sys/crypto/fips_enabled"
	// LibraryFile is the module of update-crypto-policies that writes
	// PolicyDumpFile.
	LibraryFile = "/usr/share/crypto-policies/python/cryptopolicies/cryptopolicies.py"
)

// Config is a configured policy: a base policy and its subpolicies (modules).
type Config struct {
	Policy      string
	Subpolicies []string
}

// String formats the policy as update-crypto-policies --show prints it.
func (c Config) String() string {
	if len(c.Subpolicies) == 0 {
		return c.Policy
	}
	return c.Policy + ":" + strings.Join(c.Subpolicies, ":")
}

// ParseConfig parses a policy configuration as ProfileConfig.parse_file does:
// text after # is a comment, the first non-empty line is the policy and its
// subpolicies (DEFAULT:NO-SHA1), and every later line adds subpolicies. Names
// are upper-cased.
func ParseConfig(r io.Reader) (Config, error) {
	var c Config
	first := true
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(strings.ToUpper(line), ":")
		if first {
			if parts[0] != "" {
				c.Policy = parts[0]
			}
			parts = parts[1:]
			first = false
		}
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				c.Subpolicies = append(c.Subpolicies, p)
			}
		}
	}
	return c, scanner.Err()
}

// listProperties hold algorithm lists. Older releases also wrote tls_cipher,
// ssh_cipher, ssh_group and ike_protocol.
var listProperties = map[string]bool{
	"cipher":       true,
	"group":        true,
	"hash":         true,
	"key_exchange": true,
	"mac":          true,
	"protocol":     true,
	"sign":         true,
	"tls_cipher":   true,
	"ssh_cipher":   true,
	"ssh_group":    true,
	"ike_protocol": true,
}

// Policy is a parsed policy dump: the baseline values for all scopes and the
// values that differ for a back-end scope.
type Policy struct {
	// Name is the policy named in the dump's header, such as DEFAULT:NO-SHA1.
	Name     string
	Baseline map[string]any
	// Scoped holds, per scope, the properties written as prop@scope.
	Scoped map[string]map[string]any
	// ScopeOrder lists the scopes in the order they appear in the dump.
	ScopeOrder []string
	// RelativeToParent says whether a scope's lines are relative to its
	// parent scope (openssh-server to openssh) rather than to the baseline.
	// See DumpsRelativeToParent.
	RelativeToParent bool
}

// ParsePolicy parses CURRENT.pol. Each line is `property = value` or
// `property@scope = value`. An algorithm list is split on whitespace, an
// integer is returned as int64, and anything else as a string.
func ParsePolicy(r io.Reader) (*Policy, error) {
	p := &Policy{Baseline: map[string]any{}, Scoped: map[string]map[string]any{}, RelativeToParent: true}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if rest, ok := strings.CutPrefix(line, "# Policy "); ok && p.Name == "" {
			p.Name = strings.TrimSuffix(rest, " dump")
			continue
		}
		if line == "" || line[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		prop, scope, scoped := strings.Cut(key, "@")
		v := parseValue(prop, strings.TrimSpace(value))
		if !scoped {
			p.Baseline[prop] = v
			continue
		}
		scope = strings.ToLower(scope)
		m, ok := p.Scoped[scope]
		if !ok {
			m = map[string]any{}
			p.Scoped[scope] = m
			p.ScopeOrder = append(p.ScopeOrder, scope)
		}
		m[prop] = v
	}
	return p, scanner.Err()
}

func parseValue(prop, value string) any {
	fields := strings.Fields(value)
	if listProperties[prop] || len(fields) > 1 {
		res := make([]any, len(fields))
		for i := range fields {
			res[i] = fields[i]
		}
		return res
	}
	if i, err := strconv.ParseInt(value, 10, 64); err == nil {
		return i
	}
	return value
}

// scopeParents are the scopes whose dump lines are relative to another scope
// rather than to the baseline (DUMPABLE_SCOPES in cryptopolicies.py).
var scopeParents = map[string]string{
	"nss-tls":           "nss",
	"nss-pkcs12":        "nss",
	"nss-pkcs12-import": "nss-pkcs12",
	"nss-smime":         "nss",
	"nss-smime-import":  "nss-smime",
	"openssh-client":    "openssh",
	"openssh-server":    "openssh",
}

// relativeToParent matches the DUMPABLE_SCOPES entry that names openssh as
// the parent of openssh-server.
var relativeToParent = regexp.MustCompile(`['"]openssh-server['"]\s*:\s*\(\s*['"]openssh['"]`)

// DumpsRelativeToParent reports whether the update-crypto-policies module
// source writes a scope's lines relative to its parent scope. Releases from
// 2025 on do (DUMPABLE_SCOPES maps a scope to its parent and its scope set);
// earlier ones, such as RHEL 9's, write every scope relative to the baseline
// (a scope maps to its scope set alone).
func DumpsRelativeToParent(source string) bool {
	return relativeToParent.MatchString(source)
}

// KnownScopes are the scopes current crypto-policies dumps. A scope whose
// values equal its parent's has no lines in the dump, so it is resolved from
// the parent.
var KnownScopes = []string{
	"bind", "gnutls", "java-tls", "krb5", "libreswan", "libssh", "nss",
	"nss-tls", "nss-pkcs12", "nss-pkcs12-import", "nss-smime",
	"nss-smime-import", "openssh", "openssh-client", "openssh-server",
	"openssl", "sequoia", "rpm",
}

// Scopes lists the known scopes, then any other scope in the dump.
func (p *Policy) Scopes() []string {
	res := append([]string{}, KnownScopes...)
	known := map[string]bool{}
	for _, s := range KnownScopes {
		known[s] = true
	}
	for _, s := range p.ScopeOrder {
		if !known[s] {
			res = append(res, s)
		}
	}
	return res
}

// Resolve returns the properties a back-end scope applies: the baseline,
// then the scope's parents' values, then its own.
func (p *Policy) Resolve(scope string) map[string]any {
	scope = strings.ToLower(scope)
	chain := []string{scope}
	if p.RelativeToParent {
		chain = nil
		seen := map[string]bool{}
		for s := scope; s != "" && !seen[s]; s = scopeParents[s] {
			seen[s] = true
			chain = append([]string{s}, chain...)
		}
	}

	res := make(map[string]any, len(p.Baseline))
	for k, v := range p.Baseline {
		res[k] = v
	}
	for _, s := range chain {
		for k, v := range p.Scoped[s] {
			res[k] = v
		}
	}
	return res
}
