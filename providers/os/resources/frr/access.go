// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// This file reads the blocks that decide who reaches the router and what it
// trusts: the key chains that authenticate the routing protocols, the vty
// lines that carry the shell, and the RPKI caches that validate what BGP
// hears.
//
// These were the last blocks of a real configuration that only the generic
// block view could reach.

package frr

import "strings"

// KeyChain is one `key chain <name>` block. A key chain holds the keys the
// interior gateway protocols and BFD authenticate with, so an interface that
// names a chain is only as protected as the chain is.
type KeyChain struct {
	Name      string
	Keys      []KeyChainKey
	File      string
	StartLine int
	Raw       string
}

// KeyChainKey is one `key <id>` block of a key chain.
type KeyChainKey struct {
	ID string
	// KeyStringSet reports a configured key without exposing it.
	KeyStringSet bool
	// Algorithm is the cryptographic algorithm of the key. An empty value
	// means the chain falls back to the plain text default.
	Algorithm string
	// SendLifetime and AcceptLifetime bound when the key is used. A key
	// without a lifetime never rotates.
	SendLifetime   string
	AcceptLifetime string
	Line           int
}

// VtyLine is one `line vty` block. It carries the access class that decides
// who may open a shell and the idle timeout that closes a forgotten one.
type VtyLine struct {
	// AccessClass is the IPv4 access list applied to the line, empty when
	// the line accepts every source.
	AccessClass string
	// AccessClassIPv6 is the IPv6 access list applied to the line.
	AccessClassIPv6 string
	// ExecTimeout is the idle timeout as the line spells it, for example
	// "10 0". An explicit "0 0" never times out.
	ExecTimeout string
	// LoginEnabled is false when the line carries `no login`, which drops
	// the password prompt.
	LoginEnabled bool
	// PasswordSet reports a line password without exposing it.
	PasswordSet bool
	Params      map[string]string
	File        string
	StartLine   int
	Raw         string
}

// RPKI is the `rpki` block. RPKI tells BGP which announcements are signed by
// the holder of the prefix, so a router without a reachable cache validates
// nothing.
type RPKI struct {
	// Configured reports whether the configuration has an rpki block.
	Configured bool
	// PollingPeriod, ExpireInterval and RetryInterval are the cache timers
	// in seconds. They are -1 when the block leaves them at the default.
	PollingPeriod  int64
	ExpireInterval int64
	RetryInterval  int64
	Caches         []RPKICache
	Params         map[string]string
	File           string
	StartLine      int
	Raw            string
}

// RPKICache is one `rpki cache` line.
type RPKICache struct {
	// Address is the host of the cache, or the path of a local socket.
	Address string
	Port    string
	// Transport is tcp or ssh.
	Transport string
	// SSHUser is the user of an ssh transport.
	SSHUser string
	// Preference orders the caches. A lower value is tried first.
	Preference int64
	Raw        string
}

// KeyChains builds the typed view of every `key chain` block.
func (c *Config) KeyChains() []KeyChain {
	var out []KeyChain
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "key chain" {
			continue
		}
		chain := KeyChain{
			Name:      blk.Name,
			File:      blk.File,
			StartLine: blk.StartLine,
			Raw:       blk.Raw,
		}
		for j := range blk.Blocks {
			sub := &blk.Blocks[j]
			if sub.Type != "key" {
				continue
			}
			chain.Keys = append(chain.Keys, buildKeyChainKey(sub))
		}
		out = append(out, chain)
	}
	return out
}

func buildKeyChainKey(blk *Block) KeyChainKey {
	k := KeyChainKey{ID: blk.Name, Line: blk.StartLine}
	for i := range blk.Directives {
		d := &blk.Directives[i]
		switch d.Name {
		case "key-string":
			k.KeyStringSet = !d.Negated
		case "cryptographic-algorithm":
			if len(d.Args) > 0 {
				k.Algorithm = d.Args[0]
			}
		case "send-lifetime":
			k.SendLifetime = strings.Join(d.Args, " ")
		case "accept-lifetime":
			k.AcceptLifetime = strings.Join(d.Args, " ")
		}
	}
	return k
}

// VtyLines builds the typed view of every `line vty` block.
func (c *Config) VtyLines() []VtyLine {
	var out []VtyLine
	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "line vty" {
			continue
		}
		// FRR prompts for a password unless the line says otherwise.
		l := VtyLine{
			LoginEnabled: true,
			Params:       map[string]string{},
			File:         blk.File,
			StartLine:    blk.StartLine,
			Raw:          blk.Raw,
		}
		for j := range blk.Directives {
			d := &blk.Directives[j]
			switch d.Name {
			case "access-class":
				if len(d.Args) > 0 && !d.Negated {
					l.AccessClass = d.Args[0]
				}
			case "ipv6":
				if len(d.Args) >= 2 && d.Args[0] == "access-class" && !d.Negated {
					l.AccessClassIPv6 = d.Args[1]
				}
			case "exec-timeout":
				l.ExecTimeout = strings.Join(d.Args, " ")
			case "login":
				l.LoginEnabled = !d.Negated
			case "password":
				l.PasswordSet = !d.Negated
			default:
				l.Params[directiveKey(d)] = directiveValue(d)
			}
		}
		out = append(out, l)
	}
	return out
}

// RPKIBlock builds the typed view of the `rpki` block. It reports
// `Configured` as false when the configuration has none, so a router that
// validates nothing is a readable answer rather than a missing resource.
func (c *Config) RPKIBlock() RPKI {
	r := RPKI{
		PollingPeriod:  -1,
		ExpireInterval: -1,
		RetryInterval:  -1,
		Params:         map[string]string{},
	}

	for i := range c.Blocks {
		blk := &c.Blocks[i]
		if blk.Type != "rpki" {
			continue
		}
		r.Configured = true
		r.File = blk.File
		r.StartLine = blk.StartLine
		r.Raw = blk.Raw

		for j := range blk.Directives {
			d := &blk.Directives[j]
			args := d.Args
			// Inside the block FRR repeats the `rpki` keyword on every line.
			if d.Name == "rpki" {
				if len(args) == 0 {
					continue
				}
			} else {
				args = append([]string{d.Name}, args...)
			}

			switch args[0] {
			case "polling_period", "polling-period":
				if len(args) > 1 {
					r.PollingPeriod = parseInt(args[1], -1)
				}
			case "expire_interval", "expire-interval":
				if len(args) > 1 {
					r.ExpireInterval = parseInt(args[1], -1)
				}
			case "retry_interval", "retry-interval":
				if len(args) > 1 {
					r.RetryInterval = parseInt(args[1], -1)
				}
			case "cache":
				if cache, ok := parseRPKICache(args[1:], d.Raw); ok {
					r.Caches = append(r.Caches, cache)
				}
			default:
				r.Params[args[0]] = strings.Join(args[1:], " ")
			}
		}
		break
	}
	return r
}

// parseRPKICache reads one `rpki cache` line, which takes a host and a port
// for the plain transport and a user and key files for the ssh one.
func parseRPKICache(args []string, raw string) (RPKICache, bool) {
	if len(args) == 0 {
		return RPKICache{}, false
	}

	c := RPKICache{Transport: "tcp", Preference: -1, Raw: raw}
	if args[0] == "ssh" {
		c.Transport = "ssh"
		args = args[1:]
		if len(args) == 0 {
			return RPKICache{}, false
		}
	}

	c.Address = args[0]
	rest := args[1:]
	if len(rest) > 0 && isNumeric(rest[0]) {
		c.Port = rest[0]
		rest = rest[1:]
	}
	if c.Transport == "ssh" && len(rest) > 0 {
		c.SSHUser = rest[0]
	}
	if v := argAfter(args, "preference"); v != "" {
		c.Preference = parseInt(v, -1)
	}
	return c, true
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// KeyChainKeysAsDicts renders the keys of a key chain as plain maps.
func KeyChainKeysAsDicts(keys []KeyChainKey) []any {
	out := make([]any, 0, len(keys))
	for i := range keys {
		k := &keys[i]
		out = append(out, map[string]any{
			"id":             k.ID,
			"keyStringSet":   k.KeyStringSet,
			"algorithm":      k.Algorithm,
			"sendLifetime":   k.SendLifetime,
			"acceptLifetime": k.AcceptLifetime,
			"line":           int64(k.Line),
		})
	}
	return out
}

// RPKICachesAsDicts renders the caches of the RPKI block as plain maps.
func RPKICachesAsDicts(caches []RPKICache) []any {
	out := make([]any, 0, len(caches))
	for i := range caches {
		c := &caches[i]
		out = append(out, map[string]any{
			"address":    c.Address,
			"port":       c.Port,
			"transport":  c.Transport,
			"sshUser":    c.SSHUser,
			"preference": c.Preference,
			"raw":        c.Raw,
		})
	}
	return out
}
