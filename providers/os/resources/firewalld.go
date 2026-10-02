// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// initFirewalldZone resolves `firewalld.zone("name")` lookups by name against
// the zones exposed by the firewalld resource. When the resource is being
// constructed from the firewalld.zones() accessor (i.e. all fields populated),
// we fall through and let the default factory handle it.
func initFirewalldZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}
	nameArg, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, ok := nameArg.Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}

	o, err := CreateResource(runtime, "firewalld", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	fw := o.(*mqlFirewalld)
	zones := fw.GetZones()
	if zones.Error != nil {
		return nil, nil, zones.Error
	}

	for _, z := range zones.Data {
		zone, ok := z.(*mqlFirewalldZone)
		if !ok {
			continue
		}
		if zone.Name.Data == name {
			return nil, zone, nil
		}
	}

	return nil, nil, fmt.Errorf("firewalld zone %q not found", name)
}

type mqlFirewalldInternal struct {
	fetched bool
	// cacheStatus is "running" whenever the daemon answers queries, which
	// includes the FAILED state; status() reports that one as "failed".
	cacheStatus  string
	cacheFailed  bool
	cacheDefault string
	lock         sync.Mutex
}

func (f *mqlFirewalld) id() (string, error) {
	return "firewalld", nil
}

func (z *mqlFirewalldZone) id() (string, error) {
	return "firewalld/zone/" + z.Name.Data, nil
}

func (r *mqlFirewalldRichrule) id() (string, error) {
	return "firewalld/richrule/" + r.Rule.Data, nil
}

// fetchStatus lazily loads the firewalld status and default zone.
func (f *mqlFirewalld) fetchStatus() error {
	if f.fetched {
		return nil
	}
	f.lock.Lock()
	defer f.lock.Unlock()
	if f.fetched {
		return nil
	}

	conn, ok := f.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		f.cacheStatus = "not installed"
		f.fetched = true
		return nil
	}

	// Check if firewalld is running
	o, err := CreateResource(f.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("firewall-cmd --state"),
	})
	if err != nil {
		f.cacheStatus = "not installed"
		f.fetched = true
		return nil
	}
	cmd := o.(*mqlCommand)
	exitcode := cmd.GetExitcode().Data
	state := strings.TrimSpace(cmd.GetStdout().Data)
	if exitcode != 0 {
		// A refused question is not an answer. firewall-cmd exits non-zero both
		// when the firewall is genuinely stopped and when polkit declines to
		// answer an unprivileged caller. Recording the second as "not running"
		// turns a missing permission into a clean bill of health: zones() below
		// returns nothing whenever the status is not "running", so every zone
		// and every rule silently disappears from the scan and an exposure
		// check finds nothing to object to.
		if stderr := strings.TrimSpace(cmd.GetStderr().Data); isFirewalldAuthzError(stderr) {
			return fmt.Errorf("cannot determine firewalld state: %s", stderr)
		}
		// FAILED (exit 251) is a daemon that is up but could not apply its
		// ruleset. It still answers queries, so its default zone and zones
		// are read as for a running firewall.
		f.cacheFailed = isFirewalldFailedState(cmd.GetStderr().Data)
		// firewalld 0.4 has no FAILED state: a daemon that could not apply
		// its ruleset stays in INIT, and --state says "not running" (exit
		// 252) although the daemon is up, answers queries and has loaded
		// part of its rules. Ask the daemon itself before believing it.
		if !f.cacheFailed && exitcode == firewalldNotRunningExit {
			answers, err := f.daemonAnswers()
			if err != nil {
				return err
			}
			f.cacheFailed = answers
		}
		if f.cacheFailed {
			state = "running"
		}
	}
	if state != "running" {
		f.cacheStatus = "not running"
		f.fetched = true
		return nil
	}
	f.cacheStatus = "running"

	// Get default zone
	o, err = CreateResource(f.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("firewall-cmd --get-default-zone"),
	})
	if err != nil {
		return err
	}
	cmd = o.(*mqlCommand)
	if cmd.GetExitcode().Data != 0 {
		return fmt.Errorf("firewall-cmd --get-default-zone failed: %s", cmd.Stderr.Data)
	}
	f.cacheDefault = strings.TrimSpace(cmd.Stdout.Data)

	f.fetched = true
	return nil
}

// isFirewalldAuthzError reports whether firewall-cmd failed because it was not
// permitted to answer, rather than because the firewall is stopped. polkit
// refuses an unprivileged caller with "Authorization failed" on a host where
// firewalld is running perfectly well.
func isFirewalldAuthzError(stderr string) bool {
	if stderr == "" {
		return false
	}
	s := strings.ToLower(stderr)
	for _, marker := range []string{
		"authorization failed",
		"not authorized",
		"not_authorized",
		"polkit",
		"permission denied",
		"access denied",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// firewalldNotRunningExit is firewall-cmd's NOT_RUNNING exit code.
const firewalldNotRunningExit = 252

// isFirewalldFailedState reports whether firewall-cmd --state answered
// "failed", which it prints on stderr with exit code 251.
func isFirewalldFailedState(stderr string) bool {
	return stripFirewalldColor(stderr) == "failed"
}

// daemonAnswers reports whether the firewalld daemon answers a query even
// though firewall-cmd --state called it not running.
func (f *mqlFirewalld) daemonAnswers() (bool, error) {
	o, err := CreateResource(f.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("firewall-cmd --get-default-zone"),
	})
	if err != nil {
		return false, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return false, exit.Error
	}
	stderr := cmd.GetStderr().Data
	if exit.Data != 0 && isFirewalldAuthzError(stderr) {
		return false, fmt.Errorf("cannot determine firewalld state: %s", strings.TrimSpace(stderr))
	}
	return firewalldDefaultZoneAnswered(exit.Data, cmd.GetStdout().Data), nil
}

// firewalldDefaultZoneAnswered reports whether firewall-cmd --get-default-zone
// got an answer from the daemon. A stopped daemon makes it print "FirewallD is
// not running" and exit 252.
func firewalldDefaultZoneAnswered(exitcode int64, stdout string) bool {
	return exitcode == 0 && stripFirewalldColor(stdout) != ""
}

// stripFirewalldColor trims the ANSI color codes firewall-cmd wraps its
// warnings in when it writes to a terminal (an SSH session with a pty), and
// surrounding space.
func stripFirewalldColor(s string) string {
	s = strings.ReplaceAll(s, "\x1b[91m", "")
	s = strings.ReplaceAll(s, "\x1b[00m", "")
	return strings.TrimSpace(s)
}

func (f *mqlFirewalld) status() (string, error) {
	if err := f.fetchStatus(); err != nil {
		return "", err
	}
	if f.cacheFailed {
		return "failed", nil
	}
	return f.cacheStatus, nil
}

func (f *mqlFirewalld) defaultZone() (string, error) {
	if err := f.fetchStatus(); err != nil {
		return "", err
	}
	return f.cacheDefault, nil
}

func (f *mqlFirewalld) zones() ([]any, error) {
	if err := f.fetchStatus(); err != nil {
		return nil, err
	}
	if f.cacheStatus != "running" {
		return nil, nil
	}

	o, err := CreateResource(f.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("firewall-cmd --list-all-zones"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	if cmd.GetExitcode().Data != 0 {
		return nil, fmt.Errorf("firewall-cmd --list-all-zones failed: %s", cmd.Stderr.Data)
	}

	zones := parseFirewalldZones(cmd.Stdout.Data)

	var res []any
	for _, z := range zones {
		var richRules []any
		for _, rr := range z.richRules {
			parsed := parseFirewalldRichRule(rr)
			r, err := CreateResource(f.MqlRuntime, "firewalld.richrule", map[string]*llx.RawData{
				"family":              llx.StringData(parsed.family),
				"rule":                llx.StringData(rr),
				"source":              llx.StringData(parsed.source),
				"sourceInverted":      llx.BoolData(parsed.sourceInverted),
				"destination":         llx.StringData(parsed.destination),
				"destinationInverted": llx.BoolData(parsed.destinationInverted),
				"action":              llx.StringData(parsed.action),
			})
			if err != nil {
				return nil, err
			}
			richRules = append(richRules, r)
		}

		zone, err := CreateResource(f.MqlRuntime, "firewalld.zone", map[string]*llx.RawData{
			"name":               llx.StringData(z.name),
			"target":             llx.StringData(z.target),
			"icmpBlockInversion": llx.BoolData(z.icmpBlockInversion),
			"active":             llx.BoolData(z.active),
			"interfaces":         llx.ArrayData(stringsToAny(z.interfaces), types.String),
			"sources":            llx.ArrayData(stringsToAny(z.sources), types.String),
			"services":           llx.ArrayData(stringsToAny(z.services), types.String),
			"ports":              llx.ArrayData(stringsToAny(z.ports), types.String),
			"masquerade":         llx.BoolData(z.masquerade),
			"forwardPorts":       llx.ArrayData(stringsToAny(z.forwardPorts), types.String),
			"sourcePorts":        llx.ArrayData(stringsToAny(z.sourcePorts), types.String),
			"icmpBlocks":         llx.ArrayData(stringsToAny(z.icmpBlocks), types.String),
			"richRules":          llx.ArrayData(richRules, types.Resource("firewalld.richrule")),
			"protocols":          llx.ArrayData(stringsToAny(z.protocols), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, zone)
	}
	return res, nil
}

// stringsToAny converts a string slice to []any for llx.ArrayData.
func stringsToAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// parsedZone holds the parsed output of a single zone block from firewall-cmd --list-all-zones.
type parsedZone struct {
	name               string
	target             string
	icmpBlockInversion bool
	active             bool
	interfaces         []string
	sources            []string
	services           []string
	ports              []string
	masquerade         bool
	forwardPorts       []string
	sourcePorts        []string
	icmpBlocks         []string
	richRules          []string
	protocols          []string
}

// parseFirewalldZones parses the output of `firewall-cmd --list-all-zones`.
//
// Example format:
//
//	public (active)
//	  target: default
//	  icmp-block-inversion: no
//	  interfaces: eth0
//	  sources:
//	  services: cockpit dhcpv6-client ssh
//	  ports: 8080/tcp
//	  protocols:
//	  forward: yes
//	  masquerade: no
//	  forward-ports:
//	    port=2022:proto=tcp:toport=22:toaddr=
//	  source-ports:
//	  icmp-blocks:
//	  rich rules:
//	    rule family="ipv4" source address="10.0.0.0/8" accept
//
// Rich rules are always listed one per line below their key. Forward ports
// are too since firewalld 0.9; older releases print them space-separated on
// the key's line.
func parseFirewalldZones(output string) []parsedZone {
	var zones []parsedZone
	var current *parsedZone
	inRichRules := false
	inForwardPorts := false

	for line := range strings.SplitSeq(output, "\n") {
		// Zone header: starts at column 0, non-empty, not indented
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			if current != nil {
				zones = append(zones, *current)
			}
			z := parsedZone{}
			header := strings.TrimSpace(line)
			// Parse "public (active)" or "dmz"
			if idx := strings.Index(header, " ("); idx != -1 {
				z.name = header[:idx]
				z.active = strings.Contains(header[idx:], "active")
			} else {
				z.name = header
			}
			current = &z
			inRichRules = false
			inForwardPorts = false
			continue
		}

		if current == nil {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Rich rules continuation: indented lines after "rich rules:" header
		if inRichRules {
			if strings.HasPrefix(trimmed, "rule ") {
				current.richRules = append(current.richRules, trimmed)
				continue
			}
			// If it doesn't start with "rule ", it's a new key
			inRichRules = false
		}
		if inForwardPorts {
			if strings.HasPrefix(trimmed, "port=") {
				current.forwardPorts = append(current.forwardPorts, trimmed)
				continue
			}
			inForwardPorts = false
		}

		// key: value pairs
		key, value, found := strings.Cut(trimmed, ": ")
		if !found {
			// Handle "rich rules:" with no value on same line
			switch strings.TrimSuffix(trimmed, ":") {
			case "rich rules":
				inRichRules = true
			case "forward-ports":
				inForwardPorts = true
			}
			// Also handle lines like "key:" with no value
			continue
		}
		value = strings.TrimSpace(value)

		switch key {
		case "target":
			current.target = value
		case "icmp-block-inversion":
			current.icmpBlockInversion = value == "yes"
		case "interfaces":
			current.interfaces = splitNonEmpty(value)
		case "sources":
			current.sources = splitNonEmpty(value)
		case "services":
			current.services = splitNonEmpty(value)
		case "ports":
			current.ports = splitNonEmpty(value)
		case "protocols":
			current.protocols = splitNonEmpty(value)
		case "masquerade":
			current.masquerade = value == "yes"
		case "forward-ports":
			current.forwardPorts = splitNonEmpty(value)
			inForwardPorts = true
		case "source-ports":
			current.sourcePorts = splitNonEmpty(value)
		case "icmp-blocks":
			current.icmpBlocks = splitNonEmpty(value)
		case "rich rules":
			inRichRules = true
			// Value on the same line as "rich rules:" is unusual but handle it
			if value != "" && strings.HasPrefix(value, "rule ") {
				current.richRules = append(current.richRules, value)
			}
		}
	}
	if current != nil {
		zones = append(zones, *current)
	}
	return zones
}

// splitNonEmpty splits a space-separated string and returns nil for empty input.
func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// parsedRichRule holds the parsed components of a firewalld rich rule.
type parsedRichRule struct {
	family              string
	source              string
	sourceInverted      bool
	destination         string
	destinationInverted bool
	action              string
}

// parseFirewalldRichRule extracts structured fields from a rich rule string.
// Example: `rule family="ipv4" source address="10.0.0.0/8" accept`
// Example: `rule family="ipv4" source NOT address="127.0.0.1" destination NOT address="127.0.0.1" drop`
func parseFirewalldRichRule(rule string) parsedRichRule {
	var rr parsedRichRule

	// Extract family
	if _, after, ok := strings.Cut(rule, `family="`); ok {
		if val, _, ok := strings.Cut(after, `"`); ok {
			rr.family = val
		}
	}

	// Extract source address — prefer the NOT-inverted form so `source NOT address="..."`
	// isn't misread as a plain source match via a short-circuit on `address="..."`.
	// firewalld 0.6 (RHEL 7) prints an inverted destination as `destination not`.
	rr.source, rr.sourceInverted = richRuleAddress(rule, "source")
	rr.destination, rr.destinationInverted = richRuleAddress(rule, "destination")

	// Extract action. The action element follows the match elements and may
	// carry its own options (`reject type="icmp-host-prohibited"`, `accept
	// limit value="2/m"`), so it is not always the last token. A rule with a
	// log element and no action reports "log".
	hasLog := false
	for _, tok := range richRuleTokens(rule) {
		switch tok {
		case "accept", "reject", "drop", "mark":
			rr.action = tok
		case "log":
			hasLog = true
		}
	}
	if rr.action == "" && hasLog {
		rr.action = "log"
	}

	return rr
}

// richRuleAddress returns the address of a rich rule's source or destination
// element and whether it is inverted with NOT.
func richRuleAddress(rule, element string) (string, bool) {
	for _, inv := range []struct {
		prefix   string
		inverted bool
	}{
		{element + ` NOT address="`, true},
		{element + ` not address="`, true},
		{element + ` address="`, false},
	} {
		if _, after, ok := strings.Cut(rule, inv.prefix); ok {
			if val, _, ok := strings.Cut(after, `"`); ok {
				return val, inv.inverted
			}
		}
	}
	return "", false
}

// richRuleTokens splits a rich rule on spaces outside double quotes, so a
// keyword inside a value such as `prefix="drop "` is not read as a token.
func richRuleTokens(rule string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	for _, r := range rule {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}
