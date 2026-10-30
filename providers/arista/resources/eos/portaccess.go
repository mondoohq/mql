// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"strings"
)

// eachInterfaceBlock invokes fn once per `interface <name>` block in the
// running-config, passing the interface name and the block body. The body runs
// to the next interface header, so callers that care about the `!` end-of-block
// marker check for it themselves.
func eachInterfaceBlock(runningConfig string, fn func(name, block string)) {
	matches := ifaceHeaderRe.FindAllStringSubmatchIndex(runningConfig, -1)

	for i, match := range matches {
		name := runningConfig[match[2]:match[3]]
		blockStart := match[1]
		blockEnd := len(runningConfig)
		if i+1 < len(matches) {
			blockEnd = matches[i+1][0]
		}
		fn(name, runningConfig[blockStart:blockEnd])
	}
}

// Dot1xInterface is the 802.1X configuration on one switched interface.
//
//	interface Ethernet1
//	   dot1x pae authenticator
//	   dot1x port-control auto
//	   dot1x host-mode multi-host
//	   dot1x reauthentication
//	   dot1x timeout reauth-period 3600
//
// PortControl is the field that decides whether the port enforces anything:
// "auto" runs the authentication exchange, while "force-authorized" hands out
// access to whatever plugs in and is the EOS default.
type Dot1xInterface struct {
	// Interface is the parent interface name (e.g. "Ethernet1").
	Interface string
	// PaeMode is the port access entity role, typically "authenticator".
	PaeMode string
	// PortControl is "auto", "force-authorized", or "force-unauthorized".
	PortControl string
	// HostMode is "single-host" or "multi-host".
	HostMode string
	// MacBasedAuth enables MAC authentication bypass for endpoints that
	// cannot speak 802.1X, which weakens the control to a MAC allowlist.
	MacBasedAuth bool
	// Reauthentication periodically re-runs the exchange on an authorized
	// port, so a station cannot hold access indefinitely on one success.
	Reauthentication bool
	// ReauthPeriod is the reauthentication interval in seconds (0 = unset).
	ReauthPeriod int
	// TxPeriod is the EAP request retransmit interval in seconds (0 = unset).
	TxPeriod int
	// QuietPeriod is the hold-down after a failed exchange, in seconds
	// (0 = unset).
	QuietPeriod int
	// EapolDisabled suppresses EAPOL frames on the port.
	EapolDisabled bool
}

// Dot1xConfig is the device-wide 802.1X configuration.
//
// SystemAuthControl is the master switch: without it, per-interface
// `dot1x port-control auto` lines are configured but inert, so a device can
// look like it enforces port authentication while enforcing nothing.
type Dot1xConfig struct {
	// SystemAuthControl reflects `dot1x system-auth-control`.
	SystemAuthControl bool
	// DynamicAuthorization allows a RADIUS server to change or revoke an
	// authorized session (CoA).
	DynamicAuthorization bool
	// MacBasedAuthHoldPeriod is the hold period in seconds after a failed
	// MAC authentication (0 = unset).
	MacBasedAuthHoldPeriod int
	Interfaces             []Dot1xInterface
}

// ParseDot1xConfig extracts the 802.1X configuration from running-config.
func ParseDot1xConfig(runningConfig string) *Dot1xConfig {
	cfg := &Dot1xConfig{Interfaces: []Dot1xInterface{}}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		raw := scanner.Text()
		// Global 802.1X settings are top-level; the same keywords appear
		// indented inside interface blocks with a different meaning.
		if CountLeadingSpace(raw) > 0 {
			continue
		}
		line := strings.TrimSpace(raw)

		negated := false
		if cut, ok := strings.CutPrefix(line, "no "); ok {
			negated = true
			line = cut
		}
		switch {
		case line == "dot1x system-auth-control":
			cfg.SystemAuthControl = !negated
		case line == "dot1x dynamic-authorization":
			cfg.DynamicAuthorization = !negated
		case strings.HasPrefix(line, "dot1x mac based authentication hold period "):
			if negated {
				cfg.MacBasedAuthHoldPeriod = 0
				continue
			}
			fields := strings.Fields(line)
			cfg.MacBasedAuthHoldPeriod = atoiOrZero(fields[len(fields)-1])
		}
	}

	eachInterfaceBlock(runningConfig, func(name, block string) {
		iface := Dot1xInterface{Interface: name}
		hasAny := false

		blockScanner := bufio.NewScanner(strings.NewReader(block))
		for blockScanner.Scan() {
			line := strings.TrimSpace(blockScanner.Text())
			if line == "!" || line == "end" {
				break
			}
			rest, ok := strings.CutPrefix(line, "dot1x ")
			if !ok {
				continue
			}
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				continue
			}
			hasAny = true

			switch {
			case fields[0] == "pae" && len(fields) > 1:
				iface.PaeMode = fields[1]
			case fields[0] == "port-control" && len(fields) > 1:
				iface.PortControl = fields[1]
			case fields[0] == "host-mode" && len(fields) > 1:
				iface.HostMode = fields[1]
			case rest == "mac based authentication":
				iface.MacBasedAuth = true
			case rest == "reauthentication":
				iface.Reauthentication = true
			case rest == "eapol disabled":
				iface.EapolDisabled = true
			case fields[0] == "timeout" && len(fields) > 2:
				switch fields[1] {
				case "reauth-period":
					iface.ReauthPeriod = atoiOrZero(fields[2])
				case "tx-period":
					iface.TxPeriod = atoiOrZero(fields[2])
				case "quiet-period":
					iface.QuietPeriod = atoiOrZero(fields[2])
				}
			}
		}

		// Interfaces with no 802.1X configuration at all are left out; the
		// caller decides what an unconfigured port means for its policy.
		if hasAny {
			cfg.Interfaces = append(cfg.Interfaces, iface)
		}
	})

	return cfg
}

// DhcpSnoopingConfig is the DHCP snooping configuration.
//
//	ip dhcp snooping
//	ip dhcp snooping vlan 100,200
//	ip dhcp snooping information option
//	!
//	interface Ethernet1
//	   ip dhcp snooping trust
//
// DHCP snooping drops server-role DHCP traffic arriving on untrusted ports,
// which is what stops a rogue DHCP server from handing out its own address as
// the default gateway. Trust is the setting to check: an uplink must be
// trusted and an access port must not be.
type DhcpSnoopingConfig struct {
	// Enabled reflects the bare `ip dhcp snooping` command.
	Enabled bool
	// Vlans are the VLANs snooping is enabled on, as configured. Range
	// tokens such as "100-200" are preserved verbatim.
	Vlans []string
	// InsertOption82 reflects `ip dhcp snooping information option`, which
	// stamps relay-agent information onto forwarded requests.
	InsertOption82 bool
	// Bridging reflects `ip dhcp snooping bridging`.
	Bridging bool
	// TrustedInterfaces are the interfaces carrying
	// `ip dhcp snooping trust`, held as names to match how the other
	// interface-scoped resources in this provider report them.
	TrustedInterfaces []string
}

// ParseDhcpSnooping extracts the DHCP snooping configuration.
func ParseDhcpSnooping(runningConfig string) *DhcpSnoopingConfig {
	cfg := &DhcpSnoopingConfig{
		Vlans:             []string{},
		TrustedInterfaces: []string{},
	}

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
		switch {
		case line == "ip dhcp snooping":
			cfg.Enabled = !negated
		case line == "ip dhcp snooping information option":
			cfg.InsertOption82 = !negated
		case line == "ip dhcp snooping bridging":
			cfg.Bridging = !negated
		case strings.HasPrefix(line, "ip dhcp snooping vlan "):
			if negated {
				cfg.Vlans = []string{}
				continue
			}
			// Coverage accumulates across lines. A device that renders one
			// line per VLAN would lose all but the last if this replaced.
			cfg.Vlans = appendVlans(cfg.Vlans,
				splitVlanList(strings.TrimPrefix(line, "ip dhcp snooping vlan ")))
		}
	}

	eachInterfaceBlock(runningConfig, func(name, block string) {
		if interfaceBlockHasLine(block, "ip dhcp snooping trust") {
			cfg.TrustedInterfaces = append(cfg.TrustedInterfaces, name)
		}
	})

	return cfg
}

// ArpInspectionConfig is the Dynamic ARP Inspection configuration.
//
//	ip arp inspection vlan 100,200
//	!
//	interface Ethernet1
//	   ip arp inspection trust
//
// DAI validates ARP replies against the DHCP snooping bindings, which is what
// stops ARP spoofing between hosts on the same VLAN. It has no global on
// switch: it is enabled per VLAN, so Enabled is derived from whether any VLAN
// is covered.
type ArpInspectionConfig struct {
	// Enabled is true when DAI covers at least one VLAN.
	Enabled bool
	// Vlans are the VLANs DAI is enabled on, as configured. Range tokens
	// such as "100-200" are preserved verbatim.
	Vlans []string
	// TrustedInterfaces are the interfaces carrying
	// `ip arp inspection trust`, which bypass validation.
	TrustedInterfaces []string
}

// ParseArpInspection extracts the Dynamic ARP Inspection configuration.
func ParseArpInspection(runningConfig string) *ArpInspectionConfig {
	cfg := &ArpInspectionConfig{
		Vlans:             []string{},
		TrustedInterfaces: []string{},
	}

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
		rest, ok := strings.CutPrefix(line, "ip arp inspection vlan ")
		if !ok {
			continue
		}
		if negated {
			cfg.Vlans = []string{}
			continue
		}
		// The VLAN list leads; trailing clauses such as
		// `logging acl-match matchlog` are not part of it.
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		// DAI is commonly configured a VLAN at a time, so coverage
		// accumulates across lines rather than replacing.
		cfg.Vlans = appendVlans(cfg.Vlans, splitVlanList(fields[0]))
	}
	cfg.Enabled = len(cfg.Vlans) > 0

	eachInterfaceBlock(runningConfig, func(name, block string) {
		if interfaceBlockHasLine(block, "ip arp inspection trust") {
			cfg.TrustedInterfaces = append(cfg.TrustedInterfaces, name)
		}
	})

	return cfg
}

// interfaceBlockHasLine reports whether an interface block contains an exact
// configuration line, stopping at the block's end marker.
func interfaceBlockHasLine(block, want string) bool {
	scanner := bufio.NewScanner(strings.NewReader(block))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "!" || line == "end" {
			return false
		}
		if line == want {
			return true
		}
	}
	return false
}

// appendVlans adds VLAN tokens to a coverage list, skipping ones already
// present so a configuration that repeats a VLAN across lines does not report
// it twice.
func appendVlans(existing, added []string) []string {
	seen := make(map[string]bool, len(existing))
	for _, v := range existing {
		seen[v] = true
	}
	for _, v := range added {
		if !seen[v] {
			seen[v] = true
			existing = append(existing, v)
		}
	}
	return existing
}

// splitVlanList splits a comma-separated VLAN list. Range tokens are kept as
// written rather than expanded: "100-200" is one readable token, and expanding
// it would turn a two-VLAN configuration line into a hundred-element list.
func splitVlanList(s string) []string {
	res := []string{}
	for tok := range strings.SplitSeq(strings.TrimSpace(s), ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			res = append(res, tok)
		}
	}
	return res
}
