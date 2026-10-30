// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"sort"
	"strings"
)

// MonitorSession is a port-mirroring session.
//
//	monitor session SPAN1 source Ethernet1
//	monitor session SPAN1 source Ethernet2 rx
//	monitor session SPAN1 destination Ethernet48
//	monitor session ERSPAN1 destination tunnel mode gre destination 10.0.0.1
//	monitor session SPAN1 truncate size 160
//
// A mirroring session copies production traffic somewhere else. That is a
// normal troubleshooting tool and also the cleanest way to exfiltrate traffic
// from a switch without touching a host, so an unexpected session, and
// particularly one whose destination is an off-box tunnel, is worth an
// explanation.
type MonitorSession struct {
	Name string
	// Sources are the mirrored interfaces, each with its direction.
	Sources []MonitorSource
	// DestinationInterfaces are the local ports the copy is sent to.
	DestinationInterfaces []string
	// TunnelDestinations are the remote addresses an encapsulated session
	// sends to. A session with one of these leaves the device.
	TunnelDestinations []string
	// TruncateEnabled reports whether mirrored packets are truncated.
	TruncateEnabled bool
	// TruncateSize is the truncation size in bytes (0 = unset).
	TruncateSize int
}

// MonitorSource is one mirrored interface within a session.
type MonitorSource struct {
	Interface string
	// Direction is "rx", "tx", or "both". EOS mirrors both directions when
	// the source line omits one.
	Direction string
}

// SflowDestination is one sFlow collector.
type SflowDestination struct {
	Address string
	// Port is the collector port (6343 when the configuration omits it).
	Port int
	// VRF is the routing instance the collector is reached through.
	VRF string
}

// SflowConfig is the sFlow sampling configuration.
//
//	sflow sample 16384
//	sflow polling-interval 30
//	sflow destination 10.0.0.50
//	sflow source-interface Management1
//	sflow run
//
// sFlow ships sampled packet headers and interface counters to a collector.
// The headers include real traffic, so the collector list is a data-egress
// path in the same way a mirroring destination is.
type SflowConfig struct {
	// Enabled reflects `sflow run`.
	Enabled bool
	// SampleRate is the 1-in-N packet sampling rate (0 = unset).
	SampleRate int
	// PollingInterval is the counter polling interval in seconds
	// (0 = unset).
	PollingInterval int
	// SourceInterface is the interface sourcing packets to the collectors.
	SourceInterface string
	Destinations    []SflowDestination
}

// InterfaceHardening is the per-interface Layer 3 posture.
//
//	interface Vlan100
//	   ip proxy-arp
//	   no ip redirects
//	   ip verify unicast source reachable-via rx
//
// Proxy ARP lets the switch answer ARP for addresses that are not its own,
// which blurs the segmentation a subnet boundary is supposed to provide.
// Unicast RPF drops packets arriving from a direction the routing table would
// not use to reach their source, which is the standard anti-spoofing control.
type InterfaceHardening struct {
	Interface string
	// ProxyArpEnabled reflects `ip proxy-arp`, which is off unless
	// configured.
	ProxyArpEnabled bool
	// IcmpRedirectsEnabled reflects whether the interface sends ICMP
	// redirects. EOS sends them unless `no ip redirects` is configured, so
	// this is true for an interface that says nothing about it.
	IcmpRedirectsEnabled bool
	// UnicastRpfMode is the reverse-path-forwarding mode, "rx" or "any".
	// Empty when unicast RPF is not configured.
	UnicastRpfMode string
}

// ParseMonitorSessions extracts the port-mirroring sessions. They are
// rendered as flat top-level lines, one setting per line, so a session's
// configuration accumulates across several of them.
func ParseMonitorSessions(runningConfig string) []MonitorSession {
	byName := map[string]*MonitorSession{}
	order := []string{}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		raw := scanner.Text()
		if CountLeadingSpace(raw) > 0 {
			continue
		}
		rest, ok := strings.CutPrefix(strings.TrimSpace(raw), "monitor session ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			continue
		}

		name := fields[0]
		session, ok := byName[name]
		if !ok {
			session = &MonitorSession{
				Name:                  name,
				Sources:               []MonitorSource{},
				DestinationInterfaces: []string{},
				TunnelDestinations:    []string{},
			}
			byName[name] = session
			order = append(order, name)
		}

		switch fields[1] {
		case "source":
			if len(fields) < 3 {
				continue
			}
			src := MonitorSource{Interface: fields[2], Direction: "both"}
			if len(fields) > 3 {
				switch fields[3] {
				case "rx", "tx", "both":
					src.Direction = fields[3]
				}
			}
			session.Sources = append(session.Sources, src)

		case "destination":
			if len(fields) < 3 {
				continue
			}
			if fields[2] == "tunnel" {
				// `destination tunnel mode gre destination <addr> ...` puts
				// the remote address after a second `destination` keyword.
				for i := 3; i+1 < len(fields); i++ {
					if fields[i] == "destination" {
						session.TunnelDestinations = append(session.TunnelDestinations, fields[i+1])
						break
					}
				}
				continue
			}
			session.DestinationInterfaces = append(session.DestinationInterfaces, fields[2])

		case "truncate":
			session.TruncateEnabled = true
			if len(fields) > 3 && fields[2] == "size" {
				session.TruncateSize = atoiOrZero(fields[3])
			}
		}
	}

	res := make([]MonitorSession, 0, len(order))
	for _, name := range order {
		res = append(res, *byName[name])
	}
	sort.SliceStable(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

// ParseSflowConfig extracts the sFlow sampling configuration.
func ParseSflowConfig(runningConfig string) *SflowConfig {
	cfg := &SflowConfig{Destinations: []SflowDestination{}}

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
		rest, ok := strings.CutPrefix(line, "sflow ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}

		// `sflow vrf <name> destination ...` prefixes the collector form.
		vrf := ""
		if fields[0] == "vrf" && len(fields) >= 3 {
			vrf = fields[1]
			fields = fields[2:]
		}

		switch fields[0] {
		case "run":
			cfg.Enabled = !negated

		case "sample":
			if len(fields) > 1 {
				cfg.SampleRate = atoiOrZero(fields[1])
			}

		case "polling-interval":
			if len(fields) > 1 {
				cfg.PollingInterval = atoiOrZero(fields[1])
			}

		case "source-interface", "source":
			if negated {
				cfg.SourceInterface = ""
				continue
			}
			if len(fields) > 1 {
				cfg.SourceInterface = fields[1]
			}

		case "destination":
			if len(fields) < 2 {
				continue
			}
			dest := SflowDestination{
				Address: fields[1],
				// EOS uses the well-known sFlow port when the line omits it.
				Port: 6343,
				VRF:  vrf,
			}
			if len(fields) > 2 {
				if n := atoiOrZero(fields[2]); n != 0 {
					dest.Port = n
				}
			}
			if negated {
				cfg.Destinations = removeSflowDestination(cfg.Destinations, dest)
				continue
			}
			cfg.Destinations = append(cfg.Destinations, dest)
		}
	}

	return cfg
}

// removeSflowDestination drops the collector a `no sflow destination` line
// negates.
func removeSflowDestination(dests []SflowDestination, target SflowDestination) []SflowDestination {
	for i, d := range dests {
		if d.Address == target.Address && d.VRF == target.VRF {
			return append(dests[:i], dests[i+1:]...)
		}
	}
	return dests
}

// ParseInterfaceHardening returns the Layer 3 posture of every interface
// block, including those that configure none of it: an interface that says
// nothing still has a posture, and it is the device default.
func ParseInterfaceHardening(runningConfig string) []InterfaceHardening {
	res := []InterfaceHardening{}

	eachInterfaceBlock(runningConfig, func(name, block string) {
		h := InterfaceHardening{
			Interface: name,
			// EOS sends ICMP redirects unless told not to, so the default
			// for an interface that says nothing is enabled.
			IcmpRedirectsEnabled: true,
		}

		scanner := bufio.NewScanner(strings.NewReader(block))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "!" || line == "end" {
				break
			}
			switch {
			case line == "ip proxy-arp":
				h.ProxyArpEnabled = true
			case line == "no ip proxy-arp":
				h.ProxyArpEnabled = false
			case line == "ip redirects":
				h.IcmpRedirectsEnabled = true
			case line == "no ip redirects":
				h.IcmpRedirectsEnabled = false
			case strings.HasPrefix(line, "ip verify unicast source reachable-via "):
				// EOS accepts trailing options after the mode, as in
				// `... reachable-via rx allow-default` or a trailing ACL
				// name. Only the first token is the mode itself, so keep
				// that and let the rest go: a mode of "rx allow-default"
				// would not match a policy testing for "rx".
				if fields := strings.Fields(strings.TrimPrefix(
					line, "ip verify unicast source reachable-via ")); len(fields) > 0 {
					h.UnicastRpfMode = fields[0]
				}
			case strings.HasPrefix(line, "no ip verify unicast"):
				h.UnicastRpfMode = ""
			}
		}
		res = append(res, h)
	})

	return res
}
