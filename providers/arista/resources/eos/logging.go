// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"strconv"
	"strings"
)

// LoggingHost is a single syslog collector the device ships log messages to.
//
//	logging host 10.0.0.1
//	logging host 10.0.0.1 514
//	logging host 10.0.0.1 601 protocol tcp
//	logging vrf MGMT host 10.0.0.2
//
// Port defaults to 514 and Protocol to "udp" when the line omits them, which
// matches what EOS actually uses on the wire.
type LoggingHost struct {
	Host string
	Port int
	// Protocol is "udp" or "tcp".
	Protocol string
	// VRF is the routing instance the collector is reached through. Empty
	// means the default VRF.
	VRF string
}

// LoggingConfig captures the device's syslog configuration.
//
// A device with no `logging host` entry keeps its log messages on-box only,
// where they are lost on reboot and cannot be correlated centrally. That is
// the finding most hardening benchmarks lead with, so Hosts is the field
// most audits read.
//
// Severity fields hold the token as configured ("informational", "errors",
// "disabled", or a numeric level). An empty severity means the line was not
// present in the running-config, so the EOS default applies. We deliberately
// do not substitute a default: which level EOS defaults to varies by release,
// and reporting a guess as configuration would be worse than reporting that
// nothing was configured.
type LoggingConfig struct {
	// Enabled reflects `logging on` / `no logging on`. EOS logs by default,
	// so this is true unless the config explicitly turns logging off.
	Enabled bool
	// TrapSeverity is the severity threshold for messages sent to remote
	// collectors (`logging trap <severity>`).
	TrapSeverity string
	// ConsoleSeverity is the threshold for the console (`logging console`).
	ConsoleSeverity string
	// MonitorSeverity is the threshold for terminal monitors
	// (`logging monitor`).
	MonitorSeverity string
	// BufferedSeverity is the threshold for the on-box buffer.
	BufferedSeverity string
	// BufferedSize is the on-box buffer size in bytes (0 = unset).
	BufferedSize int
	// PersistentEnabled reflects `logging persistent`, which writes the log
	// buffer to flash so it survives a reboot.
	PersistentEnabled bool
	// PersistentSize is the persistent log size in bytes (0 = unset).
	PersistentSize int
	// SourceInterface is the interface whose address is used as the source
	// of outbound syslog traffic.
	SourceInterface string
	// Facility is the syslog facility (`logging facility local6`).
	Facility string
	// TimestampFormat is the token after `logging format timestamp`, e.g.
	// "traditional" or "high-resolution".
	TimestampFormat string
	// HostnameFormat is the token after `logging format hostname`, e.g.
	// "fqdn" or "ipv4".
	HostnameFormat string
	// Rfc5424Format reflects `logging format rfc5424`.
	Rfc5424Format bool
	// Synchronous reflects `logging synchronous`.
	Synchronous bool
	Hosts       []LoggingHost
}

// ParseLoggingConfig extracts syslog configuration from running-config.
//
// Negated forms are handled so a later `no logging ...` line clears state set
// by an earlier positive line, matching how EOS renders a config diff.
func ParseLoggingConfig(runningConfig string) *LoggingConfig {
	c := &LoggingConfig{
		// EOS logs by default; only an explicit `no logging on` disables it.
		Enabled: true,
		Hosts:   []LoggingHost{},
	}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		raw := scanner.Text()
		// Syslog configuration is top-level. Indented `logging ...` lines
		// belong to an enclosing block and are a different command entirely:
		// an interface block carries `logging event link-status`, which must
		// not be read as global logging configuration.
		if CountLeadingSpace(raw) > 0 {
			continue
		}

		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "!") {
			continue
		}

		negated := false
		if rest, ok := strings.CutPrefix(line, "no "); ok {
			negated = true
			line = rest
		}
		toks, ok := strings.CutPrefix(line, "logging ")
		if !ok {
			continue
		}
		fields := strings.Fields(toks)
		if len(fields) == 0 {
			continue
		}

		// `logging vrf <name> ...` prefixes the host and source-interface
		// forms. Strip it and remember the VRF for the rest of the line.
		vrf := ""
		if fields[0] == "vrf" && len(fields) >= 3 {
			vrf = fields[1]
			fields = fields[2:]
		}

		switch fields[0] {
		case "on":
			c.Enabled = !negated
		case "host":
			if len(fields) < 2 {
				continue
			}
			h := parseLoggingHost(fields[1:], vrf)
			if negated {
				c.removeLoggingHost(h)
				continue
			}
			c.Hosts = append(c.Hosts, h)
		case "trap":
			c.TrapSeverity = loggingSeverity(fields[1:], negated)
		case "console":
			c.ConsoleSeverity = loggingSeverity(fields[1:], negated)
		case "monitor":
			c.MonitorSeverity = loggingSeverity(fields[1:], negated)
		case "buffered":
			if negated {
				c.BufferedSeverity = "disabled"
				c.BufferedSize = 0
				continue
			}
			// `logging buffered [<size>] [<severity>]` — the size is optional
			// and always leads when present.
			rest := fields[1:]
			if len(rest) > 0 {
				if n, err := strconv.Atoi(rest[0]); err == nil {
					c.BufferedSize = n
					rest = rest[1:]
				}
			}
			if len(rest) > 0 {
				c.BufferedSeverity = rest[0]
			}
		case "persistent":
			c.PersistentEnabled = !negated
			c.PersistentSize = 0
			if !negated && len(fields) > 1 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					c.PersistentSize = n
				}
			}
		case "source-interface":
			if negated {
				c.SourceInterface = ""
				continue
			}
			if len(fields) > 1 {
				c.SourceInterface = fields[1]
			}
		case "facility":
			if negated {
				c.Facility = ""
				continue
			}
			if len(fields) > 1 {
				c.Facility = fields[1]
			}
		case "synchronous":
			c.Synchronous = !negated
		case "format":
			if len(fields) < 2 {
				continue
			}
			switch fields[1] {
			case "timestamp":
				if negated {
					c.TimestampFormat = ""
				} else if len(fields) > 2 {
					c.TimestampFormat = fields[2]
				}
			case "hostname":
				if negated {
					c.HostnameFormat = ""
				} else if len(fields) > 2 {
					c.HostnameFormat = fields[2]
				}
			case "rfc5424":
				c.Rfc5424Format = !negated
			}
		}
	}

	return c
}

// parseLoggingHost reads the tokens that follow `logging [vrf X] host`.
// EOS accepts an optional port and an optional `protocol tcp|udp` clause;
// both fall back to the values EOS itself defaults to.
func parseLoggingHost(fields []string, vrf string) LoggingHost {
	h := LoggingHost{
		Host:     fields[0],
		Port:     514,
		Protocol: "udp",
		VRF:      vrf,
	}
	for i := 1; i < len(fields); i++ {
		switch {
		case fields[i] == "protocol" && i+1 < len(fields):
			h.Protocol = fields[i+1]
			i++
		default:
			if n, err := strconv.Atoi(fields[i]); err == nil {
				h.Port = n
			}
		}
	}
	return h
}

// removeLoggingHost drops the collector a `no logging host` line negates.
func (c *LoggingConfig) removeLoggingHost(target LoggingHost) {
	for i, h := range c.Hosts {
		if h.Host == target.Host && h.VRF == target.VRF {
			c.Hosts = append(c.Hosts[:i], c.Hosts[i+1:]...)
			return
		}
	}
}

// loggingSeverity reads the severity token from a `logging <dest> <severity>`
// line. A negated line ("no logging console") disables that destination.
func loggingSeverity(fields []string, negated bool) string {
	if negated {
		return "disabled"
	}
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
