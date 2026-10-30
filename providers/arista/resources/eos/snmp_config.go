// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"slices"
	"strconv"
	"strings"
)

// SnmpUser is one `snmp-server user` line: an SNMPv3 principal, or a v1/v2c
// principal on the rare devices that declare one.
//
//	snmp-server user USER-NO-AUTH GRP-READ-ONLY v3
//	snmp-server user USER-AUTH GRP-READ-ONLY v3 auth sha <passphrase>
//	snmp-server user USER-PRIV GRP-READ-ONLY v3 auth sha <passphrase> priv aes <passphrase>
//	snmp-server user USER-LOC GRP-READ-ONLY v3 localized <engineID> auth sha <key>
//	snmp-server user REMOTE-USER GRP-REMOTE remote 192.0.2.10 udp-port 666 v3
//
// The passphrase and the localized key that follow the `auth` and `priv`
// algorithm names are key material and are deliberately not kept: the
// algorithm names answer the strength question on their own, and the
// security level is derived from which clauses are present.
type SnmpUser struct {
	// Name is the security name.
	Name string
	// Group is the group whose views the user inherits.
	Group string
	// Version is normalized to "v1", "v2c", or "v3".
	Version string
	// Localized is true when the line carries a `localized <engineID>`
	// clause, meaning the credentials are already localized to an engine
	// rather than given as passphrases.
	Localized bool
	// AuthAlgorithm is the authentication algorithm, for example "md5" or
	// "sha". Empty when the user authenticates with nothing.
	AuthAlgorithm string
	// PrivAlgorithm is the privacy (encryption) algorithm, for example
	// "des" or "aes". Empty when the user's traffic is not encrypted.
	PrivAlgorithm string
	// RemoteAddress is the remote agent the user is defined against, from
	// the `remote <addr>` clause. Empty for the local agent.
	RemoteAddress string
	// RemotePort is the remote agent's port. 0 when the line omits it, in
	// which case EOS uses 162.
	RemotePort int
}

// SecurityLevel reports the USM security level the user operates at:
// "noAuthNoPriv", "authNoPriv", or "authPriv". These are the level names
// SNMPv3 itself uses.
func (u SnmpUser) SecurityLevel() string {
	switch {
	case u.AuthAlgorithm != "" && u.PrivAlgorithm != "":
		return "authPriv"
	case u.AuthAlgorithm != "":
		return "authNoPriv"
	default:
		return "noAuthNoPriv"
	}
}

// SnmpGroup is one `snmp-server group` line, which binds a security level to
// the views its members may read, write, and be notified through.
//
//	snmp-server group GRP-READ-ONLY v3 priv read v3read
//	snmp-server group GRP-READ-WRITE v3 auth read v3read write v3write
//	snmp-server group group2 v3 priv write view2 notify view1
type SnmpGroup struct {
	Name string
	// Version is normalized to "v1", "v2c", or "v3".
	Version string
	// SecurityLevel is "noauth", "auth", or "priv" as written on a v3
	// group, and empty for v1 and v2c, which have no security level.
	SecurityLevel string
	Context       string
	ReadView      string
	WriteView     string
	NotifyView    string
}

// SnmpView is one `snmp-server view` line, the MIB subtree filter a group
// reads through.
//
//	snmp-server view VW-READ iso included
//	snmp-server view VW-EXCLUDED iso excluded
//
// The configuration keywords are `include` and `exclude`, and EOS renders
// them back as `included` and `excluded`; both spellings are accepted here
// because a configuration may be captured either way.
type SnmpView struct {
	Name string
	// MibFamily is the MIB subtree the entry covers, for example "iso" or
	// "system.2".
	MibFamily string
	// Included is true for an `included` entry and false for `excluded`.
	Included bool
}

// SnmpHost is one `snmp-server host` line: a destination the device sends
// notifications to.
//
//	snmp-server host 192.0.2.20 vrf MGMT version 1 <community>
//	snmp-server host 192.0.2.20 vrf MGMT version 3 auth USER-READ-AUTH
//	snmp-server host 192.0.2.30 informs version 2c <community>
//	snmp-server host collector version 2c <community> udp-port 23
//
// Under version 1 or 2c the trailing token is the community string, a
// plaintext shared secret that travels with every notification. It is kept
// on Credential so a reference can be resolved against the communities the
// device declares, and is deliberately never published as a field of its
// own.
type SnmpHost struct {
	// Host is the destination hostname or address as configured.
	Host string
	// Vrf is the routing instance used to reach the destination. Empty
	// means the default VRF.
	Vrf string
	// NotificationType is "traps" or "informs". EOS sends traps unless the
	// line says otherwise, so an omitted keyword is reported as "traps".
	NotificationType string
	// Version is normalized to "v1", "v2c", or "v3". A line with no
	// `version` clause is reported as "v2c", the EOS default.
	Version string
	// SecurityLevel is "noauth", "auth", or "priv" for a v3 destination,
	// and empty for v1 and v2c.
	SecurityLevel string
	// Port is the destination UDP port. Reported as 162 when the line omits
	// it, matching what the device does.
	Port int
	// Credential is the trailing token: the community string for v1 and
	// v2c, or the security name for v3. It is not published as a field
	// because the v1/v2c form is a shared secret; it exists so the
	// destination can be joined to the community or user it names.
	Credential string
}

// SnmpConfig is the SNMP configuration read out of running-config, covering
// the parts `show snmp` does not report.
type SnmpConfig struct {
	Users  []SnmpUser
	Groups []SnmpGroup
	Views  []SnmpView
	Hosts  []SnmpHost

	// Location, Contact, and ChassisID are the device identity carried in
	// every notification. Empty when unset.
	Location  string
	Contact   string
	ChassisID string

	// LocalInterface is the global `snmp-server local-interface`, the
	// interface notifications are sourced from. Empty when unset.
	LocalInterface string

	// Vrfs are the routing instances SNMP is reachable in. EOS enables SNMP
	// in the default VRF and nowhere else unless told otherwise, so the
	// list starts with "default" and `no snmp-server vrf default` removes
	// it.
	Vrfs []string

	// VrfLocalInterfaces maps a routing instance to the interface SNMP is
	// sourced from within it, from `snmp-server vrf <vrf> local-interface`.
	VrfLocalInterfaces map[string]string
}

// normalizeSnmpVersion maps the version tokens EOS accepts onto one spelling.
// `snmp-server user` writes the version as `v3` while `snmp-server host`
// writes it as `version 3`, and reporting both as "v3" is what lets a query
// compare a destination against the user it names.
func normalizeSnmpVersion(tok string) string {
	switch tok {
	case "1", "v1":
		return "v1"
	case "2c", "v2c":
		return "v2c"
	case "3", "v3":
		return "v3"
	default:
		return ""
	}
}

// ParseSnmpConfig extracts SNMPv3 principals, the notification destinations,
// and the global SNMP identity from running-config.
//
// ParseSnmpCommunities covers the v1/v2c community strings, which are a
// separate mechanism; a device that has moved to v3 has no communities at
// all and is described entirely by what this returns.
func ParseSnmpConfig(runningConfig string) *SnmpConfig {
	cfg := &SnmpConfig{
		Users:              []SnmpUser{},
		Groups:             []SnmpGroup{},
		Views:              []SnmpView{},
		Hosts:              []SnmpHost{},
		VrfLocalInterfaces: map[string]string{},
	}

	// SNMP runs in the default VRF unless that is explicitly withdrawn.
	vrfEnabled := map[string]bool{"default": true}
	vrfOrder := []string{"default"}

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

		rest, ok := strings.CutPrefix(line, "snmp-server ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		keyword, args := fields[0], fields[1:]

		switch keyword {
		case "vrf":
			if len(args) == 0 {
				continue
			}
			name := args[0]
			if negated {
				vrfEnabled[name] = false
				continue
			}
			if !vrfEnabled[name] {
				vrfOrder = appendIfMissing(vrfOrder, name)
			}
			vrfEnabled[name] = true
			// `snmp-server vrf <vrf> local-interface <intf>` is the
			// per-instance source interface.
			if len(args) >= 3 && args[1] == "local-interface" {
				cfg.VrfLocalInterfaces[name] = args[2]
			}
		case "local-interface":
			if negated {
				cfg.LocalInterface = ""
				continue
			}
			if len(args) >= 1 {
				cfg.LocalInterface = args[0]
			}
		case "location":
			if negated {
				cfg.Location = ""
				continue
			}
			// The value runs to the end of the line and may contain spaces.
			cfg.Location = strings.Join(args, " ")
		case "contact":
			if negated {
				cfg.Contact = ""
				continue
			}
			cfg.Contact = strings.Join(args, " ")
		case "chassis-id":
			if negated {
				cfg.ChassisID = ""
				continue
			}
			cfg.ChassisID = strings.Join(args, " ")
		case "user":
			if negated {
				continue
			}
			if u, ok := parseSnmpUser(args); ok {
				cfg.Users = append(cfg.Users, u)
			}
		case "group":
			if negated {
				continue
			}
			if g, ok := parseSnmpGroup(args); ok {
				cfg.Groups = append(cfg.Groups, g)
			}
		case "view":
			if negated {
				continue
			}
			if v, ok := parseSnmpView(args); ok {
				cfg.Views = append(cfg.Views, v)
			}
		case "host":
			if negated {
				continue
			}
			if h, ok := parseSnmpHost(args); ok {
				cfg.Hosts = append(cfg.Hosts, h)
			}
		}
	}

	for _, name := range vrfOrder {
		if vrfEnabled[name] {
			cfg.Vrfs = append(cfg.Vrfs, name)
		}
	}
	if cfg.Vrfs == nil {
		cfg.Vrfs = []string{}
	}

	return cfg
}

func appendIfMissing(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// parseSnmpUser reads the tokens after `snmp-server user`. The clauses appear
// in a fixed order: name, group, an optional remote agent, the version, an
// optional localization engine, then the security clauses.
func parseSnmpUser(args []string) (SnmpUser, bool) {
	if len(args) < 2 {
		return SnmpUser{}, false
	}
	u := SnmpUser{Name: args[0], Group: args[1]}
	i := 2

	if i < len(args) && args[i] == "remote" && i+1 < len(args) {
		u.RemoteAddress = args[i+1]
		i += 2
		if i+1 < len(args) && args[i] == "udp-port" {
			if n, err := strconv.Atoi(args[i+1]); err == nil {
				u.RemotePort = n
			}
			i += 2
		}
	}

	if i < len(args) {
		if v := normalizeSnmpVersion(args[i]); v != "" {
			u.Version = v
			i++
		}
	}

	// `localized <engineID>` precedes the security clauses. The engine ID is
	// an identifier rather than a secret, but it is not worth a field of its
	// own; only its presence is recorded.
	if i+1 < len(args) && args[i] == "localized" {
		u.Localized = true
		i += 2
	}

	// Read only the algorithm names. Each security clause is three tokens
	// (`auth <algo> <passphrase>`), so the advance steps over the credential
	// without it being kept anywhere.
	if i+1 < len(args) && args[i] == "auth" {
		u.AuthAlgorithm = args[i+1]
		i += 3
		if i+1 < len(args) && args[i] == "priv" {
			u.PrivAlgorithm = args[i+1]
		}
	}

	return u, true
}

// parseSnmpGroup reads the tokens after `snmp-server group`. On a v3 group the
// security level follows the version as its own token.
func parseSnmpGroup(args []string) (SnmpGroup, bool) {
	if len(args) < 2 {
		return SnmpGroup{}, false
	}
	g := SnmpGroup{Name: args[0]}
	i := 1

	version := normalizeSnmpVersion(args[i])
	if version == "" {
		return SnmpGroup{}, false
	}
	g.Version = version
	i++

	if g.Version == "v3" && i < len(args) {
		switch args[i] {
		case "noauth", "auth", "priv":
			g.SecurityLevel = args[i]
			i++
		}
	}

	for i+1 < len(args) {
		switch args[i] {
		case "context":
			g.Context = args[i+1]
		case "read":
			g.ReadView = args[i+1]
		case "write":
			g.WriteView = args[i+1]
		case "notify":
			g.NotifyView = args[i+1]
		default:
			i++
			continue
		}
		i += 2
	}

	return g, true
}

// parseSnmpView reads the tokens after `snmp-server view`.
func parseSnmpView(args []string) (SnmpView, bool) {
	if len(args) < 3 {
		return SnmpView{}, false
	}
	v := SnmpView{Name: args[0], MibFamily: args[1]}
	switch args[2] {
	case "included", "include":
		v.Included = true
	case "excluded", "exclude":
		v.Included = false
	default:
		return SnmpView{}, false
	}
	return v, true
}

// parseSnmpHost reads the tokens after `snmp-server host`. The published
// command syntax for this line is malformed in the EOS manual, so the order
// here follows the manual's worked examples and the configurations EOS
// renders: host, VRF, notification kind, version, credential, port.
func parseSnmpHost(args []string) (SnmpHost, bool) {
	if len(args) == 0 {
		return SnmpHost{}, false
	}
	h := SnmpHost{
		Host: args[0],
		// EOS sends traps over v2c on port 162 unless the line says
		// otherwise. Reporting the effective value keeps a destination
		// written the short way comparable with one written in full.
		NotificationType: "traps",
		Version:          "v2c",
		Port:             162,
	}
	i := 1

	if i+1 < len(args) && args[i] == "vrf" {
		h.Vrf = args[i+1]
		i += 2
	}

	if i < len(args) && (args[i] == "informs" || args[i] == "traps") {
		h.NotificationType = args[i]
		i++
	}

	if i+1 < len(args) && args[i] == "version" {
		if v := normalizeSnmpVersion(args[i+1]); v != "" {
			h.Version = v
			i += 2
			if h.Version == "v3" && i < len(args) {
				switch args[i] {
				case "noauth", "auth", "priv":
					h.SecurityLevel = args[i]
					i++
				}
			}
		}
	}

	// The notification kind may also trail the version clause.
	if i < len(args) && (args[i] == "informs" || args[i] == "traps") {
		h.NotificationType = args[i]
		i++
	}

	if i < len(args) && args[i] != "udp-port" {
		h.Credential = args[i]
		i++
	}

	if i+1 < len(args) && args[i] == "udp-port" {
		if n, err := strconv.Atoi(args[i+1]); err == nil {
			h.Port = n
		}
	}

	return h, true
}
