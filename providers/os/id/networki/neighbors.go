// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"bufio"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Neighbor is a single entry from the ARP (IPv4) / NDP (IPv6) neighbor cache.
type Neighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	State     string `json:"state"`
}

// Neighbors returns the ARP/NDP neighbor cache of the system.
//
// NOTE we shell out to the platform's neighbor tooling rather than using
// syscalls, which do not work for SSH connection types.
func Neighbors(conn shared.Connection, pf *inventory.Platform) ([]Neighbor, error) {
	n := &neti{conn, pf}

	if pf.IsFamily(inventory.FAMILY_LINUX) {
		return n.detectLinuxNeighbors()
	}
	if pf.IsFamily(inventory.FAMILY_DARWIN) || pf.IsFamily(inventory.FAMILY_BSD) {
		return n.detectUnixNeighbors()
	}
	if pf.IsFamily(inventory.FAMILY_WINDOWS) {
		return n.detectWindowsNeighbors()
	}

	return nil, errors.New("your platform is not supported for the detection of network neighbors")
}

// normalizeMAC lowercases a MAC address, converts Windows-style dashes to
// colons, and zero-pads single-digit octets (macOS `arp` drops leading
// zeros). Incomplete/empty/all-zero addresses normalize to the empty string.
func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || strings.Contains(s, "incomplete") || strings.Contains(s, "no_entry") {
		return ""
	}
	s = strings.ReplaceAll(s, "-", ":")
	parts := strings.Split(s, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	mac := strings.Join(parts, ":")
	if mac == "00:00:00:00:00:00" {
		return ""
	}
	return mac
}

// ── Linux ────────────────────────────────────────────────────────────────────

func (n *neti) detectLinuxNeighbors() ([]Neighbor, error) {
	// Primary: `ip -j neigh show` returns a clean JSON array.
	out, err := n.RunCommand("ip -j neigh show")
	if err == nil && strings.HasPrefix(strings.TrimSpace(out), "[") {
		if neighbors, perr := parseIPNeighJSON(out); perr == nil {
			return neighbors, nil
		}
	}

	// Fallback: parse /proc/net/arp (IPv4 only, always present on Linux).
	content, err := afero.ReadFile(n.connection.FileSystem(), "/proc/net/arp")
	if err != nil {
		return nil, err
	}
	return parseProcNetArp(string(content)), nil
}

type ipNeighEntry struct {
	Dst    string   `json:"dst"`
	Dev    string   `json:"dev"`
	Lladdr string   `json:"lladdr"`
	State  []string `json:"state"`
}

func parseIPNeighJSON(out string) ([]Neighbor, error) {
	var entries []ipNeighEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		return nil, err
	}
	neighbors := make([]Neighbor, 0, len(entries))
	for _, e := range entries {
		if e.Dst == "" {
			continue
		}
		state := ""
		if len(e.State) > 0 {
			state = strings.ToLower(e.State[0])
		}
		neighbors = append(neighbors, Neighbor{
			IP:        e.Dst,
			MAC:       normalizeMAC(e.Lladdr),
			Interface: e.Dev,
			State:     state,
		})
	}
	return neighbors, nil
}

func parseProcNetArp(content string) []Neighbor {
	var neighbors []Neighbor
	scanner := bufio.NewScanner(strings.NewReader(content))
	header := true
	for scanner.Scan() {
		if header { // "IP address  HW type  Flags  HW address  Mask  Device"
			header = false
			continue
		}
		// Columns: IPaddress HWtype Flags HWaddress Mask Device
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		state := "reachable"
		if fields[2] == "0x0" { // ATF_COM not set → incomplete
			state = "incomplete"
		}
		neighbors = append(neighbors, Neighbor{
			IP:        fields[0],
			MAC:       normalizeMAC(fields[3]),
			Interface: fields[5],
			State:     state,
		})
	}
	return neighbors
}

// ── macOS / BSD ────────────────────────────────────────────────────────────

func (n *neti) detectUnixNeighbors() ([]Neighbor, error) {
	out, err := n.RunCommand("arp -an")
	if err != nil {
		return nil, err
	}
	neighbors := parseArpAn(out)

	// `arp` only exposes the IPv4 ARP table; IPv6 neighbors live in the NDP
	// cache, which `ndp -an` prints. Best-effort — skip on error.
	if ndpOut, ndpErr := n.RunCommand("ndp -an"); ndpErr == nil {
		neighbors = append(neighbors, parseNdpAn(ndpOut)...)
	}
	return neighbors, nil
}

// arpUnixRegex matches `arp -an` output, e.g.
//
//	? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
//	? (192.168.1.5) at (incomplete) on en0 ifscope [ethernet]
//	? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
var arpUnixRegex = regexp.MustCompile(`\(([^)]+)\)\s+at\s+(\S+)\s+on\s+(\S+)`)

func parseArpAn(out string) []Neighbor {
	var neighbors []Neighbor
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		m := arpUnixRegex.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip, macRaw, iface := m[1], m[2], m[3]
		state := "reachable"
		mac := ""
		if strings.Contains(macRaw, "incomplete") {
			state = "incomplete"
		} else {
			mac = normalizeMAC(macRaw)
			if strings.Contains(line, "permanent") { // static ARP entry
				state = "permanent"
			}
		}
		neighbors = append(neighbors, Neighbor{IP: ip, MAC: mac, Interface: iface, State: state})
	}
	return neighbors
}

// ndpStateCodes maps the single-letter "St" column of `ndp -an` to the
// lowercase neighbor-state vocabulary shared with the Linux/Windows paths.
var ndpStateCodes = map[string]string{
	"R": "reachable",
	"S": "stale",
	"D": "delay",
	"P": "probe",
	"I": "incomplete",
	"W": "incomplete", // waiting to be deleted
	"N": "nostate",
}

// parseNdpAn parses `ndp -an` output (IPv6 NDP neighbor cache), e.g.
//
//	Neighbor              Linklayer Address  Netif Expire    St Flgs Prbs
//	fe80::1%en0           d4:24:dd:d0:b9:5e  en0   permanent  R  R
//	2001:db8::5           aa:bb:cc:dd:ee:ff  en0   23h59m58s  R
//	fe80::abc%en0         (incomplete)       en0   expired    I
func parseNdpAn(out string) []Neighbor {
	var neighbors []Neighbor
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || fields[0] == "Neighbor" { // skip blanks + header
			continue
		}
		ip := fields[0]
		if i := strings.IndexByte(ip, '%'); i >= 0 { // strip the %zone suffix
			ip = ip[:i]
		}
		state := ndpStateCodes[fields[4]]
		if state == "" {
			state = strings.ToLower(fields[4])
		}
		if fields[3] == "permanent" {
			state = "permanent"
		}
		neighbors = append(neighbors, Neighbor{
			IP:        ip,
			MAC:       normalizeMAC(fields[1]),
			Interface: fields[2],
			State:     state,
		})
	}
	return neighbors
}

// ── Windows ────────────────────────────────────────────────────────────────

func (n *neti) detectWindowsNeighbors() ([]Neighbor, error) {
	// State is an enum; "$($_.State)" forces its label (e.g. Reachable).
	cmd := `Get-NetNeighbor | Select-Object @{Name='Ip';Expression={$_.IPAddress}}, @{Name='Mac';Expression={$_.LinkLayerAddress}}, @{Name='Interface';Expression={$_.InterfaceAlias}}, @{Name='State';Expression={"$($_.State)"}} | ConvertTo-Json`
	out, err := n.RunCommand(cmd)
	if err != nil {
		return nil, err
	}
	return parseWindowsNeighbors(out)
}

type winNeighborEntry struct {
	IP        string `json:"Ip"`
	MAC       string `json:"Mac"`
	Interface string `json:"Interface"`
	State     string `json:"State"`
}

func parseWindowsNeighbors(out string) ([]Neighbor, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return []Neighbor{}, nil
	}
	// PowerShell emits a bare object (not an array) for a single result.
	if strings.HasPrefix(out, "{") {
		out = "[" + out + "]"
	}

	var entries []winNeighborEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		return nil, err
	}
	neighbors := make([]Neighbor, 0, len(entries))
	for _, e := range entries {
		if e.IP == "" {
			continue
		}
		neighbors = append(neighbors, Neighbor{
			IP:        e.IP,
			MAC:       normalizeMAC(e.MAC),
			Interface: e.Interface,
			State:     strings.ToLower(e.State),
		})
	}
	return neighbors, nil
}
