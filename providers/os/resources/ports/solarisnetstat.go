// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ports

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// SolarisPort is one socket row from Solaris `netstat -an` or `netstat -anu`.
// State is the raw Solaris token ("LISTEN", "Idle", ...); the caller maps it
// onto the canonical state vocabulary. User and Pid are only filled when the
// listing came from `-u`, which Solaris 11.2 and later support.
type SolarisPort struct {
	// Protocol as a family-suffixed name: tcp4 | tcp6 | udp4 | udp6.
	Protocol      string
	LocalAddress  string
	LocalPort     int64
	RemoteAddress string
	RemotePort    int64
	State         string
	User          string
	Pid           int64
}

// A Solaris endpoint: an address (IPv4, IPv6, or * for the wildcard) and a
// port (or *), joined by a dot. IPv6 link-local addresses carry a %zone.
var reSolarisEndpoint = regexp.MustCompile(`^(\*|[0-9A-Fa-f:.]+(%[\w.]+)?)\.(\*|\d+)$`)

// Every TCP state Solaris netstat writes. IDLE and BOUND have no Linux
// counterpart: IDLE is a socket that was never bound, BOUND one bound to a port
// but neither listening nor connected.
var solarisTcpStates = map[string]struct{}{
	"CLOSED": {}, "IDLE": {}, "BOUND": {}, "LISTEN": {}, "SYN_SENT": {},
	"SYN_RECEIVED": {}, "ESTABLISHED": {}, "CLOSE_WAIT": {}, "FIN_WAIT_1": {},
	"CLOSING": {}, "LAST_ACK": {}, "FIN_WAIT_2": {}, "TIME_WAIT": {},
}

var solarisUdpStates = map[string]struct{}{
	"Unbound": {}, "Idle": {}, "Connected": {},
}

// ParseSolarisNetstat reads the TCP and UDP sections of Solaris `netstat -an`
// or `netstat -anu`.
//
// Each section starts with a "TCP: IPv4"-style title followed by a column
// header. With -u the header carries User, Pid and Command columns between the
// endpoints and the counters. Rows are split on whitespace rather than by
// column width because a long IPv6 address overflows its column.
//
// A UDP row leaves the remote address blank unless the socket is connected, so
// the remote column is recognised by its endpoint shape rather than position.
//
// Rows whose local endpoint is `*.*` are sockets that were never bound to a
// port. They are skipped: there is no port to report, and Linux does not list
// such sockets either. SCTP and Unix domain sections are ignored.
//
// A process may hold two sockets on one endpoint (rpcbind listens on *.111
// twice). Such rows are identical in every reported column and would resolve to
// the same cached port resource, so only the first is kept.
func ParseSolarisNetstat(r io.Reader) ([]SolarisPort, error) {
	res := []SolarisPort{}
	seen := map[SolarisPort]struct{}{}

	proto := ""
	withOwner := false

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "TCP: IPv4"):
			proto, withOwner = "tcp4", false
			continue
		case strings.HasPrefix(trimmed, "TCP: IPv6"):
			proto, withOwner = "tcp6", false
			continue
		case strings.HasPrefix(trimmed, "UDP: IPv4"):
			proto, withOwner = "udp4", false
			continue
		case strings.HasPrefix(trimmed, "UDP: IPv6"):
			proto, withOwner = "udp6", false
			continue
		case strings.HasPrefix(trimmed, "SCTP:"), strings.HasPrefix(trimmed, "Active UNIX domain sockets"):
			proto = ""
			continue
		case strings.HasPrefix(trimmed, "Local Address"):
			withOwner = strings.Contains(trimmed, " Pid ")
			continue
		case strings.HasPrefix(trimmed, "---"):
			continue
		}

		if proto == "" {
			continue
		}

		v6 := strings.HasSuffix(proto, "6")
		var entry SolarisPort
		var ok bool
		if strings.HasPrefix(proto, "tcp") {
			entry, ok = parseSolarisTcpRow(strings.Fields(line), withOwner, v6)
		} else {
			entry, ok = parseSolarisUdpRow(strings.Fields(line), withOwner, v6)
		}
		if !ok {
			continue
		}
		entry.Protocol = proto
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		res = append(res, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

// parseSolarisTcpRow reads
//
//	local remote [user pid command] swind send-q rwind recv-q state [if]
func parseSolarisTcpRow(fields []string, withOwner bool, v6 bool) (SolarisPort, bool) {
	stateIdx := -1
	for i := len(fields) - 1; i >= 2; i-- {
		if _, ok := solarisTcpStates[fields[i]]; ok {
			stateIdx = i
			break
		}
	}
	// the four counters sit between the endpoints (and owner) and the state
	if stateIdx < 6 || !isSolarisEndpoint(fields[0]) || !isSolarisEndpoint(fields[1]) {
		return SolarisPort{}, false
	}

	entry := SolarisPort{State: fields[stateIdx]}
	if withOwner {
		entry.User, entry.Pid = solarisOwner(fields[2 : stateIdx-4])
	}
	return fillSolarisEndpoints(entry, fields[0], fields[1], v6)
}

// parseSolarisUdpRow reads
//
//	local [remote] [user pid command] state [if] send-buf tx-overflows recv-buf rx-overflows
func parseSolarisUdpRow(fields []string, withOwner bool, v6 bool) (SolarisPort, bool) {
	stateIdx := -1
	for i := 1; i < len(fields); i++ {
		if _, ok := solarisUdpStates[fields[i]]; ok {
			stateIdx = i
			break
		}
	}
	if stateIdx < 1 || !isSolarisEndpoint(fields[0]) {
		return SolarisPort{}, false
	}

	middle := fields[1:stateIdx]
	remote := ""
	if len(middle) > 0 && isSolarisEndpoint(middle[0]) {
		remote = middle[0]
		middle = middle[1:]
	}

	entry := SolarisPort{State: fields[stateIdx]}
	if withOwner {
		entry.User, entry.Pid = solarisOwner(middle)
	}
	return fillSolarisEndpoints(entry, fields[0], remote, v6)
}

// solarisOwner reads the `user pid command` columns. They are blank for a
// socket no process holds any more (TIME_WAIT), which yields no owner.
func solarisOwner(fields []string) (string, int64) {
	if len(fields) < 2 {
		return "", 0
	}
	pid, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", 0
	}
	return fields[0], pid
}

// fillSolarisEndpoints splits both endpoints. v6 comes from the section title,
// not the address, because the wildcard `*.22` reads the same in both families.
func fillSolarisEndpoints(entry SolarisPort, local string, remote string, v6 bool) (SolarisPort, bool) {
	entry.LocalAddress, entry.LocalPort = splitDottedEndpoint(local, v6)
	if entry.LocalPort == 0 {
		// never bound: no port to report
		return SolarisPort{}, false
	}
	if remote != "" {
		entry.RemoteAddress, entry.RemotePort = splitDottedEndpoint(remote, v6)
	}
	return entry, true
}

func isSolarisEndpoint(s string) bool {
	return reSolarisEndpoint.MatchString(s)
}
