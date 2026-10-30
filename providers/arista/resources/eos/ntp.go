// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"bufio"
	"strconv"
	"strings"
)

type showNtpStatus struct {
	Status string `json:"status"`
}

func (s *showNtpStatus) GetCmd() string {
	return "show ntp status"
}

func (eos *Eos) NtpStatus() (*showNtpStatus, error) {
	shRsp := &showNtpStatus{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	err = handle.AddCommand(shRsp)
	if err != nil {
		return nil, err
	}

	if err := handle.Call(); err != nil {
		return nil, err
	}
	handle.Close()

	return shRsp, nil
}

// NtpServer is a single upstream time source the device synchronizes against.
//
//	ntp server 0.pool.ntp.org prefer
//	ntp server vrf MGMT 10.0.0.1 iburst
//	ntp server 192.168.100.1 local-interface Management1 key 1
//
// Auditing the server list answers whether the device takes its time from
// approved sources. Time that can be moved by an attacker undermines
// certificate validity windows, log correlation, and any authentication
// scheme with a replay window.
type NtpServer struct {
	// Address is the server hostname or IP as configured.
	Address string
	// VRF is the routing instance used to reach the server. Empty means the
	// default VRF.
	VRF string
	// Prefer marks the server as the preferred sync source.
	Prefer bool
	// IBurst sends a burst of packets on startup for faster initial sync.
	IBurst bool
	// Version is the NTP protocol version (0 = unset).
	Version int
	// MinPoll and MaxPoll are the poll-interval bounds as powers of two
	// (0 = unset).
	MinPoll int
	MaxPoll int
	// LocalInterface is the source interface for packets to this server,
	// from either the `local-interface` or `source` keyword.
	LocalInterface string
	// KeyID is the authentication key this server is authenticated with.
	// 0 means the server line references no key, so its responses are
	// accepted unauthenticated.
	KeyID int
}

// NtpServeState describes whether the device answers NTP queries from others.
//
//	ntp serve all
//	ntp serve ipv4 access-group NTP-CLIENTS
//
// A switch serving time to anyone that asks is a reflection/amplification
// source. When serving is intended, an access-group should bound who may ask.
type NtpServeState struct {
	// Enabled is true when the device is configured to answer NTP queries.
	Enabled bool
	// AccessGroup is the access-list restricting which clients may query
	// the device. Empty means unrestricted.
	AccessGroup string
}

// ParseNtpServers extracts the configured upstream NTP servers from
// running-config.
func ParseNtpServers(runningConfig string) []NtpServer {
	res := []NtpServer{}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, "ntp server ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}

		s := NtpServer{}
		// `ntp server vrf <name> <host> ...` puts the VRF ahead of the host.
		if fields[0] == "vrf" && len(fields) >= 3 {
			s.VRF = fields[1]
			fields = fields[2:]
		}
		s.Address = fields[0]

		for i := 1; i < len(fields); i++ {
			// Keyword options consume the token that follows them; flags
			// stand alone.
			next := ""
			if i+1 < len(fields) {
				next = fields[i+1]
			}
			switch fields[i] {
			case "prefer":
				s.Prefer = true
			case "iburst":
				s.IBurst = true
			case "version":
				s.Version = atoiOrZero(next)
				i++
			case "minpoll":
				s.MinPoll = atoiOrZero(next)
				i++
			case "maxpoll":
				s.MaxPoll = atoiOrZero(next)
				i++
			case "key":
				s.KeyID = atoiOrZero(next)
				i++
			case "local-interface", "source":
				s.LocalInterface = next
				i++
			}
		}
		res = append(res, s)
	}

	return res
}

// ParseNtpServeState reports whether the device serves time to NTP clients and
// which access-list, if any, bounds who may ask.
func ParseNtpServeState(runningConfig string) *NtpServeState {
	state := &NtpServeState{}

	scanner := bufio.NewScanner(strings.NewReader(runningConfig))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		negated := false
		if cut, ok := strings.CutPrefix(line, "no "); ok {
			negated = true
			line = cut
		}
		rest, ok := strings.CutPrefix(line, "ntp serve ")
		if !ok {
			continue
		}

		fields := strings.Fields(rest)
		// Drop an address-family qualifier (`ntp serve ipv4 ...`) so the
		// remaining tokens are the same for both families.
		if len(fields) > 0 && (fields[0] == "ipv4" || fields[0] == "ipv6") {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "all":
			state.Enabled = !negated
		case "access-group":
			if negated {
				state.AccessGroup = ""
				continue
			}
			// Serving is implied by binding an access-group to it.
			state.Enabled = true
			if len(fields) > 1 {
				state.AccessGroup = fields[1]
			}
		}
	}

	return state
}

// atoiOrZero parses an integer token, yielding 0 for anything unparseable so
// a malformed option does not discard the rest of the line.
func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
