// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ports

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type State int64

const (
	Closed      = 1
	Listen      = 2
	SynSent     = 3
	SynReceived = 4
	Established = 5
	FinWait1    = 6
	FinWait2    = 7
	CloseWait   = 8
	Closing     = 9
	LastAck     = 10
	TimeWait    = 11
	DeleteTCB   = 12
	// Bound is 100 in the MSFT_NetTCPConnection State enum, not 13: a socket
	// that is bound but neither listening nor connected.
	Bound = 100
)

type WinPort struct {
	State         State
	LocalAddress  string
	LocalPort     int64
	RemoteAddress string
	RemotePort    int64
	OwningProcess int64
}

func ParseWindowsNetTCPConnections(r io.Reader) ([]WinPort, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseWinPorts(data)
}

func parseWinPorts(data []byte) ([]WinPort, error) {
	entries, err := powershell.UnmarshalList[WinPort](data)
	if err != nil {
		return nil, err
	}

	// convert any ipv6 address (basically if they contain a ':')
	// to a more ipv6-friendly address surrounded by []s
	for i := range entries {
		entries[i].LocalAddress = bracketIPv6(entries[i].LocalAddress)
		entries[i].RemoteAddress = bracketIPv6(entries[i].RemoteAddress)
	}

	return entries, nil
}

func bracketIPv6(addr string) string {
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]", addr)
	}
	return addr
}

// WinUDPEndpoint is a UDP endpoint from Get-NetUDPEndpoint.
type WinUDPEndpoint struct {
	LocalAddress  string
	LocalPort     int64
	OwningProcess int64
}

// WinConnections is the output of the Windows ports script: the TCP
// connections from Get-NetTCPConnection and the UDP endpoints from
// Get-NetUDPEndpoint, read in one PowerShell process.
type WinConnections struct {
	TCP []WinPort
	UDP []WinUDPEndpoint
}

// ParseWindowsNetConnections decodes {"tcp": [...], "udp": [...]}. Each list
// may arrive in any of the shapes powershell.UnmarshalList accepts; a list the
// host has nothing in is empty.
func ParseWindowsNetConnections(r io.Reader) (*WinConnections, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var raw struct {
		TCP json.RawMessage `json:"tcp"`
		UDP json.RawMessage `json:"udp"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	res := &WinConnections{TCP: []WinPort{}, UDP: []WinUDPEndpoint{}}
	if len(raw.TCP) > 0 {
		if res.TCP, err = parseWinPorts(raw.TCP); err != nil {
			return nil, err
		}
	}
	if len(raw.UDP) > 0 {
		if res.UDP, err = powershell.UnmarshalList[WinUDPEndpoint](raw.UDP); err != nil {
			return nil, err
		}
		for i := range res.UDP {
			res.UDP[i].LocalAddress = bracketIPv6(res.UDP[i].LocalAddress)
		}
	}
	return res, nil
}
