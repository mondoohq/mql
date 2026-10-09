// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// This file reads the runtime state of the daemons other than BGP: the OSPF
// and IS-IS adjacencies, the BFD sessions, and the interfaces zebra knows.
//
// An adjacency and a session are time-varying. They describe the moment of
// the scan, so a policy over them tests the running fabric rather than its
// configuration.

package frr

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OSPFNeighbor is one adjacency of OSPF or OSPFv3.
type OSPFNeighbor struct {
	// Version is 2 for OSPF and 3 for OSPFv3.
	Version int64
	// NeighborID is the router id of the neighbor.
	NeighborID string
	// State is the adjacency state, for example Full or ExStart. Only Full
	// and, on a broadcast link, 2-Way carry traffic.
	State string
	// Full reports whether the adjacency reached Full.
	Full bool
	// Role is the designated router role, for example DR, BDR or DROther.
	Role string
	// Priority is the election priority of the neighbor.
	Priority int64
	// Address is the address of the neighbor, and LocalAddress the address
	// of the local side.
	Address      string
	LocalAddress string
	Interface    string
	// UptimeMsec is how long the adjacency has held its state.
	UptimeMsec int64
	// DeadTimeMsec is the time left before the neighbor is declared down.
	DeadTimeMsec int64
	// RetransmitCount is the retransmit queue length, which grows when a
	// link drops packets.
	RetransmitCount int64
	Details         map[string]any
}

// ospfNeighborKeys lists the JSON keys of the same value across FRR versions
// and across the two protocol versions.
var (
	ospfNeighborIDKeys = []string{"neighborId", "routerId", "neighborIp"}
	ospfStateKeys      = []string{"nbrState", "state", "converged"}
	ospfRoleKeys       = []string{"role", "nbrPriority2"}
	ospfIfaceKeys      = []string{"ifaceName", "interfaceName", "interface"}
	ospfAddressKeys    = []string{"address", "ifaceAddress", "neighborAddress"}
	ospfLocalKeys      = []string{"ifaceAddress", "localAddress"}
	ospfUptimeKeys     = []string{"upTimeInMsec", "upTimeMsec", "durationMsec"}
	ospfDeadKeys       = []string{"deadTimeMsecs", "deadTimeMsec", "routerDeadIntervalTimerDueMsec"}
	ospfRetransmitKeys = []string{"retransmitCounter", "linkStateRetransmissionListCounter"}
	ospfPriorityKeys   = []string{"nbrPriority", "priority"}
)

// ParseOSPFNeighbors reads `show ip ospf neighbor json` and
// `show ipv6 ospf6 neighbor json`. The first prints a map of arrays keyed by
// router id, the second an array, so both shapes are read.
func ParseOSPFNeighbors(version int64, data []byte) ([]OSPFNeighbor, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("cannot parse ospf neighbors: %w", err)
	}

	raw, ok := root["neighbors"]
	if !ok {
		return nil, nil
	}

	var out []OSPFNeighbor

	// The array shape of OSPFv3.
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err == nil {
		for i := range list {
			out = append(out, convertOSPFNeighbor(version, "", list[i]))
		}
		return out, nil
	}

	// The map of arrays shape of OSPF, keyed by router id.
	var byID map[string][]map[string]any
	if err := json.Unmarshal(raw, &byID); err != nil {
		return nil, fmt.Errorf("cannot parse ospf neighbor list: %w", err)
	}
	for _, id := range sortedKeysOf(byID) {
		for i := range byID[id] {
			out = append(out, convertOSPFNeighbor(version, id, byID[id][i]))
		}
	}
	return out, nil
}

func convertOSPFNeighbor(version int64, id string, obj map[string]any) OSPFNeighbor {
	n := OSPFNeighbor{Version: version, NeighborID: id, Details: obj}
	if v := firstString(obj, ospfNeighborIDKeys); v != "" {
		n.NeighborID = v
	}
	n.State = firstString(obj, ospfStateKeys)
	// FRR prints the state of a broadcast link as `Full/DR`, where the part
	// after the slash is the role.
	if state, role, found := strings.Cut(n.State, "/"); found {
		n.State = state
		n.Role = role
	}
	if role := firstString(obj, ospfRoleKeys); role != "" {
		n.Role = role
	}
	n.Full = strings.EqualFold(n.State, "Full")
	n.Interface = firstString(obj, ospfIfaceKeys)
	n.Address = firstString(obj, ospfAddressKeys)
	n.LocalAddress = firstString(obj, ospfLocalKeys)
	if v, ok := firstInt(obj, ospfPriorityKeys); ok {
		n.Priority = v
	}
	if v, ok := firstInt(obj, ospfUptimeKeys); ok {
		n.UptimeMsec = v
	}
	if v, ok := firstInt(obj, ospfDeadKeys); ok {
		n.DeadTimeMsec = v
	}
	if v, ok := firstInt(obj, ospfRetransmitKeys); ok {
		n.RetransmitCount = v
	}
	return n
}

// ISISNeighbor is one adjacency of IS-IS.
type ISISNeighbor struct {
	// Area is the instance tag the adjacency belongs to.
	Area string
	// SystemID is the system id or the hostname of the neighbor.
	SystemID string
	// Interface is the circuit the adjacency runs on.
	Interface string
	// Level is the IS-IS level of the adjacency (1, 2 or 1-2).
	Level string
	// State is the adjacency state, for example Up or Init.
	State string
	// Up reports whether the adjacency is up.
	Up bool
	// ExpiresIn is the hold time left, as FRR prints it.
	ExpiresIn string
	// SNPA is the subnetwork point of attachment, which is the MAC address
	// on an Ethernet circuit.
	SNPA    string
	Details map[string]any
}

// ParseISISNeighbors reads `show isis neighbor json`. FRR groups the
// adjacencies by area and by circuit, and the keys differ between versions,
// so the walk is tolerant.
func ParseISISNeighbors(data []byte) ([]ISISNeighbor, error) {
	var root struct {
		Areas []struct {
			Area     string           `json:"area"`
			Circuits []map[string]any `json:"circuits"`
		} `json:"areas"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("cannot parse isis neighbors: %w", err)
	}

	var out []ISISNeighbor
	for _, area := range root.Areas {
		for _, circuit := range area.Circuits {
			n := ISISNeighbor{Area: area.Area, Details: circuit}
			n.SystemID = firstString(circuit, []string{"adj", "systemId", "sysId"})
			if n.SystemID == "" {
				// A circuit without an adjacency is not a neighbor.
				continue
			}

			// The circuit details sit in an `interface` object on recent
			// versions and next to the adjacency on older ones.
			details := circuit
			if inner, ok := circuit["interface"].(map[string]any); ok {
				details = inner
				n.Details = inner
			}
			n.Interface = firstString(details, []string{"name", "interface", "circuit"})
			n.Level = firstString(details, []string{"level", "adj-level"})
			n.State = firstString(details, []string{"state", "adj-state"})
			n.ExpiresIn = firstString(details, []string{"expires-in", "expiresIn", "hold"})
			n.SNPA = firstString(details, []string{"snpa", "SNPA"})
			n.Up = strings.EqualFold(n.State, "Up")
			out = append(out, n)
		}
	}
	return out, nil
}

// BFDSession is one session of `show bfd peers json`. BFD drops a dead
// neighbor faster than any protocol timer, so its state decides how fast the
// fabric reconverges.
type BFDSession struct {
	Peer         string
	Local        string
	VRF          string
	Interface    string
	MultiHop     bool
	Status       string
	Up           bool
	UptimeSec    int64
	Diagnostic   string
	RemoteDiag   string
	DetectMulti  int64
	ReceiveMsec  int64
	TransmitMsec int64
	EchoMsec     int64
	// RemoteDetectMulti, RemoteReceiveMsec and RemoteTransmitMsec are what
	// the peer asked for. The session uses the slower of the two sides.
	RemoteDetectMulti  int64
	RemoteReceiveMsec  int64
	RemoteTransmitMsec int64
	Details            map[string]any
}

// ParseBFDSessions reads `show bfd peers json`, which prints an array with
// hyphenated keys.
func ParseBFDSessions(data []byte) ([]BFDSession, error) {
	var list []map[string]any
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("cannot parse bfd peers: %w", err)
	}

	out := make([]BFDSession, 0, len(list))
	for i := range list {
		obj := list[i]
		s := BFDSession{Details: obj}
		s.Peer = firstString(obj, []string{"peer"})
		s.Local = firstString(obj, []string{"local"})
		s.VRF = firstString(obj, []string{"vrf"})
		s.Interface = firstString(obj, []string{"interface"})
		s.MultiHop = firstBool(obj, []string{"multihop", "multiHop"})
		s.Status = firstString(obj, []string{"status"})
		s.Up = strings.EqualFold(s.Status, "up")
		s.Diagnostic = firstString(obj, []string{"diagnostic"})
		s.RemoteDiag = firstString(obj, []string{"remote-diagnostic", "remoteDiagnostic"})
		if v, ok := firstInt(obj, []string{"uptime"}); ok {
			s.UptimeSec = v
		}
		if v, ok := firstInt(obj, []string{"detect-multiplier", "detectMultiplier"}); ok {
			s.DetectMulti = v
		}
		if v, ok := firstInt(obj, []string{"receive-interval", "receiveInterval"}); ok {
			s.ReceiveMsec = v
		}
		if v, ok := firstInt(obj, []string{"transmit-interval", "transmitInterval"}); ok {
			s.TransmitMsec = v
		}
		if v, ok := firstInt(obj, []string{"echo-interval", "echoInterval"}); ok {
			s.EchoMsec = v
		}
		if v, ok := firstInt(obj, []string{"remote-detect-multiplier", "remoteDetectMultiplier"}); ok {
			s.RemoteDetectMulti = v
		}
		if v, ok := firstInt(obj, []string{"remote-receive-interval", "remoteReceiveInterval"}); ok {
			s.RemoteReceiveMsec = v
		}
		if v, ok := firstInt(obj, []string{"remote-transmit-interval", "remoteTransmitInterval"}); ok {
			s.RemoteTransmitMsec = v
		}
		out = append(out, s)
	}
	return out, nil
}

// ZebraInterface is one interface of `show interface json`, which is the
// view of the routing daemon rather than of the kernel.
type ZebraInterface struct {
	Name string
	// AdminUp and OperUp are the administrative and the operational state.
	AdminUp bool
	OperUp  bool
	// VRF is the VRF the interface belongs to.
	VRF     string
	IfIndex int64
	MTU     int64
	Speed   int64
	Type    string
	// HardwareAddress is the MAC address of the interface.
	HardwareAddress string
	// Addresses holds the addresses zebra knows for the interface.
	Addresses []string
	// LinkDowns counts how often the link went down, which is how a flapping
	// link shows up without a log.
	LinkDowns int64
	LinkUps   int64
	// ProtocolDown reports an interface that a protocol has taken down.
	ProtocolDown bool
	Details      map[string]any
}

// ParseZebraInterfaces reads `show interface json`, which maps the interface
// name to its state.
func ParseZebraInterfaces(data []byte) ([]ZebraInterface, error) {
	var root map[string]map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("cannot parse interfaces: %w", err)
	}

	out := make([]ZebraInterface, 0, len(root))
	for _, name := range sortedKeysOf(root) {
		obj := root[name]
		i := ZebraInterface{Name: name, Details: obj}
		i.AdminUp = strings.EqualFold(firstString(obj, []string{"administrativeStatus"}), "up")
		i.OperUp = strings.EqualFold(firstString(obj, []string{"operationalStatus"}), "up")
		i.VRF = firstString(obj, []string{"vrfName", "vrf"})
		i.Type = firstString(obj, []string{"type", "interfaceType"})
		i.HardwareAddress = firstString(obj, []string{"hardwareAddress", "macAddress"})
		i.ProtocolDown = firstBool(obj, []string{"protocolDown", "protodown"})
		if v, ok := firstInt(obj, []string{"ifIndex", "ifindex"}); ok {
			i.IfIndex = v
		}
		if v, ok := firstInt(obj, []string{"mtu"}); ok {
			i.MTU = v
		}
		if v, ok := firstInt(obj, []string{"speed"}); ok {
			i.Speed = v
		}
		if v, ok := firstInt(obj, []string{"linkDowns"}); ok {
			i.LinkDowns = v
		}
		if v, ok := firstInt(obj, []string{"linkUps"}); ok {
			i.LinkUps = v
		}
		if list, ok := obj["ipAddresses"].([]any); ok {
			for _, item := range list {
				switch t := item.(type) {
				case string:
					i.Addresses = append(i.Addresses, t)
				case map[string]any:
					if addr := firstString(t, []string{"address"}); addr != "" {
						i.Addresses = append(i.Addresses, addr)
					}
				}
			}
		}
		out = append(out, i)
	}
	return out, nil
}
