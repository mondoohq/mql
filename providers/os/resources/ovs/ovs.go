// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package ovs decodes the Open vSwitch configuration database.
//
// ovs-vsctl prints rows as OVSDB JSON, which wraps every non-scalar value in a
// tagged pair such as ["set", [...]], ["map", [[k, v], ...]] or ["uuid", "..."].
// This package unwraps that encoding and joins the Bridge, Port and Interface
// tables into the bridge topology the switch actually runs.
package ovs

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
)

// Bridge is one Open vSwitch bridge.
type Bridge struct {
	UUID         string
	Name         string
	DatapathType string
	FailMode     string
	Protocols    []string
	STPEnabled   bool
	RSTPEnabled  bool
	ExternalIDs  map[string]string
	OtherConfig  map[string]string
	PortUUIDs    []string
}

// Port is one port of a bridge.
type Port struct {
	UUID           string
	Name           string
	BridgeName     string
	VlanMode       string
	Tag            int64
	Tagged         bool
	Trunks         []int64
	ExternalIDs    map[string]string
	OtherConfig    map[string]string
	InterfaceUUIDs []string
}

// Interface is one interface of a port.
type Interface struct {
	UUID        string
	Name        string
	PortName    string
	BridgeName  string
	Type        string
	AdminState  string
	LinkState   string
	MACInUse    string
	MTU         int64
	OFPort      int64
	Error       string
	ExternalIDs map[string]string
	Options     map[string]string
}

// Topology is the joined content of the three tables.
type Topology struct {
	Bridges    []Bridge
	Ports      []Port
	Interfaces []Interface
}

// table is the JSON envelope ovs-vsctl --format=json prints.
type table struct {
	Headings []string `json:"headings"`
	Data     [][]any  `json:"data"`
}

// row is one database row, keyed by column name.
type row map[string]any

// parseTable reads one ovs-vsctl JSON document into rows keyed by column.
func parseTable(raw string) ([]row, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	var decoded table
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, err
	}

	rows := make([]row, 0, len(decoded.Data))
	for _, values := range decoded.Data {
		if len(values) != len(decoded.Headings) {
			return nil, fmt.Errorf("ovs row has %d values for %d columns", len(values), len(decoded.Headings))
		}
		r := make(row, len(values))
		for i, heading := range decoded.Headings {
			r[heading] = values[i]
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// ParseTopology reads the Bridge, Port and Interface documents and joins them.
//
// A port or an interface that no bridge references is still reported, with an
// empty bridge name, so an orphaned row is visible rather than dropped.
func ParseTopology(bridgeJSON, portJSON, interfaceJSON string) (*Topology, error) {
	bridgeRows, err := parseTable(bridgeJSON)
	if err != nil {
		return nil, fmt.Errorf("cannot read the Bridge table: %w", err)
	}
	portRows, err := parseTable(portJSON)
	if err != nil {
		return nil, fmt.Errorf("cannot read the Port table: %w", err)
	}
	interfaceRows, err := parseTable(interfaceJSON)
	if err != nil {
		return nil, fmt.Errorf("cannot read the Interface table: %w", err)
	}

	topology := &Topology{
		Bridges:    make([]Bridge, 0, len(bridgeRows)),
		Ports:      make([]Port, 0, len(portRows)),
		Interfaces: make([]Interface, 0, len(interfaceRows)),
	}

	for _, r := range bridgeRows {
		topology.Bridges = append(topology.Bridges, Bridge{
			UUID:         uuidValue(r["_uuid"]),
			Name:         stringValue(r["name"]),
			DatapathType: stringValue(r["datapath_type"]),
			FailMode:     stringValue(r["fail_mode"]),
			Protocols:    stringSetValue(r["protocols"]),
			STPEnabled:   boolValue(r["stp_enable"]),
			RSTPEnabled:  boolValue(r["rstp_enable"]),
			ExternalIDs:  mapValue(r["external_ids"]),
			OtherConfig:  mapValue(r["other_config"]),
			PortUUIDs:    uuidSetValue(r["ports"]),
		})
	}

	bridgeByPortUUID := map[string]string{}
	for _, bridge := range topology.Bridges {
		for _, portUUID := range bridge.PortUUIDs {
			bridgeByPortUUID[portUUID] = bridge.Name
		}
	}

	for _, r := range portRows {
		uuid := uuidValue(r["_uuid"])
		vlanTag, hasVlanTag := intValue(r["tag"])
		topology.Ports = append(topology.Ports, Port{
			UUID:           uuid,
			Name:           stringValue(r["name"]),
			BridgeName:     bridgeByPortUUID[uuid],
			VlanMode:       stringValue(r["vlan_mode"]),
			Tag:            vlanTag,
			Tagged:         hasVlanTag,
			Trunks:         intSetValue(r["trunks"]),
			ExternalIDs:    mapValue(r["external_ids"]),
			OtherConfig:    mapValue(r["other_config"]),
			InterfaceUUIDs: uuidSetValue(r["interfaces"]),
		})
	}

	type portRef struct{ port, bridge string }
	portByInterfaceUUID := map[string]portRef{}
	for _, port := range topology.Ports {
		for _, interfaceUUID := range port.InterfaceUUIDs {
			portByInterfaceUUID[interfaceUUID] = portRef{port: port.Name, bridge: port.BridgeName}
		}
	}

	for _, r := range interfaceRows {
		uuid := uuidValue(r["_uuid"])
		mtu, _ := intValue(r["mtu"])
		ofport, _ := intValue(r["ofport"])
		ref := portByInterfaceUUID[uuid]
		topology.Interfaces = append(topology.Interfaces, Interface{
			UUID:        uuid,
			Name:        stringValue(r["name"]),
			PortName:    ref.port,
			BridgeName:  ref.bridge,
			Type:        stringValue(r["type"]),
			AdminState:  stringValue(r["admin_state"]),
			LinkState:   stringValue(r["link_state"]),
			MACInUse:    stringValue(r["mac_in_use"]),
			MTU:         mtu,
			OFPort:      ofport,
			Error:       stringValue(r["error"]),
			ExternalIDs: mapValue(r["external_ids"]),
			Options:     mapValue(r["options"]),
		})
	}

	return topology, nil
}

// tagged unwraps an OVSDB tagged value such as ["set", [...]].
//
// The second result is false for a plain scalar, which OVSDB writes without a
// tag.
func tagged(value any) (string, any, bool) {
	pair, ok := value.([]any)
	if !ok || len(pair) != 2 {
		return "", nil, false
	}
	tag, ok := pair[0].(string)
	if !ok {
		return "", nil, false
	}
	return tag, pair[1], true
}

// stringValue reads a string column. An empty OVSDB set means the column is
// unset, which reads as an empty string.
func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if tag, inner, ok := tagged(value); ok && tag == "set" {
		if items, ok := inner.([]any); ok && len(items) == 1 {
			return stringValue(items[0])
		}
	}
	return ""
}

// uuidValue reads a ["uuid", "..."] column.
func uuidValue(value any) string {
	tag, inner, ok := tagged(value)
	if !ok || (tag != "uuid" && tag != "named-uuid") {
		return ""
	}
	text, _ := inner.(string)
	return text
}

func boolValue(value any) bool {
	if flag, ok := value.(bool); ok {
		return flag
	}
	if tag, inner, ok := tagged(value); ok && tag == "set" {
		if items, ok := inner.([]any); ok && len(items) == 1 {
			return boolValue(items[0])
		}
	}
	return false
}

// intValue reads an integer column. The second result is false when the column
// is unset, so an unset VLAN tag is not read as VLAN 0.
func intValue(value any) (int64, bool) {
	if number, ok := value.(float64); ok {
		return int64(number), true
	}
	if tag, inner, ok := tagged(value); ok && tag == "set" {
		if items, ok := inner.([]any); ok && len(items) == 1 {
			return intValue(items[0])
		}
	}
	return 0, false
}

// setItems returns the members of a set column. OVSDB writes a one-member set
// as the bare value, so a scalar counts as a set of one.
func setItems(value any) []any {
	if value == nil {
		return nil
	}
	tag, inner, ok := tagged(value)
	if !ok {
		return []any{value}
	}
	if tag != "set" {
		// A single uuid or a single tagged scalar is a set of one.
		return []any{value}
	}
	items, ok := inner.([]any)
	if !ok {
		return nil
	}
	return items
}

func stringSetValue(value any) []string {
	items := setItems(value)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text := stringValue(item); text != "" {
			out = append(out, text)
		}
	}
	return out
}

func uuidSetValue(value any) []string {
	items := setItems(value)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if uuid := uuidValue(item); uuid != "" {
			out = append(out, uuid)
		}
	}
	return out
}

func intSetValue(value any) []int64 {
	items := setItems(value)
	out := make([]int64, 0, len(items))
	for _, item := range items {
		if number, ok := intValue(item); ok {
			out = append(out, number)
		}
	}
	return out
}

// mapValue reads a ["map", [[k, v], ...]] column.
func mapValue(value any) map[string]string {
	tag, inner, ok := tagged(value)
	if !ok || tag != "map" {
		return nil
	}
	pairs, ok := inner.([]any)
	if !ok || len(pairs) == 0 {
		return nil
	}
	out := make(map[string]string, len(pairs))
	for _, raw := range pairs {
		pair, ok := raw.([]any)
		if !ok || len(pair) != 2 {
			continue
		}
		key := stringValue(pair[0])
		if key == "" {
			continue
		}
		out[key] = stringValue(pair[1])
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParseVersion reads the version from the first line of `ovs-vsctl --version`.
func ParseVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		return fields[len(fields)-1]
	}
	return ""
}

// VsctlFailure turns a failed ovs-vsctl run into an error. ovs-vsctl names the
// reason the database could not be reached in parentheses at the end of its
// message: a socket the user may not open is a refusal, a missing or refusing
// socket means ovsdb-server is not running. Anything else is returned with the
// exit code and stderr, unclassified.
func VsctlFailure(exitCode int64, stderr string) error {
	msg := strings.TrimSpace(stderr)
	switch {
	case strings.Contains(msg, "database connection failed (Permission denied)"):
		return llx.Forbidden(errors.New(msg))
	case strings.Contains(msg, "database connection failed (No such file or directory)"),
		strings.Contains(msg, "database connection failed (Connection refused)"):
		return llx.Unavailable(errors.New(msg))
	case msg == "":
		return fmt.Errorf("ovs-vsctl failed with exit code %d", exitCode)
	default:
		return fmt.Errorf("ovs-vsctl failed with exit code %d: %s", exitCode, msg)
	}
}
