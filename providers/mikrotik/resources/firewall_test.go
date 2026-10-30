// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRowID(t *testing.T) {
	// RouterOS supplies its internal handle on every print reply
	assert.Equal(t, "p/*1A", rowID("p/", map[string]string{".id": "*1A", "list": "banned"}, "banned", "10.0.0.1"))
	// without a handle the key is composed from the row's own attributes
	assert.Equal(t, "p/banned/10.0.0.1", rowID("p/", map[string]string{"list": "banned"}, "banned", "10.0.0.1"))
	assert.Equal(t, "p//", rowID("p/", map[string]string{}, "", ""))
}

func TestBoolField(t *testing.T) {
	row := map[string]string{"log": "true", "disabled": "no", "dynamic": ""}

	assert.Equal(t, true, boolField(row, "log").Value)
	assert.Equal(t, false, boolField(row, "disabled").Value)
	// an attribute present but empty is a reported false, not an absent value
	assert.Equal(t, false, boolField(row, "dynamic").Value)
	// an attribute the device never reported stays null rather than becoming a
	// fabricated false on a security flag
	assert.Nil(t, boolField(row, "invalid").Value)
}

func TestIntField(t *testing.T) {
	row := map[string]string{"bytes": "4096", "packets": "0"}

	assert.Equal(t, int64(4096), intField(row, "bytes").Value)
	assert.Equal(t, int64(0), intField(row, "packets").Value)
	assert.Nil(t, intField(row, "max-entries").Value)
}

func TestListField(t *testing.T) {
	row := map[string]string{"topics": "system,error,critical", "policy": ""}

	assert.Equal(t, []any{"system", "error", "critical"}, listField(row, "topics").Value)
	assert.Equal(t, []any{}, listField(row, "policy").Value)
	assert.Nil(t, listField(row, "missing").Value)
}

func TestPresenceField(t *testing.T) {
	row := map[string]string{"secret": "not-a-real-secret", "password": "", "key": "   "}

	// the secret's presence is reported; the secret itself never is
	assert.Equal(t, true, presenceField(row, "secret").Value)
	assert.Equal(t, false, presenceField(row, "password").Value)
	assert.Equal(t, false, presenceField(row, "key").Value)
	assert.Nil(t, presenceField(row, "absent").Value)
}

func TestFirewallRuleArgs(t *testing.T) {
	row := map[string]string{
		".id":              "*7",
		"chain":            "input",
		"action":           "drop",
		"protocol":         "tcp",
		"src-address":      "203.0.113.0/24",
		"dst-address":      "198.51.100.1",
		"src-address-list": "banned",
		"dst-address-list": "management",
		"src-port":         "1024-65535",
		"dst-port":         "22",
		"in-interface":     "ether1",
		"out-interface":    "bridge1",
		"log":              "yes",
		"log-prefix":       "blocked",
		"bytes":            "8192",
		"packets":          "64",
		"disabled":         "false",
		"dynamic":          "false",
		"comment":          "drop inbound ssh",
	}
	args := firewallRuleArgs("mikrotik.ip.firewall.raw/", row)

	assert.Equal(t, "mikrotik.ip.firewall.raw/*7", args["__id"].Value)
	assert.Equal(t, "input", args["chain"].Value)
	assert.Equal(t, "drop", args["action"].Value)
	assert.Equal(t, "tcp", args["protocol"].Value)
	// address lists are what filter, mangle, and raw rules reference by name
	assert.Equal(t, "banned", args["srcAddressList"].Value)
	assert.Equal(t, "management", args["dstAddressList"].Value)
	assert.Equal(t, "22", args["dstPort"].Value)
	assert.Equal(t, true, args["log"].Value)
	assert.Equal(t, int64(8192), args["bytes"].Value)
	assert.Equal(t, false, args["disabled"].Value)
	// the device did not report "invalid" on this rule
	assert.Nil(t, args["invalid"].Value)
}

func TestFirewallRuleArgsEmptyRow(t *testing.T) {
	// a menu that returns nothing must not manufacture flags
	args := firewallRuleArgs("p/", map[string]string{})

	// every fallback part is kept, empties included, so two differently
	// shaped rows can never collapse onto the same cache key
	assert.Equal(t, "p///", args["__id"].Value)
	assert.Equal(t, "", args["chain"].Value)
	assert.Nil(t, args["log"].Value)
	assert.Nil(t, args["disabled"].Value)
	assert.Nil(t, args["dynamic"].Value)
	assert.Nil(t, args["bytes"].Value)
	assert.Nil(t, args["packets"].Value)
}

func TestAddressListArgs(t *testing.T) {
	row := map[string]string{
		".id":           "*3",
		"list":          "banned",
		"address":       "203.0.113.5",
		"creation-time": "2026-08-01 10:11:12",
		"timeout":       "1d2h3m",
		"dynamic":       "true",
		"disabled":      "false",
		"comment":       "auto-added by port scan detector",
	}
	args := addressListArgs("mikrotik.ip.firewall.addressList/", row)

	assert.Equal(t, "mikrotik.ip.firewall.addressList/*3", args["__id"].Value)
	assert.Equal(t, "banned", args["list"].Value)
	assert.Equal(t, "203.0.113.5", args["address"].Value)
	assert.Equal(t, "1d2h3m", args["timeout"].Value)
	assert.Equal(t, true, args["dynamic"].Value)
	assert.Equal(t, false, args["disabled"].Value)
}

func TestAddressListArgsStaticEntry(t *testing.T) {
	// a static entry carries no timeout and RouterOS omits the attribute
	args := addressListArgs("p/", map[string]string{"list": "allowed", "address": "10.0.0.0/8"})

	assert.Equal(t, "p/allowed/10.0.0.0/8", args["__id"].Value)
	assert.Equal(t, "", args["timeout"].Value)
	assert.Nil(t, args["dynamic"].Value)
}

func TestConnectionTrackingArgs(t *testing.T) {
	row := map[string]string{
		"enabled":                 "auto",
		"loose-tcp-tracking":      "yes",
		"total-entries":           "42",
		"max-entries":             "131072",
		"tcp-established-timeout": "1d",
		"udp-timeout":             "10s",
		"generic-timeout":         "10m",
	}
	args := connectionTrackingArgs(row)

	assert.Equal(t, "mikrotik.ip.firewall.connectionTracking", args["__id"].Value)
	// enabled is a tri-state on RouterOS (auto/yes/no), not a boolean
	assert.Equal(t, "auto", args["enabled"].Value)
	assert.Equal(t, true, args["looseTcpTracking"].Value)
	assert.Equal(t, int64(42), args["totalEntries"].Value)
	assert.Equal(t, int64(131072), args["maxEntries"].Value)
	assert.Equal(t, "1d", args["tcpEstablishedTimeout"].Value)
	// timeouts the device did not report stay empty rather than inventing one
	assert.Equal(t, "", args["icmpTimeout"].Value)
}

func TestConnectionTrackingArgsAbsentMenu(t *testing.T) {
	// PrintOne yields an empty map for a menu with no records; the accessor
	// returns null for that case, and nothing here may read as configured
	args := connectionTrackingArgs(map[string]string{})

	assert.Equal(t, "", args["enabled"].Value)
	assert.Nil(t, args["looseTcpTracking"].Value)
	assert.Nil(t, args["totalEntries"].Value)
	assert.Nil(t, args["maxEntries"].Value)
}
