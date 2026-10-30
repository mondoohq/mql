// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsesDefaultCommunityName(t *testing.T) {
	for _, name := range []string{"public", "private", "Public", " PRIVATE "} {
		got := usesDefaultCommunityName(name)
		require.NotNil(t, got, "usesDefaultCommunityName(%q)", name)
		assert.True(t, *got, "usesDefaultCommunityName(%q)", name)
	}

	for _, name := range []string{"site-ro", "publicity", "priv"} {
		got := usesDefaultCommunityName(name)
		require.NotNil(t, got, "usesDefaultCommunityName(%q)", name)
		assert.False(t, *got, "usesDefaultCommunityName(%q)", name)
	}

	// an unread name is not proof the community was renamed
	assert.Nil(t, usesDefaultCommunityName(""))
	assert.Nil(t, usesDefaultCommunityName("   "))
}

func TestSnmpCommunityArgs(t *testing.T) {
	row := map[string]string{
		".id":          "*1",
		"name":         "public",
		"addresses":    "0.0.0.0/0",
		"security":     "none",
		"read-access":  "yes",
		"write-access": "yes",
		"default":      "true",
		"disabled":     "false",
	}
	args := snmpCommunityArgs(row)

	assert.Equal(t, "mikrotik.snmp.community/*1", args["__id"].Value)
	// the default name answered from anywhere, with write access
	assert.Equal(t, true, args["usesDefaultCommunityName"].Value)
	assert.Equal(t, "0.0.0.0/0", args["addresses"].Value)
	assert.Equal(t, true, args["readAccess"].Value)
	assert.Equal(t, true, args["writeAccess"].Value)
	assert.Equal(t, "none", args["security"].Value)
	assert.Equal(t, true, args["default"].Value)

	// the community string itself never reaches the result
	assert.NotContains(t, args, "name")
	for field, v := range args {
		assert.NotEqual(t, "public", v.Value, "field %q leaked the community string", field)
	}
}

func TestSnmpCommunityArgsV3(t *testing.T) {
	args := snmpCommunityArgs(map[string]string{
		".id":                     "*2",
		"name":                    "site-ro",
		"addresses":               "198.51.100.0/24",
		"security":                "private",
		"read-access":             "yes",
		"write-access":            "no",
		"authentication-protocol": "SHA1",
		"encryption-protocol":     "AES",
		"authentication-password": "not-a-real-password",
		"encryption-password":     "",
	})

	assert.Equal(t, false, args["usesDefaultCommunityName"].Value)
	assert.Equal(t, false, args["writeAccess"].Value)
	assert.Equal(t, "SHA1", args["authenticationProtocol"].Value)
	// passwords are reported as presence only
	assert.Equal(t, true, args["hasAuthenticationPassword"].Value)
	assert.Equal(t, false, args["hasEncryptionPassword"].Value)
	for field, v := range args {
		assert.NotEqual(t, "not-a-real-password", v.Value, "field %q leaked the password", field)
	}
}

func TestSnmpCommunityArgsAbsentAttributes(t *testing.T) {
	args := snmpCommunityArgs(map[string]string{".id": "*3"})

	assert.Nil(t, args["usesDefaultCommunityName"].Value)
	assert.Nil(t, args["readAccess"].Value)
	// an unreported write-access must not read as read-only
	assert.Nil(t, args["writeAccess"].Value)
	assert.Nil(t, args["hasAuthenticationPassword"].Value)
}

func TestLoggingRuleArgs(t *testing.T) {
	row := map[string]string{
		".id":      "*5",
		"topics":   "system,error,critical,account",
		"action":   "remote",
		"prefix":   "",
		"disabled": "false",
		"invalid":  "false",
	}
	args := loggingRuleArgs(row)

	assert.Equal(t, "mikrotik.system.logging.rule/*5", args["__id"].Value)
	assert.Equal(t, []any{"system", "error", "critical", "account"}, args["topics"].Value)
	// the action name is carried only by action
	assert.NotContains(t, args, "action")
	assert.Equal(t, false, args["disabled"].Value)
}

func TestLoggingRuleArgsAbsentAttributes(t *testing.T) {
	args := loggingRuleArgs(map[string]string{"action": "memory"})

	assert.Equal(t, "mikrotik.system.logging.rule//memory", args["__id"].Value)
	assert.Nil(t, args["topics"].Value)
	assert.Nil(t, args["disabled"].Value)
}

func TestLoggingActionArgsMemoryDefault(t *testing.T) {
	// the RouterOS default: a memory ring buffer a reboot erases
	args := loggingActionArgs(map[string]string{
		"name":                "memory",
		"target":              "memory",
		"memory-lines":        "1000",
		"memory-stop-on-full": "no",
	})

	assert.Equal(t, "mikrotik.system.logging.action/memory", args["__id"].Value)
	assert.Equal(t, "memory", args["target"].Value)
	assert.Equal(t, int64(1000), args["memoryLines"].Value)
	assert.Equal(t, false, args["memoryStopOnFull"].Value)
	// a memory action carries no collector, and none may be invented
	assert.Equal(t, "", args["remote"].Value)
	assert.Nil(t, args["remotePort"].Value)
}

func TestLoggingActionArgsRemote(t *testing.T) {
	args := loggingActionArgs(map[string]string{
		"name":               "remote",
		"target":             "remote",
		"remote":             "198.51.100.20",
		"remote-port":        "514",
		"src-address":        "198.51.100.2",
		"bsd-syslog":         "yes",
		"syslog-facility":    "daemon",
		"syslog-severity":    "auto",
		"syslog-time-format": "bsd-syslog",
	})

	assert.Equal(t, "remote", args["target"].Value)
	assert.Equal(t, "198.51.100.20", args["remote"].Value)
	assert.Equal(t, int64(514), args["remotePort"].Value)
	assert.Equal(t, true, args["bsdSyslog"].Value)
	assert.Equal(t, "daemon", args["syslogFacility"].Value)
}

func TestLoggingActionArgsAbsentAttributes(t *testing.T) {
	args := loggingActionArgs(map[string]string{"name": "bare"})

	assert.Nil(t, args["memoryLines"].Value)
	assert.Nil(t, args["memoryStopOnFull"].Value)
	assert.Nil(t, args["diskStopOnFull"].Value)
	assert.Nil(t, args["bsdSyslog"].Value)
}
