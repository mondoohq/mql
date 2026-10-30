// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package snmpd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every line below was loaded by Net-SNMP 5.9.4 snmpd (Debian 13) with
// -Drouser,rwuser,authuser debugging; the expectations match the group and
// access lines snmpd generated for it.
func TestUsers(t *testing.T) {
	content := `# VACM users
rouser plain
rwuser writer noauth
RWUSER upper NOAUTHNOPRIV
rwuser -s usm modeled authnopriv .1.3.6.1.2.1
rouser -s TSM tlsuser priv -V systemonly
rouser viewctx authpriv -V systemonly ctxA
rouser prefixctx auth .1.3 ctx*
rouser "quoted user" noauth   # trailing comment
authuser read,write authw noauth
authuser notify|log notifier priv
authuser read:write -s usm colon auth
authuser write onlywrite
authuser bogus,read partial
rocommunity public default
`
	users := Users(content)
	require.Len(t, users, 13)

	byName := map[string]User{}
	for _, u := range users {
		byName[u.Name] = u
	}

	tests := []struct {
		name string
		want User
	}{
		{"plain", User{Directive: "rouser", Name: "plain", Access: "ro", AccessTypes: []string{"read"}, SecurityLevel: "auth", SecurityModel: "usm", Line: 2}},
		{"writer", User{Directive: "rwuser", Name: "writer", Access: "rw", AccessTypes: []string{"read", "write"}, SecurityLevel: "noauth", SecurityModel: "usm", Line: 3}},
		{"upper", User{Directive: "rwuser", Name: "upper", Access: "rw", AccessTypes: []string{"read", "write"}, SecurityLevel: "noauth", SecurityModel: "usm", Line: 4}},
		{"modeled", User{Directive: "rwuser", Name: "modeled", Access: "rw", AccessTypes: []string{"read", "write"}, SecurityLevel: "auth", SecurityModel: "usm", OID: ".1.3.6.1.2.1", Line: 5}},
		{"tlsuser", User{Directive: "rouser", Name: "tlsuser", Access: "ro", AccessTypes: []string{"read"}, SecurityLevel: "priv", SecurityModel: "tsm", View: "systemonly", Line: 6}},
		{"viewctx", User{Directive: "rouser", Name: "viewctx", Access: "ro", AccessTypes: []string{"read"}, SecurityLevel: "priv", SecurityModel: "usm", View: "systemonly", ContextName: "ctxA", Line: 7}},
		{"prefixctx", User{Directive: "rouser", Name: "prefixctx", Access: "ro", AccessTypes: []string{"read"}, SecurityLevel: "auth", SecurityModel: "usm", OID: ".1.3", ContextName: "ctx*", Line: 8}},
		{"quoted user", User{Directive: "rouser", Name: "quoted user", Access: "ro", AccessTypes: []string{"read"}, SecurityLevel: "noauth", SecurityModel: "usm", Line: 9}},
		{"authw", User{Directive: "authuser", Name: "authw", Access: "rw", AccessTypes: []string{"read", "write"}, SecurityLevel: "noauth", SecurityModel: "usm", Line: 10}},
		{"notifier", User{Directive: "authuser", Name: "notifier", Access: "none", AccessTypes: []string{"notify", "log"}, SecurityLevel: "priv", SecurityModel: "usm", Line: 11}},
		{"colon", User{Directive: "authuser", Name: "colon", Access: "rw", AccessTypes: []string{"read", "write"}, SecurityLevel: "auth", SecurityModel: "usm", Line: 12}},
		{"onlywrite", User{Directive: "authuser", Name: "onlywrite", Access: "rw", AccessTypes: []string{"write"}, SecurityLevel: "auth", SecurityModel: "usm", Line: 13}},
		// snmpd reports "Illegal view name" for bogus but still grants read.
		{"partial", User{Directive: "authuser", Name: "partial", Access: "ro", AccessTypes: []string{"read"}, SecurityLevel: "auth", SecurityModel: "usm", Line: 14}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := byName[tc.name]
			require.True(t, ok, "user %q not parsed", tc.name)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("file order is kept", func(t *testing.T) {
		assert.Equal(t, "plain", users[0].Name)
		assert.Equal(t, "partial", users[len(users)-1].Name)
	})
}

// Each of these lines is rejected by snmpd when it loads the configuration
// (verified against Net-SNMP 5.9.4), so none grants access.
func TestUsersRejectedLines(t *testing.T) {
	tests := map[string]string{
		"missing user":                      "rwuser",
		"-s without model or user":          "rouser -s",
		"-s without user":                   "rouser -s usm",
		"unknown security level":            "rwuser bob bogus",
		"uppercase -S is a user name":       "rwuser -S usm bob",
		"-V without a view":                 "rouser bob auth -V",
		"authuser without user":             "authuser read",
		"authuser types are case-sensitive": "authuser READ bob noauth",
		"authuser with no known type":       "authuser bogus bob noauth",
		"not a user directive":              "rocommunity public",
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, Users(line))
		})
	}
}

func TestUsersMixedCaseAuthuserTypes(t *testing.T) {
	// snmpd drops READ (Illegal view name) and keeps write.
	users := Users("authuser READ,write bob noauth")
	require.Len(t, users, 1)
	assert.Equal(t, []string{"write"}, users[0].AccessTypes)
	assert.Equal(t, "rw", users[0].Access)
}

func TestUsersEmpty(t *testing.T) {
	assert.Empty(t, Users(""))
	assert.Empty(t, Users("# rwuser commented noauth\n\n"))
}
