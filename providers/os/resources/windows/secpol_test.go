// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestParseSecpol(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/secpol.toml"))
	require.NoError(t, err)

	encoded := powershell.Encode(SecpolScript)
	f, err := mock.RunCommand(encoded)
	require.NoError(t, err)

	secpol, err := ParseSecpol(f.Stdout)
	require.NoError(t, err)

	rights, err := secpol.PrivilegeRightSids(nil)
	require.NoError(t, err)

	assert.Equal(t, "42", secpol.SystemAccess["MaximumPasswordAge"])
	assert.Equal(t, "chris", secpol.SystemAccess["NewAdministratorName"])
	assert.Equal(t, "0", secpol.EventAudit["AuditLogonEvents"])
	assert.Equal(t, []any{"S-1-1-0", "S-1-5-32-544", "S-1-5-32-545", "S-1-5-32-551"}, rights["SeNetworkLogonRight"])
	assert.Equal(t, "3,0", secpol.RegistryValues["MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FullPrivilegeAuditing"])
}

const secpolWithNames = `[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 0
[Event Audit]
AuditSystemEvents = 0
[Registry Values]
MACHINE\System\foo=4,0
[Privilege Rights]
SeDenyNetworkLogonRight = Guest,*S-1-5-32-544
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545,Gast
[Version]
signature="$CHICAGO$"
Revision=1
`

func TestParseSecpolKeepsRawPrincipals(t *testing.T) {
	// The parse step reports the principals as exported, names included, and
	// lists the names a resolver would have to translate.
	secpol, err := ParseSecpol(strings.NewReader(secpolWithNames))
	require.NoError(t, err)

	assert.Equal(t, []string{"Guest", "S-1-5-32-544"}, secpol.PrivilegeRights["SeDenyNetworkLogonRight"])
	assert.Equal(t, []string{"Gast", "Guest"}, secpol.AccountNames())
}

func TestPrivilegeRightSidsWithoutResolver(t *testing.T) {
	// Without a resolver nothing can translate the names, so
	// secpol.privilegerights output stays restricted to SIDs.
	secpol, err := ParseSecpol(strings.NewReader(secpolWithNames))
	require.NoError(t, err)

	rights, err := secpol.PrivilegeRightSids(nil)
	require.NoError(t, err)

	assert.Equal(t, []any{"S-1-5-32-544"}, rights["SeDenyNetworkLogonRight"])
	assert.Equal(t, []any{"S-1-5-32-544", "S-1-5-32-545"}, rights["SeInteractiveLogonRight"])
}

func TestPrivilegeRightSidsResolvesNames(t *testing.T) {
	secpol, err := ParseSecpol(strings.NewReader(secpolWithNames))
	require.NoError(t, err)

	var requested []string
	rights, err := secpol.PrivilegeRightSids(func(names []string) (map[string]string, error) {
		requested = names
		return map[string]string{
			"Guest": "S-1-5-21-1234567890-1234567890-1234567890-501",
			"Gast":  "*S-1-5-32-546",
		}, nil
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"Gast", "Guest"}, requested)
	assert.Equal(t, []any{"S-1-5-21-1234567890-1234567890-1234567890-501", "S-1-5-32-544"}, rights["SeDenyNetworkLogonRight"])
	assert.Equal(t, []any{"S-1-5-32-544", "S-1-5-32-545", "S-1-5-32-546"}, rights["SeInteractiveLogonRight"])
}

func TestPrivilegeRightSidsResolverError(t *testing.T) {
	secpol, err := ParseSecpol(strings.NewReader(secpolWithNames))
	require.NoError(t, err)

	// A failing lookup must not cost the caller the three sections that were
	// parsed without it.
	_, err = secpol.PrivilegeRightSids(func(names []string) (map[string]string, error) {
		return nil, assert.AnError
	})
	require.Error(t, err)
	assert.Equal(t, "0", secpol.SystemAccess["MinimumPasswordAge"])
	assert.Equal(t, "0", secpol.EventAudit["AuditSystemEvents"])
	assert.Equal(t, "4,0", secpol.RegistryValues[`MACHINE\System\foo`])
}

func TestParseSecpolWithoutNamesSkipsResolver(t *testing.T) {
	input := `[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 0
[Event Audit]
AuditSystemEvents = 0
[Registry Values]
MACHINE\System\foo=4,0
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=1
`
	secpol, err := ParseSecpol(strings.NewReader(input))
	require.NoError(t, err)

	called := false
	rights, err := secpol.PrivilegeRightSids(func(names []string) (map[string]string, error) {
		called = true
		return nil, nil
	})
	require.NoError(t, err)

	assert.False(t, called)
	assert.Equal(t, []any{"S-1-5-32-544"}, rights["SeDenyNetworkLogonRight"])
}

func TestParseSecpolNormalizesPrivilegeRightSIDs(t *testing.T) {
	input := `[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 0
[Event Audit]
AuditSystemEvents = 0
[Registry Values]
MACHINE\System\foo=4,0
[Privilege Rights]
SeDenyNetworkLogonRight = S-1-5-32-545,*S-1-5-32-544,Guest,,not-a-sid,S-1-X-0,*S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=1
`
	secpol, err := ParseSecpol(strings.NewReader(input))
	require.NoError(t, err)

	rights, err := secpol.PrivilegeRightSids(nil)
	require.NoError(t, err)

	assert.Equal(t, []any{"S-1-5-32-544", "S-1-5-32-545"}, rights["SeDenyNetworkLogonRight"])
}

func TestSidLookupScript(t *testing.T) {
	script := SidLookupScript([]string{"Gast", `DOMAIN\O'Brien`})
	assert.Contains(t, script, `$names = @('Gast','DOMAIN\O''Brien')`)
}

func TestParseSidLookup(t *testing.T) {
	lookup, err := ParseSidLookup(strings.NewReader(
		"Gast\tS-1-5-32-546\r\nDOMAIN\\Some User\t*S-1-5-21-1-2-3-1001\nbroken line\nNoSid\t\nEmpty\tnot-a-sid\n",
	))
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"Gast":              "S-1-5-32-546",
		"DOMAIN\\Some User": "S-1-5-21-1-2-3-1001",
	}, lookup)
}
