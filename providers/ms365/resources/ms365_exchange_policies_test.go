// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exchange domain collections (e.g. AllowedSenderDomains on hosted content
// filter policies, Domains on sharing policies) are MultiValuedProperty<...>
// values. Depending on the cmdlet and ConvertTo-Json serialization each entry
// is emitted as a bare string or as an object with a "Domain" field, and a
// single-element collection may be a scalar rather than an array. Decoding any
// of these into exchangeDomainList must succeed and normalize to []string.
func TestExchangeDomainList_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"null", `null`, nil},
		{"empty array", `[]`, []string{}},
		{"string array", `["contoso.com","fabrikam.com"]`, []string{"contoso.com", "fabrikam.com"}},
		{"single string", `"contoso.com"`, []string{"contoso.com"}},
		{
			"object array",
			`[{"Domain":"contoso.com","IncludeSubDomains":false},{"Domain":"fabrikam.com"}]`,
			[]string{"contoso.com", "fabrikam.com"},
		},
		{"single object", `{"Domain":"contoso.com","IncludeSubDomains":true}`, []string{"contoso.com"}},
		{"object without domain", `[{"Foo":"bar"}]`, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got exchangeDomainList
			require.NoError(t, json.Unmarshal([]byte(tc.in), &got))
			assert.Equal(t, tc.want, []string(got))
		})
	}
}

// Regression: a hosted content filter policy whose AllowedSenderDomains is an
// array of SmtpDomainWithSubdomains objects previously aborted the whole
// resource with "cannot unmarshal object ... of type string".
func TestExchangeHostedContentFilterPolicy_ObjectAllowedSenderDomains(t *testing.T) {
	raw := `{
		"Identity": "Default",
		"Name": "Default",
		"AllowedSenderDomains": [{"Domain":"contoso.com","IncludeSubDomains":false}],
		"BlockedSenderDomains": []
	}`
	var p ExchangeHostedContentFilterPolicy
	require.NoError(t, json.Unmarshal([]byte(raw), &p))
	assert.Equal(t, []string{"contoso.com"}, []string(p.AllowedSenderDomains))
	assert.Empty(t, []string(p.BlockedSenderDomains))
}

// Regression: sharing policy Domains are SharingPolicyDomain objects and must
// decode without aborting the resource.
func TestExchangeSharingPolicy_ObjectDomains(t *testing.T) {
	raw := `{
		"Identity": "Default Sharing Policy",
		"Name": "Default Sharing Policy",
		"Enabled": true,
		"Default": true,
		"Domains": [{"Domain":"contoso.com","DomainType":"CalendarSharingFreeBusySimple"}]
	}`
	var p ExchangeSharingPolicy
	require.NoError(t, json.Unmarshal([]byte(raw), &p))
	assert.Equal(t, []string{"contoso.com"}, []string(p.Domains))
}

// Get-QuarantinePolicy (both the Exchange admin REST endpoint and the
// ExchangeOnlineManagement module) no longer returns
// EndUserQuarantinePermissionsValue; the permissions arrive only as the
// EndUserQuarantinePermissions string. These payloads mirror live output.
func TestQuarantinePolicyPermissions(t *testing.T) {
	raw := []any{}
	require.NoError(t, json.Unmarshal([]byte(`[
		{"Identity": "org\\DefaultFullAccessPolicy", "Name": "DefaultFullAccessPolicy", "ESNEnabled": false,
		 "EndUserQuarantinePermissions": "[PermissionToBlockSender: False\r\nPermissionToDelete: True\r\nPermissionToDownload: True\r\nPermissionToPreview: True\r\nPermissionToRelease: True\r\nPermissionToRequestRelease: False\r\nPermissionToViewHeader: False\r\nPermissionToAllowSender: True]"},
		{"Identity": "org\\AdminOnlyAccessPolicy", "Name": "AdminOnlyAccessPolicy", "ESNEnabled": false,
		 "EndUserQuarantinePermissions": "[PermissionToBlockSender: False\r\nPermissionToDelete: False\r\nPermissionToDownload: False\r\nPermissionToPreview: False\r\nPermissionToRelease: False\r\nPermissionToRequestRelease: False\r\nPermissionToViewHeader: False\r\nPermissionToAllowSender: False]"},
		{"Identity": "org\\Limited", "Name": "Limited", "ESNEnabled": true,
		 "EndUserQuarantinePermissions": "[PermissionToBlockSender: True\r\nPermissionToDelete: True\r\nPermissionToDownload: False\r\nPermissionToPreview: True\r\nPermissionToRelease: False\r\nPermissionToRequestRelease: True\r\nPermissionToViewHeader: True\r\nPermissionToAllowSender: False]"},
		{"Identity": "org\\Legacy", "Name": "Legacy", "EndUserQuarantinePermissionsValue": 43},
		{"Identity": "org\\Absent", "Name": "Absent"}
	]`), &raw))
	policies, err := decodeExchangeList[ExchangeQuarantinePolicy](raw)
	require.NoError(t, err)
	require.Len(t, policies, 5)

	type want struct {
		mask  int64
		flags map[string]bool
	}
	cases := []want{
		{103, map[string]bool{ // Delete+Preview+Release+AllowSender+Download
			"permissionToViewHeader": false, "permissionToDownload": true, "permissionToAllowSender": true,
			"permissionToBlockSender": false, "permissionToRequestRelease": false, "permissionToRelease": true,
			"permissionToPreview": true, "permissionToDelete": true,
		}},
		{0, map[string]bool{
			"permissionToViewHeader": false, "permissionToDownload": false, "permissionToAllowSender": false,
			"permissionToBlockSender": false, "permissionToRequestRelease": false, "permissionToRelease": false,
			"permissionToPreview": false, "permissionToDelete": false,
		}},
		{155, map[string]bool{ // ViewHeader+BlockSender+RequestRelease+Preview+Delete
			"permissionToViewHeader": true, "permissionToDownload": false, "permissionToAllowSender": false,
			"permissionToBlockSender": true, "permissionToRequestRelease": true, "permissionToRelease": false,
			"permissionToPreview": true, "permissionToDelete": true,
		}},
		{43, map[string]bool{ // documented Limited access preset, from the value alone
			"permissionToViewHeader": false, "permissionToDownload": false, "permissionToAllowSender": true,
			"permissionToBlockSender": false, "permissionToRequestRelease": true, "permissionToRelease": false,
			"permissionToPreview": true, "permissionToDelete": true,
		}},
	}
	for i, w := range cases {
		mask, flags := quarantinePolicyPermissions(policies[i])
		require.NotNil(t, mask, policies[i].Name)
		assert.Equal(t, w.mask, *mask, policies[i].Name)
		require.Len(t, flags, 8, policies[i].Name)
		for field, granted := range w.flags {
			require.NotNil(t, flags[field], "%s %s", policies[i].Name, field)
			assert.Equal(t, granted, *flags[field], "%s %s", policies[i].Name, field)
		}
	}

	// Neither the value nor the string: null, not 0.
	mask, flags := quarantinePolicyPermissions(policies[4])
	assert.Nil(t, mask)
	require.Len(t, flags, 8)
	for field, v := range flags {
		assert.Nil(t, v, field)
	}
}

func TestParseQuarantinePermissions_Malformed(t *testing.T) {
	assert.Empty(t, parseQuarantinePermissions(""))
	assert.Empty(t, parseQuarantinePermissions("[]"))
	assert.Equal(t, map[string]bool{"PermissionToDelete": true},
		parseQuarantinePermissions("PermissionToDelete: True\nPermissionToPreview: maybe\ngarbage"))
}
