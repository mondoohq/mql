// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// --- OWA mailbox policy: personal accounts ---

// Get-OwaMailboxPolicy leaves PersonalAccountsEnabled unset on a policy that
// never configured it. Decoding that into a plain bool would report a tenant
// that made no decision as one that disallows personal accounts, which is the
// answer an audit wants to see, and so the one that must not be invented.
func TestExchangeOwaMailboxPolicy_PersonalAccountFields(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		wantAccounts  *bool
		wantCalendars *bool
	}{
		{
			// the live Default policy in a real tenant
			name:          "accounts unreported, calendars on",
			raw:           `{"Identity":"OwaMailboxPolicy-Default","PersonalAccountsEnabled":null,"PersonalAccountCalendarsEnabled":true}`,
			wantAccounts:  nil,
			wantCalendars: new(true),
		},
		{
			name:          "property absent entirely",
			raw:           `{"Identity":"OwaMailboxPolicy-Default"}`,
			wantAccounts:  nil,
			wantCalendars: nil,
		},
		{
			name:          "both explicitly disabled",
			raw:           `{"Identity":"x","PersonalAccountsEnabled":false,"PersonalAccountCalendarsEnabled":false}`,
			wantAccounts:  new(false),
			wantCalendars: new(false),
		},
		{
			name:          "both explicitly enabled",
			raw:           `{"Identity":"x","PersonalAccountsEnabled":true,"PersonalAccountCalendarsEnabled":true}`,
			wantAccounts:  new(true),
			wantCalendars: new(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p ExchangeOwaMailboxPolicy
			require.NoError(t, json.Unmarshal([]byte(tc.raw), &p))
			assert.Equal(t, tc.wantAccounts, p.PersonalAccountsEnabled)
			assert.Equal(t, tc.wantCalendars, p.PersonalAccountCalendarsEnabled)
		})
	}
}

//go:fix inline
func boolPtr(b bool) *bool { return new(b) }

// --- Priority account protection ---

// emailTenantSettingsJSON is the row Get-EmailTenantSettings returned for a
// live tenant. Both transports emit PascalCase property names, while the field
// is read by its camelCase name.
const emailTenantSettingsJSON = `{
  "EnablePriorityAccountProtection": true,
  "Identity": "contoso.onmicrosoft.com\\Default",
  "Name": "Default",
  "IsValid": true
}`

func TestEmailTenantSettings_PriorityAccountProtection(t *testing.T) {
	var row any
	require.NoError(t, json.Unmarshal([]byte(emailTenantSettingsJSON), &row))

	d, err := convert.JsonToDict(row)
	require.NoError(t, err)
	assert.True(t, dictBoolValue(d, "enablePriorityAccountProtection"))

	// a section that did not run must not read as "protection is off"
	empty, err := convert.JsonToDict(nil)
	require.NoError(t, err)
	assert.True(t, isAbsentSection(nil))
	assert.False(t, dictBoolValue(empty, "enablePriorityAccountProtection"))
}

// --- Preset security policy rules ---

func TestProtectionPolicyRuleFields(t *testing.T) {
	raw := `{
	  "Identity": "Strict Preset Security Policy",
	  "Name": "Strict Preset Security Policy",
	  "State": "Enabled",
	  "Priority": 0,
	  "EOPProtectionPolicy": "Strict Preset Security Policy",
	  "SentTo": ["ceo@contoso.com"],
	  "SentToMemberOf": ["Priority Accounts"],
	  "RecipientDomainIs": "contoso.com",
	  "ExceptIfSentTo": [],
	  "Comment": "",
	  "WhenChanged": "2026-08-19T10:11:12Z"
	}`
	var row map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &row))

	fields := protectionPolicyRuleFields(row, "eop", "Strict Preset Security Policy", "Strict Preset Security Policy")

	assert.Equal(t, "protectionPolicyRule-eop-Strict Preset Security Policy", fields["__id"].Value)
	assert.Equal(t, "eop", fields["kind"].Value)
	assert.Equal(t, "Enabled", fields["state"].Value)
	assert.Equal(t, int64(0), fields["priority"].Value)
	assert.Equal(t, []any{"ceo@contoso.com"}, fields["sentTo"].Value)
	assert.Equal(t, []any{"Priority Accounts"}, fields["sentToMemberOf"].Value)
	// a single-valued multi-valued property serializes as a bare string
	assert.Equal(t, []any{"contoso.com"}, fields["recipientDomainIs"].Value)
	assert.Equal(t, []any{}, fields["exceptIfSentTo"].Value)
	assert.NotNil(t, fields["whenChanged"].Value)

	// the two cmdlets can name the same rule, so kind has to reach the id or
	// the second row would be served the first one's cached values
	atp := protectionPolicyRuleFields(row, "atp", "Strict Preset Security Policy", "Strict Preset Security Policy")
	assert.NotEqual(t, fields["__id"].Value, atp["__id"].Value)
}

// --- Sensitivity label policies ---

func TestLabelPolicyFields(t *testing.T) {
	raw := `{
	  "Name": "Company labels",
	  "Guid": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
	  "Enabled": true,
	  "Mode": "Enforce",
	  "Labels": ["Public", "Confidential"],
	  "Workload": ["Exchange", "SharePoint"],
	  "DistributionStatus": "Success",
	  "Comment": "published to everyone",
	  "WhenCreated": "/Date(1679714247577)/",
	  "WhenChanged": "2026-08-19T10:11:12Z"
	}`
	var row map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &row))

	fields := labelPolicyFields(row, "3f2504e0-4f89-11d3-9a0c-0305e82c3301", "3f2504e0-4f89-11d3-9a0c-0305e82c3301")

	assert.Equal(t, "Company labels", fields["name"].Value)
	assert.Equal(t, true, fields["enabled"].Value)
	assert.Equal(t, "Enforce", fields["mode"].Value)
	assert.Equal(t, []any{"Public", "Confidential"}, fields["labels"].Value)
	// Workload is a list on some module versions and a string on others
	assert.Equal(t, "Exchange, SharePoint", fields["workload"].Value)
	assert.Equal(t, "Success", fields["distributionStatus"].Value)
	// the legacy /Date(ms)/ form has to parse, not silently drop to null
	assert.NotNil(t, fields["whenCreated"].Value)
	assert.NotNil(t, fields["whenChanged"].Value)
}

// Enabled decides whether a label policy counts as published, so a row that
// does not carry the property has to read null. Reporting false would answer
// "this policy is switched off" with a value the service never sent.
func TestLabelPolicyFields_EnabledIsNullableAndTolerant(t *testing.T) {
	tests := []struct {
		name string
		row  map[string]any
		want any
	}{
		{"real bool true", map[string]any{"Enabled": true}, true},
		{"real bool false", map[string]any{"Enabled": false}, false},
		// ConvertTo-Json on some module versions emits booleans as strings
		{"string True", map[string]any{"Enabled": "True"}, true},
		{"string false", map[string]any{"Enabled": "false"}, false},
		{"property absent", map[string]any{}, nil},
		{"explicit null", map[string]any{"Enabled": nil}, nil},
		// an unparseable value is not evidence the policy is off
		{"unexpected type", map[string]any{"Enabled": 1.0}, nil},
		{"unexpected string", map[string]any{"Enabled": "Pending"}, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, labelPolicyFields(tc.row, "g", "g")["enabled"].Value)
		})
	}
}

// --- Microsoft Authenticator feature settings ---

// authenticatorBetaJSON is the MicrosoftAuthenticator configuration the beta
// authenticationMethodsPolicy returned for a live tenant. companionAppAllowedState
// and numberMatchingRequiredState are absent from the v1.0 model entirely, which
// is why this reads from beta.
const authenticatorBetaJSON = `{
  "@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration",
  "id": "MicrosoftAuthenticator",
  "state": "disabled",
  "isSoftwareOathEnabled": false,
  "featureSettings": {
    "companionAppAllowedState": {
      "state": "default",
      "includeTarget": {"id": "all_users", "targetType": "group"},
      "excludeTarget": {"id": "00000000-0000-0000-0000-000000000000", "targetType": "group"}
    },
    "numberMatchingRequiredState": {
      "state": "enabled",
      "includeTarget": {"id": "all_users", "targetType": "group"}
    },
    "displayAppInformationRequiredState": {"state": "default"},
    "displayLocationInformationRequiredState": {"state": "default"}
  }
}`

func TestMicrosoftAuthenticatorBetaFeatureSettings(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(authenticatorBetaJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateAuthenticationMethodConfigurationFromDiscriminatorValue)
	require.NoError(t, err)

	cfg, ok := parsed.(betamodels.MicrosoftAuthenticatorAuthenticationMethodConfigurationable)
	require.True(t, ok, "the discriminator must resolve to the Microsoft Authenticator configuration")

	fs := cfg.GetFeatureSettings()
	require.NotNil(t, fs)

	companion := fs.GetCompanionAppAllowedState()
	require.NotNil(t, companion, "the companion-app toggle is the reason this reads from beta")
	assert.Equal(t, "default", *enumPtrString(companion.GetState()))
	require.NotNil(t, companion.GetIncludeTarget())
	assert.Equal(t, "all_users", *companion.GetIncludeTarget().GetId())

	numberMatching := fs.GetNumberMatchingRequiredState()
	require.NotNil(t, numberMatching)
	assert.Equal(t, "enabled", *enumPtrString(numberMatching.GetState()))

	// a target the tenant never set is absent, and must stay absent rather
	// than becoming an empty group
	assert.Nil(t, numberMatching.GetExcludeTarget())
}

// --- absent vs empty ---

// The controls behind these sections turn on the result being empty, so a
// section that did not run has to stay distinguishable from one that ran and
// matched nothing. The PowerShell script leaves a failed cmdlet at $null for
// exactly this reason.
func TestNewSections_AbsentIsNotEmpty(t *testing.T) {
	t.Run("security and compliance label policies", func(t *testing.T) {
		var failed SecurityAndComplianceReport
		require.NoError(t, json.Unmarshal([]byte(`{"LabelPolicy":null}`), &failed))
		assert.Nil(t, failed.LabelPolicy)
		assert.True(t, isAbsentSection(failed.LabelPolicy))

		var ran SecurityAndComplianceReport
		require.NoError(t, json.Unmarshal([]byte(`{"LabelPolicy":[]}`), &ran))
		assert.NotNil(t, ran.LabelPolicy)
		assert.False(t, isAbsentSection(ran.LabelPolicy))
	})

	t.Run("preset rules need both cmdlets", func(t *testing.T) {
		// a preset is turned on by one EOP rule and one ATP rule, so half an
		// answer cannot support "the preset is not in use"
		var half ExchangeOnlineReport
		require.NoError(t, json.Unmarshal([]byte(`{"EOPProtectionPolicyRule":[],"ATPProtectionPolicyRule":null}`), &half))
		assert.True(t, isAbsentSection(half.EOPProtectionPolicyRule) || isAbsentSection(half.ATPProtectionPolicyRule))

		var both ExchangeOnlineReport
		require.NoError(t, json.Unmarshal([]byte(`{"EOPProtectionPolicyRule":[],"ATPProtectionPolicyRule":[]}`), &both))
		assert.False(t, isAbsentSection(both.EOPProtectionPolicyRule) || isAbsentSection(both.ATPProtectionPolicyRule))
	})

	t.Run("priority account protection", func(t *testing.T) {
		var failed ExchangeOnlineReport
		require.NoError(t, json.Unmarshal([]byte(`{"EmailTenantSettings":null}`), &failed))
		assert.True(t, isAbsentSection(failed.EmailTenantSettings))
	})
}
