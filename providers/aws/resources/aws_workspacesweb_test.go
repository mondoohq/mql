// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== portal typed-ref null-state =====

func TestPortalIpAccessSettingsNullWhenNoArn(t *testing.T) {
	p := &mqlAwsWorkspaceswebPortal{}
	p.cacheIpAccessSettingsArn = ""
	got, err := p.ipAccessSettings()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, p.IpAccessSettings.IsNull())
	assert.True(t, p.IpAccessSettings.IsSet())
}

func TestPortalTrustStoreNullWhenNoArn(t *testing.T) {
	p := &mqlAwsWorkspaceswebPortal{}
	p.cacheTrustStoreArn = ""
	got, err := p.trustStore()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, p.TrustStore.IsNull())
}

func TestPortalUserSettingsNullWhenNoArn(t *testing.T) {
	p := &mqlAwsWorkspaceswebPortal{}
	p.cacheUserSettingsArn = ""
	got, err := p.userSettings()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, p.UserSettings.IsNull())
}

func TestPortalUserAccessLoggingSettingNullWhenNoArn(t *testing.T) {
	p := &mqlAwsWorkspaceswebPortal{}
	p.cacheUserAccessLoggingSettingsArn = ""
	got, err := p.userAccessLoggingSetting()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, p.UserAccessLoggingSetting.IsNull())
}

// ===== customer-managed key null-state (cache empty after detail fetch) =====

func TestPortalCustomerManagedKeyNullWhenCacheEmpty(t *testing.T) {
	p := &mqlAwsWorkspaceswebPortal{}
	p.detailFetched = true // simulate detail already fetched, no CMK on the portal
	got, err := p.customerManagedKey()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, p.CustomerManagedKey.IsNull())
}

func TestIpAccessSettingCustomerManagedKeyNullWhenCacheEmpty(t *testing.T) {
	r := &mqlAwsWorkspaceswebIpAccessSetting{}
	r.detailFetched = true
	got, err := r.customerManagedKey()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, r.CustomerManagedKey.IsNull())
}

func TestUserSettingCustomerManagedKeyNullWhenCacheEmpty(t *testing.T) {
	r := &mqlAwsWorkspaceswebUserSetting{}
	r.detailFetched = true
	got, err := r.customerManagedKey()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, r.CustomerManagedKey.IsNull())
}

// ===== lazy-loaded fields cache through =====

func TestIpAccessSettingIpRulesReturnsCache(t *testing.T) {
	r := &mqlAwsWorkspaceswebIpAccessSetting{}
	r.detailFetched = true
	r.cacheIpRules = []any{
		map[string]any{"ipRange": "10.0.0.0/8", "description": "corp"},
	}
	got, err := r.ipRules()
	require.NoError(t, err)
	require.Len(t, got, 1)
	rule := got[0].(map[string]any)
	assert.Equal(t, "10.0.0.0/8", rule["ipRange"])
	assert.Equal(t, "corp", rule["description"])
}

func TestUserSettingWebAuthnAllowedReturnsCache(t *testing.T) {
	r := &mqlAwsWorkspaceswebUserSetting{}
	r.detailFetched = true
	r.cacheWebAuthnAllowed = "Enabled"
	got, err := r.webAuthnAllowed()
	require.NoError(t, err)
	assert.Equal(t, "Enabled", got)
}

// ===== associatedPortals helper =====

func TestAssociatedPortalsFromArnsSkipsEmpty(t *testing.T) {
	// Empty list → empty result
	got, err := associatedPortalsFromArns(nil, []string{})
	require.NoError(t, err)
	assert.Empty(t, got)

	// All-empty list → empty result (skip behavior)
	got, err = associatedPortalsFromArns(nil, []string{"", ""})
	require.NoError(t, err)
	assert.Empty(t, got)
}

// ===== ipRulesToDicts helper =====

func TestIpRulesToDictsEmpty(t *testing.T) {
	got := ipRulesToDicts(nil)
	assert.Empty(t, got)
}

// ===== awsString helper =====

func TestAwsStringNil(t *testing.T) {
	assert.Equal(t, "", awsString(nil))
}

func TestAwsStringValue(t *testing.T) {
	s := "hello"
	assert.Equal(t, "hello", awsString(&s))
}
