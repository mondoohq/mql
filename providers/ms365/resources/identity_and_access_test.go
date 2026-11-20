// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/microsoft/kiota-abstractions-go/serialization"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Measured: Global Administrator's PIM policy on an E5 developer tenant,
// 2026-11-20 (GET /policies/roleManagementPolicyAssignments?$expand=policy($expand=rules)).
func measuredEnablementRule(id string, enabled ...string) models.UnifiedRoleManagementPolicyRuleable {
	r := models.NewUnifiedRoleManagementPolicyEnablementRule()
	r.SetId(ptr(id))
	r.SetEnabledRules(enabled)
	return r
}

func measuredApprovalRule() models.UnifiedRoleManagementPolicyRuleable {
	s := models.NewApprovalSettings()
	s.SetIsApprovalRequired(ptr(false))
	s.SetIsApprovalRequiredForExtension(ptr(false))
	s.SetIsRequestorJustificationRequired(ptr(true))
	s.SetApprovalMode(ptr("SingleStage"))
	r := models.NewUnifiedRoleManagementPolicyApprovalRule()
	r.SetId(ptr("Approval_EndUser_Assignment"))
	r.SetSetting(s)
	return r
}

func measuredExpirationRule(t *testing.T, id string, required bool, duration string) models.UnifiedRoleManagementPolicyRuleable {
	d, err := serialization.ParseISODuration(duration)
	require.NoError(t, err)
	r := models.NewUnifiedRoleManagementPolicyExpirationRule()
	r.SetId(ptr(id))
	r.SetIsExpirationRequired(ptr(required))
	r.SetMaximumDuration(d)
	return r
}

func TestPolicyRuleSettings(t *testing.T) {
	t.Run("enablement", func(t *testing.T) {
		rule := measuredEnablementRule("Enablement_EndUser_Assignment", "MultiFactorAuthentication", "Justification")
		assert.Equal(t, "enablement", policyRuleKind(rule))
		f := policyRuleSettings(rule)
		assert.Equal(t, []any{"MultiFactorAuthentication", "Justification"}, f["enabledRules"].Value)
		// a field the kind does not carry is null, not false
		assert.Nil(t, f["isApprovalRequired"].Value)
		assert.Nil(t, f["maximumDuration"].Value)
	})

	// Measured: Enablement_Admin_Eligibility on the same policy has no requirements.
	t.Run("enablement with none enabled is an empty list", func(t *testing.T) {
		f := policyRuleSettings(measuredEnablementRule("Enablement_Admin_Eligibility"))
		assert.Equal(t, []any{}, f["enabledRules"].Value)
	})

	t.Run("approval", func(t *testing.T) {
		rule := measuredApprovalRule()
		assert.Equal(t, "approval", policyRuleKind(rule))
		f := policyRuleSettings(rule)
		assert.Equal(t, false, f["isApprovalRequired"].Value)
		assert.Equal(t, false, f["isApprovalRequiredForExtension"].Value)
		assert.Equal(t, true, f["isRequestorJustificationRequired"].Value)
		assert.Equal(t, "SingleStage", f["approvalMode"].Value)
		assert.Nil(t, f["enabledRules"].Value)
	})

	// Synthetic: an approval rule without a setting block; no target showed this.
	t.Run("approval without settings stays null", func(t *testing.T) {
		r := models.NewUnifiedRoleManagementPolicyApprovalRule()
		r.SetId(ptr("Approval_EndUser_Assignment"))
		f := policyRuleSettings(r)
		assert.Nil(t, f["isApprovalRequired"].Value)
	})

	t.Run("expiration keeps the ISO 8601 duration", func(t *testing.T) {
		for _, c := range []struct {
			id       string
			required bool
			duration string
		}{
			{"Expiration_EndUser_Assignment", true, "PT8H"},
			{"Expiration_Admin_Eligibility", false, "P365D"},
			{"Expiration_Admin_Assignment", false, "P180D"},
		} {
			rule := measuredExpirationRule(t, c.id, c.required, c.duration)
			assert.Equal(t, "expiration", policyRuleKind(rule))
			f := policyRuleSettings(rule)
			assert.Equal(t, c.required, f["isExpirationRequired"].Value, c.id)
			assert.Equal(t, c.duration, f["maximumDuration"].Value, c.id)
		}
	})

	t.Run("authentication context", func(t *testing.T) {
		// Measured: disabled with a null claim value.
		r := models.NewUnifiedRoleManagementPolicyAuthenticationContextRule()
		r.SetId(ptr("AuthenticationContext_EndUser_Assignment"))
		r.SetIsEnabled(ptr(false))
		assert.Equal(t, "authenticationContext", policyRuleKind(r))
		f := policyRuleSettings(r)
		assert.Equal(t, false, f["authenticationContextEnabled"].Value)
		assert.Nil(t, f["authenticationContextClaimValue"].Value)
	})

	t.Run("notification", func(t *testing.T) {
		r := models.NewUnifiedRoleManagementPolicyNotificationRule()
		r.SetId(ptr("Notification_Admin_EndUser_Assignment"))
		assert.Equal(t, "notification", policyRuleKind(r))
	})
}

// Every policy carries rules with the same IDs. Two policies whose activation
// rules differ must keep their own values.
func TestPolicyRulesAreKeyedByPolicy(t *testing.T) {
	runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)

	ga, err := newMqlRoleManagementPolicyRule(runtime, "Directory_tenant_policyA",
		measuredEnablementRule("Enablement_EndUser_Assignment", "MultiFactorAuthentication", "Justification"))
	require.NoError(t, err)
	// Synthetic: a second role whose activation requires nothing.
	other, err := newMqlRoleManagementPolicyRule(runtime, "Directory_tenant_policyB",
		measuredEnablementRule("Enablement_EndUser_Assignment"))
	require.NoError(t, err)

	gaRule := ga.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicyRule)
	otherRule := other.(*mqlMicrosoftIdentityAndAccessPrivilegedIdentityManagementPolicyRule)
	assert.Equal(t, "Enablement_EndUser_Assignment", otherRule.Id.Data)
	assert.Equal(t, []any{"MultiFactorAuthentication", "Justification"}, gaRule.EnabledRules.Data)
	assert.Equal(t, []any{}, otherRule.EnabledRules.Data)
	assert.NotEqual(t, gaRule.MqlID(), otherRule.MqlID())
}
