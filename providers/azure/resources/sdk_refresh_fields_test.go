// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	apps "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v5"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func sdkRefreshTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

func isNullField(state plugin.State) bool {
	return state&plugin.StateIsNull != 0
}

// The list path decodes policy assignments from raw REST into our own struct,
// so a mistyped JSON tag would read as "no settings" on every assignment.
func TestPolicyAssignmentSelfServeExemptionSettings(t *testing.T) {
	decode := func(t *testing.T, raw string) map[string]*llx.RawData {
		t.Helper()
		page := PolicyAssignments{}
		require.NoError(t, json.Unmarshal([]byte(raw), &page))
		require.Len(t, page.PolicyAssignments, 1)
		args, err := policyAssignmentArgs(page.PolicyAssignments[0])
		require.NoError(t, err)
		return args
	}

	t.Run("enabled with covered definitions", func(t *testing.T) {
		args := decode(t, `{"value":[{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/policyAssignments/a1",
			"properties":{"displayName":"a1","selfServeExemptionSettings":{"enabled":true,"policyDefinitionReferenceIds":["ref-1","ref-2"]}}}]}`)
		assert.Equal(t, true, args["selfServeExemptionEnabled"].Value)
		assert.Equal(t, []any{"ref-1", "ref-2"}, args["selfServeExemptionPolicyDefinitionReferenceIds"].Value)
	})

	t.Run("explicitly disabled without a reference list", func(t *testing.T) {
		args := decode(t, `{"value":[{"id":"/a2","properties":{"selfServeExemptionSettings":{"enabled":false}}}]}`)
		assert.Equal(t, false, args["selfServeExemptionEnabled"].Value)
		assert.Equal(t, llx.NilData, args["selfServeExemptionPolicyDefinitionReferenceIds"])
	})

	t.Run("absent settings are null, not false", func(t *testing.T) {
		args := decode(t, `{"value":[{"id":"/a3","properties":{"displayName":"a3"}}]}`)
		assert.Equal(t, llx.NilData, args["selfServeExemptionEnabled"])
		assert.Equal(t, llx.NilData, args["selfServeExemptionPolicyDefinitionReferenceIds"])
	})
}

// The single-assignment lookup decodes through the SDK. Its conversion must
// keep an absent ID list null, like the list path, rather than empty.
func TestSelfServeFromSDK(t *testing.T) {
	assert.Nil(t, selfServeFromSDK(nil))

	var noIDs armpolicy.SelfServeExemptionSettings
	require.NoError(t, json.Unmarshal([]byte(`{"enabled":true}`), &noIDs))
	enabled, refIds := selfServeExemptionFields(selfServeFromSDK(&noIDs))
	assert.Equal(t, true, enabled.Value)
	assert.Equal(t, llx.NilData, refIds)

	var withIDs armpolicy.SelfServeExemptionSettings
	require.NoError(t, json.Unmarshal([]byte(`{"enabled":false,"policyDefinitionReferenceIds":["ref-1"]}`), &withIDs))
	withIDs.PolicyDefinitionReferenceIDs = append(withIDs.PolicyDefinitionReferenceIDs, nil)
	enabled, refIds = selfServeExemptionFields(selfServeFromSDK(&withIDs))
	assert.Equal(t, false, enabled.Value)
	assert.Equal(t, []any{"ref-1"}, refIds.Value)
}

// The fields only arrive when the request names an api-version that carries
// them. Pinning an older version silently reports every one as absent.
func TestPolicyAPIVersionsCarryNewFields(t *testing.T) {
	// selfServeExemptionSettings first appears in 2025-11-01.
	assert.GreaterOrEqual(t, policyAssignmentsAPIVersion, "2025-11-01")
	// exemptionManagementMode first appears in 2025-12-01-preview.
	assert.GreaterOrEqual(t, policyExemptionsAPIVersion, "2025-12-01-preview")
}

func TestPolicyExemptionManagementMode(t *testing.T) {
	decode := func(t *testing.T, raw string) *mqlAzureSubscriptionPolicyExemption {
		t.Helper()
		list := azurePolicyExemptionList{}
		require.NoError(t, json.Unmarshal([]byte(raw), &list))
		require.Len(t, list.Value, 1)
		res, err := newMqlPolicyExemption(sdkRefreshTestRuntime(), &list.Value[0])
		require.NoError(t, err)
		return res.(*mqlAzureSubscriptionPolicyExemption)
	}

	t.Run("self-serve exemption", func(t *testing.T) {
		ex := decode(t, `{"value":[{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/policyExemptions/e1","name":"e1",
			"properties":{"policyAssignmentId":"/x","exemptionCategory":"Waiver","exemptionManagementMode":"UserSelfServe"}}]}`)
		assert.Equal(t, "UserSelfServe", ex.ManagementMode.Data)
		assert.False(t, isNullField(ex.ManagementMode.State))
	})

	t.Run("mode not reported is null", func(t *testing.T) {
		ex := decode(t, `{"value":[{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/policyExemptions/e2","name":"e2",
			"properties":{"policyAssignmentId":"/x","exemptionCategory":"Mitigated"}}]}`)
		assert.True(t, isNullField(ex.ManagementMode.State))
	})
}

func TestFirewallAiSecurityAddOn(t *testing.T) {
	decode := func(t *testing.T, raw string) *mqlAzureSubscriptionNetworkServiceFirewall {
		t.Helper()
		fw := network.AzureFirewall{}
		require.NoError(t, json.Unmarshal([]byte(raw), &fw))
		res, err := azureFirewallToMql(sdkRefreshTestRuntime(), fw)
		require.NoError(t, err)
		return res
	}

	on := decode(t, `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw1","name":"fw1","properties":{"aiSecurityAddOn":true}}`)
	assert.True(t, on.AiSecurityAddOn.Data)
	assert.False(t, isNullField(on.AiSecurityAddOn.State))

	off := decode(t, `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw2","name":"fw2","properties":{"aiSecurityAddOn":false}}`)
	assert.False(t, off.AiSecurityAddOn.Data)
	assert.False(t, isNullField(off.AiSecurityAddOn.State))

	absent := decode(t, `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw3","name":"fw3","properties":{}}`)
	assert.True(t, isNullField(absent.AiSecurityAddOn.State))
}

func TestContainerAppAllowScalingRuleOverride(t *testing.T) {
	decode := func(t *testing.T, raw string) *mqlAzureSubscriptionContainerAppServiceContainerApp {
		t.Helper()
		app := apps.ContainerApp{}
		require.NoError(t, json.Unmarshal([]byte(raw), &app))
		res, err := acaContainerAppToMQL(sdkRefreshTestRuntime(), &app)
		require.NoError(t, err)
		return res.(*mqlAzureSubscriptionContainerAppServiceContainerApp)
	}

	set := decode(t, `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/containerApps/fa","name":"fa","kind":"functionapp",
		"properties":{"template":{"scale":{"minReplicas":0,"maxReplicas":5,"allowScalingRuleOverride":true}}}}`)
	assert.True(t, set.AllowScalingRuleOverride.Data)
	assert.False(t, isNullField(set.AllowScalingRuleOverride.State))

	unset := decode(t, `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/containerApps/web","name":"web",
		"properties":{"template":{"scale":{"minReplicas":1}}}}`)
	assert.True(t, isNullField(unset.AllowScalingRuleOverride.State))
}

func TestContainerAppJobRunningState(t *testing.T) {
	decode := func(t *testing.T, raw string) *mqlAzureSubscriptionContainerAppServiceJob {
		t.Helper()
		job := apps.Job{}
		require.NoError(t, json.Unmarshal([]byte(raw), &job))
		res, err := acaJobToMQL(sdkRefreshTestRuntime(), &job)
		require.NoError(t, err)
		return res
	}

	suspended := decode(t, `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/j1","name":"j1",
		"properties":{"provisioningState":"Succeeded","runningState":"Suspended","configuration":{"triggerType":"Schedule"}}}`)
	assert.Equal(t, "Suspended", suspended.RunningState.Data)
	assert.Equal(t, "Schedule", suspended.TriggerType.Data)

	unreported := decode(t, `{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/j2","name":"j2","properties":{}}`)
	assert.True(t, isNullField(unreported.RunningState.State))
}
