// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/search/armsearch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/llx"
)

const testNspConfigID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai/networkSecurityPerimeterConfigurations/perimeter1.assoc1"

func TestNspConfigurationArgsFromCognitiveServices(t *testing.T) {
	// Synthetic: an enforced association with one inbound rule and one issue; no target showed this.
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	cfg := &armcognitiveservices.NetworkSecurityPerimeterConfiguration{
		ID:   to.Ptr(testNspConfigID),
		Name: to.Ptr("perimeter1.assoc1"),
		Type: to.Ptr("Microsoft.CognitiveServices/accounts/networkSecurityPerimeterConfigurations"),
		SystemData: &armcognitiveservices.SystemData{
			CreatedBy: to.Ptr("admin@example.com"),
			CreatedAt: &created,
		},
		Properties: &armcognitiveservices.NetworkSecurityPerimeterConfigurationProperties{
			NetworkSecurityPerimeter: &armcognitiveservices.NetworkSecurityPerimeter{
				ID:            to.Ptr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityPerimeters/perimeter1"),
				Location:      to.Ptr("eastus"),
				PerimeterGUID: to.Ptr("00000000-0000-0000-0000-000000000001"),
			},
			Profile: &armcognitiveservices.NetworkSecurityPerimeterProfileInfo{
				Name:                      to.Ptr("defaultProfile"),
				AccessRulesVersion:        to.Ptr[int64](3),
				DiagnosticSettingsVersion: to.Ptr[int64](1),
				EnabledLogCategories:      []*string{to.Ptr("NspPublicInboundPerimeterRulesDenied")},
				AccessRules: []*armcognitiveservices.NetworkSecurityPerimeterAccessRule{{
					Name: to.Ptr("allow-office"),
					Properties: &armcognitiveservices.NetworkSecurityPerimeterAccessRuleProperties{
						Direction:       to.Ptr(armcognitiveservices.NspAccessRuleDirectionInbound),
						AddressPrefixes: []*string{to.Ptr("203.0.113.0/24")},
					},
				}},
			},
			ResourceAssociation: &armcognitiveservices.NetworkSecurityPerimeterConfigurationAssociationInfo{
				Name:       to.Ptr("assoc1"),
				AccessMode: to.Ptr("Enforced"),
			},
			ProvisioningIssues: []*armcognitiveservices.ProvisioningIssue{{
				Name: to.Ptr("issue1"),
				Properties: &armcognitiveservices.ProvisioningIssueProperties{
					IssueType: to.Ptr("ConfigurationPropagationFailure"),
					Severity:  to.Ptr("Error"),
				},
			}},
			ProvisioningState: to.Ptr("Succeeded"),
		},
	}

	rec, err := decodeNspConfiguration(cfg)
	require.NoError(t, err)
	args := nspConfigurationArgs(rec)

	assert.Equal(t, testNspConfigID, args["id"].Value)
	assert.Equal(t, "Succeeded", args["provisioningState"].Value)
	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityPerimeters/perimeter1", args["perimeterId"].Value)
	assert.Equal(t, "eastus", args["perimeterLocation"].Value)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", args["perimeterGuid"].Value)
	assert.Equal(t, "defaultProfile", args["profileName"].Value)
	assert.Equal(t, int64(3), args["accessRulesVersion"].Value)
	assert.Equal(t, int64(1), args["diagnosticSettingsVersion"].Value)
	assert.Equal(t, []any{"NspPublicInboundPerimeterRulesDenied"}, args["enabledLogCategories"].Value)
	assert.Equal(t, "assoc1", args["associationName"].Value)
	assert.Equal(t, "Enforced", args["associationAccessMode"].Value)

	rules := args["accessRules"].Value.([]any)
	require.Len(t, rules, 1)
	rule := rules[0].(map[string]any)
	// properties are flattened into the rule, matching the storage and
	// monitor configurations.
	assert.Equal(t, "allow-office", rule["name"])
	assert.Equal(t, "Inbound", rule["direction"])
	assert.Equal(t, []any{"203.0.113.0/24"}, rule["addressPrefixes"])
	assert.NotContains(t, rule, "properties")

	issues := args["provisioningIssues"].Value.([]any)
	require.Len(t, issues, 1)
	issue := issues[0].(map[string]any)
	assert.Equal(t, "ConfigurationPropagationFailure", issue["issueType"])
	assert.Equal(t, "Error", issue["severity"])

	assert.Equal(t, "admin@example.com", rec.SystemData["createdBy"])
}

func TestNspConfigurationArgsFromSearch(t *testing.T) {
	// Synthetic: a learning-mode association on a search service; no target showed this.
	cfg := &armsearch.NetworkSecurityPerimeterConfiguration{
		ID: to.Ptr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Search/searchServices/srch/networkSecurityPerimeterConfigurations/p.a"),
		Properties: &armsearch.NetworkSecurityPerimeterConfigurationProperties{
			Profile: &armsearch.NetworkSecurityProfile{
				AccessRules: []*armsearch.AccessRule{{
					Name: to.Ptr("to-mail"),
					Properties: &armsearch.AccessRuleProperties{
						Direction:      to.Ptr(armsearch.AccessRuleDirectionOutbound),
						EmailAddresses: []*string{to.Ptr("soc@example.com")},
					},
				}},
			},
			ResourceAssociation: &armsearch.ResourceAssociation{
				AccessMode: to.Ptr(armsearch.ResourceAssociationAccessModeLearning),
			},
			ProvisioningState: to.Ptr(armsearch.NetworkSecurityPerimeterConfigurationProvisioningStateSucceeded),
		},
	}
	rec, err := decodeNspConfiguration(cfg)
	require.NoError(t, err)
	args := nspConfigurationArgs(rec)

	assert.Equal(t, "Learning", args["associationAccessMode"].Value)
	assert.Equal(t, "Succeeded", args["provisioningState"].Value)
	rule := args["accessRules"].Value.([]any)[0].(map[string]any)
	assert.Equal(t, "Outbound", rule["direction"])
	assert.Equal(t, []any{"soc@example.com"}, rule["emailAddresses"])
	// No perimeter block was sent: these are unknown, not empty.
	assert.Nil(t, args["perimeterId"].Value)
	assert.Nil(t, args["associationName"].Value)
	assert.Nil(t, args["accessRulesVersion"].Value)
}

func TestNspConfigurationArgsWithoutProperties(t *testing.T) {
	// Synthetic: an entry with no properties object; no target showed this.
	rec, err := decodeNspConfiguration(&armcognitiveservices.NetworkSecurityPerimeterConfiguration{ID: to.Ptr(testNspConfigID)})
	require.NoError(t, err)
	args := nspConfigurationArgs(rec)
	assert.Nil(t, args["provisioningState"].Value)
	assert.Nil(t, args["associationAccessMode"].Value)
	assert.Equal(t, []any{}, args["accessRules"].Value)
	assert.Equal(t, []any{}, args["provisioningIssues"].Value)
}

func TestNspConfigurationsToMqlSkipsEntriesWithoutID(t *testing.T) {
	runtime := cacheIDTestRuntime()
	// Synthetic: a nil entry and an id-less entry around a valid one; no target showed this.
	res, err := nspConfigurationsToMql(runtime, []*armcognitiveservices.NetworkSecurityPerimeterConfiguration{
		nil,
		{Name: to.Ptr("no-id")},
		{ID: to.Ptr(testNspConfigID), Name: to.Ptr("perimeter1.assoc1")},
	})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "perimeter1.assoc1", res[0].(*mqlAzureSubscriptionNetworkSecurityPerimeterConfiguration).Name.Data)
}

func TestNspConfigurationsFailure(t *testing.T) {
	const perm = "Microsoft.CognitiveServices/accounts/networkSecurityPerimeterConfigurations/read"
	notFound := func() error {
		return armError(http.StatusNotFound, `{"error":{"code":"ResourceNotFound","message":"not found"}}`)
	}
	forbidden := func() error {
		return armError(http.StatusForbidden, `{"error":{"code":"AuthorizationFailed","message":"does not have authorization"}}`)
	}

	t.Run("without structured errors an unsupported resource is an empty list", func(t *testing.T) {
		setStructuredErrors(t, false)
		res, err := nspConfigurationsFailure(notFound(), "account", perm)
		require.NoError(t, err)
		assert.Equal(t, []any{}, res)
	})

	t.Run("with structured errors an unsupported resource is NotApplicable", func(t *testing.T) {
		setStructuredErrors(t, true)
		_, err := nspConfigurationsFailure(notFound(), "account", perm)
		assert.True(t, errors.Is(err, llx.ErrNotApplicable))
	})

	t.Run("a refusal is never an empty list", func(t *testing.T) {
		setStructuredErrors(t, false)
		res, err := nspConfigurationsFailure(forbidden(), "account", perm)
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("with structured errors a refusal is Forbidden", func(t *testing.T) {
		setStructuredErrors(t, true)
		_, err := nspConfigurationsFailure(forbidden(), "account", perm)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
	})
}
