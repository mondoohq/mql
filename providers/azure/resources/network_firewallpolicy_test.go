// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func int32Ptr(i int32) *int32 { return &i }

// TestFirewallPolicyRuleCollectionsDict guards the assumption that
// firewallPolicy.ruleCollectionGroups relies on: converting the polymorphic
// []FirewallPolicyRuleCollectionClassification slice through JsonToDictSlice
// preserves the rule-collection discriminator (ruleCollectionType), the
// collection's action/priority/name, and the nested rules with their own
// ruleType discriminator and per-type fields. If the SDK's MarshalJSON ever
// stops emitting those, the ruleCollections dict silently loses its shape.
func TestFirewallPolicyRuleCollectionsDict(t *testing.T) {
	filterAction := network.FirewallPolicyFilterRuleCollectionActionTypeAllow
	httpsProto := network.FirewallPolicyRuleApplicationProtocolTypeHTTPS

	collections := []network.FirewallPolicyRuleCollectionClassification{
		&network.FirewallPolicyFilterRuleCollection{
			Name:     strPtr("allow-web"),
			Priority: int32Ptr(200),
			Action: &network.FirewallPolicyFilterRuleCollectionAction{
				Type: &filterAction,
			},
			Rules: []network.FirewallPolicyRuleClassification{
				&network.ApplicationRule{
					Name:            strPtr("allow-github"),
					SourceAddresses: []*string{strPtr("10.0.0.0/8")},
					TargetFqdns:     []*string{strPtr("github.com")},
					Protocols: []*network.FirewallPolicyRuleApplicationProtocol{
						{ProtocolType: &httpsProto, Port: int32Ptr(443)},
					},
				},
			},
		},
	}

	dicts, err := convert.JsonToDictSlice(collections)
	require.NoError(t, err)
	require.Len(t, dicts, 1)

	rc, ok := dicts[0].(map[string]any)
	require.True(t, ok, "rule collection should serialize to an object")

	// the collection discriminator and its scalars survive
	assert.Equal(t, "FirewallPolicyFilterRuleCollection", rc["ruleCollectionType"])
	assert.Equal(t, "allow-web", rc["name"])
	assert.Equal(t, float64(200), rc["priority"])

	action, ok := rc["action"].(map[string]any)
	require.True(t, ok, "filter collection action should be an object")
	assert.Equal(t, "Allow", action["type"])

	rules, ok := rc["rules"].([]any)
	require.True(t, ok, "rule collection should carry a rules list")
	require.Len(t, rules, 1)

	rule, ok := rules[0].(map[string]any)
	require.True(t, ok)
	// the nested rule keeps its own ruleType discriminator and app-rule fields
	assert.Equal(t, "ApplicationRule", rule["ruleType"])
	assert.Equal(t, "allow-github", rule["name"])
	assert.Equal(t, []any{"github.com"}, rule["targetFqdns"])
	assert.Equal(t, []any{"10.0.0.0/8"}, rule["sourceAddresses"])

	protocols, ok := rule["protocols"].([]any)
	require.True(t, ok)
	require.Len(t, protocols, 1)
	proto, ok := protocols[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Https", proto["protocolType"])
	assert.Equal(t, float64(443), proto["port"])
}
