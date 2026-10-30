// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"strings"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

func (r *mqlSnowflakeAccount) networkPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	account := r.GetAccountId()
	networkPolicies, err := client.NetworkPolicies.Show(ctx, &sdk.ShowNetworkPolicyRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range networkPolicies {
		mqlNetworkPolicy, err := newMqlSnowflakeNetworkPolicy(r.MqlRuntime, networkPolicies[i])
		if err != nil {
			return nil, err
		}

		mqlNetworkPolicy.account = account.Data

		list = append(list, mqlNetworkPolicy)
	}

	return list, nil
}

type mqlSnowflakeNetworkPolicyInternal struct {
	account string
}

func newMqlSnowflakeNetworkPolicy(runtime *plugin.Runtime, networkPolicy sdk.NetworkPolicy) (*mqlSnowflakeNetworkPolicy, error) {
	createdAt := snowflakeTime(networkPolicy.CreatedOn)

	r, err := CreateResource(runtime, "snowflake.networkPolicy", map[string]*llx.RawData{
		"__id":                         llx.StringData(networkPolicy.Name),
		"name":                         llx.StringData(networkPolicy.Name),
		"entriesInAllowedIpList":       llx.IntData(networkPolicy.EntriesInAllowedIpList),
		"entriesInBlockedIpList":       llx.IntData(networkPolicy.EntriesInBlockedIpList),
		"entriesInAllowedNetworkRules": llx.IntData(networkPolicy.EntriesInAllowedNetworkRules),
		"entriesInBlockedNetworkRules": llx.IntData(networkPolicy.EntriesInBlockedNetworkRules),
		"comment":                      llx.StringData(networkPolicy.Comment),
		"createdAt":                    createdAt,
	})
	if err != nil {
		return nil, err
	}
	mqlResource := r.(*mqlSnowflakeNetworkPolicy)
	return mqlResource, nil
}

// NetworkRulesSnowflakeDTO is needed to unpack the applied network rules from the JSON response from Snowflake
type NetworkRulesSnowflakeDTO struct {
	FullyQualifiedRuleName string
}

func (r *mqlSnowflakeNetworkPolicy) gatherNetworkPolicyDetails() error {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	networkDescriptions, err := client.NetworkPolicies.Describe(ctx, sdk.NewAccountObjectIdentifier(r.Name.Data))
	if err != nil {
		return err
	}

	// set default values
	r.AllowedIpList = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.BlockedIpList = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.AllowedNetworkRules = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.BlockedNetworkRules = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}

	for _, desc := range networkDescriptions {
		switch desc.Name {
		case "ALLOWED_IP_LIST":
			ipList := strings.Split(desc.Value, ",")
			r.AllowedIpList = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(ipList), Error: nil, State: plugin.StateIsSet}
		case "BLOCKED_IP_LIST":
			ipList := strings.Split(desc.Value, ",")
			r.BlockedIpList = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(ipList), Error: nil, State: plugin.StateIsSet}
		case "ALLOWED_NETWORK_RULE_LIST":
			var networkRules []NetworkRulesSnowflakeDTO
			err := json.Unmarshal([]byte(desc.Value), &networkRules)
			if err != nil {
				return err
			}
			networkRulesFullyQualified := make([]string, len(networkRules))
			for i, ele := range networkRules {
				networkRulesFullyQualified[i] = sdk.NewSchemaObjectIdentifierFromFullyQualifiedName(ele.FullyQualifiedRuleName).FullyQualifiedName()
			}
			r.AllowedNetworkRules = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(networkRulesFullyQualified), Error: nil, State: plugin.StateIsSet}
		case "BLOCKED_NETWORK_RULE_LIST":
			var networkRules []NetworkRulesSnowflakeDTO
			err := json.Unmarshal([]byte(desc.Value), &networkRules)
			if err != nil {
				return err
			}
			networkRulesFullyQualified := make([]string, len(networkRules))
			for i, ele := range networkRules {
				networkRulesFullyQualified[i] = sdk.NewSchemaObjectIdentifierFromFullyQualifiedName(ele.FullyQualifiedRuleName).FullyQualifiedName()
			}
			r.BlockedNetworkRules = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(networkRulesFullyQualified), Error: nil, State: plugin.StateIsSet}
		}
	}
	return nil
}

func (r *mqlSnowflakeNetworkPolicy) allowedIpList() ([]any, error) {
	return nil, r.gatherNetworkPolicyDetails()
}

func (r *mqlSnowflakeNetworkPolicy) blockedIpList() ([]any, error) {
	return nil, r.gatherNetworkPolicyDetails()
}

func (r *mqlSnowflakeNetworkPolicy) allowedNetworkRules() ([]any, error) {
	return nil, r.gatherNetworkPolicyDetails()
}

func (r *mqlSnowflakeNetworkPolicy) blockedNetworkRules() ([]any, error) {
	return nil, r.gatherNetworkPolicyDetails()
}
