// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeNetworkRuleInternal struct {
	valuesLock    sync.Mutex
	valuesLoaded  bool
	valuesLoadErr error
	valuesDenied  bool
	values        []any
}

func (r *mqlSnowflakeAccount) networkRules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	rules, err := client.NetworkRules.Show(ctx, sdk.NewShowNetworkRuleRequest())
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(rules))
	for i := range rules {
		mqlRule, err := newMqlSnowflakeNetworkRule(r.MqlRuntime, rules[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlRule)
	}

	return list, nil
}

func newMqlSnowflakeNetworkRule(runtime *plugin.Runtime, rule sdk.NetworkRule) (*mqlSnowflakeNetworkRule, error) {
	r, err := CreateResource(runtime, "snowflake.networkRule", map[string]*llx.RawData{
		"__id":               llx.StringData(rule.ID().FullyQualifiedName()),
		"name":               llx.StringData(rule.Name),
		"databaseName":       llx.StringData(rule.DatabaseName),
		"schemaName":         llx.StringData(rule.SchemaName),
		"owner":              llx.StringData(rule.Owner),
		"ownerRoleType":      llx.StringData(rule.OwnerRoleType),
		"comment":            llx.StringData(rule.Comment),
		"type":               llx.StringData(string(rule.Type)),
		"mode":               llx.StringData(string(rule.Mode)),
		"entriesInValueList": llx.IntData(rule.EntriesInValueList),
		"createdAt":          llx.TimeData(rule.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeNetworkRule), nil
}

func (r *mqlSnowflakeNetworkRule) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeNetworkRule) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

// markValuesNull records that the value list was not readable. A list accessor
// returning (nil, nil) alone renders as an empty array, so the null state has to
// be set explicitly for the field to read as unknown.
func (r *mqlSnowflakeNetworkRule) markValuesNull() {
	r.ValueList.State = plugin.StateIsSet | plugin.StateIsNull
}

func (r *mqlSnowflakeNetworkRule) valueList() ([]any, error) {
	if r.valuesLoaded {
		if r.valuesDenied {
			r.markValuesNull()
			return nil, nil
		}
		return r.values, r.valuesLoadErr
	}
	r.valuesLock.Lock()
	defer r.valuesLock.Unlock()
	if r.valuesLoaded {
		if r.valuesDenied {
			r.markValuesNull()
			return nil, nil
		}
		return r.values, r.valuesLoadErr
	}

	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	details, err := client.NetworkRules.Describe(ctx,
		sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data),
	)
	if err != nil {
		r.valuesLoaded = true
		if isAccessDenied(err) {
			// DESCRIBE NETWORK RULE requires OWNERSHIP, which no role holds on
			// the rules Snowflake ships in SNOWFLAKE.EXTERNAL_ACCESS. Report
			// the values as unknown rather than failing the field, and never as
			// an empty list: empty would read as "this rule permits nothing",
			// the opposite of what an unreadable rule means, and would let a
			// check asserting no open value pass on a rule nobody has read.
			r.valuesDenied = true
			r.markValuesNull()
			log.Debug().
				Str("rule", r.Name.Data).
				Str("schema", r.SchemaName.Data).
				Str("database", r.DatabaseName.Data).
				Msg("snowflake: insufficient privileges to describe network rule, value list unavailable")
			return nil, nil
		}
		r.valuesLoadErr = err
		return nil, err
	}

	r.values = convert.SliceAnyToInterface(details.ValueList)
	r.valuesLoaded = true
	return r.values, nil
}
