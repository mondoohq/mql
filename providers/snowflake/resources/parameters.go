// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// mqlSnowflakeAccountInternal caches the account-wide responses that several
// fields share, so touching more than one of them does not reissue the same
// statement. The account resource is a singleton, which makes it the one place
// every other resource can reach a per-scan cache from.
//
// SHOW PARAMETERS backs parameters and networkPolicy. The grant cache and the
// role and user name indexes back the role hierarchy walks; see role_graph.go.
// The database, schema, and warehouse indexes back the references other
// resources hold to those objects; see object_index.go.
type mqlSnowflakeAccountInternal struct {
	parametersOnce      sync.Once
	cachedParameters    []*sdk.Parameter
	cachedParametersErr error

	grantCacheOnce sync.Once
	cachedGrants   *snowflakeGrantCache

	roleIndexOnce      sync.Once
	cachedRoleIndex    map[string]sdk.Role
	cachedRoleIndexErr error

	userIndexOnce      sync.Once
	cachedUserIndex    map[string]sdk.User
	cachedUserIndexErr error

	keySetIndex keySetIndex

	cachedDatabaseIndex  memoIndex[sdk.Database]
	cachedSchemaIndex    memoIndex[sdk.Schema]
	cachedWarehouseIndex memoIndex[sdk.Warehouse]

	cachedNetworkPolicyIndex memoIndex[*mqlSnowflakeNetworkPolicy]
	cachedNetworkRuleIndex   memoIndex[*mqlSnowflakeNetworkRule]
	cachedSecretIndex        memoIndex[*mqlSnowflakeSecret]

	policyAttachmentsOnce      sync.Once
	cachedPolicyAttachments    *policyAttachments
	cachedPolicyAttachmentsErr error
}

// showAccountParameters fetches the account-level parameters from Snowflake,
// memoizing the result on the resource. Both parameters() and networkPolicy()
// route through here, so touching either (or both) on the same account hits the
// Snowflake API at most once.
func (r *mqlSnowflakeAccount) showAccountParameters() ([]*sdk.Parameter, error) {
	r.parametersOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		client := conn.Client()
		ctx := context.Background()

		r.cachedParameters, r.cachedParametersErr = client.Parameters.ShowParameters(ctx, &sdk.ShowParametersOptions{
			In: &sdk.ParametersIn{
				Account: new(true),
			},
		})
	})
	return r.cachedParameters, r.cachedParametersErr
}

// findParameterValue returns the value of the parameter whose key matches the
// given key (case-insensitively), or an empty string when no such parameter is
// present.
func findParameterValue(parameters []*sdk.Parameter, key string) string {
	for _, p := range parameters {
		if p == nil {
			continue
		}
		if strings.EqualFold(p.Key, key) {
			return p.Value
		}
	}
	return ""
}

func (r *mqlSnowflakeAccount) parameters() ([]any, error) {
	parameters, err := r.showAccountParameters()
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range parameters {
		mqlResource, err := newMqlSnowflakeParameter(r.MqlRuntime, "account", parameters[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlResource)
	}

	return list, nil
}

func (r *mqlSnowflakeAccount) networkPolicy() (string, error) {
	parameters, err := r.showAccountParameters()
	if err != nil {
		return "", err
	}
	return findParameterValue(parameters, "NETWORK_POLICY"), nil
}

func (r *mqlSnowflakeAccount) cortexEnabledCrossRegion() (string, error) {
	parameters, err := r.showAccountParameters()
	if err != nil {
		return "", err
	}
	return findParameterValue(parameters, "CORTEX_ENABLED_CROSS_REGION"), nil
}

// newMqlSnowflakeParameter builds a parameter resource. scope qualifies the
// cache key so identically-named parameters at different scopes (account vs a
// given user) do not collide: the same key (e.g. TIMEZONE) exists at the
// account level and on every user, and a bare-key __id would make every user's
// parameters resolve to the first-seen instance.
func newMqlSnowflakeParameter(runtime *plugin.Runtime, scope string, parameter *sdk.Parameter) (*mqlSnowflakeParameter, error) {
	r, err := CreateResource(runtime, "snowflake.parameter", map[string]*llx.RawData{
		"__id":         llx.StringData(scope + "/" + parameter.Key),
		"key":          llx.StringData(parameter.Key),
		"value":        llx.StringData(parameter.Value),
		"description":  llx.StringData(parameter.Description),
		"defaultValue": llx.StringData(parameter.Default),
		"level":        llx.StringData(string(parameter.Level)),
	})
	if err != nil {
		return nil, err
	}
	mqlResource := r.(*mqlSnowflakeParameter)
	return mqlResource, nil
}
