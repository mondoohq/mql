// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeSessionPolicyInternal struct {
	descLock          sync.Mutex
	descLoaded        bool
	descLoadErr       error
	descIdleTimeout   int64
	descUiIdleTimeout int64
	refsMemo          policyReferenceMemo
}

func (r *mqlSnowflakeAccount) sessionPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	policies, err := client.SessionPolicies.Show(ctx, sdk.NewShowSessionPolicyRequest())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range policies {
		mqlPolicy, err := newMqlSnowflakeSessionPolicy(r.MqlRuntime, policies[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlPolicy)
	}

	return list, nil
}

func newMqlSnowflakeSessionPolicy(runtime *plugin.Runtime, policy sdk.SessionPolicy) (*mqlSnowflakeSessionPolicy, error) {
	r, err := CreateResource(runtime, "snowflake.sessionPolicy", map[string]*llx.RawData{
		"__id":          llx.StringData(policy.ID().FullyQualifiedName()),
		"name":          llx.StringData(policy.Name),
		"databaseName":  llx.StringData(policy.DatabaseName),
		"schemaName":    llx.StringData(policy.SchemaName),
		"kind":          llx.StringData(policy.Kind),
		"owner":         llx.StringData(policy.Owner),
		"ownerRoleType": llx.StringData(policy.OwnerRoleType),
		"comment":       llx.StringData(policy.Comment),
		"options":       llx.StringData(policy.Options),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeSessionPolicy), nil
}

func (r *mqlSnowflakeSessionPolicy) gatherSessionPolicyDetails() error {
	if r.descLoaded {
		return r.descLoadErr
	}
	r.descLock.Lock()
	defer r.descLock.Unlock()
	if r.descLoaded {
		return r.descLoadErr
	}

	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	// The SDK's typed Describe expects horizontal columns, but Snowflake returns
	// DESCRIBE SESSION POLICY as a vertical property/value table, so the typed
	// timeout fields come back zero. Read the raw rows and parse them here.
	// FullyQualifiedName double-quotes each identifier component (`"db"."schema"."name"`),
	// and the components originate from Snowflake's own SHOW output, so the
	// interpolation into the QueryUnsafe statement is a properly quoted identifier.
	id := sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
	rows, err := client.QueryUnsafe(ctx, fmt.Sprintf("DESCRIBE SESSION POLICY %s", id.FullyQualifiedName()))
	if err != nil {
		r.descLoaded = true
		r.descLoadErr = err
		return err
	}

	props := sessionPolicyDescribeProps(rows)
	r.descIdleTimeout = parseSnowflakeInt(props["SESSION_IDLE_TIMEOUT_MINS"])
	r.descUiIdleTimeout = parseSnowflakeInt(props["SESSION_UI_IDLE_TIMEOUT_MINS"])
	r.descLoaded = true
	return nil
}

// sessionPolicyDescribeProps flattens DESCRIBE SESSION POLICY rows (each a
// property/value pair) into a property-keyed map. Column names are matched
// case-insensitively since the driver may return them in either case.
func sessionPolicyDescribeProps(rows []map[string]*any) map[string]string {
	props := map[string]string{}
	for _, row := range rows {
		var property, value string
		for k, v := range row {
			switch strings.ToLower(k) {
			case "property":
				property = unsafeCellString(v)
			case "value":
				value = unsafeCellString(v)
			}
		}
		if property != "" {
			props[property] = value
		}
	}
	return props
}

// unsafeCellString renders a QueryUnsafe cell (a *any) as a trimmed string.
func unsafeCellString(v *any) string {
	if v == nil || *v == nil {
		return ""
	}
	if s, ok := (*v).(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprintf("%v", *v))
}

// parseSnowflakeInt parses a Snowflake integer property value, returning 0 for
// empty or non-numeric input.
func parseSnowflakeInt(value string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (r *mqlSnowflakeSessionPolicy) sessionIdleTimeoutMins() (int64, error) {
	if err := r.gatherSessionPolicyDetails(); err != nil {
		return 0, err
	}
	return r.descIdleTimeout, nil
}

func (r *mqlSnowflakeSessionPolicy) sessionUiIdleTimeoutMins() (int64, error) {
	if err := r.gatherSessionPolicyDetails(); err != nil {
		return 0, err
	}
	return r.descUiIdleTimeout, nil
}
