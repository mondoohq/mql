// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
	"go.mondoo.com/mql/types"
)

type mqlSnowflakeFailoverGroupInternal struct {
	id         sdk.AccountObjectIdentifier
	cacheOwner string
}

func (r *mqlSnowflakeAccount) failoverGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	groups, err := conn.Client().FailoverGroups.Show(context.Background(), &sdk.ShowFailoverGroupRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(groups))
	for i := range groups {
		mqlGroup, err := newMqlSnowflakeFailoverGroup(r.MqlRuntime, groups[i])
		if err != nil {
			return nil, err
		}
		out = append(out, mqlGroup)
	}
	return out, nil
}

func newMqlSnowflakeFailoverGroup(runtime *plugin.Runtime, g sdk.FailoverGroup) (*mqlSnowflakeFailoverGroup, error) {
	objectTypes := make([]any, 0, len(g.ObjectTypes))
	for _, ot := range g.ObjectTypes {
		objectTypes = append(objectTypes, string(ot))
	}
	integrationTypes := make([]any, 0, len(g.AllowedIntegrationTypes))
	for _, it := range g.AllowedIntegrationTypes {
		integrationTypes = append(integrationTypes, string(it))
	}
	accounts := make([]any, 0, len(g.AllowedAccounts))
	for _, a := range g.AllowedAccounts {
		accounts = append(accounts, a.FullyQualifiedName())
	}

	// SHOW FAILOVER GROUPS returns an empty primary column for the primary group
	// itself (a primary doesn't reference another primary). The SDK still constructs
	// an ExternalObjectIdentifier from the empty string, whose FullyQualifiedName()
	// renders as "." — guard against that misleading value.
	primary := ""
	if !g.IsPrimary && g.Primary.Name() != "" {
		primary = g.Primary.FullyQualifiedName()
	}

	r, err := CreateResource(runtime, "snowflake.failoverGroup", map[string]*llx.RawData{
		"__id":                    llx.StringData(g.ID().FullyQualifiedName()),
		"name":                    llx.StringData(g.Name),
		"type":                    llx.StringData(g.Type),
		"isPrimary":               llx.BoolData(g.IsPrimary),
		"primary":                 llx.StringData(primary),
		"objectTypes":             llx.ArrayData(objectTypes, types.String),
		"allowedIntegrationTypes": llx.ArrayData(integrationTypes, types.String),
		"allowedAccounts":         llx.ArrayData(accounts, types.String),
		"replicationSchedule":     llx.StringData(g.ReplicationSchedule),
		"secondaryState":          llx.StringData(string(g.SecondaryState)),
		"nextScheduledRefresh":    llx.StringData(g.NextScheduledRefresh),
		"regionGroup":             llx.StringData(g.RegionGroup),
		"snowflakeRegion":         llx.StringData(g.SnowflakeRegion),
		"comment":                 llx.StringData(g.Comment),
		"createdAt":               llx.TimeData(g.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlGroup := r.(*mqlSnowflakeFailoverGroup)
	mqlGroup.id = g.ID()
	mqlGroup.cacheOwner = g.Owner
	return mqlGroup, nil
}

func (r *mqlSnowflakeFailoverGroup) databases() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	ids, err := conn.Client().FailoverGroups.ShowDatabases(context.Background(), r.id)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.FullyQualifiedName())
	}
	return out, nil
}

func (r *mqlSnowflakeFailoverGroup) shares() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	ids, err := conn.Client().FailoverGroups.ShowShares(context.Background(), r.id)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.FullyQualifiedName())
	}
	return out, nil
}

func (r *mqlSnowflakeFailoverGroup) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}
