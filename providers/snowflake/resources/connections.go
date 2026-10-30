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

func (r *mqlSnowflakeAccount) connections() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	connections, err := client.Connections.Show(ctx, sdk.NewShowConnectionRequest())
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(connections))
	for i := range connections {
		mqlConnection, err := newMqlSnowflakeConnection(r.MqlRuntime, connections[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlConnection)
	}

	return list, nil
}

func newMqlSnowflakeConnection(runtime *plugin.Runtime, c sdk.Connection) (*mqlSnowflakeConnection, error) {
	var primary string
	if c.IsPrimary {
		primary = c.ID().FullyQualifiedName()
	} else {
		primary = c.Primary.FullyQualifiedName()
	}

	failoverAccounts := make([]any, 0, len(c.FailoverAllowedToAccounts))
	for _, acc := range c.FailoverAllowedToAccounts {
		failoverAccounts = append(failoverAccounts, acc.FullyQualifiedName())
	}

	var comment string
	if c.Comment != nil {
		comment = *c.Comment
	}
	var regionGroup string
	if c.RegionGroup != nil {
		regionGroup = *c.RegionGroup
	}

	r, err := CreateResource(runtime, "snowflake.connection", map[string]*llx.RawData{
		"__id":                      llx.StringData(c.ID().FullyQualifiedName()),
		"name":                      llx.StringData(c.Name),
		"comment":                   llx.StringData(comment),
		"isPrimary":                 llx.BoolData(c.IsPrimary),
		"primary":                   llx.StringData(primary),
		"failoverAllowedToAccounts": llx.ArrayData(failoverAccounts, types.String),
		"snowflakeRegion":           llx.StringData(c.SnowflakeRegion),
		"regionGroup":               llx.StringData(regionGroup),
		"accountName":               llx.StringData(c.AccountName),
		"accountLocator":            llx.StringData(c.AccountLocator),
		"organizationName":          llx.StringData(c.OrganizationName),
		"connectionUrl":             llx.StringData(c.ConnectionUrl),
		"createdAt":                 llx.TimeData(c.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeConnection), nil
}
