// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// SHOW DATABASE ROLES returns CreatedOn as a string with no format documented by
// Snowflake. Observed formats include "2024-01-15 12:34:56.789 -0800" and
// RFC3339-style; try both and fall back to nil so MQL renders a null time.
func parseSnowflakeShowTimestamp(s string) *time.Time {
	if s == "" {
		return nil
	}
	layouts := []string{
		"2006-01-02 15:04:05.999999999 -0700",
		"2006-01-02 15:04:05.999999999 -0700 MST",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

func (r *mqlSnowflakeDatabase) roles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	dbID := sdk.NewAccountObjectIdentifier(r.Name.Data)

	roles, err := conn.Client().DatabaseRoles.Show(
		context.Background(),
		sdk.NewShowDatabaseRoleRequest().WithDatabase(dbID),
	)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(roles))
	for i := range roles {
		mqlRole, err := newMqlSnowflakeDatabaseRole(r.MqlRuntime, r.Name.Data, roles[i])
		if err != nil {
			return nil, err
		}
		out = append(out, mqlRole)
	}
	return out, nil
}

func newMqlSnowflakeDatabaseRole(runtime *plugin.Runtime, databaseName string, role sdk.DatabaseRole) (*mqlSnowflakeDatabaseRole, error) {
	// SHOW DATABASE ROLES does not populate DatabaseName on the row; backfill from caller.
	if role.DatabaseName == "" {
		role.DatabaseName = databaseName
	}

	r, err := CreateResource(runtime, "snowflake.databaseRole", map[string]*llx.RawData{
		"__id":                   llx.StringData(role.ID().FullyQualifiedName()),
		"name":                   llx.StringData(role.Name),
		"databaseName":           llx.StringData(role.DatabaseName),
		"owner":                  llx.StringData(role.Owner),
		"ownerRoleType":          llx.StringData(role.OwnerRoleType),
		"comment":                llx.StringData(role.Comment),
		"isCurrent":              llx.BoolData(role.IsCurrent),
		"isInherited":            llx.BoolData(role.IsInherited),
		"grantedToRoles":         llx.IntData(role.GrantedToRoles),
		"grantedToDatabaseRoles": llx.IntData(role.GrantedToDatabaseRoles),
		"grantedDatabaseRoles":   llx.IntData(role.GrantedDatabaseRoles),
		"createdAt":              llx.TimeDataPtr(parseSnowflakeShowTimestamp(role.CreatedOn)),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeDatabaseRole), nil
}
