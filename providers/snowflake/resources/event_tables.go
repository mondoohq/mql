// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeEventTableInternal struct {
	cacheOwner string
}

func (r *mqlSnowflakeAccount) eventTables() ([]any, error) {
	return listSnowflakeEventTables(r.MqlRuntime, sdk.In{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) eventTables() ([]any, error) {
	return listSnowflakeEventTables(r.MqlRuntime, sdk.In{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeEventTables fetches event tables within the given scope
// (account-wide or a single database) and maps them to resources.
func listSnowflakeEventTables(runtime *plugin.Runtime, in sdk.In) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	tables, err := conn.Client().EventTables.Show(context.Background(),
		sdk.NewShowEventTableRequest().WithIn(in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(tables))
	for i := range tables {
		mqlTable, err := newMqlSnowflakeEventTable(runtime, tables[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlTable)
	}
	return list, nil
}

func newMqlSnowflakeEventTable(runtime *plugin.Runtime, table sdk.EventTable) (*mqlSnowflakeEventTable, error) {
	r, err := CreateResource(runtime, "snowflake.eventTable", map[string]*llx.RawData{
		"__id":          llx.StringData(snowflakeSchemaObjectID(table.DatabaseName, table.SchemaName, table.Name)),
		"name":          llx.StringData(table.Name),
		"databaseName":  llx.StringData(table.DatabaseName),
		"schemaName":    llx.StringData(table.SchemaName),
		"ownerRoleType": llx.StringData(table.OwnerRoleType),
		"comment":       llx.StringData(table.Comment),
		"createdAt":     snowflakeTime(table.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlTable := r.(*mqlSnowflakeEventTable)
	mqlTable.cacheOwner = table.Owner
	return mqlTable, nil
}

func (r *mqlSnowflakeEventTable) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeEventTable) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeEventTable) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}
