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

type mqlSnowflakeDynamicTableInternal struct {
	cacheOwner     string
	cacheWarehouse string
}

func (r *mqlSnowflakeAccount) dynamicTables() ([]any, error) {
	return listSnowflakeDynamicTables(r.MqlRuntime, &sdk.In{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) dynamicTables() ([]any, error) {
	return listSnowflakeDynamicTables(r.MqlRuntime, &sdk.In{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeDynamicTables fetches dynamic tables within the given scope
// (account-wide or a single database) and maps them to resources.
func listSnowflakeDynamicTables(runtime *plugin.Runtime, in *sdk.In) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	tables, err := conn.Client().DynamicTables.Show(context.Background(),
		sdk.NewShowDynamicTableRequest().WithIn(*in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(tables))
	for i := range tables {
		mqlTable, err := newMqlSnowflakeDynamicTable(runtime, tables[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlTable)
	}
	return list, nil
}

func newMqlSnowflakeDynamicTable(runtime *plugin.Runtime, table sdk.DynamicTable) (*mqlSnowflakeDynamicTable, error) {
	r, err := CreateResource(runtime, "snowflake.dynamicTable", map[string]*llx.RawData{
		"__id":                llx.StringData(snowflakeSchemaObjectID(table.DatabaseName, table.SchemaName, table.Name)),
		"name":                llx.StringData(table.Name),
		"databaseName":        llx.StringData(table.DatabaseName),
		"schemaName":          llx.StringData(table.SchemaName),
		"ownerRoleType":       llx.StringData(table.OwnerRoleType),
		"text":                llx.StringData(table.Text),
		"targetLag":           llx.StringData(table.TargetLag),
		"refreshMode":         llx.StringData(string(table.RefreshMode)),
		"refreshModeReason":   llx.StringData(table.RefreshModeReason),
		"schedulingState":     llx.StringData(string(table.SchedulingState)),
		"rows":                llx.IntData(int64(table.Rows)),
		"bytes":               llx.IntData(int64(table.Bytes)),
		"clusterBy":           llx.StringData(table.ClusterBy),
		"automaticClustering": llx.BoolData(table.AutomaticClustering),
		"isClone":             llx.BoolData(table.IsClone),
		"isReplica":           llx.BoolData(table.IsReplica),
		"lastSuspendedOn":     snowflakeTimePtr(table.LastSuspendedOn),
		"dataTimestamp":       snowflakeTimePtr(table.DataTimestamp),
		"comment":             llx.StringData(table.Comment),
		"createdAt":           snowflakeTime(table.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlTable := r.(*mqlSnowflakeDynamicTable)
	mqlTable.cacheOwner = table.Owner
	mqlTable.cacheWarehouse = table.Warehouse
	return mqlTable, nil
}

func (r *mqlSnowflakeDynamicTable) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeDynamicTable) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeDynamicTable) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

func (r *mqlSnowflakeDynamicTable) warehouse() (*mqlSnowflakeWarehouse, error) {
	return resolveWarehouseRef(r.MqlRuntime, r.cacheWarehouse, &r.Warehouse)
}
