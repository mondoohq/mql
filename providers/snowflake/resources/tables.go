// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeTableInternal struct {
	cacheOwner string
}

func (r *mqlSnowflakeAccount) tables() ([]any, error) {
	return listSnowflakeTables(r.MqlRuntime, sdk.ExtendedIn{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) tables() ([]any, error) {
	return listSnowflakeTables(r.MqlRuntime, sdk.ExtendedIn{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeTables fetches tables within the given scope (account-wide or a
// single database) and maps them to resources.
func listSnowflakeTables(runtime *plugin.Runtime, in sdk.ExtendedIn) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	tables, err := conn.Client().Tables.Show(context.Background(),
		sdk.NewShowTableRequest().WithIn(in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(tables))
	for i := range tables {
		mqlTable, err := newMqlSnowflakeTable(runtime, tables[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlTable)
	}
	return list, nil
}

func newMqlSnowflakeTable(runtime *plugin.Runtime, table sdk.Table) (*mqlSnowflakeTable, error) {
	droppedAt := llx.NilData
	if table.DroppedOn != nil {
		droppedAt = parseSnowflakeTime(*table.DroppedOn)
	}

	r, err := CreateResource(runtime, "snowflake.table", map[string]*llx.RawData{
		// Build the id from the raw name parts rather than the SDK's ID()
		// helper, which can panic on identifiers it fails to parse.
		"__id":                       llx.StringData(snowflakeSchemaObjectID(table.DatabaseName, table.SchemaName, table.Name)),
		"name":                       llx.StringData(table.Name),
		"databaseName":               llx.StringData(table.DatabaseName),
		"schemaName":                 llx.StringData(table.SchemaName),
		"ownerRoleType":              llx.StringData(table.OwnerRoleType),
		"kind":                       llx.StringData(table.Kind),
		"rows":                       llx.IntData(int64(table.Rows)),
		"bytes":                      llx.IntDataPtr(table.Bytes),
		"clusterBy":                  llx.StringData(table.ClusterBy),
		"retentionTime":              llx.IntData(int64(table.RetentionTime)),
		"automaticClustering":        llx.BoolData(table.AutomaticClustering),
		"changeTracking":             llx.BoolData(table.ChangeTracking),
		"searchOptimization":         llx.BoolData(table.SearchOptimization),
		"searchOptimizationProgress": llx.StringData(table.SearchOptimizationProgress),
		"searchOptimizationBytes":    llx.IntDataPtr(table.SearchOptimizationBytes),
		"isExternal":                 llx.BoolData(table.IsExternal),
		"enableSchemaEvolution":      llx.BoolData(table.EnableSchemaEvolution),
		"isEvent":                    llx.BoolData(table.IsEvent),
		"budget":                     llx.StringDataPtr(table.Budget),
		"comment":                    llx.StringData(table.Comment),
		"createdAt":                  parseSnowflakeTime(table.CreatedOn),
		"droppedAt":                  droppedAt,
	})
	if err != nil {
		return nil, err
	}
	mqlTable := r.(*mqlSnowflakeTable)
	mqlTable.cacheOwner = table.Owner
	return mqlTable, nil
}

func (r *mqlSnowflakeTable) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeTable) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeTable) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

// initSnowflakeTable resolves a table by its database, schema, and name so
// references from other resources (such as the source table of a materialized
// view) can hydrate a full table from just its identity.
func initSnowflakeTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}
	dbRaw, ok1 := args["databaseName"]
	schemaRaw, ok2 := args["schemaName"]
	nameRaw, ok3 := args["name"]
	if !ok1 || !ok2 || !ok3 {
		return args, nil, nil
	}
	databaseName, _ := dbRaw.Value.(string)
	schemaName, _ := schemaRaw.Value.(string)
	name, _ := nameRaw.Value.(string)
	if databaseName == "" || schemaName == "" || name == "" {
		return nil, nil, fmt.Errorf("snowflake.table requires a non-empty databaseName, schemaName, and name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	tables, err := conn.Client().Tables.Show(context.Background(), sdk.NewShowTableRequest().
		WithLike(sdk.Like{Pattern: new(name)}).
		WithIn(sdk.ExtendedIn{Schema: sdk.NewDatabaseObjectIdentifier(databaseName, schemaName)}))
	if err != nil {
		return nil, nil, err
	}
	for i := range tables {
		if tables[i].Name == name && tables[i].DatabaseName == databaseName && tables[i].SchemaName == schemaName {
			res, err := newMqlSnowflakeTable(runtime, tables[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("snowflake.table %q not found in %q.%q", name, databaseName, schemaName)
}

// resolveTableRefByFQN resolves a fully qualified table name (the form
// Snowflake reports in SHOW output, such as "DB"."SCHEMA"."TABLE") to its
// table. A name that cannot be parsed resolves to null rather than failing the
// surrounding query.
func resolveTableRefByFQN(runtime *plugin.Runtime, fqn string, field *plugin.TValue[*mqlSnowflakeTable]) (*mqlSnowflakeTable, error) {
	if fqn == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id, err := sdk.ParseSchemaObjectIdentifier(fqn)
	if err != nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveTableRef(runtime, id.DatabaseName(), id.SchemaName(), id.Name(), field)
}

// resolveTableRef returns the table a database/schema/name triple refers to, or
// a null resource when any coordinate is empty. A table the caller cannot see
// resolves to null rather than failing the surrounding query, matching how the
// other object references degrade.
func resolveTableRef(runtime *plugin.Runtime, databaseName, schemaName, name string, field *plugin.TValue[*mqlSnowflakeTable]) (*mqlSnowflakeTable, error) {
	if databaseName == "" || schemaName == "" || name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "snowflake.table", map[string]*llx.RawData{
		"databaseName": llx.StringData(databaseName),
		"schemaName":   llx.StringData(schemaName),
		"name":         llx.StringData(name),
	})
	if err != nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlSnowflakeTable), nil
}
