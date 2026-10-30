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

type mqlSnowflakeMaterializedViewInternal struct {
	cacheOwner        string
	cacheSourceDB     string
	cacheSourceSchema string
	cacheSourceTable  string
}

func (r *mqlSnowflakeAccount) materializedViews() ([]any, error) {
	return listSnowflakeMaterializedViews(r.MqlRuntime, sdk.In{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) materializedViews() ([]any, error) {
	return listSnowflakeMaterializedViews(r.MqlRuntime, sdk.In{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeMaterializedViews fetches materialized views within the given
// scope (account-wide or a single database) and maps them to resources.
func listSnowflakeMaterializedViews(runtime *plugin.Runtime, in sdk.In) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	views, err := conn.Client().MaterializedViews.Show(context.Background(),
		sdk.NewShowMaterializedViewRequest().WithIn(in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(views))
	for i := range views {
		mqlView, err := newMqlSnowflakeMaterializedView(runtime, views[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlView)
	}
	return list, nil
}

func newMqlSnowflakeMaterializedView(runtime *plugin.Runtime, view sdk.MaterializedView) (*mqlSnowflakeMaterializedView, error) {
	r, err := CreateResource(runtime, "snowflake.materializedView", map[string]*llx.RawData{
		"__id":                llx.StringData(snowflakeSchemaObjectID(view.DatabaseName, view.SchemaName, view.Name)),
		"name":                llx.StringData(view.Name),
		"databaseName":        llx.StringData(view.DatabaseName),
		"schemaName":          llx.StringData(view.SchemaName),
		"ownerRoleType":       llx.StringData(view.OwnerRoleType),
		"text":                llx.StringData(view.Text),
		"isSecure":            llx.BoolData(view.IsSecure),
		"rows":                llx.IntData(int64(view.Rows)),
		"bytes":               llx.IntData(int64(view.Bytes)),
		"clusterBy":           llx.StringData(view.ClusterBy),
		"automaticClustering": llx.BoolData(view.AutomaticClustering),
		"invalid":             llx.BoolData(view.Invalid),
		"invalidReason":       llx.StringData(view.InvalidReason),
		"behindBy":            llx.StringData(view.BehindBy),
		"refreshedOn":         snowflakeTime(view.RefreshedOn),
		"compactedOn":         snowflakeTime(view.CompactedOn),
		"budget":              llx.StringData(view.Budget),
		"comment":             llx.StringData(view.Comment),
		"createdAt":           parseSnowflakeTime(view.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlView := r.(*mqlSnowflakeMaterializedView)
	mqlView.cacheOwner = view.Owner
	mqlView.cacheSourceDB = view.SourceDatabaseName
	mqlView.cacheSourceSchema = view.SourceSchemaName
	mqlView.cacheSourceTable = view.SourceTableName
	return mqlView, nil
}

func (r *mqlSnowflakeMaterializedView) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeMaterializedView) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeMaterializedView) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

func (r *mqlSnowflakeMaterializedView) sourceTable() (*mqlSnowflakeTable, error) {
	return resolveTableRef(r.MqlRuntime, r.cacheSourceDB, r.cacheSourceSchema, r.cacheSourceTable, &r.SourceTable)
}
