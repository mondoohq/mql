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

type mqlSnowflakeStreamlitInternal struct {
	cacheOwner     string
	cacheWarehouse string
}

func (r *mqlSnowflakeAccount) streamlits() ([]any, error) {
	return listSnowflakeStreamlits(r.MqlRuntime, sdk.In{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) streamlits() ([]any, error) {
	return listSnowflakeStreamlits(r.MqlRuntime, sdk.In{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeStreamlits fetches Streamlit apps within the given scope
// (account-wide or a single database) and maps them to resources.
func listSnowflakeStreamlits(runtime *plugin.Runtime, in sdk.In) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	streamlits, err := conn.Client().Streamlits.Show(context.Background(),
		sdk.NewShowStreamlitRequest().WithIn(in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(streamlits))
	for i := range streamlits {
		mqlStreamlit, err := newMqlSnowflakeStreamlit(runtime, streamlits[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlStreamlit)
	}
	return list, nil
}

func newMqlSnowflakeStreamlit(runtime *plugin.Runtime, streamlit sdk.Streamlit) (*mqlSnowflakeStreamlit, error) {
	r, err := CreateResource(runtime, "snowflake.streamlit", map[string]*llx.RawData{
		"__id":          llx.StringData(snowflakeSchemaObjectID(streamlit.DatabaseName, streamlit.SchemaName, streamlit.Name)),
		"name":          llx.StringData(streamlit.Name),
		"databaseName":  llx.StringData(streamlit.DatabaseName),
		"schemaName":    llx.StringData(streamlit.SchemaName),
		"ownerRoleType": llx.StringData(streamlit.OwnerRoleType),
		"title":         llx.StringData(streamlit.Title),
		"urlId":         llx.StringData(streamlit.UrlId),
		"comment":       llx.StringData(streamlit.Comment),
		"createdAt":     parseSnowflakeTime(streamlit.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlStreamlit := r.(*mqlSnowflakeStreamlit)
	mqlStreamlit.cacheOwner = streamlit.Owner
	mqlStreamlit.cacheWarehouse = streamlit.QueryWarehouse
	return mqlStreamlit, nil
}

func (r *mqlSnowflakeStreamlit) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeStreamlit) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeStreamlit) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

func (r *mqlSnowflakeStreamlit) queryWarehouse() (*mqlSnowflakeWarehouse, error) {
	return resolveWarehouseRef(r.MqlRuntime, r.cacheWarehouse, &r.QueryWarehouse)
}
