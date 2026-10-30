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

type mqlSnowflakeAlertInternal struct {
	cacheOwner     string
	cacheWarehouse string
}

func (r *mqlSnowflakeAccount) alerts() ([]any, error) {
	return listSnowflakeAlerts(r.MqlRuntime, &sdk.In{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) alerts() ([]any, error) {
	return listSnowflakeAlerts(r.MqlRuntime, &sdk.In{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeAlerts fetches alerts within the given scope (account-wide or a
// single database) and maps them to resources.
func listSnowflakeAlerts(runtime *plugin.Runtime, in *sdk.In) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	alerts, err := conn.Client().Alerts.Show(context.Background(), &sdk.ShowAlertRequest{In: in})
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(alerts))
	for i := range alerts {
		mqlAlert, err := newMqlSnowflakeAlert(runtime, alerts[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlAlert)
	}
	return list, nil
}

func newMqlSnowflakeAlert(runtime *plugin.Runtime, alert sdk.Alert) (*mqlSnowflakeAlert, error) {
	r, err := CreateResource(runtime, "snowflake.alert", map[string]*llx.RawData{
		"__id":          llx.StringData(snowflakeSchemaObjectID(alert.DatabaseName, alert.SchemaName, alert.Name)),
		"name":          llx.StringData(alert.Name),
		"databaseName":  llx.StringData(alert.DatabaseName),
		"schemaName":    llx.StringData(alert.SchemaName),
		"ownerRoleType": llx.StringData(alert.OwnerRoleType),
		"schedule":      llx.StringData(alert.Schedule),
		"state":         llx.StringData(string(alert.State)),
		"condition":     llx.StringData(alert.Condition),
		"action":        llx.StringData(alert.Action),
		"comment":       llx.StringDataPtr(alert.Comment),
		"createdAt":     snowflakeTime(alert.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlAlert := r.(*mqlSnowflakeAlert)
	mqlAlert.cacheOwner = alert.Owner
	mqlAlert.cacheWarehouse = alert.Warehouse
	return mqlAlert, nil
}

func (r *mqlSnowflakeAlert) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeAlert) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeAlert) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

func (r *mqlSnowflakeAlert) warehouse() (*mqlSnowflakeWarehouse, error) {
	return resolveWarehouseRef(r.MqlRuntime, r.cacheWarehouse, &r.Warehouse)
}
