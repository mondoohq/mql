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

// initSnowflakeWarehouse resolves a single warehouse by name so typed
// references (such as snowflake.task.warehouse) can hydrate a full warehouse
// from just its name. A caller that already supplied more than the name is left
// untouched.
func initSnowflakeWarehouse(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("snowflake.warehouse requires a non-empty name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	warehouses, err := client.Warehouses.Show(ctx, &sdk.ShowWarehouseRequest{Like: &sdk.Like{Pattern: new(name)}})
	if err != nil {
		return nil, nil, err
	}
	for i := range warehouses {
		if warehouses[i].Name == name {
			res, err := newMqlSnowflakeWarehouse(runtime, warehouses[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("snowflake.warehouse %q not found", name)
}

// snowflakeWarehouseByName resolves a warehouse by name, returning nil (not an
// error) when no such warehouse is listable (dropped, or not visible to the
// caller). Callers treat a nil result as a null typed reference rather than
// failing the query.
//
// The account's warehouse index answers this without a statement. Anything the
// index cannot answer, including an index that could not be read at all, falls
// through to the SHOW WAREHOUSES LIKE below, so a name the index misses is
// still confirmed against Snowflake before it is reported as absent.
func snowflakeWarehouseByName(runtime *plugin.Runtime, name string) (*mqlSnowflakeWarehouse, error) {
	if name == "" {
		return nil, nil
	}
	if warehouse, ok := indexedWarehouse(runtime, name); ok {
		return newMqlSnowflakeWarehouse(runtime, warehouse)
	}
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	warehouses, err := conn.Client().Warehouses.Show(context.Background(), &sdk.ShowWarehouseRequest{Like: &sdk.Like{Pattern: new(name)}})
	if err != nil {
		return nil, err
	}
	for i := range warehouses {
		if warehouses[i].Name == name {
			return newMqlSnowflakeWarehouse(runtime, warehouses[i])
		}
	}
	return nil, nil
}

// resolveWarehouseRef resolves a warehouse name to its warehouse, reporting the
// reference as null when the name is empty or the warehouse is not one the
// caller can list, rather than failing the surrounding query.
func resolveWarehouseRef(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlSnowflakeWarehouse]) (*mqlSnowflakeWarehouse, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	wh, err := snowflakeWarehouseByName(runtime, name)
	if err != nil {
		return nil, err
	}
	if wh == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return wh, nil
}

func (r *mqlSnowflakeAccount) warehouses() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	warehouses, err := client.Warehouses.Show(ctx, &sdk.ShowWarehouseRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range warehouses {
		mqlResource, err := newMqlSnowflakeWarehouse(r.MqlRuntime, warehouses[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlResource)
	}

	return list, nil
}

func newMqlSnowflakeWarehouse(runtime *plugin.Runtime, warehouse sdk.Warehouse) (*mqlSnowflakeWarehouse, error) {
	r, err := CreateResource(runtime, "snowflake.warehouse", map[string]*llx.RawData{
		"__id":                            llx.StringData(warehouse.ID().FullyQualifiedName()),
		"name":                            llx.StringData(warehouse.Name),
		"state":                           llx.StringData(string(warehouse.State)),
		"type":                            llx.StringData(string(warehouse.Type)),
		"size":                            llx.StringDataPtr((*string)(warehouse.Size)),
		"minClusterCount":                 llx.IntDataPtr(warehouse.MinClusterCount),
		"maxClusterCount":                 llx.IntDataPtr(warehouse.MaxClusterCount),
		"startedClusterCount":             llx.IntDataPtr(warehouse.StartedClusters),
		"running":                         llx.IntDataPtr(warehouse.Running),
		"queued":                          llx.IntDataPtr(warehouse.Queued),
		"isDefault":                       llx.BoolData(warehouse.IsDefault),
		"isCurrent":                       llx.BoolData(warehouse.IsCurrent),
		"autoSuspend":                     llx.IntDataPtr(warehouse.AutoSuspend),
		"autoResume":                      llx.BoolData(warehouse.AutoResume),
		"available":                       llx.FloatData(warehouse.Available),
		"provisioning":                    llx.FloatData(warehouse.Provisioning),
		"quiescing":                       llx.FloatData(warehouse.Quiescing),
		"other":                           llx.FloatData(warehouse.Other),
		"owner":                           llx.StringData(warehouse.Owner),
		"ownerRoleType":                   llx.StringData(warehouse.OwnerRoleType),
		"comment":                         llx.StringData(warehouse.Comment),
		"enableQueryAcceleration":         llx.BoolDataPtr(warehouse.EnableQueryAcceleration),
		"queryAccelerationMaxScaleFactor": llx.IntDataPtr(warehouse.QueryAccelerationMaxScaleFactor),
		"scalingPolicy":                   llx.StringDataPtr((*string)(warehouse.ScalingPolicy)),
		"createdAt":                       llx.TimeData(warehouse.CreatedOn),
		"resumedAt":                       llx.TimeData(warehouse.ResumedOn),
		"updatedAt":                       llx.TimeData(warehouse.UpdatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlResource := r.(*mqlSnowflakeWarehouse)
	mqlResource.cacheResourceMonitor = warehouse.ResourceMonitor.Name()
	return mqlResource, nil
}

// mqlSnowflakeWarehouseInternal holds the governing resource-monitor name that
// resourceMonitorRef() resolves.
type mqlSnowflakeWarehouseInternal struct {
	cacheResourceMonitor string
}

func (r *mqlSnowflakeWarehouse) resourceMonitorRef() (*mqlSnowflakeResourceMonitor, error) {
	return snowflakeResourceMonitorByName(r.MqlRuntime, r.cacheResourceMonitor, &r.ResourceMonitorRef)
}
