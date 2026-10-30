// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// mqlSnowflakeCortexSearchServiceInternal memoizes the per-service DESCRIBE
// response. SHOW CORTEX SEARCH SERVICES returns only name/database/schema/
// comment/created_on, so the warehouse, target lag, definition, and query URL
// come from a DESCRIBE call. Every field backed by that call routes through
// describe(), so touching one (or all) of them hits the API at most once.
type mqlSnowflakeCortexSearchServiceInternal struct {
	describeOnce sync.Once
	details      *sdk.CortexSearchServiceDetails
	detailsErr   error
}

func (r *mqlSnowflakeAccount) cortexSearchServices() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	services, err := client.CortexSearchServices.Show(ctx,
		sdk.NewShowCortexSearchServiceRequest().WithIn(sdk.In{Account: new(true)}))
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range services {
		mqlResource, err := newMqlSnowflakeCortexSearchService(r.MqlRuntime, services[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlResource)
	}

	return list, nil
}

func newMqlSnowflakeCortexSearchService(runtime *plugin.Runtime, service sdk.CortexSearchService) (*mqlSnowflakeCortexSearchService, error) {
	// Build the fully qualified __id from the raw name parts rather than the
	// SDK's ID() helper, which can panic on identifiers it fails to parse.
	id := service.DatabaseName + "." + service.SchemaName + "." + service.Name
	r, err := CreateResource(runtime, "snowflake.cortexSearchService", map[string]*llx.RawData{
		"__id":         llx.StringData(id),
		"name":         llx.StringData(service.Name),
		"databaseName": llx.StringData(service.DatabaseName),
		"schemaName":   llx.StringData(service.SchemaName),
		"comment":      llx.StringData(service.Comment),
		"createdAt":    llx.TimeData(service.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeCortexSearchService), nil
}

// describe fetches and memoizes the DESCRIBE CORTEX SEARCH SERVICE response for
// this service, backing the warehouse, targetLag, definition, and
// serviceQueryUrl fields with a single API call.
func (r *mqlSnowflakeCortexSearchService) describe() (*sdk.CortexSearchServiceDetails, error) {
	r.describeOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		client := conn.Client()
		ctx := context.Background()

		id := sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
		r.details, r.detailsErr = client.CortexSearchServices.Describe(ctx, id)
	})
	return r.details, r.detailsErr
}

func (r *mqlSnowflakeCortexSearchService) warehouse() (*mqlSnowflakeWarehouse, error) {
	details, err := r.describe()
	if err != nil {
		return nil, err
	}
	if details == nil || details.Warehouse == "" {
		r.Warehouse.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	wh, err := snowflakeWarehouseByName(r.MqlRuntime, details.Warehouse)
	if err != nil {
		return nil, err
	}
	if wh == nil {
		r.Warehouse.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return wh, nil
}

func (r *mqlSnowflakeCortexSearchService) targetLag() (string, error) {
	details, err := r.describe()
	if err != nil {
		return "", err
	}
	if details == nil {
		return "", nil
	}
	return details.TargetLag, nil
}

func (r *mqlSnowflakeCortexSearchService) definition() (string, error) {
	details, err := r.describe()
	if err != nil {
		return "", err
	}
	if details == nil || details.Definition == nil {
		return "", nil
	}
	return *details.Definition, nil
}

func (r *mqlSnowflakeCortexSearchService) serviceQueryUrl() (string, error) {
	details, err := r.describe()
	if err != nil {
		return "", err
	}
	if details == nil {
		return "", nil
	}
	return details.ServiceQueryUrl, nil
}
