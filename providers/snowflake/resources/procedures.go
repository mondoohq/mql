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

func (r *mqlSnowflakeAccount) procedures() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	procedures, err := client.Procedures.Show(ctx, &sdk.ShowProcedureRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range procedures {
		mqlPasswordPolicy, err := newMqlSnowflakeProcedure(r.MqlRuntime, procedures[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlPasswordPolicy)
	}

	return list, nil
}

func newMqlSnowflakeProcedure(runtime *plugin.Runtime, procedure sdk.Procedure) (*mqlSnowflakeProcedure, error) {
	r, err := CreateResource(runtime, "snowflake.procedure", map[string]*llx.RawData{
		// Build __id from raw fields, not procedure.ID(): the SDK's ID() panics
		// (nil deref in TableDataType.ToLegacyDataTypeSql) for a procedure whose
		// signature involves a TABLE type. ArgumentsRaw disambiguates overloads.
		"__id":                 llx.StringData(procedure.CatalogName + "." + procedure.SchemaName + "." + procedure.Name + "/" + procedure.ArgumentsRaw),
		"name":                 llx.StringData(procedure.Name),
		"description":          llx.StringData(procedure.Description),
		"schemaName":           llx.StringData(procedure.SchemaName),
		"isBuiltin":            llx.BoolData(procedure.IsBuiltin),
		"isAggregate":          llx.BoolData(procedure.IsAggregate),
		"isAnsi":               llx.BoolData(procedure.IsAnsi),
		"minNumberOfArguments": llx.IntData(procedure.MinNumArguments),
		"maxNumberOfArguments": llx.IntData(procedure.MaxNumArguments),
		"arguments":            llx.StringData(procedure.ArgumentsRaw),
		"catalogName":          llx.StringData(procedure.CatalogName),
		"isTableFunction":      llx.BoolData(procedure.IsTableFunction),
		"validForClustering":   llx.BoolData(procedure.ValidForClustering),
		"isSecure":             llx.BoolData(procedure.IsSecure),
	})
	if err != nil {
		return nil, err
	}
	mqlResource := r.(*mqlSnowflakeProcedure)
	return mqlResource, nil
}
