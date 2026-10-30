// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeFunctionInternal struct {
	cacheExternalAccessIntegrations []string
	cacheSecrets                    []sdk.SchemaObjectIdentifier
}

func (r *mqlSnowflakeAccount) functions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	functions, err := client.Functions.Show(ctx, sdk.NewShowFunctionRequest())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range functions {
		mqlFunction, err := newMqlSnowflakeFunction(r.MqlRuntime, functions[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlFunction)
	}
	return list, nil
}

func newMqlSnowflakeFunction(runtime *plugin.Runtime, function sdk.Function) (*mqlSnowflakeFunction, error) {
	// Build the cache key from the raw fields rather than function.ID(): the
	// SDK's ID() panics (nil deref in TableDataType.ToLegacyDataTypeSql) for
	// functions whose signature involves a TABLE type. ArgumentsRaw carries the
	// full signature, so it disambiguates overloads.
	r, err := CreateResource(runtime, "snowflake.function", map[string]*llx.RawData{
		"__id":               llx.StringData(function.CatalogName + "." + function.SchemaName + "." + function.Name + "/" + function.ArgumentsRaw),
		"name":               llx.StringData(function.Name),
		"databaseName":       llx.StringData(function.CatalogName),
		"schemaName":         llx.StringData(function.SchemaName),
		"language":           llx.StringData(function.Language),
		"isSecure":           llx.BoolData(function.IsSecure),
		"isExternalFunction": llx.BoolData(function.IsExternalFunction),
		"isBuiltin":          llx.BoolData(function.IsBuiltin),
		"isAggregate":        llx.BoolData(function.IsAggregate),
		"isTableFunction":    llx.BoolData(function.IsTableFunction),
		"isMemoizable":       llx.BoolData(function.IsMemoizable),
		"isDataMetric":       llx.BoolData(function.IsDataMetric),
		"arguments":          llx.StringData(function.ArgumentsRaw),
		"description":        llx.StringData(function.Description),
	})
	if err != nil {
		return nil, err
	}
	mqlFunc := r.(*mqlSnowflakeFunction)
	// SHOW FUNCTIONS returns external_access_integrations as a comma-separated
	// list of account-level integration names.
	if function.ExternalAccessIntegrations != nil {
		for _, raw := range sdk.ParseCommaSeparatedStringArray(*function.ExternalAccessIntegrations, false) {
			id, err := sdk.ParseAccountObjectIdentifier(raw)
			if err != nil {
				continue
			}
			mqlFunc.cacheExternalAccessIntegrations = append(mqlFunc.cacheExternalAccessIntegrations, id.Name())
		}
	}
	// SHOW FUNCTIONS returns secrets as a JSON object mapping a secret variable
	// name to the bound secret's fully qualified name; a function may bind the
	// same secret under several variables, so dedupe.
	if function.Secrets != nil && *function.Secrets != "" {
		parsed := map[string]string{}
		if err := json.Unmarshal([]byte(*function.Secrets), &parsed); err == nil {
			seen := map[string]bool{}
			for _, fqn := range parsed {
				id, err := sdk.ParseSchemaObjectIdentifier(fqn)
				if err != nil {
					continue
				}
				if seen[id.FullyQualifiedName()] {
					continue
				}
				seen[id.FullyQualifiedName()] = true
				mqlFunc.cacheSecrets = append(mqlFunc.cacheSecrets, id)
			}
		}
	}
	return mqlFunc, nil
}

func (r *mqlSnowflakeFunction) externalAccessIntegrations() ([]any, error) {
	out := []any{}
	for _, name := range r.cacheExternalAccessIntegrations {
		res, err := NewResource(r.MqlRuntime, "snowflake.externalAccessIntegration", map[string]*llx.RawData{
			"name": llx.StringData(name),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlSnowflakeFunction) secrets() ([]any, error) {
	out := []any{}
	for _, id := range r.cacheSecrets {
		res, err := NewResource(r.MqlRuntime, "snowflake.secret", map[string]*llx.RawData{
			"databaseName": llx.StringData(id.DatabaseName()),
			"schemaName":   llx.StringData(id.SchemaName()),
			"name":         llx.StringData(id.Name()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
