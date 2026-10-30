// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// errSchemaNotFound marks a schema that SHOW SCHEMAS does not report. It is a
// sentinel rather than a bare error so a caller resolving a reference can tell
// "this schema is not listed" apart from "the lookup itself failed", and
// degrade only the former.
var errSchemaNotFound = errors.New("snowflake schema not found")

// initSnowflakeSchema resolves a schema by its database and name when the
// resource is requested through a typed reference (e.g.
// snowflake.rowAccessPolicy.schema). Listing via the account goes through
// CreateResource, which skips init, so this only runs for on-demand lookups.
func initSnowflakeSchema(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Keyed by databaseName + name; more than those two keys means the caller
	// already supplied full data, so skip the lookup.
	if len(args) > 2 {
		return args, nil, nil
	}
	dbRaw, ok1 := args["databaseName"]
	nameRaw, ok2 := args["name"]
	if !ok1 || !ok2 {
		return args, nil, nil
	}
	databaseName, _ := dbRaw.Value.(string)
	name, _ := nameRaw.Value.(string)
	if databaseName == "" || name == "" {
		return nil, nil, fmt.Errorf("snowflake.schema requires a non-empty databaseName and name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	schemas, err := client.Schemas.Show(ctx, &sdk.ShowSchemaRequest{
		Like: &sdk.Like{Pattern: new(name)},
		In:   &sdk.ExtendedIn{Database: sdk.NewAccountObjectIdentifier(databaseName)},
	})
	if err != nil {
		return nil, nil, err
	}
	for i := range schemas {
		if schemas[i].Name == name && schemas[i].DatabaseName == databaseName {
			res, err := newMqlSnowflakeSchema(runtime, schemas[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("snowflake.schema %q not found in database %q: %w", name, databaseName, errSchemaNotFound)
}

// resolveSchemaRef returns the typed schema a database/name pair refers to, or a
// null resource when either coordinate is empty. Shared by the row-access-policy
// and network-rule resources.
//
// The account's schema index answers this without a statement. Anything the
// index cannot answer, including an index that could not be read at all, falls
// through to the per-name lookup in initSnowflakeSchema.
func resolveSchemaRef(runtime *plugin.Runtime, databaseName, schemaName string, field *plugin.TValue[*mqlSnowflakeSchema]) (*mqlSnowflakeSchema, error) {
	if databaseName == "" || schemaName == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if schema, ok := indexedSchema(runtime, databaseName, schemaName); ok {
		return newMqlSnowflakeSchema(runtime, schema)
	}
	res, err := NewResource(runtime, "snowflake.schema", map[string]*llx.RawData{
		"databaseName": llx.StringData(databaseName),
		"name":         llx.StringData(schemaName),
	})
	if err != nil {
		if errors.Is(err, errSchemaNotFound) {
			// SHOW SCHEMAS omits schemas owned by an application, so an object
			// can name a schema that is real and yet unlistable. Every network
			// rule Snowflake ships sits in SNOWFLAKE.EXTERNAL_ACCESS, which is
			// one of these. Report the reference as unknown rather than failing
			// the field on the owning resource.
			log.Debug().
				Str("database", databaseName).
				Str("schema", schemaName).
				Msg("snowflake: schema is not listed, reporting the reference as null")
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlSnowflakeSchema), nil
}

func (r *mqlSnowflakeSchema) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeAccount) schemas() ([]any, error) {
	return listSnowflakeSchemas(r.MqlRuntime, &sdk.ExtendedIn{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) schemas() ([]any, error) {
	return listSnowflakeSchemas(r.MqlRuntime, &sdk.ExtendedIn{
		Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeSchemas fetches schemas within the given scope (account-wide or a
// single database) and maps them to resources.
func listSnowflakeSchemas(runtime *plugin.Runtime, in *sdk.ExtendedIn) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	schemas, err := conn.Client().Schemas.Show(context.Background(), &sdk.ShowSchemaRequest{In: in})
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(schemas))
	for i := range schemas {
		mqlSchema, err := newMqlSnowflakeSchema(runtime, schemas[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlSchema)
	}

	return list, nil
}

func newMqlSnowflakeSchema(runtime *plugin.Runtime, schema sdk.Schema) (*mqlSnowflakeSchema, error) {
	r, err := CreateResource(runtime, "snowflake.schema", map[string]*llx.RawData{
		"__id":          llx.StringData(schema.ID().FullyQualifiedName()),
		"name":          llx.StringData(schema.Name),
		"databaseName":  llx.StringData(schema.DatabaseName),
		"isDefault":     llx.BoolData(schema.IsDefault),
		"isCurrent":     llx.BoolData(schema.IsCurrent),
		"owner":         llx.StringData(schema.Owner),
		"ownerRoleType": llx.StringData(schema.OwnerRoleType),
		"comment":       llx.StringData(schema.Comment),
		"options":       llx.StringDataPtr(schema.Options),
		"retentionTime": llx.StringData(schema.RetentionTime),
		"createdAt":     llx.TimeData(schema.CreatedOn),
		"droppedAt":     llx.TimeData(schema.DroppedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeSchema), nil
}
