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

type mqlSnowflakeStreamInternal struct {
	cacheOwner      string
	cacheTable      string
	cacheBaseTables []string
}

func (r *mqlSnowflakeAccount) streams() ([]any, error) {
	return listSnowflakeStreams(r.MqlRuntime, sdk.ExtendedIn{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) streams() ([]any, error) {
	return listSnowflakeStreams(r.MqlRuntime, sdk.ExtendedIn{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeStreams fetches streams within the given scope (account-wide or
// a single database) and maps them to resources.
func listSnowflakeStreams(runtime *plugin.Runtime, in sdk.ExtendedIn) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	streams, err := conn.Client().Streams.Show(context.Background(),
		sdk.NewShowStreamRequest().WithIn(in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(streams))
	for i := range streams {
		mqlStream, err := newMqlSnowflakeStream(runtime, streams[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlStream)
	}
	return list, nil
}

func newMqlSnowflakeStream(runtime *plugin.Runtime, stream sdk.Stream) (*mqlSnowflakeStream, error) {
	sourceType := ""
	if stream.SourceType != nil {
		sourceType = string(*stream.SourceType)
	}
	mode := ""
	if stream.Mode != nil {
		mode = string(*stream.Mode)
	}
	staleAfter := llx.NilData
	if stream.StaleAfter != nil {
		staleAfter = llx.TimeData(*stream.StaleAfter)
	}

	r, err := CreateResource(runtime, "snowflake.stream", map[string]*llx.RawData{
		"__id":          llx.StringData(snowflakeSchemaObjectID(stream.DatabaseName, stream.SchemaName, stream.Name)),
		"name":          llx.StringData(stream.Name),
		"databaseName":  llx.StringData(stream.DatabaseName),
		"schemaName":    llx.StringData(stream.SchemaName),
		"ownerRoleType": llx.StringDataPtr(stream.OwnerRoleType),
		"sourceType":    llx.StringData(sourceType),
		"type":          llx.StringDataPtr(stream.Type),
		"stale":         llx.BoolData(stream.Stale),
		"staleAfter":    staleAfter,
		"mode":          llx.StringData(mode),
		"invalidReason": llx.StringDataPtr(stream.InvalidReason),
		"comment":       llx.StringDataPtr(stream.Comment),
		"createdAt":     snowflakeTime(stream.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlStream := r.(*mqlSnowflakeStream)
	if stream.Owner != nil {
		mqlStream.cacheOwner = *stream.Owner
	}
	if stream.TableName != nil {
		mqlStream.cacheTable = stream.TableName.FullyQualifiedName()
	}
	mqlStream.cacheBaseTables = make([]string, 0, len(stream.BaseTables))
	for _, id := range stream.BaseTables {
		mqlStream.cacheBaseTables = append(mqlStream.cacheBaseTables, id.FullyQualifiedName())
	}
	return mqlStream, nil
}

func (r *mqlSnowflakeStream) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeStream) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeStream) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

func (r *mqlSnowflakeStream) table() (*mqlSnowflakeTable, error) {
	return resolveTableRefByFQN(r.MqlRuntime, r.cacheTable, &r.Table)
}

// baseTables resolves the tables the stream ultimately reads from. A name that
// cannot be resolved is skipped rather than failing the query, so a stream over
// a view whose underlying tables the caller cannot see still lists the ones it
// can.
func (r *mqlSnowflakeStream) baseTables() ([]any, error) {
	out := []any{}
	for _, fqn := range r.cacheBaseTables {
		if fqn == "" {
			continue
		}
		id, err := sdk.ParseSchemaObjectIdentifier(fqn)
		if err != nil {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "snowflake.table", map[string]*llx.RawData{
			"databaseName": llx.StringData(id.DatabaseName()),
			"schemaName":   llx.StringData(id.SchemaName()),
			"name":         llx.StringData(id.Name()),
		})
		if err != nil {
			continue
		}
		out = append(out, res.(*mqlSnowflakeTable))
	}
	return out, nil
}
