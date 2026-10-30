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

func (r *mqlSnowflakeAccount) stages() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	stages, err := client.Stages.Show(ctx, &sdk.ShowStageRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range stages {
		mqlResource, err := newMqlSnowflakeStage(r.MqlRuntime, stages[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlResource)
	}

	return list, nil
}

func newMqlSnowflakeStage(runtime *plugin.Runtime, user sdk.Stage) (*mqlSnowflakeStage, error) {
	r, err := CreateResource(runtime, "snowflake.stage", map[string]*llx.RawData{
		"__id":             llx.StringData(user.ID().FullyQualifiedName()),
		"name":             llx.StringData(user.Name),
		"databaseName":     llx.StringData(user.DatabaseName),
		"schemaName":       llx.StringData(user.SchemaName),
		"owner":            llx.StringData(user.Owner),
		"comment":          llx.StringData(user.Comment),
		"createdAt":        llx.TimeData(user.CreatedOn),
		"hasCredentials":   llx.BoolData(user.HasCredentials),
		"hasEncryptionKey": llx.BoolData(user.HasEncryptionKey),
		"url":              llx.StringData(user.Url),
		"type":             llx.StringData(string(user.Type)),
		"cloud":            llx.StringDataPtr((*string)(user.Cloud)),
		"endpoint":         llx.StringDataPtr(user.Endpoint),
		"ownerRoleType":    llx.StringDataPtr(user.OwnerRoleType),
		"directoryEnabled": llx.BoolData(user.DirectoryEnabled),
	})
	if err != nil {
		return nil, err
	}
	mqlResource := r.(*mqlSnowflakeStage)
	if user.StorageIntegration != nil {
		mqlResource.cacheStoreIntegration = user.StorageIntegration.Name()
	}
	return mqlResource, nil
}

// resolveStageRef resolves a fully qualified stage name (the form Snowflake
// reports in SHOW output, such as "DB"."SCHEMA"."STAGE") to its stage. A name
// that cannot be parsed, or a stage the caller cannot see, resolves to null
// rather than failing the surrounding query.
func resolveStageRef(runtime *plugin.Runtime, fqn string, field *plugin.TValue[*mqlSnowflakeStage]) (*mqlSnowflakeStage, error) {
	if fqn == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id, err := sdk.ParseSchemaObjectIdentifier(fqn)
	if err != nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	stages, err := conn.Client().Stages.Show(context.Background(), &sdk.ShowStageRequest{
		Like: &sdk.Like{Pattern: new(id.Name())},
		In:   &sdk.ExtendedIn{Schema: sdk.NewDatabaseObjectIdentifier(id.DatabaseName(), id.SchemaName())},
	})
	if err != nil {
		return nil, err
	}
	for i := range stages {
		if stages[i].Name == id.Name() && stages[i].DatabaseName == id.DatabaseName() && stages[i].SchemaName == id.SchemaName() {
			return newMqlSnowflakeStage(runtime, stages[i])
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// mqlSnowflakeStageInternal holds the backing storage-integration name that
// storageIntegration() resolves.
type mqlSnowflakeStageInternal struct {
	cacheStoreIntegration string
}

func (r *mqlSnowflakeStage) storageIntegration() (*mqlSnowflakeStorageIntegration, error) {
	name := r.cacheStoreIntegration
	if name == "" {
		r.StorageIntegration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "snowflake.storageIntegration", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlSnowflakeStorageIntegration), nil
}
