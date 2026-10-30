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

type mqlSnowflakePipeInternal struct {
	cacheOwner            string
	cacheIntegration      string
	cacheErrorIntegration string
}

func (r *mqlSnowflakeAccount) pipes() ([]any, error) {
	return listSnowflakePipes(r.MqlRuntime, &sdk.In{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) pipes() ([]any, error) {
	return listSnowflakePipes(r.MqlRuntime, &sdk.In{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakePipes fetches pipes within the given scope (account-wide or a
// single database) and maps them to resources.
func listSnowflakePipes(runtime *plugin.Runtime, in *sdk.In) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	pipes, err := conn.Client().Pipes.Show(context.Background(), &sdk.ShowPipeRequest{In: in})
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(pipes))
	for i := range pipes {
		mqlPipe, err := newMqlSnowflakePipe(runtime, pipes[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlPipe)
	}
	return list, nil
}

func newMqlSnowflakePipe(runtime *plugin.Runtime, pipe sdk.Pipe) (*mqlSnowflakePipe, error) {
	r, err := CreateResource(runtime, "snowflake.pipe", map[string]*llx.RawData{
		"__id":                llx.StringData(snowflakeSchemaObjectID(pipe.DatabaseName, pipe.SchemaName, pipe.Name)),
		"name":                llx.StringData(pipe.Name),
		"databaseName":        llx.StringData(pipe.DatabaseName),
		"schemaName":          llx.StringData(pipe.SchemaName),
		"ownerRoleType":       llx.StringData(pipe.OwnerRoleType),
		"definition":          llx.StringData(pipe.Definition),
		"notificationChannel": llx.StringData(pipe.NotificationChannel),
		"pattern":             llx.StringData(pipe.Pattern),
		"invalidReason":       llx.StringData(pipe.InvalidReason),
		"comment":             llx.StringData(pipe.Comment),
		"createdAt":           parseSnowflakeTime(pipe.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	mqlPipe := r.(*mqlSnowflakePipe)
	mqlPipe.cacheOwner = pipe.Owner
	mqlPipe.cacheIntegration = pipe.Integration
	mqlPipe.cacheErrorIntegration = pipe.ErrorIntegration
	return mqlPipe, nil
}

func (r *mqlSnowflakePipe) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakePipe) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakePipe) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

func (r *mqlSnowflakePipe) integration() (*mqlSnowflakeNotificationIntegration, error) {
	return resolveNotificationIntegrationRef(r.MqlRuntime, r.cacheIntegration, &r.Integration)
}

func (r *mqlSnowflakePipe) errorIntegration() (*mqlSnowflakeNotificationIntegration, error) {
	return resolveNotificationIntegrationRef(r.MqlRuntime, r.cacheErrorIntegration, &r.ErrorIntegration)
}
