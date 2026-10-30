// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
	"go.mondoo.com/mql/types"
)

type mqlSnowflakeSecretInternal struct {
	descLock        sync.Mutex
	descLoaded      bool
	descLoadErr     error
	descUsername    string
	descIntegration string
	descAccessExp   *time.Time
	descRefreshExp  *time.Time
}

// initSnowflakeSecret resolves a single secret by its database, schema, and
// name so typed references (such as snowflake.function.secrets) can hydrate a
// full secret from just its identity.
func initSnowflakeSecret(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}
	dbRaw, ok1 := args["databaseName"]
	schemaRaw, ok2 := args["schemaName"]
	nameRaw, ok3 := args["name"]
	if !ok1 || !ok2 || !ok3 {
		return args, nil, nil
	}
	databaseName, _ := dbRaw.Value.(string)
	schemaName, _ := schemaRaw.Value.(string)
	name, _ := nameRaw.Value.(string)
	if databaseName == "" || schemaName == "" || name == "" {
		return nil, nil, fmt.Errorf("snowflake.secret requires a non-empty databaseName, schemaName, and name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	secrets, err := conn.Client().Secrets.Show(context.Background(), sdk.NewShowSecretRequest().
		WithLike(sdk.Like{Pattern: new(name)}).
		WithIn(sdk.ExtendedIn{Schema: sdk.NewDatabaseObjectIdentifier(databaseName, schemaName)}))
	if err != nil {
		return nil, nil, err
	}
	for i := range secrets {
		if secrets[i].Name == name && secrets[i].SchemaName == schemaName && secrets[i].DatabaseName == databaseName {
			res, err := newMqlSnowflakeSecret(runtime, secrets[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("snowflake.secret %q not found in %s.%s", name, databaseName, schemaName)
}

func (r *mqlSnowflakeAccount) secrets() ([]any, error) {
	return listSnowflakeSecrets(r.MqlRuntime, sdk.ExtendedIn{Account: new(true)})
}

func (r *mqlSnowflakeDatabase) secrets() ([]any, error) {
	return listSnowflakeSecrets(r.MqlRuntime, sdk.ExtendedIn{Database: sdk.NewAccountObjectIdentifier(r.Name.Data)})
}

// listSnowflakeSecrets fetches secrets within the given scope (account-wide or a
// single database) and maps them to resources.
func listSnowflakeSecrets(runtime *plugin.Runtime, in sdk.ExtendedIn) ([]any, error) {
	conn := runtime.Connection.(*connection.SnowflakeConnection)
	secrets, err := conn.Client().Secrets.Show(context.Background(),
		sdk.NewShowSecretRequest().WithIn(in))
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(secrets))
	for i := range secrets {
		mqlSecret, err := newMqlSnowflakeSecret(runtime, secrets[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlSecret)
	}

	return list, nil
}

func newMqlSnowflakeSecret(runtime *plugin.Runtime, secret sdk.Secret) (*mqlSnowflakeSecret, error) {
	comment := ""
	if secret.Comment != nil {
		comment = *secret.Comment
	}

	scopes := make([]any, 0, len(secret.OauthScopes))
	for _, s := range secret.OauthScopes {
		scopes = append(scopes, s)
	}

	r, err := CreateResource(runtime, "snowflake.secret", map[string]*llx.RawData{
		"__id":          llx.StringData(secret.ID().FullyQualifiedName()),
		"name":          llx.StringData(secret.Name),
		"databaseName":  llx.StringData(secret.DatabaseName),
		"schemaName":    llx.StringData(secret.SchemaName),
		"owner":         llx.StringData(secret.Owner),
		"ownerRoleType": llx.StringData(secret.OwnerRoleType),
		"comment":       llx.StringData(comment),
		"secretType":    llx.StringData(secret.SecretType),
		"oauthScopes":   llx.ArrayData(scopes, types.String),
		"createdAt":     llx.TimeData(secret.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeSecret), nil
}

func (r *mqlSnowflakeSecret) gatherDescribe() error {
	if r.descLoaded {
		return r.descLoadErr
	}
	r.descLock.Lock()
	defer r.descLock.Unlock()
	if r.descLoaded {
		return r.descLoadErr
	}

	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	details, err := client.Secrets.Describe(ctx,
		sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data),
	)
	if err != nil {
		r.descLoaded = true
		r.descLoadErr = err
		return err
	}

	if details.Username != nil {
		r.descUsername = *details.Username
	}
	if details.IntegrationName != nil {
		r.descIntegration = *details.IntegrationName
	}
	r.descAccessExp = details.OauthAccessTokenExpiryTime
	r.descRefreshExp = details.OauthRefreshTokenExpiryTime

	r.descLoaded = true
	return nil
}

func (r *mqlSnowflakeSecret) username() (string, error) {
	if err := r.gatherDescribe(); err != nil {
		return "", err
	}
	return r.descUsername, nil
}

func (r *mqlSnowflakeSecret) integrationName() (string, error) {
	if err := r.gatherDescribe(); err != nil {
		return "", err
	}
	return r.descIntegration, nil
}

func (r *mqlSnowflakeSecret) oauthAccessTokenExpiryTime() (*time.Time, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	if r.descAccessExp == nil {
		r.OauthAccessTokenExpiryTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.descAccessExp, nil
}

func (r *mqlSnowflakeSecret) oauthRefreshTokenExpiryTime() (*time.Time, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	if r.descRefreshExp == nil {
		r.OauthRefreshTokenExpiryTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.descRefreshExp, nil
}
