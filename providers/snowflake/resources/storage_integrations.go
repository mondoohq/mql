// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeStorageIntegrationInternal struct {
	descLock    sync.Mutex
	descLoaded  bool
	descProps   map[string]string
	descLoadErr error
}

func (r *mqlSnowflakeAccount) storageIntegrations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	integrations, err := client.StorageIntegrations.Show(ctx, sdk.NewShowStorageIntegrationRequest())
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(integrations))
	for i := range integrations {
		mqlIntegration, err := newMqlSnowflakeStorageIntegration(r.MqlRuntime, integrations[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlIntegration)
	}

	return list, nil
}

func newMqlSnowflakeStorageIntegration(runtime *plugin.Runtime, integration sdk.StorageIntegration) (*mqlSnowflakeStorageIntegration, error) {
	r, err := CreateResource(runtime, "snowflake.storageIntegration", map[string]*llx.RawData{
		"__id":      llx.StringData(integration.ID().FullyQualifiedName()),
		"name":      llx.StringData(integration.Name),
		"type":      llx.StringData(integration.StorageType),
		"category":  llx.StringData(integration.Category),
		"enabled":   llx.BoolData(integration.Enabled),
		"comment":   llx.StringData(integration.Comment),
		"createdAt": llx.TimeData(integration.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeStorageIntegration), nil
}

func (r *mqlSnowflakeStorageIntegration) describeProperties() (map[string]string, error) {
	if r.descLoaded {
		return r.descProps, r.descLoadErr
	}
	r.descLock.Lock()
	defer r.descLock.Unlock()
	if r.descLoaded {
		return r.descProps, r.descLoadErr
	}

	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	props, err := client.StorageIntegrations.Describe(ctx, sdk.NewAccountObjectIdentifier(r.Name.Data))
	if err != nil {
		r.descLoaded = true
		r.descLoadErr = err
		return nil, err
	}

	out := make(map[string]string, len(props))
	for _, p := range props {
		out[p.Name] = p.Value
	}
	r.descProps = out
	r.descLoaded = true
	return out, nil
}

func (r *mqlSnowflakeStorageIntegration) properties() (map[string]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		out[k] = v
	}
	return out, nil
}

func (r *mqlSnowflakeStorageIntegration) prop(key string) (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props[key], nil
}

func (r *mqlSnowflakeStorageIntegration) storageProvider() (string, error) {
	return r.prop("STORAGE_PROVIDER")
}

func (r *mqlSnowflakeStorageIntegration) storageAllowedLocations() ([]any, error) {
	v, err := r.prop("STORAGE_ALLOWED_LOCATIONS")
	if err != nil {
		return nil, err
	}
	return splitCommaList(v), nil
}

func (r *mqlSnowflakeStorageIntegration) storageBlockedLocations() ([]any, error) {
	v, err := r.prop("STORAGE_BLOCKED_LOCATIONS")
	if err != nil {
		return nil, err
	}
	return splitCommaList(v), nil
}

func (r *mqlSnowflakeStorageIntegration) storageAwsRoleArn() (string, error) {
	return r.prop("STORAGE_AWS_ROLE_ARN")
}

func (r *mqlSnowflakeStorageIntegration) storageAwsIamUserArn() (string, error) {
	return r.prop("STORAGE_AWS_IAM_USER_ARN")
}

func (r *mqlSnowflakeStorageIntegration) storageAwsExternalId() (string, error) {
	return r.prop("STORAGE_AWS_EXTERNAL_ID")
}

func (r *mqlSnowflakeStorageIntegration) storageGcpServiceAccount() (string, error) {
	return r.prop("STORAGE_GCP_SERVICE_ACCOUNT")
}

func (r *mqlSnowflakeStorageIntegration) azureTenantId() (string, error) {
	return r.prop("AZURE_TENANT_ID")
}

func (r *mqlSnowflakeStorageIntegration) azureConsentUrl() (string, error) {
	return r.prop("AZURE_CONSENT_URL")
}

func (r *mqlSnowflakeStorageIntegration) azureMultiTenantAppName() (string, error) {
	return r.prop("AZURE_MULTI_TENANT_APP_NAME")
}

// initSnowflakeStorageIntegration resolves a storage integration by name so
// typed references (such as snowflake.stage.storageIntegration) can hydrate a
// full integration from just its name.
func initSnowflakeStorageIntegration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("snowflake.storageIntegration requires a non-empty name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	integrations, err := client.StorageIntegrations.Show(ctx, sdk.NewShowStorageIntegrationRequest().WithLike(sdk.Like{Pattern: new(name)}))
	if err != nil {
		return nil, nil, err
	}
	for i := range integrations {
		if integrations[i].Name == name {
			res, err := newMqlSnowflakeStorageIntegration(runtime, integrations[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("snowflake.storageIntegration %q not found", name)
}
