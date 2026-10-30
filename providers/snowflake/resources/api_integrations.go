// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeApiIntegrationInternal struct {
	descLock    sync.Mutex
	descLoaded  bool
	descProps   map[string]string
	descLoadErr error
}

func (r *mqlSnowflakeAccount) apiIntegrations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	integrations, err := client.ApiIntegrations.Show(ctx, sdk.NewShowApiIntegrationRequest())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range integrations {
		mqlIntegration, err := newMqlSnowflakeApiIntegration(r.MqlRuntime, integrations[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlIntegration)
	}

	return list, nil
}

func newMqlSnowflakeApiIntegration(runtime *plugin.Runtime, integration sdk.ApiIntegration) (*mqlSnowflakeApiIntegration, error) {
	r, err := CreateResource(runtime, "snowflake.apiIntegration", map[string]*llx.RawData{
		"__id":      llx.StringData(integration.ID().FullyQualifiedName()),
		"name":      llx.StringData(integration.Name),
		"type":      llx.StringData(integration.ApiType),
		"category":  llx.StringData(integration.Category),
		"enabled":   llx.BoolData(integration.Enabled),
		"comment":   llx.StringData(integration.Comment),
		"createdAt": llx.TimeData(integration.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeApiIntegration), nil
}

func (r *mqlSnowflakeApiIntegration) describeProperties() (map[string]string, error) {
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

	props, err := client.ApiIntegrations.Describe(ctx, sdk.NewAccountObjectIdentifier(r.Name.Data))
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

func (r *mqlSnowflakeApiIntegration) properties() (map[string]any, error) {
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

// splitPrefixes parses Snowflake's bracketed prefix list. Snowflake renders
// these as e.g. "[https://api.example.com/, https://other.example.com/]".
// Splits on ", " (comma-space) — the actual Snowflake delimiter — so URLs
// containing literal commas survive intact.
func splitPrefixes(value string) []any {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if value == "" {
		return []any{}
	}
	parts := strings.Split(value, ", ")
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (r *mqlSnowflakeApiIntegration) apiAllowedPrefixes() ([]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	return splitPrefixes(props["API_ALLOWED_PREFIXES"]), nil
}

func (r *mqlSnowflakeApiIntegration) apiBlockedPrefixes() ([]any, error) {
	props, err := r.describeProperties()
	if err != nil {
		return nil, err
	}
	return splitPrefixes(props["API_BLOCKED_PREFIXES"]), nil
}

func (r *mqlSnowflakeApiIntegration) apiAwsRoleArn() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props["API_AWS_ROLE_ARN"], nil
}

func (r *mqlSnowflakeApiIntegration) apiAwsExternalId() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props["API_AWS_EXTERNAL_ID"], nil
}

func (r *mqlSnowflakeApiIntegration) azureTenantId() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props["AZURE_TENANT_ID"], nil
}

func (r *mqlSnowflakeApiIntegration) azureAdApplicationId() (string, error) {
	props, err := r.describeProperties()
	if err != nil {
		return "", err
	}
	return props["AZURE_AD_APPLICATION_ID"], nil
}
