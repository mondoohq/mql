// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/datadog/connection"
	"go.mondoo.com/mql/types"
)

// Cloud integrations are standing credentials Datadog holds against another
// provider, so the fields modeled here describe what the grant reaches and how
// it authenticates. The credentials themselves (Azure client secrets, GCP
// private keys, Okta API tokens, Fastly and Confluent API keys) are
// deliberately never mapped: Datadog redacts most of them on read, and a
// redacted-but-present field reads as "no secret configured" when it actually
// means "not shown".

// --- Google Cloud ---

func (r *mqlDatadog) integrationGcpAccounts() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewGCPIntegrationApi(conn.ApiClient())

	resp, httpResp, err := api.ListGCPSTSAccounts(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> Google Cloud integrations not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []interface{}
	for _, acc := range resp.GetData() {
		attrs := acc.GetAttributes()
		meta := acc.GetMeta()

		res, err := CreateResource(r.MqlRuntime, "datadog.integration.gcp", map[string]*llx.RawData{
			"id":                                   llx.StringData(acc.GetId()),
			"clientEmail":                          llx.StringData(attrs.GetClientEmail()),
			"accessibleProjects":                   llx.ArrayData(toAnyStrings(meta.GetAccessibleProjects()), "\x02"),
			"isCspmEnabled":                        llx.BoolData(attrs.GetIsCspmEnabled()),
			"isSecurityCommandCenterEnabled":       llx.BoolData(attrs.GetIsSecurityCommandCenterEnabled()),
			"resourceCollectionEnabled":            llx.BoolData(attrs.GetResourceCollectionEnabled()),
			"isResourceChangeCollectionEnabled":    llx.BoolData(attrs.GetIsResourceChangeCollectionEnabled()),
			"isPerProjectQuotaEnabled":             llx.BoolData(attrs.GetIsPerProjectQuotaEnabled()),
			"isGlobalLocationEnabled":              llx.BoolData(attrs.GetIsGlobalLocationEnabled()),
			"isOrgFolderResourceCollectionEnabled": llx.BoolDataPtr(attrs.IsOrgFolderResourceCollectionEnabled),
			"automute":                             llx.BoolData(attrs.GetAutomute()),
			"hostFilters":                          llx.ArrayData(toAnyStrings(attrs.GetHostFilters()), "\x02"),
			"cloudRunRevisionFilters":              llx.ArrayData(toAnyStrings(attrs.GetCloudRunRevisionFilters()), "\x02"),
			"regionFilterConfigs":                  llx.ArrayData(toAnyStrings(attrs.GetRegionFilterConfigs()), "\x02"),
			"accountTags":                          llx.ArrayData(toAnyStrings(attrs.GetAccountTags()), "\x02"),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}

	return all, nil
}

func (r *mqlDatadogIntegrationGcp) id() (string, error) {
	return "datadog.integration.gcp/" + r.Id.Data, nil
}

// --- Azure ---

func (r *mqlDatadog) integrationAzureAccounts() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV1.NewAzureIntegrationApi(conn.ApiClient())

	accounts, httpResp, err := api.ListAzureIntegration(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> Azure integrations not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []interface{}
	for _, acc := range accounts {
		// Azure integrations carry no server-assigned identifier. The tenant
		// and application pair is what uniquely names the app registration
		// Datadog authenticates with, so it forms the cache key. Both halves
		// are already exposed as fields, which is why no synthetic id field
		// is declared.
		res, err := CreateResource(r.MqlRuntime, "datadog.integration.azure", map[string]*llx.RawData{
			"__id":                      llx.StringData("datadog.integration.azure/" + acc.GetTenantName() + "/" + acc.GetClientId()),
			"tenantName":                llx.StringData(acc.GetTenantName()),
			"clientId":                  llx.StringData(acc.GetClientId()),
			"secretlessAuthEnabled":     llx.BoolData(acc.GetSecretlessAuthEnabled()),
			"cspmEnabled":               llx.BoolData(acc.GetCspmEnabled()),
			"resourceCollectionEnabled": llx.BoolData(acc.GetResourceCollectionEnabled()),
			"metricsEnabled":            llx.BoolData(acc.GetMetricsEnabled()),
			"customMetricsEnabled":      llx.BoolData(acc.GetCustomMetricsEnabled()),
			"usageMetricsEnabled":       llx.BoolData(acc.GetUsageMetricsEnabled()),
			"automute":                  llx.BoolData(acc.GetAutomute()),
			"hostFilters":               llx.StringData(acc.GetHostFilters()),
			"appServicePlanFilters":     llx.StringData(acc.GetAppServicePlanFilters()),
			"containerAppFilters":       llx.StringData(acc.GetContainerAppFilters()),
			"errors":                    llx.ArrayData(toAnyStrings(acc.GetErrors()), "\x02"),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}

	return all, nil
}

// --- Okta ---

func (r *mqlDatadog) integrationOktaAccounts() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewOktaIntegrationApi(conn.ApiClient())

	resp, httpResp, err := api.ListOktaAccounts(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> Okta integrations not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []interface{}
	for _, acc := range resp.GetData() {
		attrs := acc.GetAttributes()
		res, err := CreateResource(r.MqlRuntime, "datadog.integration.okta", map[string]*llx.RawData{
			"id":         llx.StringData(acc.GetId()),
			"name":       llx.StringData(attrs.GetName()),
			"domain":     llx.StringData(attrs.GetDomain()),
			"authMethod": llx.StringData(attrs.GetAuthMethod()),
			"clientId":   llx.StringData(attrs.GetClientId()),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}

	return all, nil
}

func (r *mqlDatadogIntegrationOkta) id() (string, error) {
	return "datadog.integration.okta/" + r.Id.Data, nil
}

// --- Cloudflare ---

func (r *mqlDatadog) integrationCloudflareAccounts() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewCloudflareIntegrationApi(conn.ApiClient())

	resp, httpResp, err := api.ListCloudflareAccounts(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> Cloudflare integrations not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []interface{}
	for _, acc := range resp.GetData() {
		attrs := acc.GetAttributes()
		res, err := CreateResource(r.MqlRuntime, "datadog.integration.cloudflare", map[string]*llx.RawData{
			"id":        llx.StringData(acc.GetId()),
			"name":      llx.StringData(attrs.GetName()),
			"email":     llx.StringData(attrs.GetEmail()),
			"resources": llx.ArrayData(toAnyStrings(attrs.GetResources()), "\x02"),
			"zones":     llx.ArrayData(toAnyStrings(attrs.GetZones()), "\x02"),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}

	return all, nil
}

func (r *mqlDatadogIntegrationCloudflare) id() (string, error) {
	return "datadog.integration.cloudflare/" + r.Id.Data, nil
}

// --- Fastly ---

func (r *mqlDatadog) integrationFastlyAccounts() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewFastlyIntegrationApi(conn.ApiClient())

	resp, httpResp, err := api.ListFastlyAccounts(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> Fastly integrations not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []interface{}
	for _, acc := range resp.GetData() {
		attrs := acc.GetAttributes()

		// Dict values cross the plugin boundary as JSON, so the tag slice has
		// to be widened to []interface{} rather than passed as []string.
		services := make([]interface{}, 0, len(attrs.GetServices()))
		for _, svc := range attrs.GetServices() {
			services = append(services, map[string]interface{}{
				"id":   svc.GetId(),
				"tags": toAnyStrings(svc.GetTags()),
			})
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.integration.fastly", map[string]*llx.RawData{
			"id":       llx.StringData(acc.GetId()),
			"name":     llx.StringData(attrs.GetName()),
			"services": llx.ArrayData(services, "\x13"),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}

	return all, nil
}

func (r *mqlDatadogIntegrationFastly) id() (string, error) {
	return "datadog.integration.fastly/" + r.Id.Data, nil
}

// --- Confluent Cloud ---

func (r *mqlDatadog) integrationConfluentAccounts() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewConfluentCloudApi(conn.ApiClient())

	resp, httpResp, err := api.ListConfluentAccount(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> Confluent Cloud integrations not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []interface{}
	for _, acc := range resp.GetData() {
		attrs := acc.GetAttributes()

		resources := make([]interface{}, 0, len(attrs.GetResources()))
		for _, cr := range attrs.GetResources() {
			resources = append(resources, map[string]interface{}{
				"id":                  cr.GetId(),
				"resourceType":        cr.GetResourceType(),
				"enableCustomMetrics": cr.GetEnableCustomMetrics(),
				"tags":                toAnyStrings(cr.GetTags()),
			})
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.integration.confluent", map[string]*llx.RawData{
			"id":        llx.StringData(acc.GetId()),
			"tags":      llx.ArrayData(toAnyStrings(attrs.GetTags()), "\x02"),
			"resources": llx.ArrayData(resources, "\x13"),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}

	return all, nil
}

func (r *mqlDatadogIntegrationConfluent) id() (string, error) {
	return "datadog.integration.confluent/" + r.Id.Data, nil
}

// --- Snowflake and Databricks ---

// integrationDataflows reads which collections an integration account has
// switched on. Datadog names each collection by its wire key (for example
// snowflake-security-logs) and the SDK gives every one its own field, so the
// response is read back through its JSON form: that keeps collections the SDK
// does not model yet, which land in AdditionalProperties, instead of silently
// dropping them. A collection reported without an enabled state is left out
// rather than reported as disabled.
func integrationDataflows(dataflows interface{}) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	if dataflows == nil {
		return out, nil
	}
	raw, err := json.Marshal(dataflows)
	if err != nil {
		return nil, err
	}
	var flows map[string]json.RawMessage
	if err := json.Unmarshal(raw, &flows); err != nil {
		return nil, err
	}
	for name, body := range flows {
		var flow struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.Unmarshal(body, &flow); err != nil || flow.Enabled == nil {
			continue
		}
		out[name] = *flow.Enabled
	}
	return out, nil
}

// unparsedAuthType reads auth_type out of an authentication object the SDK
// could not match to one of its known methods. Datadog may add methods, and
// the discriminator still names them even when the rest of the shape is new.
func unparsedAuthType(unparsed interface{}) *string {
	m, ok := unparsed.(map[string]interface{})
	if !ok {
		return nil
	}
	s, ok := m["auth_type"].(string)
	if !ok || s == "" {
		return nil
	}
	return &s
}

func snowflakeAuthType(auth *datadogV2.SnowflakeIntegrationAccountAuthenticationResponse) *string {
	if auth == nil {
		return nil
	}
	if pk := auth.SnowflakeIntegrationAccountPrivateKeyAuthResponse; pk != nil {
		s := string(pk.AuthType)
		return &s
	}
	return unparsedAuthType(auth.UnparsedObject)
}

// databricksAuth returns the authentication method and, for OAuth, the client
// ID of the service principal. Datadog never returns the token or the client
// secret, and neither is read here.
func databricksAuth(auth *datadogV2.DatabricksIntegrationAccountAuthenticationResponse) (authType *string, clientId *string) {
	if auth == nil {
		return nil, nil
	}
	switch {
	case auth.DatabricksIntegrationAccountOAuthAuthResponse != nil:
		o := auth.DatabricksIntegrationAccountOAuthAuthResponse
		s := string(o.AuthType)
		id := o.ClientId
		return &s, &id
	case auth.DatabricksIntegrationAccountPrivateActionRunnerAuthResponse != nil:
		s := string(auth.DatabricksIntegrationAccountPrivateActionRunnerAuthResponse.AuthType)
		return &s, nil
	case auth.DatabricksIntegrationAccountBearerTokenAuthResponse != nil:
		s := string(auth.DatabricksIntegrationAccountBearerTokenAuthResponse.AuthType)
		return &s, nil
	}
	return unparsedAuthType(auth.UnparsedObject), nil
}

func snowflakeAccountArgs(acc datadogV2.SnowflakeIntegrationAccountResponseData) (map[string]*llx.RawData, error) {
	attrs := acc.GetAttributes()
	settings := attrs.GetSettings()

	var dataflows interface{}
	if attrs.Dataflows != nil {
		dataflows = attrs.Dataflows
	}
	flows, err := integrationDataflows(dataflows)
	if err != nil {
		return nil, err
	}

	return map[string]*llx.RawData{
		"id":                llx.StringData(acc.GetId()),
		"name":              llx.StringData(attrs.GetName()),
		"accountIdentifier": llx.StringData(settings.GetSnowflakeAccountIdentifier()),
		"username":          llx.StringData(settings.GetUsername()),
		"authType":          llx.StringDataPtr(snowflakeAuthType(attrs.Authentication)),
		"dataflows":         llx.MapData(flows, types.Bool),
	}, nil
}

func databricksAccountArgs(acc datadogV2.DatabricksIntegrationAccountResponseData) (map[string]*llx.RawData, error) {
	attrs := acc.GetAttributes()
	settings := attrs.GetSettings()

	var dataflows interface{}
	if attrs.Dataflows != nil {
		dataflows = attrs.Dataflows
	}
	flows, err := integrationDataflows(dataflows)
	if err != nil {
		return nil, err
	}

	authType, clientId := databricksAuth(attrs.Authentication)
	return map[string]*llx.RawData{
		"id":           llx.StringData(acc.GetId()),
		"name":         llx.StringData(attrs.GetName()),
		"workspaceUrl": llx.StringData(settings.GetWorkspaceUrl()),
		"authType":     llx.StringDataPtr(authType),
		"clientId":     llx.StringDataPtr(clientId),
		"dataflows":    llx.MapData(flows, types.Bool),
	}, nil
}

func (r *mqlDatadog) integrationSnowflakeAccounts() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewSnowflakeIntegrationApi(conn.ApiClient())

	resp, httpResp, err := api.ListSnowflakeIntegrationAccounts(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			return nil, llx.Forbidden(err)
		}
		return nil, err
	}

	var all []interface{}
	for _, acc := range resp.GetData() {
		args, err := snowflakeAccountArgs(acc)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "datadog.integration.snowflake", args)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogIntegrationSnowflake) id() (string, error) {
	return "datadog.integration.snowflake/" + r.Id.Data, nil
}

func (r *mqlDatadog) integrationDatabricksAccounts() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewDatabricksIntegrationApi(conn.ApiClient())

	resp, httpResp, err := api.ListDatabricksIntegrationAccounts(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			return nil, llx.Forbidden(err)
		}
		return nil, err
	}

	var all []interface{}
	for _, acc := range resp.GetData() {
		args, err := databricksAccountArgs(acc)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "datadog.integration.databricks", args)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogIntegrationDatabricks) id() (string, error) {
	return "datadog.integration.databricks/" + r.Id.Data, nil
}
