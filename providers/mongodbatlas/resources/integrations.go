// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// integrationEndpoint picks the destination address out of a third-party
// integration record. The record is a union across every supported service and
// only the fields of the configured kind are populated, so the address lives
// under a different name depending on the kind.
func integrationEndpoint(i admin.ThirdPartyIntegration) *string {
	if i.Url != nil {
		return i.Url
	}
	return i.MicrosoftTeamsWebhookUrl
}

// integrationSendsResourceTags reports whether the integration forwards project
// and cluster resource tags. Datadog reports this under one name and Prometheus
// under another, and only the one matching the configured kind is set.
func integrationSendsResourceTags(i admin.ThirdPartyIntegration) *bool {
	return firstBool(i.SendUserProvidedResourceTags, i.SendUserProvidedResourceTagsEnabled)
}

// thirdPartyIntegrations lists the services the project routes alerts and
// metrics to. Every credential the record carries inline (an API token, an API
// key, a service key, a licence key, a read and a write token, a webhook secret
// and a Prometheus password) is deliberately not read; a destination address is
// reduced to its host, since a webhook URL routinely carries its own token.
func (r *mqlMongodbatlas) thirdPartyIntegrations() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	err = forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.ThirdPartyIntegrationsAPI.
			ListGroupIntegrations(ctx, pid).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			if isAccessDenied(httpResp) {
				r.ThirdPartyIntegrations.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			integration := results[i]
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.thirdPartyIntegration", map[string]*llx.RawData{
				// Atlas allows one integration per type per project, and the
				// type is present on every record while the id is not, so the
				// project and the type are the stable pair.
				"__id":                         llx.StringData("mongodbatlas.thirdPartyIntegration/" + pid + "/" + integration.GetType()),
				"id":                           llx.StringDataPtr(integration.Id),
				"type":                         llx.StringDataPtr(integration.Type),
				"enabled":                      llx.BoolDataPtr(integration.Enabled),
				"region":                       llx.StringDataPtr(integration.Region),
				"endpointHost":                 llx.StringDataPtr(hostPtrOf(integrationEndpoint(integration))),
				"hasSecret":                    llx.BoolData(isSet(integration.Secret)),
				"channelName":                  llx.StringDataPtr(integration.ChannelName),
				"teamName":                     llx.StringDataPtr(integration.TeamName),
				"accountId":                    llx.StringDataPtr(integration.AccountId),
				"username":                     llx.StringDataPtr(integration.Username),
				"serviceDiscovery":             llx.StringDataPtr(integration.ServiceDiscovery),
				"sendCollectionLatencyMetrics": llx.BoolDataPtr(integration.SendCollectionLatencyMetrics),
				"sendDatabaseMetrics":          llx.BoolDataPtr(integration.SendDatabaseMetrics),
				"sendQueryStatsMetrics":        llx.BoolDataPtr(integration.SendQueryStatsMetrics),
				"sendUserProvidedResourceTags": llx.BoolDataPtr(integrationSendsResourceTags(integration)),
			})
			if err != nil {
				return 0, err
			}
			out = append(out, res)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// metricIntegrations lists the project's OpenTelemetry export destinations,
// which Atlas keeps separately from the third-party service integrations. Both
// have to be read to see everywhere project telemetry goes.
func (r *mqlMongodbatlas) metricIntegrations() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	err = forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.MetricIntegrationsAPI.
			ListGroupMetricIntegrations(ctx, pid).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			if isAccessDenied(httpResp) {
				r.MetricIntegrations.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			mi := results[i]

			// Atlas redacts the header values, so only the names are read: a
			// redacted value is still a value nobody needs in a schema.
			headerNames := []string{}
			for _, h := range mi.GetHeadersRedacted() {
				headerNames = append(headerNames, h.GetName())
			}

			endpoint := mi.Endpoint
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.metricIntegration", map[string]*llx.RawData{
				"__id":                   llx.StringData("mongodbatlas.metricIntegration/" + pid + "/" + mi.GetMetricIntegrationId()),
				"id":                     llx.StringData(mi.GetMetricIntegrationId()),
				"integrationType":        llx.StringData(mi.GetIntegrationType()),
				"providerType":           llx.StringData(mi.GetProviderType()),
				"authType":               llx.StringData(mi.GetAuthType()),
				"endpointHost":           llx.StringDataPtr(hostPtrOf(&endpoint)),
				"aggregationTemporality": llx.StringData(mi.GetAggregationTemporality()),
				"metricSelection":        llx.ArrayData(strSlice(mi.GetMetricSelection()), types.String),
				"headerNames":            llx.ArrayData(strSlice(headerNames), types.String),
			})
			if err != nil {
				return 0, err
			}
			out = append(out, res)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
