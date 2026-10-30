// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/tailscale/connection"
	"go.mondoo.com/mql/types"
	tsclient "tailscale.com/client/tailscale/v2"
)

func (r *mqlTailscaleWebhook) id() (string, error) {
	return "tailscale/webhook/" + r.EndpointId.Data, nil
}

func initTailscaleWebhook(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requiredStringArg(args, "endpointId")
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.TailscaleConnection)
	wh, err := conn.Client().Webhooks().Get(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}

	resource, err := createTailscaleWebhookResource(runtime, wh)
	if err != nil {
		return nil, nil, err
	}

	return args, resource, nil
}

func createTailscaleWebhookResource(runtime *plugin.Runtime, wh *tsclient.Webhook) (plugin.Resource, error) {
	subs := make([]any, 0, len(wh.Subscriptions))
	for _, s := range wh.Subscriptions {
		subs = append(subs, string(s))
	}
	return CreateResource(runtime, "tailscale.webhook", map[string]*llx.RawData{
		"endpointId":       llx.StringData(wh.EndpointID),
		"endpointUrl":      llx.StringData(wh.EndpointURL),
		"providerType":     llx.StringData(string(wh.ProviderType)),
		"creatorLoginName": llx.StringData(wh.CreatorLoginName),
		"created":          llx.TimeDataPtr(optionalTimeValue(wh.Created)),
		"lastModified":     llx.TimeDataPtr(optionalTimeValue(wh.LastModified)),
		"subscriptions":    llx.ArrayData(subs, types.String),
	})
}

func (t *mqlTailscale) webhooks() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)
	hooks, err := conn.Client().Webhooks().List(context.Background())
	if err != nil {
		return nil, err
	}

	resources := []any{}
	for i := range hooks {
		resource, err := createTailscaleWebhookResource(t.MqlRuntime, &hooks[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}
