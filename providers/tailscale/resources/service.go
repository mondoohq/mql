// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/tailscale/connection"
	"go.mondoo.com/mql/types"
	tsclient "tailscale.com/client/tailscale/v2"
)

func (r *mqlTailscaleService) id() (string, error) {
	return "tailscale/service/" + r.Name.Data, nil
}

func initTailscaleService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, err := requiredStringArg(args, "name")
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.TailscaleConnection)
	svc, err := conn.Client().Services().Get(context.Background(), name)
	if err != nil {
		return nil, nil, err
	}

	resource, err := createTailscaleServiceResource(runtime, svc)
	if err != nil {
		return nil, nil, err
	}

	return args, resource, nil
}

func createTailscaleServiceResource(runtime *plugin.Runtime, svc *tsclient.Service) (plugin.Resource, error) {
	annotations := make(map[string]any, len(svc.Annotations))
	for k, v := range svc.Annotations {
		annotations[k] = v
	}

	return CreateResource(runtime, "tailscale.service", map[string]*llx.RawData{
		"name":        llx.StringData(svc.Name),
		"displayName": llx.StringData(svc.DisplayName),
		"addresses":   llx.ArrayData(convert.SliceAnyToInterface(svc.Addrs), types.String),
		"ports":       llx.ArrayData(convert.SliceAnyToInterface(svc.Ports), types.String),
		"tags":        llx.ArrayData(convert.SliceAnyToInterface(svc.Tags), types.String),
		"comment":     llx.StringData(svc.Comment),
		"annotations": llx.MapData(annotations, types.String),
	})
}

// services lists the services published on the tailnet. A 403 means the
// tailnet's plan does not include services or the credential lacks the read
// scope, and a 404 means the endpoint carries nothing for this tailnet. Both
// degrade to an empty list rather than failing the whole query.
func (t *mqlTailscale) services() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)

	svcs, err := conn.Client().Services().List(context.Background())
	if err != nil {
		if connection.IsUnavailable(err) {
			log.Debug().Err(err).Msg("tailscale> no services available for this tailnet")
			return []any{}, nil
		}
		return nil, err
	}

	resources := []any{}
	for i := range svcs {
		resource, err := createTailscaleServiceResource(t.MqlRuntime, &svcs[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}
