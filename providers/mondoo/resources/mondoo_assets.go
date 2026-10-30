// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	mondoogql "go.mondoo.com/mondoo-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
	"go.mondoo.com/mql/providers/mondoo/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

func (m *mqlMondooAsset) id() (string, error) {
	return m.Mrn.Data, nil
}

type gqlAsset struct {
	ID                  string
	Mrn                 string
	State               string
	Name                string
	AssetType           string `graphql:"asset_type"`
	UpdatedAt           *string
	LastScoreUpdateTime *string
	// Annotations map[string]string
	Annotations []keyValue
	Labels      []keyValue
	Score       struct {
		Grade string
		Value int
	}
}

func initMondooAsset(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	// if asset is only initialized with a mrn, we will try to look it up
	rawMrn, mrnOk := args["mrn"]
	if !mrnOk {
		return args, nil, nil
	}

	// fetch the asset from mondoo
	conn := runtime.Connection.(*connection.Connection)
	asset, err := fetchAssetByMrn(context.Background(), conn, rawMrn.Value.(string))
	if err != nil {
		return nil, nil, err
	}

	args["name"] = llx.StringData(asset.Name)
	args["mrn"] = llx.StringData(asset.Mrn)
	args["platform"] = llx.StringData(asset.AssetType)
	args["state"] = llx.StringData(asset.State)
	args["annotations"] = llx.MapData(keyvals2map(asset.Annotations), types.Map(types.String, types.String))
	args["labels"] = llx.MapData(keyvals2map(asset.Labels), types.Map(types.String, types.String))
	args["updatedAt"] = llx.TimeDataPtr(string2time(asset.UpdatedAt))
	args["lastScoreUpdateTime"] = llx.TimeDataPtr(string2time(asset.LastScoreUpdateTime))
	args["scoreGrade"] = llx.StringData(asset.Score.Grade)
	args["scoreValue"] = llx.IntData(asset.Score.Value)

	return args, nil, nil
}

func fetchAssetByMrn(ctx context.Context, conn *connection.Connection, mrn string) (*gqlAsset, error) {
	var q struct {
		Asset gqlAsset `graphql:"asset(mrn: $mrn)"`
	}
	vars := map[string]any{
		"mrn": mondoogql.String(mrn),
	}

	if err := conn.Client.Query(ctx, &q, vars); err != nil {
		return nil, err
	}

	return &q.Asset, nil
}

func (m *mqlMondooAsset) resources() ([]any, error) {
	conn := m.MqlRuntime.Connection.(*connection.Connection)
	upstream := conn.Upstream

	explorer, err := recording.NewRemoteServices(upstream.ApiEndpoint, upstream.Plugins, upstream.HttpClient)
	if err != nil {
		return nil, err
	}

	list, err := explorer.ListResources(context.Background(), &recording.ListResourcesReq{
		EntityMrn: m.Mrn.Data,
	})
	if err != nil {
		return nil, multierr.Wrap(err, "failed to list resources for asset "+m.Mrn.Data)
	}

	res := make([]any, len(list.Resources))
	for i := range list.Resources {
		resource := list.Resources[i]
		raw, err := CreateResource(m.MqlRuntime, "mondoo.resource", map[string]*llx.RawData{
			"name": llx.StringData(resource.Resource),
			"id":   llx.StringData(resource.Id),
		})
		if err != nil {
			return nil, multierr.Wrap(err, "failed to initialize resource on Mondoo asset "+m.Mrn.Data)
		}
		res[i] = raw
	}

	return res, nil
}

func (m *mqlMondooResource) id() (string, error) {
	return m.Name.Data + "/" + m.Id.Data, nil
}
