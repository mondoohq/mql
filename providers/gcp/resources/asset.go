// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectAssetServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) assetInventory() (*mqlGcpProjectAssetService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.assetService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_cloudasset)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectAssetService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_cloudasset).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectAssetService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	if args == nil {
		args = make(map[string]*llx.RawData)
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectAssetService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.assetService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectAssetServiceResource) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectAssetServiceIamPolicy) id() (string, error) {
	return g.Resource.Data, g.Resource.Error
}

func (g *mqlGcpProjectAssetService) resources() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(asset.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := asset.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
		Scope:    fmt.Sprintf("projects/%s", projectId),
		PageSize: 500,
	})

	var res []any
	for {
		r, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not search Cloud Asset Inventory resources")
				break
			}
			return nil, err
		}

		var additionalAttributes any
		if r.AdditionalAttributes != nil {
			additionalAttributes = r.AdditionalAttributes.AsMap()
		}

		mqlRes, err := CreateResource(g.MqlRuntime, "gcp.project.assetService.resource", map[string]*llx.RawData{
			"name":                   llx.StringData(r.Name),
			"assetType":              llx.StringData(r.AssetType),
			"displayName":            llx.StringData(r.DisplayName),
			"description":            llx.StringData(r.Description),
			"location":               llx.StringData(r.Location),
			"project":                llx.StringData(r.Project),
			"organization":           llx.StringData(r.Organization),
			"folders":                llx.ArrayData(convert.SliceAnyToInterface(r.Folders), types.String),
			"createTime":             llx.TimeDataPtr(timestampAsTimePtr(r.CreateTime)),
			"updateTime":             llx.TimeDataPtr(timestampAsTimePtr(r.UpdateTime)),
			"state":                  llx.StringData(r.State),
			"labels":                 llx.MapData(convert.MapToInterfaceMap(r.Labels), types.String),
			"networkTags":            llx.ArrayData(convert.SliceAnyToInterface(r.NetworkTags), types.String),
			"parentFullResourceName": llx.StringData(r.ParentFullResourceName),
			"additionalAttributes":   llx.DictData(additionalAttributes),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRes)
	}

	return res, nil
}

func (g *mqlGcpProjectAssetService) iamPolicies() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(asset.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := asset.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.SearchAllIamPolicies(ctx, &assetpb.SearchAllIamPoliciesRequest{
		Scope:    fmt.Sprintf("projects/%s", projectId),
		PageSize: 500,
	})

	var res []any
	for {
		r, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not search Cloud Asset Inventory IAM policies")
				break
			}
			return nil, err
		}

		bindings := make([]any, 0, len(r.GetPolicy().GetBindings()))
		// Index-suffixed: a policy can hold several bindings for the same role
		// that differ only by condition, so a role-keyed id collapses them.
		for i, b := range r.GetPolicy().GetBindings() {
			mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
				"id":                   llx.StringData(r.Resource + "-" + strconv.Itoa(i)),
				"role":                 llx.StringData(b.GetRole()),
				"members":              llx.ArrayData(convert.SliceAnyToInterface(b.GetMembers()), types.String),
				"conditionTitle":       llx.StringData(b.GetCondition().GetTitle()),
				"conditionExpression":  llx.StringData(b.GetCondition().GetExpression()),
				"conditionDescription": llx.StringData(b.GetCondition().GetDescription()),
			})
			if err != nil {
				return nil, err
			}
			bindings = append(bindings, mqlBinding)
		}

		mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.assetService.iamPolicy", map[string]*llx.RawData{
			"resource":     llx.StringData(r.Resource),
			"assetType":    llx.StringData(r.AssetType),
			"project":      llx.StringData(r.Project),
			"organization": llx.StringData(r.Organization),
			"folders":      llx.ArrayData(convert.SliceAnyToInterface(r.Folders), types.String),
			"bindings":     llx.ArrayData(bindings, types.Resource("gcp.resourcemanager.binding")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}

	return res, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectAssetService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_cloudasset)
}
