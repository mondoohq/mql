// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	modelarmor "cloud.google.com/go/modelarmor/apiv1"
	"cloud.google.com/go/modelarmor/apiv1/modelarmorpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mqlGcpProjectModelArmorServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) modelArmor() (*mqlGcpProjectModelArmorService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.modelArmorService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_modelarmor)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectModelArmorService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_modelarmor).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectModelArmorService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	args = map[string]*llx.RawData{
		"projectId": llx.StringData(conn.ResourceID()),
	}
	return args, nil, nil
}

func (g *mqlGcpProjectModelArmorService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/modelArmorService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectModelArmorService) templates() ([]any, error) {
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
	creds, err := conn.Credentials(modelarmor.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := modelarmor.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListTemplates(ctx, &modelarmorpb.ListTemplatesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		template, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, err
		}

		mqlTemplate, err := newMqlModelArmorServiceTemplate(g.MqlRuntime, projectId, template)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTemplate)
	}

	return res, nil
}

// newMqlModelArmorServiceTemplate maps a Model Armor Template proto into the MQL
// resource. Shared by templates() and the discovered-asset init.
func newMqlModelArmorServiceTemplate(runtime *plugin.Runtime, projectId string, template *modelarmorpb.Template) (*mqlGcpProjectModelArmorServiceTemplate, error) {
	filterConfig, err := protoToDict(template.FilterConfig)
	if err != nil {
		return nil, err
	}
	templateMetadata, err := protoToDict(template.TemplateMetadata)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.modelArmorService.template", map[string]*llx.RawData{
		"name":             llx.StringData(template.Name),
		"projectId":        llx.StringData(projectId),
		"createdAt":        llx.TimeDataPtr(timestampAsTimePtr(template.CreateTime)),
		"updatedAt":        llx.TimeDataPtr(timestampAsTimePtr(template.UpdateTime)),
		"labels":           llx.MapData(convert.MapToInterfaceMap(template.Labels), types.String),
		"filterConfig":     llx.DictData(filterConfig),
		"templateMetadata": llx.DictData(templateMetadata),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectModelArmorServiceTemplate), nil
}

// initGcpProjectModelArmorServiceTemplate resolves a single Model Armor template.
// When invoked for a discovered gcp-modelarmor-template asset (no args), it
// reconstructs the resource name from the asset identifier and fetches it so the
// asset resolves to exactly one template instead of an empty husk.
func initGcpProjectModelArmorServiceTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Fully populated (e.g., from CreateResource in templates()); nothing to do.
	if len(args) > 1 {
		return args, nil, nil
	}
	if args == nil {
		args = make(map[string]*llx.RawData)
	}

	// Resolve from the asset identifier when accessed as a discovered asset.
	if len(args) == 0 {
		ids := getAssetIdentifier(runtime)
		if ids == nil {
			return nil, nil, errors.New("no asset identifier found")
		}
		args["name"] = llx.StringData(fmt.Sprintf("projects/%s/locations/%s/templates/%s", ids.project, ids.region, ids.name))
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.modelArmorService.template requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.modelArmorService.template requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	projectId := parseProjectFromPath(name)
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. Memoized per project, so this is free after the first caller.
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_modelarmor); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Model Armor API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(modelarmor.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := modelarmor.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	template, err := client.GetTemplate(ctx, &modelarmorpb.GetTemplateRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}

	res, err := newMqlModelArmorServiceTemplate(runtime, parseProjectFromPath(name), template)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (g *mqlGcpProjectModelArmorServiceTemplate) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectModelArmorServiceFloorSetting) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectModelArmorService) floorSetting() (*mqlGcpProjectModelArmorServiceFloorSetting, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		g.FloorSetting.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}

	fs, err := getModelArmorFloorSetting(g.MqlRuntime, modelArmorFloorSettingName("projects/"+g.ProjectId.Data))
	if err != nil {
		// Through v14 a refused project floor setting keeps reading as null,
		// as it did in v13.
		if !plugin.StructuredErrors() && (errors.Is(err, llx.ErrForbidden) || errors.Is(err, llx.ErrNotApplicable)) {
			g.FloorSetting.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	if fs == nil {
		g.FloorSetting.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return fs, nil
}

func (g *mqlGcpOrganization) modelArmorFloorSetting() (*mqlGcpProjectModelArmorServiceFloorSetting, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	// g.Id.Data is "organizations/{id}" per initGcpOrganization
	fs, err := getModelArmorFloorSetting(g.MqlRuntime, modelArmorFloorSettingName(g.Id.Data))
	if err != nil {
		return nil, err
	}
	if fs == nil {
		g.ModelArmorFloorSetting.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return fs, nil
}

func (g *mqlGcpFolder) modelArmorFloorSetting() (*mqlGcpProjectModelArmorServiceFloorSetting, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	fs, err := getModelArmorFloorSetting(g.MqlRuntime, modelArmorFloorSettingName(folderResourceName(g.Id.Data)))
	if err != nil {
		return nil, err
	}
	if fs == nil {
		g.ModelArmorFloorSetting.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return fs, nil
}

// modelArmorFloorSettingName returns the floor setting resource name for a
// project, folder, or organization parent ("projects/p", "folders/f",
// "organizations/o"). Floor settings only exist in the global location.
func modelArmorFloorSettingName(parent string) string {
	return parent + "/locations/global/floorSetting"
}

// getModelArmorFloorSetting fetches the floor setting with the given resource
// name. It returns nil, nil when none is configured on that parent. A refused
// call is returned classified: an API that is not enabled is NotApplicable, a
// denied one Forbidden.
func getModelArmorFloorSetting(runtime *plugin.Runtime, name string) (*mqlGcpProjectModelArmorServiceFloorSetting, error) {
	conn := runtime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(modelarmor.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := modelarmor.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	fs, err := client.GetFloorSetting(ctx, &modelarmorpb.GetFloorSettingRequest{Name: name})
	if err != nil {
		if rerr := classifyRefusal(err, "modelarmor.floorSettings.get"); rerr != nil {
			return nil, rerr
		}
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	return newMqlModelArmorFloorSetting(runtime, fs)
}

// newMqlModelArmorFloorSetting maps a Model Armor FloorSetting proto into the
// MQL resource. The resource name carries the parent, so the floor settings of
// a project, a folder, and an organization never share a cache entry.
func newMqlModelArmorFloorSetting(runtime *plugin.Runtime, fs *modelarmorpb.FloorSetting) (*mqlGcpProjectModelArmorServiceFloorSetting, error) {
	filterConfig, err := protoToDict(fs.FilterConfig)
	if err != nil {
		return nil, err
	}
	aiPlatformFloorSetting, err := protoToDict(fs.AiPlatformFloorSetting)
	if err != nil {
		return nil, err
	}
	googleMcpServerFloorSetting, err := protoToDict(fs.GoogleMcpServerFloorSetting)
	if err != nil {
		return nil, err
	}
	floorSettingMetadata, err := protoToDict(fs.FloorSettingMetadata)
	if err != nil {
		return nil, err
	}

	integratedServices := make([]any, 0, len(fs.IntegratedServices))
	for _, is := range fs.IntegratedServices {
		integratedServices = append(integratedServices, is.String())
	}

	res, err := CreateResource(runtime, "gcp.project.modelArmorService.floorSetting", map[string]*llx.RawData{
		"name":                          llx.StringData(fs.Name),
		"filterConfig":                  llx.DictData(filterConfig),
		"enableFloorSettingEnforcement": llx.BoolData(fs.GetEnableFloorSettingEnforcement()),
		"integratedServices":            llx.ArrayData(integratedServices, types.String),
		"aiPlatformFloorSetting":        llx.DictData(aiPlatformFloorSetting),
		"googleMcpServerFloorSetting":   llx.DictData(googleMcpServerFloorSetting),
		"floorSettingMetadata":          llx.DictData(floorSettingMetadata),
		"created":                       llx.TimeDataPtr(timestampAsTimePtr(fs.CreateTime)),
		"updated":                       llx.TimeDataPtr(timestampAsTimePtr(fs.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectModelArmorServiceFloorSetting), nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectModelArmorService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_modelarmor)
}
