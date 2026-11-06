// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	dlp "cloud.google.com/go/dlp/apiv2"
	"cloud.google.com/go/dlp/apiv2/dlppb"
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
	locationpb "google.golang.org/genproto/googleapis/cloud/location"
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

// modelArmorLocations is the fallback list of Model Armor template
// locations (the us and eu multi-regions and the regions), used when the
// project's ListLocations call fails. Last updated: 2026-11.
// See: https://docs.cloud.google.com/model-armor/locations
var modelArmorLocations = []string{
	"us", "eu",
	"asia-northeast1", "asia-northeast3", "asia-south1", "asia-southeast1",
	"australia-southeast2", "northamerica-northeast2", "southamerica-east1",
	"us-central1", "us-east1", "us-east4", "us-west1",
	"europe-southwest1", "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west9",
}

// modelArmorEndpoint returns the regional or multi-regional endpoint that
// serves templates in a location. The global endpoint only serves floor
// settings, so templates must be read through the endpoint of their location.
func modelArmorEndpoint(location string) string {
	return fmt.Sprintf("modelarmor.%s.rep.googleapis.com:443", location)
}

// modelArmorTemplateLocations keeps the location IDs that hold templates,
// dropping "global" (floor settings only) and duplicates.
func modelArmorTemplateLocations(ids []string) []string {
	seen := map[string]bool{}
	res := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" || id == "global" || seen[id] {
			continue
		}
		seen[id] = true
		res = append(res, id)
	}
	return res
}

// listAcrossModelArmorLocations runs fn for every location and merges the
// results. A location that fails is logged and skipped so the others are
// still reported; when every location fails, the first error is returned,
// classified if it is a refusal.
func listAcrossModelArmorLocations(locations []string, fn func(location string) ([]any, error)) ([]any, error) {
	res := []any{}
	var firstErr error
	failed := 0
	for _, location := range locations {
		items, err := fn(location)
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			log.Warn().Err(err).Str("location", location).
				Msg("model armor template listing failed, continuing with the remaining locations")
			continue
		}
		res = append(res, items...)
	}
	if len(locations) > 0 && failed == len(locations) {
		return listRefusal(firstErr, "cannot list model armor templates", "modelarmor.templates.list")
	}
	return res, nil
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
	locations := modelArmorLocations
	if globalClient, err := modelarmor.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption()); err == nil {
		var ids []string
		it := globalClient.ListLocations(ctx, &locationpb.ListLocationsRequest{Name: "projects/" + projectId})
		for {
			l, err := it.Next()
			if errors.Is(err, iterator.Done) {
				if found := modelArmorTemplateLocations(ids); len(found) > 0 {
					locations = found
				}
				break
			}
			if err != nil {
				log.Debug().Err(err).Msg("model armor: could not list locations, using the built-in location list")
				break
			}
			ids = append(ids, l.GetLocationId())
		}
		globalClient.Close()
	}

	return listAcrossModelArmorLocations(locations, func(location string) ([]any, error) {
		client, err := modelarmor.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(modelArmorEndpoint(location)))
		if err != nil {
			return nil, err
		}
		defer client.Close()

		it := client.ListTemplates(ctx, &modelarmorpb.ListTemplatesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, location),
		})
		var res []any
		for {
			template, err := it.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					return res, nil
				}
				return nil, err
			}
			mqlTemplate, err := newMqlModelArmorServiceTemplate(g.MqlRuntime, projectId, template)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTemplate)
		}
		return res, nil
	})
}

// newMqlModelArmorServiceTemplate maps a Model Armor Template proto into the MQL
// resource. Shared by templates() and the discovered-asset init.
func newMqlModelArmorServiceTemplate(runtime *plugin.Runtime, projectId string, template *modelarmorpb.Template) (*mqlGcpProjectModelArmorServiceTemplate, error) {
	cfg := modelArmorTemplateConfigOf(template)
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
		"location":         llx.StringData(modelArmorLocationFromName(template.Name)),

		"sdpBasicEnabled":               llx.BoolData(cfg.sdpBasicEnabled),
		"piAndJailbreakFilterEnabled":   llx.BoolData(cfg.piAndJailbreakEnabled),
		"piAndJailbreakConfidenceLevel": llx.StringData(cfg.piAndJailbreakConfidence),
		"maliciousUriFilterEnabled":     llx.BoolData(cfg.maliciousUriEnabled),
		"csamFilterEnabled":             llx.BoolData(cfg.csamEnabled),
		"enforcementType":               llx.StringData(cfg.enforcementType),
		"logSanitizeOperations":         llx.BoolData(template.GetTemplateMetadata().GetLogSanitizeOperations()),
		"logTemplateOperations":         llx.BoolData(template.GetTemplateMetadata().GetLogTemplateOperations()),
	})
	if err != nil {
		return nil, err
	}
	mqlT := res.(*mqlGcpProjectModelArmorServiceTemplate)
	mqlT.cacheInspectTemplate = cfg.inspectTemplate
	mqlT.cacheDeidentifyTemplate = cfg.deidentifyTemplate
	mqlT.cacheRaiFilters = cfg.raiFilters
	return mqlT, nil
}

type mqlGcpProjectModelArmorServiceTemplateInternal struct {
	cacheInspectTemplate    string
	cacheDeidentifyTemplate string
	cacheRaiFilters         []modelArmorRaiFilter
}

type modelArmorRaiFilter struct {
	filterType      string
	confidenceLevel string
}

// modelArmorTemplateConfig is the typed view of a template's filters. A
// filter whose settings are absent is not enabled.
type modelArmorTemplateConfig struct {
	sdpBasicEnabled          bool
	inspectTemplate          string
	deidentifyTemplate       string
	piAndJailbreakEnabled    bool
	piAndJailbreakConfidence string
	maliciousUriEnabled      bool
	csamEnabled              bool
	raiFilters               []modelArmorRaiFilter
	enforcementType          string
}

func modelArmorTemplateConfigOf(t *modelarmorpb.Template) modelArmorTemplateConfig {
	var c modelArmorTemplateConfig
	fc := t.GetFilterConfig()
	sdp := fc.GetSdpSettings()
	c.sdpBasicEnabled = sdp.GetBasicConfig().GetFilterEnforcement() == modelarmorpb.SdpBasicConfig_ENABLED
	c.inspectTemplate = sdp.GetAdvancedConfig().GetInspectTemplate()
	c.deidentifyTemplate = sdp.GetAdvancedConfig().GetDeidentifyTemplate()
	pi := fc.GetPiAndJailbreakFilterSettings()
	c.piAndJailbreakEnabled = pi.GetFilterEnforcement() == modelarmorpb.PiAndJailbreakFilterSettings_ENABLED
	if pi.GetConfidenceLevel() != modelarmorpb.DetectionConfidenceLevel_DETECTION_CONFIDENCE_LEVEL_UNSPECIFIED {
		c.piAndJailbreakConfidence = pi.GetConfidenceLevel().String()
	}
	c.maliciousUriEnabled = fc.GetMaliciousUriFilterSettings().GetFilterEnforcement() == modelarmorpb.MaliciousUriFilterSettings_ENABLED
	c.csamEnabled = fc.GetCsamFilterSettings().GetFilterEnforcement() == modelarmorpb.CsamFilterSettings_ENABLED
	c.raiFilters = []modelArmorRaiFilter{}
	for _, f := range fc.GetRaiSettings().GetRaiFilters() {
		if f == nil {
			continue
		}
		rf := modelArmorRaiFilter{filterType: f.GetFilterType().String()}
		if f.GetConfidenceLevel() != modelarmorpb.DetectionConfidenceLevel_DETECTION_CONFIDENCE_LEVEL_UNSPECIFIED {
			rf.confidenceLevel = f.GetConfidenceLevel().String()
		}
		c.raiFilters = append(c.raiFilters, rf)
	}
	if et := t.GetTemplateMetadata().GetEnforcementType(); et != modelarmorpb.Template_TemplateMetadata_ENFORCEMENT_TYPE_UNSPECIFIED {
		c.enforcementType = et.String()
	}
	return c
}

// modelArmorLocationFromName reads the location of a
// projects/{p}/locations/{l}/templates/{t} name.
func modelArmorLocationFromName(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

func (g *mqlGcpProjectModelArmorServiceTemplate) raiFilters() ([]any, error) {
	res := make([]any, 0, len(g.cacheRaiFilters))
	for i, f := range g.cacheRaiFilters {
		r, err := CreateResource(g.MqlRuntime, "gcp.project.modelArmorService.template.raiFilter", map[string]*llx.RawData{
			"__id":            llx.StringData(fmt.Sprintf("%s/raiFilters/%d", g.Name.Data, i)),
			"filterType":      llx.StringData(f.filterType),
			"confidenceLevel": llx.StringData(f.confidenceLevel),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGcpProjectModelArmorServiceTemplate) inspectTemplate() (*mqlGcpProjectDlpServiceInspectTemplate, error) {
	if g.cacheInspectTemplate == "" {
		g.InspectTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()
	tmpl, err := client.GetInspectTemplate(ctx, &dlppb.GetInspectTemplateRequest{Name: g.cacheInspectTemplate})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			g.InspectTemplate.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	inspectConfig, err := protoToDict(tmpl.InspectConfig)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.inspectTemplate", map[string]*llx.RawData{
		"name":          llx.StringData(tmpl.Name),
		"displayName":   llx.StringData(tmpl.DisplayName),
		"description":   llx.StringData(tmpl.Description),
		"inspectConfig": llx.DictData(inspectConfig),
		"created":       llx.TimeDataPtr(timestampAsTimePtr(tmpl.CreateTime)),
		"updated":       llx.TimeDataPtr(timestampAsTimePtr(tmpl.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDlpServiceInspectTemplate), nil
}

func (g *mqlGcpProjectModelArmorServiceTemplate) deidentifyTemplate() (*mqlGcpProjectDlpServiceDeidentifyTemplate, error) {
	if g.cacheDeidentifyTemplate == "" {
		g.DeidentifyTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(dlp.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := dlp.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()
	tmpl, err := client.GetDeidentifyTemplate(ctx, &dlppb.GetDeidentifyTemplateRequest{Name: g.cacheDeidentifyTemplate})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			g.DeidentifyTemplate.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	deidentifyConfig, err := protoToDict(tmpl.DeidentifyConfig)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.dlpService.deidentifyTemplate", map[string]*llx.RawData{
		"name":             llx.StringData(tmpl.Name),
		"displayName":      llx.StringData(tmpl.DisplayName),
		"description":      llx.StringData(tmpl.Description),
		"deidentifyConfig": llx.DictData(deidentifyConfig),
		"created":          llx.TimeDataPtr(timestampAsTimePtr(tmpl.CreateTime)),
		"updated":          llx.TimeDataPtr(timestampAsTimePtr(tmpl.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDlpServiceDeidentifyTemplate), nil
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
	client, err := modelarmor.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(modelArmorEndpoint(modelArmorLocationFromName(name))))
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
