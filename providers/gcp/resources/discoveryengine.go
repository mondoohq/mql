// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	discoveryengine "cloud.google.com/go/discoveryengine/apiv1"
	"cloud.google.com/go/discoveryengine/apiv1/discoveryenginepb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
)

// discoveryEngineLocations lists the Discovery Engine multi-region locations.
// Unlike Vertex AI, Discovery Engine resources live in these three locations
// only. See https://docs.cloud.google.com/generative-ai-app-builder/docs/locations
var discoveryEngineLocations = []string{"global", "us", "eu"}

// defaultDiscoveryEngineCollection is the built-in collection that hosts data
// stores and engines. The API has no method to enumerate collections, so we
// scan the default collection that the console and most deployments use.
const defaultDiscoveryEngineCollection = "default_collection"

// discoveryEngineEndpoint returns the regional API endpoint for a location.
func discoveryEngineEndpoint(location string) string {
	if location == "global" {
		return "discoveryengine.googleapis.com:443"
	}
	return fmt.Sprintf("%s-discoveryengine.googleapis.com:443", location)
}

// discoveryEngineLocationFromName extracts the location from a Discovery Engine
// resource name of the form projects/{project}/locations/{location}/....
func discoveryEngineLocationFromName(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

func (g *mqlGcpProject) discoveryEngine() (*mqlGcpProjectDiscoveryEngineService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.discoveryEngineService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_discoveryengine)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectDiscoveryEngineService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_discoveryengine).Msg("gcp service is not enabled, skipping")
	}
	return svc, nil
}

type mqlGcpProjectDiscoveryEngineServiceInternal struct {
	serviceGate
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectDiscoveryEngineService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_discoveryengine)
}

// listAcrossDiscoveryEngineLocations runs fn for every Discovery Engine
// location and merges the results. A location that fails is logged and
// skipped so the other locations' resources are still reported; the error is
// returned only when every location failed.
func listAcrossDiscoveryEngineLocations(kind string, locations []string, fn func(location string) ([]any, error)) ([]any, error) {
	var (
		items    = []any{}
		firstErr error
		failed   int
	)
	for _, location := range locations {
		locationItems, err := fn(location)
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			log.Warn().Err(err).Str("kind", kind).Str("location", location).
				Msg("discovery engine location listing failed, continuing with the remaining locations")
			continue
		}
		items = append(items, locationItems...)
	}
	if len(locations) > 0 && failed == len(locations) {
		return nil, firstErr
	}
	return items, nil
}

func initGcpProjectDiscoveryEngineService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectDiscoveryEngineService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/discoveryEngineService", g.ProjectId.Data), nil
}

// newMqlDiscoveryEngineDataStore maps a Discovery Engine DataStore proto into an
// MQL resource. Shared by the dataStores() lister and engine.dataStores().
func newMqlDiscoveryEngineDataStore(runtime *plugin.Runtime, ds *discoveryenginepb.DataStore) (*mqlGcpProjectDiscoveryEngineServiceDataStore, error) {
	solutionTypes := make([]any, 0, len(ds.SolutionTypes))
	for _, st := range ds.SolutionTypes {
		solutionTypes = append(solutionTypes, st.String())
	}

	// Enum fields are reported only when their message is present: a data
	// store without a CMEK config or a Workspace config reads as empty, not
	// as the enum's zero value.
	var cmekState string
	if cfg := ds.GetCmekConfig(); cfg != nil {
		cmekState = cfg.GetState().String()
	}
	var workspaceType string
	if ws := ds.GetWorkspaceConfig(); ws != nil {
		workspaceType = ws.GetType().String()
	}

	res, err := CreateResource(runtime, "gcp.project.discoveryEngineService.dataStore", map[string]*llx.RawData{
		"name":                     llx.StringData(ds.Name),
		"displayName":              llx.StringData(ds.DisplayName),
		"industryVertical":         llx.StringData(ds.IndustryVertical.String()),
		"solutionTypes":            llx.ArrayData(solutionTypes, types.String),
		"contentConfig":            llx.StringData(ds.ContentConfig.String()),
		"defaultSchemaId":          llx.StringData(ds.DefaultSchemaId),
		"aclEnabled":               llx.BoolData(ds.AclEnabled),
		"kmsKeyName":               llx.StringData(ds.KmsKeyName),
		"cmekState":                llx.StringData(cmekState),
		"workspaceType":            llx.StringData(workspaceType),
		"workspaceSuperAdminEmail": llx.StringData(ds.GetWorkspaceConfig().GetSuperAdminEmailAddress()),
		"createdAt":                llx.TimeDataPtr(timestampAsTimePtr(ds.CreateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlDs := res.(*mqlGcpProjectDiscoveryEngineServiceDataStore)
	mqlDs.cacheKmsKeyName = ds.KmsKeyName
	mqlDs.cacheSuperAdminServiceAccount = ds.GetWorkspaceConfig().GetSuperAdminServiceAccount()
	mqlDs.cacheProjectId = projectFromResourceName(ds.Name)
	mqlDs.cacheSensitiveDataProtectionPolicy = ds.GetDataProtectionPolicy().GetSensitiveDataProtectionPolicy().GetPolicy()
	return mqlDs, nil
}

func (g *mqlGcpProjectDiscoveryEngineService) listDataStoresInLocation(ctx context.Context, creds *googleoauth.Credentials, projectId, location string) ([]any, error) {
	client, err := discoveryengine.NewDataStoreClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(location)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var items []any
	it := client.ListDataStores(ctx, &discoveryenginepb.ListDataStoresRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s/collections/%s", projectId, location, defaultDiscoveryEngineCollection),
	})
	for {
		ds, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				break
			}
			return nil, err
		}
		mqlDs, err := newMqlDiscoveryEngineDataStore(g.MqlRuntime, ds)
		if err != nil {
			return nil, err
		}
		items = append(items, mqlDs)
	}
	return items, nil
}

func (g *mqlGcpProjectDiscoveryEngineService) dataStores() ([]any, error) {
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
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	return listAcrossDiscoveryEngineLocations("dataStores", discoveryEngineLocations, func(location string) ([]any, error) {
		return g.listDataStoresInLocation(ctx, creds, projectId, location)
	})
}

func (g *mqlGcpProjectDiscoveryEngineServiceDataStore) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpProjectDiscoveryEngineServiceDataStoreInternal struct {
	cacheKmsKeyName               string
	cacheSuperAdminServiceAccount string
	cacheProjectId                string
	// resource name of the Sensitive Data Protection content policy
	cacheSensitiveDataProtectionPolicy string
}

func (a *mqlGcpProjectDiscoveryEngineServiceDataStore) sensitiveDataProtectionPolicy() (*mqlGcpProjectDlpServiceContentPolicy, error) {
	if a.cacheSensitiveDataProtectionPolicy == "" {
		a.SensitiveDataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	cp, err := getDlpContentPolicyByName(a.MqlRuntime, a.cacheSensitiveDataProtectionPolicy)
	if err != nil {
		return nil, err
	}
	if cp == nil {
		a.SensitiveDataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return cp, nil
}

func (a *mqlGcpProjectDiscoveryEngineServiceDataStore) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectDiscoveryEngineServiceDataStore) workspaceSuperAdminServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	email := a.cacheSuperAdminServiceAccount
	projectId := serviceAccountProjectFromEmail(email)
	if projectId == "" {
		projectId = a.cacheProjectId
	}
	return vertexaiServiceAccountRef(a.MqlRuntime, &a.WorkspaceSuperAdminServiceAccount, projectId, email)
}

// serviceAccountProjectFromEmail returns the project that owns a user-managed
// service account, read from its "{name}@{project}.iam.gserviceaccount.com"
// address. Any other address, including a Google-managed service agent's,
// yields "", leaving the caller to fall back to a project it already knows.
func serviceAccountProjectFromEmail(email string) string {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return ""
	}
	project, ok := strings.CutSuffix(domain, ".iam.gserviceaccount.com")
	// Google-managed service agents live in gcp-sa-* projects that the
	// customer cannot list.
	if !ok || project == "" || strings.Contains(project, ".") || strings.HasPrefix(project, "gcp-sa-") {
		return ""
	}
	return project
}

func (g *mqlGcpProjectDiscoveryEngineService) listEnginesInLocation(ctx context.Context, creds *googleoauth.Credentials, projectId, location string) ([]any, error) {
	client, err := discoveryengine.NewEngineClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(location)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var items []any
	it := client.ListEngines(ctx, &discoveryenginepb.ListEnginesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s/collections/%s", projectId, location, defaultDiscoveryEngineCollection),
	})
	for {
		engine, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				break
			}
			return nil, err
		}

		posture := discoveryEngineEnginePostureOf(engine)
		mqlEngine, err := CreateResource(g.MqlRuntime, "gcp.project.discoveryEngineService.engine", map[string]*llx.RawData{
			"name":                       llx.StringData(engine.Name),
			"displayName":                llx.StringData(engine.DisplayName),
			"solutionType":               llx.StringData(engine.SolutionType.String()),
			"industryVertical":           llx.StringData(engine.IndustryVertical.String()),
			"disableAnalytics":           llx.BoolData(engine.DisableAnalytics),
			"appType":                    llx.StringData(posture.appType),
			"features":                   llx.MapData(posture.features, types.String),
			"modelConfigs":               llx.MapData(posture.modelConfigs, types.String),
			"observabilityEnabled":       llx.BoolDataPtr(posture.observabilityEnabled),
			"sensitiveLoggingEnabled":    llx.BoolDataPtr(posture.sensitiveLoggingEnabled),
			"marketplaceAgentVisibility": llx.StringData(posture.marketplaceAgentVisibility),
			"createdAt":                  llx.TimeDataPtr(timestampAsTimePtr(engine.CreateTime)),
			"updatedAt":                  llx.TimeDataPtr(timestampAsTimePtr(engine.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlEngineRes := mqlEngine.(*mqlGcpProjectDiscoveryEngineServiceEngine)
		mqlEngineRes.cacheDataStoreIds = engine.DataStoreIds
		mqlEngineRes.cacheKmsKeyName = engine.GetCmekConfig().GetKmsKey()
		items = append(items, mqlEngine)
	}
	return items, nil
}

func (g *mqlGcpProjectDiscoveryEngineService) engines() ([]any, error) {
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
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	return listAcrossDiscoveryEngineLocations("engines", discoveryEngineLocations, func(location string) ([]any, error) {
		return g.listEnginesInLocation(ctx, creds, projectId, location)
	})
}

func (g *mqlGcpProjectDiscoveryEngineServiceEngine) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

type mqlGcpProjectDiscoveryEngineServiceEngineInternal struct {
	cacheDataStoreIds []string
	cacheKmsKeyName   string
}

// discoveryEngineEnginePosture is the security posture an engine reports
// inline. Enum values are reported only when set: an unspecified enum reads
// as empty, and an absent observability config as null.
type discoveryEngineEnginePosture struct {
	appType                    string
	features                   map[string]any
	modelConfigs               map[string]any
	observabilityEnabled       *bool
	sensitiveLoggingEnabled    *bool
	marketplaceAgentVisibility string
}

func discoveryEngineEnginePostureOf(engine *discoveryenginepb.Engine) discoveryEngineEnginePosture {
	p := discoveryEngineEnginePosture{
		features:     map[string]any{},
		modelConfigs: map[string]any{},
	}
	if engine.GetAppType() != discoveryenginepb.Engine_APP_TYPE_UNSPECIFIED {
		p.appType = engine.GetAppType().String()
	}
	for k, v := range engine.GetFeatures() {
		p.features[k] = v.String()
	}
	for k, v := range engine.GetModelConfigs() {
		p.modelConfigs[k] = v.String()
	}
	if cfg := engine.GetObservabilityConfig(); cfg != nil {
		obs, sens := cfg.GetObservabilityEnabled(), cfg.GetSensitiveLoggingEnabled()
		p.observabilityEnabled = &obs
		p.sensitiveLoggingEnabled = &sens
	}
	if v := engine.GetMarketplaceAgentVisibility(); v != discoveryenginepb.Engine_MARKETPLACE_AGENT_VISIBILITY_UNSPECIFIED {
		p.marketplaceAgentVisibility = v.String()
	}
	return p
}

func (g *mqlGcpProjectDiscoveryEngineServiceEngine) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, g.cacheKmsKeyName)
}

func (g *mqlGcpProjectDiscoveryEngineServiceEngine) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := discoveryengine.NewEngineClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(discoveryEngineLocationFromName(name))),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: name,
		Options:  &iampb.GetPolicyOptions{RequestedPolicyVersion: 3},
	})
	if err != nil {
		return listRefusal(err, "cannot read discovery engine app IAM policy", "discoveryengine.engines.getIamPolicy")
	}
	return iampbBindingsToMql(g.MqlRuntime, name, policy.GetBindings())
}

// public is null when the IAM policy could not be read: a refusal must not
// read as "not public".
func (g *mqlGcpProjectDiscoveryEngineServiceEngine) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	if bindings.Data == nil {
		g.Public.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

// discoveryEngineDefaultWidgetConfigId is the ID the console gives the
// widget configuration it creates with every app.
const discoveryEngineDefaultWidgetConfigId = "default_search_widget_config"

func (g *mqlGcpProjectDiscoveryEngineServiceEngine) widgetConfig() (*mqlGcpProjectDiscoveryEngineServiceWidgetConfig, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	engineName := g.Name.Data
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := discoveryengine.NewWidgetConfigClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(discoveryEngineLocationFromName(engineName))),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	wc, err := client.GetWidgetConfig(ctx, &discoveryenginepb.GetWidgetConfigRequest{
		Name: engineName + "/widgetConfigs/" + discoveryEngineDefaultWidgetConfigId,
	})
	if err != nil {
		if s, ok := grpcStatusOf(err); ok && s.Code() == codes.NotFound {
			g.WidgetConfig.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		rerr := classifyRefusal(err, "discoveryengine.widgetConfigs.get")
		if rerr == nil {
			return nil, err
		}
		if !plugin.StructuredErrors() {
			log.Warn().Err(err).Msg("cannot read discovery engine widget config")
			g.WidgetConfig.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, rerr
	}

	access := wc.GetAccessSettings()
	res, err := CreateResource(g.MqlRuntime, "gcp.project.discoveryEngineService.widgetConfig", map[string]*llx.RawData{
		"name":                          llx.StringData(wc.GetName()),
		"allowPublicAccess":             llx.BoolData(access.GetAllowPublicAccess()),
		"enableWebApp":                  llx.BoolData(access.GetEnableWebApp()),
		"allowlistedDomains":            llx.ArrayData(convert.SliceAnyToInterface(access.GetAllowlistedDomains()), types.String),
		"workforceIdentityPoolProvider": llx.StringData(access.GetWorkforceIdentityPoolProvider()),
		"llmEnabled":                    llx.BoolData(wc.GetLlmEnabled()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDiscoveryEngineServiceWidgetConfig), nil
}

func (g *mqlGcpProjectDiscoveryEngineServiceWidgetConfig) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDiscoveryEngineServiceEngine) assistants() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	engineName := g.Name.Data
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := discoveryengine.NewAssistantClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(discoveryEngineLocationFromName(engineName))),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	res := []any{}
	it := client.ListAssistants(ctx, &discoveryenginepb.ListAssistantsRequest{Parent: engineName})
	for {
		a, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				break
			}
			return listRefusal(err, "cannot list discovery engine assistants", "discoveryengine.assistants.list")
		}
		mqlA, err := newMqlDiscoveryEngineAssistant(g.MqlRuntime, a)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlA)
	}
	return res, nil
}

type mqlGcpProjectDiscoveryEngineServiceAssistantInternal struct {
	cachePromptTemplate   string
	cacheResponseTemplate string
	cacheContentPolicy    string
}

// discoveryEngineAssistantPolicy is the typed view of an assistant's
// customer policy and tools.
type discoveryEngineAssistantPolicy struct {
	promptTemplate   string
	responseTemplate string
	failureMode      string
	bannedPhrases    []string
	contentPolicy    string
	webGroundingType string
	enabledTools     []string
}

func discoveryEngineAssistantPolicyOf(a *discoveryenginepb.Assistant) discoveryEngineAssistantPolicy {
	var p discoveryEngineAssistantPolicy
	cp := a.GetCustomerPolicy()
	if ma := cp.GetModelArmorConfig(); ma != nil {
		p.promptTemplate = ma.GetUserPromptTemplate()
		p.responseTemplate = ma.GetResponseTemplate()
		if ma.GetFailureMode() != discoveryenginepb.Assistant_CustomerPolicy_ModelArmorConfig_FAILURE_MODE_UNSPECIFIED {
			p.failureMode = ma.GetFailureMode().String()
		}
	}
	p.bannedPhrases = make([]string, 0, len(cp.GetBannedPhrases()))
	for _, bp := range cp.GetBannedPhrases() {
		p.bannedPhrases = append(p.bannedPhrases, bp.GetPhrase())
	}
	p.contentPolicy = cp.GetDataProtectionPolicy().GetSensitiveDataProtectionPolicy().GetPolicy()
	if a.GetWebGroundingType() != discoveryenginepb.Assistant_WEB_GROUNDING_TYPE_UNSPECIFIED {
		p.webGroundingType = a.GetWebGroundingType().String()
	}
	connectors := make([]string, 0, len(a.GetEnabledTools()))
	for c := range a.GetEnabledTools() {
		connectors = append(connectors, c)
	}
	sort.Strings(connectors)
	p.enabledTools = []string{}
	for _, c := range connectors {
		for _, ti := range a.GetEnabledTools()[c].GetToolInfo() {
			p.enabledTools = append(p.enabledTools, ti.GetToolName())
		}
	}
	return p
}

func newMqlDiscoveryEngineAssistant(runtime *plugin.Runtime, a *discoveryenginepb.Assistant) (*mqlGcpProjectDiscoveryEngineServiceAssistant, error) {
	p := discoveryEngineAssistantPolicyOf(a)
	res, err := CreateResource(runtime, "gcp.project.discoveryEngineService.assistant", map[string]*llx.RawData{
		"name":                  llx.StringData(a.GetName()),
		"displayName":           llx.StringData(a.GetDisplayName()),
		"description":           llx.StringData(a.GetDescription()),
		"modelArmorFailureMode": llx.StringData(p.failureMode),
		"bannedPhrases":         llx.ArrayData(convert.SliceAnyToInterface(p.bannedPhrases), types.String),
		"webGroundingType":      llx.StringData(p.webGroundingType),
		"enabledTools":          llx.ArrayData(convert.SliceAnyToInterface(p.enabledTools), types.String),
		"createdAt":             llx.TimeDataPtr(timestampAsTimePtr(a.GetCreateTime())),
		"updatedAt":             llx.TimeDataPtr(timestampAsTimePtr(a.GetUpdateTime())),
	})
	if err != nil {
		return nil, err
	}
	mqlA := res.(*mqlGcpProjectDiscoveryEngineServiceAssistant)
	mqlA.cachePromptTemplate = p.promptTemplate
	mqlA.cacheResponseTemplate = p.responseTemplate
	mqlA.cacheContentPolicy = p.contentPolicy
	return mqlA, nil
}

func (g *mqlGcpProjectDiscoveryEngineServiceAssistant) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectDiscoveryEngineServiceAssistant) modelArmorPromptTemplate() (*mqlGcpProjectModelArmorServiceTemplate, error) {
	return modelArmorTemplateRef(g.MqlRuntime, &g.ModelArmorPromptTemplate, g.cachePromptTemplate)
}

func (g *mqlGcpProjectDiscoveryEngineServiceAssistant) modelArmorResponseTemplate() (*mqlGcpProjectModelArmorServiceTemplate, error) {
	return modelArmorTemplateRef(g.MqlRuntime, &g.ModelArmorResponseTemplate, g.cacheResponseTemplate)
}

// modelArmorTemplateRef resolves a Model Armor template by its full resource
// name, marking the field null when no template is set.
func modelArmorTemplateRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectModelArmorServiceTemplate], name string) (*mqlGcpProjectModelArmorServiceTemplate, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.modelArmorService.template", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectModelArmorServiceTemplate), nil
}

func (g *mqlGcpProjectDiscoveryEngineServiceAssistant) sensitiveDataProtectionPolicy() (*mqlGcpProjectDlpServiceContentPolicy, error) {
	if g.cacheContentPolicy == "" {
		g.SensitiveDataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	cp, err := getDlpContentPolicyByName(g.MqlRuntime, g.cacheContentPolicy)
	if err != nil {
		return nil, err
	}
	if cp == nil {
		g.SensitiveDataProtectionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return cp, nil
}

func (g *mqlGcpProjectDiscoveryEngineServiceEngine) dataStores() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	if len(g.cacheDataStoreIds) == 0 {
		return []any{}, nil
	}

	engineName := g.Name.Data
	location := discoveryEngineLocationFromName(engineName)
	// The collection parent is the engine name up to and excluding "/engines/...".
	collectionParent := engineName
	if before, _, ok := strings.Cut(engineName, "/engines/"); ok {
		collectionParent = before
	}
	if location == "" || collectionParent == engineName {
		return []any{}, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(discoveryengine.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := discoveryengine.NewDataStoreClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(discoveryEngineEndpoint(location)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	items := make([]any, 0, len(g.cacheDataStoreIds))
	for _, id := range g.cacheDataStoreIds {
		ds, err := client.GetDataStore(ctx, &discoveryenginepb.GetDataStoreRequest{
			Name: fmt.Sprintf("%s/dataStores/%s", collectionParent, id),
		})
		if err != nil {
			if isInapplicable(err) {
				continue
			}
			return nil, err
		}
		mqlDs, err := newMqlDiscoveryEngineDataStore(g.MqlRuntime, ds)
		if err != nil {
			return nil, err
		}
		items = append(items, mqlDs)
	}
	return items, nil
}
