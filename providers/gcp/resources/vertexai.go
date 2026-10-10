// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	aiplatform "cloud.google.com/go/aiplatform/apiv1"
	"cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
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

// vertexaiRegions lists the known Vertex AI regions to iterate when listing resources.
// TODO: Replace with a dynamic location listing API call when available to avoid
// missing resources in newly added GCP regions. Last updated: 2026-03.
// See: https://docs.cloud.google.com/gemini-enterprise-agent-platform/machine-learning/general/locations
var vertexaiRegions = []string{
	"us-central1",
	"us-east1",
	"us-east4",
	"us-south1",
	"us-west1",
	"us-west2",
	"us-west4",
	"northamerica-northeast1",
	"northamerica-northeast2",
	"southamerica-east1",
	"europe-central2",
	"europe-north1",
	"europe-southwest1",
	"europe-west1",
	"europe-west2",
	"europe-west3",
	"europe-west4",
	"europe-west6",
	"europe-west8",
	"europe-west9",
	"asia-east1",
	"asia-east2",
	"asia-northeast1",
	"asia-northeast3",
	"asia-south1",
	"asia-southeast1",
	"asia-southeast2",
	"australia-southeast1",
	"australia-southeast2",
	"me-central1",
	"me-central2",
	"me-west1",
	"africa-south1",
}

// vertexaiMaxConcurrency is the maximum number of regions to query concurrently.
const vertexaiMaxConcurrency = 10

func vertexaiEndpoint(region string) string {
	return fmt.Sprintf("%s-aiplatform.googleapis.com:443", region)
}

type mqlGcpProjectVertexaiServiceInternal struct {
	serviceGate
	// skippedRegions tracks regions where the API is not available, keyed by
	// resource kind. It MUST be per-kind: Vertex AI sub-services have very
	// different regional footprints (the RAG data service is available in a
	// handful of regions and reports the rest as FailedPrecondition), so a
	// single shared set lets the narrowest accessor shrink the region list for
	// every other one — silently truncating models, endpoints and jobs.
	skippedRegions map[string]map[string]bool
	lock           sync.Mutex
}

// getRegions returns the list of candidate regions for one resource kind,
// excluding any that kind has previously marked as skipped.
func (g *mqlGcpProjectVertexaiService) getRegions(kind string) []string {
	g.lock.Lock()
	defer g.lock.Unlock()
	skipped := g.skippedRegions[kind]
	if len(skipped) == 0 {
		return vertexaiRegions
	}
	regions := make([]string, 0, len(vertexaiRegions))
	for _, r := range vertexaiRegions {
		if !skipped[r] {
			regions = append(regions, r)
		}
	}
	return regions
}

// markRegionSkipped records a region where the API returned a skippable error
// for one resource kind.
func (g *mqlGcpProjectVertexaiService) markRegionSkipped(kind, region string) {
	g.lock.Lock()
	defer g.lock.Unlock()
	if g.skippedRegions == nil {
		g.skippedRegions = make(map[string]map[string]bool)
	}
	if g.skippedRegions[kind] == nil {
		g.skippedRegions[kind] = make(map[string]bool)
	}
	g.skippedRegions[kind][region] = true
}

// vertexaiRegionResult holds the result of listing resources in a single region.
type vertexaiRegionResult struct {
	items   []any
	skipped bool
	err     error
	region  string
}

func (g *mqlGcpProject) vertexai() (*mqlGcpProjectVertexaiService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_aiplatform)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectVertexaiService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_aiplatform).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectVertexaiService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_aiplatform)
}

func initGcpProjectVertexaiService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (g *mqlGcpProjectVertexaiService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/vertexaiService", g.ProjectId.Data), nil
}

// listAcrossRegions runs fn concurrently across all candidate regions with bounded
// concurrency. It collects results, marks skipped regions, and returns the aggregated items.
func (g *mqlGcpProjectVertexaiService) listAcrossRegions(
	kind string,
	fn func(ctx context.Context, region string) ([]any, bool, error),
) ([]any, error) {
	regions := g.getRegions(kind)
	ctx := context.Background()

	results := make([]vertexaiRegionResult, len(regions))
	sem := make(chan struct{}, vertexaiMaxConcurrency)
	var wg sync.WaitGroup

	for i, region := range regions {
		wg.Add(1)
		go func(idx int, r string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, skipped, err := fn(ctx, r)
			results[idx] = vertexaiRegionResult{items: items, skipped: skipped, err: err, region: r}
		}(i, region)
	}
	wg.Wait()

	// A single region failing must not discard the ~33 that succeeded. Vertex
	// AI fans out over one regional endpoint per region, so any one of them can
	// return Unavailable, DeadlineExceeded or ResourceExhausted independently --
	// none of which isInapplicable covers -- and the whole inventory
	// used to disappear behind it. Only report an error when EVERY region
	// failed, which is the case that actually means "this did not work".
	var (
		res       []any
		firstErr  error
		failed    int
		attempted int
	)
	for _, r := range results {
		attempted++
		if r.err != nil {
			failed++
			if firstErr == nil {
				firstErr = r.err
			}
			log.Warn().Err(r.err).Str("kind", kind).Str("region", r.region).
				Msg("vertexai region listing failed, continuing with the remaining regions")
			continue
		}
		if r.skipped {
			g.markRegionSkipped(kind, r.region)
		}
		res = append(res, r.items...)
	}
	if attempted > 0 && failed == attempted {
		return nil, firstErr
	}
	return res, nil
}

func (g *mqlGcpProjectVertexaiService) models() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("models", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewModelClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListModels(ctx, &aiplatformpb.ListModelsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			model, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			mqlModel, err := newMqlVertexaiModel(g.MqlRuntime, model)
			if err != nil {
				return nil, false, err
			}
			items = append(items, mqlModel)
		}
		return items, false, nil
	})
}

// newMqlVertexaiModel maps a Vertex AI Model proto into an MQL resource. It is
// shared by the models() lister and the deployment.model() reference.
func newMqlVertexaiModel(runtime *plugin.Runtime, model *aiplatformpb.Model) (*mqlGcpProjectVertexaiServiceModel, error) {
	modelSourceInfo, err := protoToDict(model.ModelSourceInfo)
	if err != nil {
		return nil, err
	}
	baseModelSource, err := protoToDict(model.BaseModelSource)
	if err != nil {
		return nil, err
	}
	containerSpec, err := protoToDict(model.ContainerSpec)
	if err != nil {
		return nil, err
	}
	encryptionSpec, err := protoToDict(model.EncryptionSpec)
	if err != nil {
		return nil, err
	}

	deploymentTypes := make([]any, 0, len(model.SupportedDeploymentResourcesTypes))
	for _, dt := range model.SupportedDeploymentResourcesTypes {
		deploymentTypes = append(deploymentTypes, dt.String())
	}

	mqlModel, err := CreateResource(runtime, "gcp.project.vertexaiService.model", map[string]*llx.RawData{
		"name":                              llx.StringData(model.Name),
		"displayName":                       llx.StringData(model.DisplayName),
		"description":                       llx.StringData(model.Description),
		"versionId":                         llx.StringData(model.VersionId),
		"versionAliases":                    llx.ArrayData(convert.SliceAnyToInterface(model.VersionAliases), types.String),
		"versionDescription":                llx.StringData(model.VersionDescription),
		"modelSourceInfo":                   llx.DictData(modelSourceInfo),
		"baseModelSource":                   llx.DictData(baseModelSource),
		"satisfiesPzs":                      llx.BoolData(model.SatisfiesPzs),
		"satisfiesPzi":                      llx.BoolData(model.SatisfiesPzi),
		"containerSpec":                     llx.DictData(containerSpec),
		"supportedDeploymentResourcesTypes": llx.ArrayData(deploymentTypes, types.String),
		"supportedInputStorageFormats":      llx.ArrayData(convert.SliceAnyToInterface(model.SupportedInputStorageFormats), types.String),
		"supportedOutputStorageFormats":     llx.ArrayData(convert.SliceAnyToInterface(model.SupportedOutputStorageFormats), types.String),
		"trainingPipeline":                  llx.StringData(model.TrainingPipeline),
		"artifactUri":                       llx.StringData(model.ArtifactUri),
		"encryptionSpec":                    llx.DictData(encryptionSpec),
		"labels":                            llx.MapData(convert.MapToInterfaceMap(model.Labels), types.String),
		"etag":                              llx.StringData(model.Etag),
		"createdAt":                         llx.TimeDataPtr(timestampAsTimePtr(model.CreateTime)),
		"updatedAt":                         llx.TimeDataPtr(timestampAsTimePtr(model.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	res := mqlModel.(*mqlGcpProjectVertexaiServiceModel)
	res.cacheKmsKeyName = model.GetEncryptionSpec().GetKmsKeyName()
	res.cacheOriginalModelName = model.GetOriginalModelInfo().GetModel()
	res.cachePipelineJobName = model.PipelineJob
	return res, nil
}

func (g *mqlGcpProjectVertexaiServiceModel) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) endpoints() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("endpoints", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewEndpointClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListEndpoints(ctx, &aiplatformpb.ListEndpointsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			ep, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			mqlEndpoint, err := newMqlVertexaiEndpoint(g.MqlRuntime, projectId, ep)
			if err != nil {
				return nil, false, err
			}
			items = append(items, mqlEndpoint)
		}
		return items, false, nil
	})
}

// newMqlVertexaiEndpoint maps a Vertex AI Endpoint proto into an MQL resource,
// including its deployed-model sub-resources. It is shared by the endpoints()
// lister and the typed endpoint() references.
func newMqlVertexaiEndpoint(runtime *plugin.Runtime, projectId string, ep *aiplatformpb.Endpoint) (*mqlGcpProjectVertexaiServiceEndpoint, error) {
	deployedModels := make([]any, 0, len(ep.DeployedModels))
	deployments := make([]any, 0, len(ep.DeployedModels))
	for _, dm := range ep.DeployedModels {
		d, err := protoToDict(dm)
		if err != nil {
			return nil, err
		}
		deployedModels = append(deployedModels, d)

		var privSA, predictUri, explainUri, healthUri string
		if pe := dm.PrivateEndpoints; pe != nil {
			privSA = pe.ServiceAttachment
			predictUri = pe.PredictHttpUri
			explainUri = pe.ExplainHttpUri
			healthUri = pe.HealthHttpUri
		}

		mqlDeployment, err := CreateResource(runtime, "gcp.project.vertexaiService.endpoint.deployment", map[string]*llx.RawData{
			"__id":                     llx.StringData(fmt.Sprintf("%s/deployment/%s", ep.Name, dm.Id)),
			"id":                       llx.StringData(dm.Id),
			"displayName":              llx.StringData(dm.DisplayName),
			"modelVersionId":           llx.StringData(dm.ModelVersionId),
			"serviceAccountEmail":      llx.StringData(dm.ServiceAccount),
			"disableContainerLogging":  llx.BoolData(dm.DisableContainerLogging),
			"enableAccessLogging":      llx.BoolData(dm.EnableAccessLogging),
			"privateServiceAttachment": llx.StringData(privSA),
			"predictHttpUri":           llx.StringData(predictUri),
			"explainHttpUri":           llx.StringData(explainUri),
			"healthHttpUri":            llx.StringData(healthUri),
			"createdAt":                llx.TimeDataPtr(timestampAsTimePtr(dm.CreateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlDeploymentRes := mqlDeployment.(*mqlGcpProjectVertexaiServiceEndpointDeployment)
		mqlDeploymentRes.cacheModelName = dm.Model
		mqlDeploymentRes.cacheProjectId = projectId
		deployments = append(deployments, mqlDeployment)
	}
	encryptionSpec, err := protoToDict(ep.EncryptionSpec)
	if err != nil {
		return nil, err
	}

	trafficSplit := make(map[string]any, len(ep.TrafficSplit))
	for k, v := range ep.TrafficSplit {
		trafficSplit[k] = int64(v)
	}

	pscProjectAllowlist := []any{}
	var pscServiceAttachment string
	if psc := ep.PrivateServiceConnectConfig; psc != nil {
		pscServiceAttachment = psc.ServiceAttachment
		for _, p := range psc.ProjectAllowlist {
			pscProjectAllowlist = append(pscProjectAllowlist, p)
		}
	}

	var predictionLoggingEnabled bool
	var predictionLoggingSamplingRate float64
	var predictionLoggingBQ string
	if pl := ep.PredictRequestResponseLoggingConfig; pl != nil {
		predictionLoggingEnabled = pl.Enabled
		predictionLoggingSamplingRate = pl.SamplingRate
		if pl.BigqueryDestination != nil {
			predictionLoggingBQ = pl.BigqueryDestination.OutputUri
		}
	}

	mqlEndpoint, err := CreateResource(runtime, "gcp.project.vertexaiService.endpoint", map[string]*llx.RawData{
		"name":                                 llx.StringData(ep.Name),
		"displayName":                          llx.StringData(ep.DisplayName),
		"description":                          llx.StringData(ep.Description),
		"deployments":                          llx.ArrayData(deployments, types.Resource("gcp.project.vertexaiService.endpoint.deployment")),
		"encryptionSpec":                       llx.DictData(encryptionSpec),
		"enablePrivateServiceConnect":          llx.BoolData(ep.EnablePrivateServiceConnect),
		"pscProjectAllowlist":                  llx.ArrayData(pscProjectAllowlist, types.String),
		"pscServiceAttachment":                 llx.StringData(pscServiceAttachment),
		"predictionLoggingEnabled":             llx.BoolData(predictionLoggingEnabled),
		"predictionLoggingSamplingRate":        llx.FloatData(predictionLoggingSamplingRate),
		"predictionLoggingBigqueryDestination": llx.StringData(predictionLoggingBQ),
		"dedicatedEndpointEnabled":             llx.BoolData(ep.DedicatedEndpointEnabled),
		"dedicatedEndpointDns":                 llx.StringData(ep.DedicatedEndpointDns),
		"privateModelServerEnabled":            llx.BoolData(ep.PrivateModelServerEnabled),
		"satisfiesPzs":                         llx.BoolData(ep.SatisfiesPzs),
		"satisfiesPzi":                         llx.BoolData(ep.SatisfiesPzi),
		"trafficSplit":                         llx.MapData(trafficSplit, types.Int),
		"labels":                               llx.MapData(convert.MapToInterfaceMap(ep.Labels), types.String),
		"etag":                                 llx.StringData(ep.Etag),
		"createdAt":                            llx.TimeDataPtr(timestampAsTimePtr(ep.CreateTime)),
		"updatedAt":                            llx.TimeDataPtr(timestampAsTimePtr(ep.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlRef := mqlEndpoint.(*mqlGcpProjectVertexaiServiceEndpoint)
	mqlRef.cacheNetwork = ep.Network
	res := mqlEndpoint.(*mqlGcpProjectVertexaiServiceEndpoint)
	res.cacheKmsKeyName = ep.GetEncryptionSpec().GetKmsKeyName()
	return res, nil
}

// resolveVertexaiEndpointRef fetches the Vertex AI endpoint identified by
// endpointName (a full resource name) and maps it into a fully-populated MQL
// resource. Like resolveVertexaiModelRef, it resolves directly via GetEndpoint
// because the gcp.project.vertexaiService.endpoint resource has no init
// function, so a bare NewResource(..., {"name": ...}) would yield a husk.
func resolveVertexaiEndpointRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectVertexaiServiceEndpoint], endpointName string) (*mqlGcpProjectVertexaiServiceEndpoint, error) {
	region := vertexaiRegionFromName(endpointName)
	if endpointName == "" || region == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := runtime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := aiplatform.NewEndpointClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(region)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	ep, err := client.GetEndpoint(ctx, &aiplatformpb.GetEndpointRequest{Name: endpointName})
	if err != nil {
		if isInapplicable(err) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return newMqlVertexaiEndpoint(runtime, vertexaiProjectFromName(endpointName), ep)
}

func (g *mqlGcpProjectVertexaiServiceEndpoint) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiServiceEndpoint) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cacheNetwork, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.NetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

type mqlGcpProjectVertexaiServiceEndpointDeploymentInternal struct {
	cacheModelName string
	cacheProjectId string
}

// vertexaiRegionFromName extracts the location from a Vertex AI resource name
// of the form projects/{project}/locations/{location}/....
func vertexaiRegionFromName(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

// vertexaiProjectFromName extracts the project from a Vertex AI resource name
// of the form projects/{project}/locations/{location}/....
func vertexaiProjectFromName(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "projects" {
			return parts[i+1]
		}
	}
	return ""
}

// resolveVertexaiModelRef fetches the Vertex AI model identified by modelName
// (a full resource name) and maps it into a fully-populated MQL resource. It is
// shared by every accessor that exposes a typed model reference. We resolve the
// model directly via GetModel rather than NewResource because the
// gcp.project.vertexaiService.model resource has no init function — a bare
// NewResource(..., {"name": ...}) would yield a husk with only the name set, so
// any field traversal beyond name would fail.
func resolveVertexaiModelRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectVertexaiServiceModel], modelName string) (*mqlGcpProjectVertexaiServiceModel, error) {
	region := vertexaiRegionFromName(modelName)
	if modelName == "" || region == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := runtime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := aiplatform.NewModelClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(region)),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	m, err := client.GetModel(ctx, &aiplatformpb.GetModelRequest{Name: modelName})
	if err != nil {
		if isInapplicable(err) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return newMqlVertexaiModel(runtime, m)
}

func (d *mqlGcpProjectVertexaiServiceEndpointDeployment) model() (*mqlGcpProjectVertexaiServiceModel, error) {
	return resolveVertexaiModelRef(d.MqlRuntime, &d.Model, d.cacheModelName)
}

func (d *mqlGcpProjectVertexaiServiceEndpointDeployment) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if d.ServiceAccountEmail.Error != nil {
		return nil, d.ServiceAccountEmail.Error
	}
	email := d.ServiceAccountEmail.Data
	if email == "" || d.cacheProjectId == "" {
		d.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(d.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(d.cacheProjectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func (g *mqlGcpProjectVertexaiService) pipelineJobs() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("pipelineJobs", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewPipelineClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListPipelineJobs(ctx, &aiplatformpb.ListPipelineJobsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			job, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			mqlJob, err := newMqlVertexaiPipelineJob(g.MqlRuntime, job)
			if err != nil {
				return nil, false, err
			}
			items = append(items, mqlJob)
		}
		return items, false, nil
	})
}

// newMqlVertexaiPipelineJob maps a Vertex AI PipelineJob proto into an MQL
// resource. It is shared by the pipelineJobs() lister and the
// initGcpProjectVertexaiServicePipelineJob single-instance resolver.
func newMqlVertexaiPipelineJob(runtime *plugin.Runtime, job *aiplatformpb.PipelineJob) (*mqlGcpProjectVertexaiServicePipelineJob, error) {
	pipelineSpec, err := protoToDict(job.PipelineSpec)
	if err != nil {
		return nil, err
	}
	runtimeConfig, err := protoToDict(job.RuntimeConfig)
	if err != nil {
		return nil, err
	}
	encryptionSpec, err := protoToDict(job.EncryptionSpec)
	if err != nil {
		return nil, err
	}
	templateMetadata, err := protoToDict(job.TemplateMetadata)
	if err != nil {
		return nil, err
	}
	errDict, err := protoToDict(job.Error)
	if err != nil {
		return nil, err
	}

	reservedIpRanges := make([]any, 0, len(job.ReservedIpRanges))
	for _, r := range job.ReservedIpRanges {
		reservedIpRanges = append(reservedIpRanges, r)
	}

	mqlJob, err := CreateResource(runtime, "gcp.project.vertexaiService.pipelineJob", map[string]*llx.RawData{
		"name":             llx.StringData(job.Name),
		"displayName":      llx.StringData(job.DisplayName),
		"state":            llx.StringData(job.State.String()),
		"pipelineSpec":     llx.DictData(pipelineSpec),
		"runtimeConfig":    llx.DictData(runtimeConfig),
		"encryptionSpec":   llx.DictData(encryptionSpec),
		"templateUri":      llx.StringData(job.TemplateUri),
		"templateMetadata": llx.DictData(templateMetadata),
		"error":            llx.DictData(errDict),
		"reservedIpRanges": llx.ArrayData(reservedIpRanges, types.String),
		"labels":           llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
		"createdAt":        llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
		"updatedAt":        llx.TimeDataPtr(timestampAsTimePtr(job.UpdateTime)),
		"startTime":        llx.TimeDataPtr(timestampAsTimePtr(job.StartTime)),
		"endTime":          llx.TimeDataPtr(timestampAsTimePtr(job.EndTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlRef := mqlJob.(*mqlGcpProjectVertexaiServicePipelineJob)
	mqlRef.cacheServiceAccount = job.ServiceAccount
	mqlRef.cacheNetwork = job.Network
	res := mqlJob.(*mqlGcpProjectVertexaiServicePipelineJob)
	res.cacheKmsKeyName = job.GetEncryptionSpec().GetKmsKeyName()
	res.cacheScheduleName = job.ScheduleName
	return res, nil
}

func (g *mqlGcpProjectVertexaiServicePipelineJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiServicePipelineJob) serviceAccountRef() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	email := g.cacheServiceAccount
	projectId := projectFromResourceName(g.Name.Data)
	if email == "" || projectId == "" {
		g.ServiceAccountRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func (g *mqlGcpProjectVertexaiServicePipelineJob) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cacheNetwork, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.NetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func (g *mqlGcpProjectVertexaiServiceIndexEndpoint) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cacheNetwork, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.NetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func (g *mqlGcpProjectVertexaiService) datasets() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("datasets", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewDatasetClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListDatasets(ctx, &aiplatformpb.ListDatasetsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			ds, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			// Dataset.Metadata is a *structpb.Value which can be any JSON type
			// (struct, list, string, etc.), so use AsInterface() instead of protoToDict.
			var metadata any
			if ds.Metadata != nil {
				metadata = ds.Metadata.AsInterface()
			}
			encryptionSpec, err := protoToDict(ds.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlDs, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.dataset", map[string]*llx.RawData{
				"name":              llx.StringData(ds.Name),
				"displayName":       llx.StringData(ds.DisplayName),
				"description":       llx.StringData(ds.Description),
				"metadataSchemaUri": llx.StringData(ds.MetadataSchemaUri),
				"metadata":          llx.DictData(metadata),
				"encryptionSpec":    llx.DictData(encryptionSpec),
				"labels":            llx.MapData(convert.MapToInterfaceMap(ds.Labels), types.String),
				"etag":              llx.StringData(ds.Etag),
				"createdAt":         llx.TimeDataPtr(timestampAsTimePtr(ds.CreateTime)),
				"updatedAt":         llx.TimeDataPtr(timestampAsTimePtr(ds.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlDs.(*mqlGcpProjectVertexaiServiceDataset).cacheKmsKeyName = ds.GetEncryptionSpec().GetKmsKeyName()
			items = append(items, mqlDs)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceDataset) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) featureOnlineStores() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("featureOnlineStores", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewFeatureOnlineStoreAdminClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListFeatureOnlineStores(ctx, &aiplatformpb.ListFeatureOnlineStoresRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			store, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			bigtable, err := protoToDict(store.GetBigtable())
			if err != nil {
				return nil, false, err
			}
			optimized, err := protoToDict(store.GetOptimized())
			if err != nil {
				return nil, false, err
			}
			dedicatedServingEndpoint, err := protoToDict(store.DedicatedServingEndpoint)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(store.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlStore, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.featureOnlineStore", map[string]*llx.RawData{
				"name":                     llx.StringData(store.Name),
				"state":                    llx.StringData(store.State.String()),
				"bigtable":                 llx.DictData(bigtable),
				"optimized":                llx.DictData(optimized),
				"dedicatedServingEndpoint": llx.DictData(dedicatedServingEndpoint),
				"encryptionSpec":           llx.DictData(encryptionSpec),
				"labels":                   llx.MapData(convert.MapToInterfaceMap(store.Labels), types.String),
				"etag":                     llx.StringData(store.Etag),
				"satisfiesPzs":             llx.BoolData(store.SatisfiesPzs),
				"satisfiesPzi":             llx.BoolData(store.SatisfiesPzi),
				"createdAt":                llx.TimeDataPtr(timestampAsTimePtr(store.CreateTime)),
				"updatedAt":                llx.TimeDataPtr(timestampAsTimePtr(store.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlStore.(*mqlGcpProjectVertexaiServiceFeatureOnlineStore).cacheKmsKeyName = store.GetEncryptionSpec().GetKmsKeyName()
			items = append(items, mqlStore)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceFeatureOnlineStore) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// ---------------------------------------------------------------
// Tensorboards
// ---------------------------------------------------------------

func (g *mqlGcpProjectVertexaiServiceTensorboard) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) tensorboards() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("tensorboards", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewTensorboardClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListTensorboards(ctx, &aiplatformpb.ListTensorboardsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			tb, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			encryptionSpec, err := protoToDict(tb.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlTB, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.tensorboard", map[string]*llx.RawData{
				"name":           llx.StringData(tb.Name),
				"displayName":    llx.StringData(tb.DisplayName),
				"description":    llx.StringData(tb.Description),
				"isDefault":      llx.BoolData(tb.IsDefault),
				"labels":         llx.MapData(convert.MapToInterfaceMap(tb.Labels), types.String),
				"encryptionSpec": llx.DictData(encryptionSpec),
				"created":        llx.TimeDataPtr(timestampAsTimePtr(tb.CreateTime)),
				"updated":        llx.TimeDataPtr(timestampAsTimePtr(tb.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlTB.(*mqlGcpProjectVertexaiServiceTensorboard).cacheKmsKeyName = tb.GetEncryptionSpec().GetKmsKeyName()
			items = append(items, mqlTB)
		}
		return items, false, nil
	})
}

// ---------------------------------------------------------------
// Custom Jobs
// ---------------------------------------------------------------

func (g *mqlGcpProjectVertexaiServiceCustomJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiServiceCustomJob) serviceAccountRef() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	email := g.cacheServiceAccount
	projectId := projectFromResourceName(g.Name.Data)
	if email == "" || projectId == "" {
		g.ServiceAccountRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func (g *mqlGcpProjectVertexaiServiceCustomJob) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.cacheNetwork == "" {
		g.NetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	n, err := getNetworkByUrl(g.cacheNetwork, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.NetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func initGcpProjectVertexaiServiceCustomJob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		args = make(map[string]*llx.RawData)
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
			args["location"] = llx.StringData(ids.region)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.vertexaiService.customJob requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.vertexaiService.customJob requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	// Accept either the full resource path or a short name + location from
	// the asset-identifier-driven discovery path.
	var fullName, region, projectId string
	if strings.HasPrefix(name, "projects/") {
		fullName = name
		region = parseLocationFromPath(name)
		projectId = parseProjectFromPath(name)
	} else {
		locRaw := args["location"]
		projRaw := args["projectId"]
		if locRaw == nil || projRaw == nil {
			return nil, nil, errors.New("vertexai custom job init: projectId and location required when name is not a full resource path")
		}
		region, _ = locRaw.Value.(string)
		projectId, _ = projRaw.Value.(string)
		fullName = fmt.Sprintf("projects/%s/locations/%s/customJobs/%s", projectId, region, name)
	}

	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. The answer is memoized per project, so this is free after the
	// first caller.
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_aiplatform); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Vertex AI API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := aiplatform.NewJobClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(region)),
	)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	job, err := client.GetCustomJob(ctx, &aiplatformpb.GetCustomJobRequest{Name: fullName})
	if err != nil {
		return nil, nil, err
	}

	res, err := mqlVertexAICustomJobFromProto(runtime, job)
	if err != nil {
		return nil, nil, err
	}
	delete(args, "location")
	return args, res, nil
}

// initGcpProjectVertexaiServiceEndpoint resolves a single Vertex AI endpoint.
// When accessed as a discovered asset (no args) it reconstructs the full
// resource name from the asset identifier, then fetches it directly with
// GetEndpoint so the resource is fully populated instead of an empty husk.
func initGcpProjectVertexaiServiceEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args == nil {
		args = make(map[string]*llx.RawData)
	}
	if len(args) == 0 {
		ids := getAssetIdentifier(runtime)
		if ids == nil {
			return nil, nil, errors.New("no asset identifier found")
		}
		args["name"] = llx.StringData(fmt.Sprintf("projects/%s/locations/%s/endpoints/%s", ids.project, ids.region, ids.name))
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.vertexaiService.endpoint requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.vertexaiService.endpoint requires a non-empty "name" argument`)
	}

	region := vertexaiRegionFromName(name)
	if region == "" {
		return nil, nil, errors.New("vertexai endpoint init: could not determine region from name " + name)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. The answer is memoized per project, so this is free after the
	// first caller.
	projectId := parseProjectFromPath(name)
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_aiplatform); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Vertex AI API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := aiplatform.NewEndpointClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(region)),
	)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	ep, err := client.GetEndpoint(ctx, &aiplatformpb.GetEndpointRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}

	res, err := newMqlVertexaiEndpoint(runtime, vertexaiProjectFromName(name), ep)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// initGcpProjectVertexaiServicePipelineJob resolves a single Vertex AI pipeline
// job. Like the endpoint init, it reconstructs the full resource name from the
// asset identifier when accessed as a discovered asset and fetches it with
// GetPipelineJob.
func initGcpProjectVertexaiServicePipelineJob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args == nil {
		args = make(map[string]*llx.RawData)
	}
	if len(args) == 0 {
		ids := getAssetIdentifier(runtime)
		if ids == nil {
			return nil, nil, errors.New("no asset identifier found")
		}
		args["name"] = llx.StringData(fmt.Sprintf("projects/%s/locations/%s/pipelineJobs/%s", ids.project, ids.region, ids.name))
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.vertexaiService.pipelineJob requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.vertexaiService.pipelineJob requires a non-empty "name" argument`)
	}

	region := vertexaiRegionFromName(name)
	if region == "" {
		return nil, nil, errors.New("vertexai pipeline job init: could not determine region from name " + name)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. The answer is memoized per project, so this is free after the
	// first caller.
	projectId := parseProjectFromPath(name)
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_aiplatform); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Vertex AI API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := aiplatform.NewPipelineClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(region)),
	)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	job, err := client.GetPipelineJob(ctx, &aiplatformpb.GetPipelineJobRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}

	res, err := newMqlVertexaiPipelineJob(runtime, job)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// initGcpProjectVertexaiServiceNotebookRuntimeTemplate resolves a single Vertex
// AI notebook runtime template. Like the endpoint init, it reconstructs the
// full resource name from the asset identifier when accessed as a discovered
// asset and fetches it with GetNotebookRuntimeTemplate.
func initGcpProjectVertexaiServiceNotebookRuntimeTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args == nil {
		args = make(map[string]*llx.RawData)
	}
	if len(args) == 0 {
		ids := getAssetIdentifier(runtime)
		if ids == nil {
			return nil, nil, errors.New("no asset identifier found")
		}
		args["name"] = llx.StringData(fmt.Sprintf("projects/%s/locations/%s/notebookRuntimeTemplates/%s", ids.project, ids.region, ids.name))
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.vertexaiService.notebookRuntimeTemplate requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.vertexaiService.notebookRuntimeTemplate requires a non-empty "name" argument`)
	}

	region := vertexaiRegionFromName(name)
	if region == "" {
		return nil, nil, errors.New("vertexai notebook runtime template init: could not determine region from name " + name)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. The answer is memoized per project, so this is free after the
	// first caller.
	projectId := parseProjectFromPath(name)
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_aiplatform); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Vertex AI API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := aiplatform.NewNotebookClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(region)),
	)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	tmpl, err := client.GetNotebookRuntimeTemplate(ctx, &aiplatformpb.GetNotebookRuntimeTemplateRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}

	res, err := newMqlVertexaiNotebookRuntimeTemplate(runtime, tmpl)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// customJobSpecFields extracts the security-relevant scalar fields from a
// Vertex AI custom-job spec — the run-as service account, the peering network,
// and whether interactive web-access portals are enabled. The protobuf getters
// are nil-safe, so an absent spec yields zero values.
func customJobSpecFields(spec *aiplatformpb.CustomJobSpec) (serviceAccount, network string, enableWebAccess bool) {
	return spec.GetServiceAccount(), spec.GetNetwork(), spec.GetEnableWebAccess()
}

func mqlVertexAICustomJobFromProto(runtime *plugin.Runtime, job *aiplatformpb.CustomJob) (*mqlGcpProjectVertexaiServiceCustomJob, error) {
	jobSpec, err := protoToDict(job.JobSpec)
	if err != nil {
		return nil, err
	}
	serviceAccount, network, enableWebAccess := customJobSpecFields(job.GetJobSpec())
	encryptionSpec, err := protoToDict(job.EncryptionSpec)
	if err != nil {
		return nil, err
	}
	errorDict, err := protoToDict(job.Error)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.vertexaiService.customJob", map[string]*llx.RawData{
		"name":            llx.StringData(job.Name),
		"displayName":     llx.StringData(job.DisplayName),
		"state":           llx.StringData(job.State.String()),
		"jobSpec":         llx.DictData(jobSpec),
		"enableWebAccess": llx.BoolData(enableWebAccess),
		"labels":          llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
		"encryptionSpec":  llx.DictData(encryptionSpec),
		"error":           llx.DictData(errorDict),
		"created":         llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
		"updated":         llx.TimeDataPtr(timestampAsTimePtr(job.UpdateTime)),
		"startTime":       llx.TimeDataPtr(timestampAsTimePtr(job.StartTime)),
		"endTime":         llx.TimeDataPtr(timestampAsTimePtr(job.EndTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlRef := res.(*mqlGcpProjectVertexaiServiceCustomJob)
	mqlRef.cacheServiceAccount = serviceAccount
	mqlRef.cacheNetwork = network
	res.(*mqlGcpProjectVertexaiServiceCustomJob).cacheKmsKeyName = job.GetEncryptionSpec().GetKmsKeyName()
	return res.(*mqlGcpProjectVertexaiServiceCustomJob), nil
}

func (g *mqlGcpProjectVertexaiService) customJobs() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("customJobs", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewJobClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListCustomJobs(ctx, &aiplatformpb.ListCustomJobsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			job, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			mqlJob, err := mqlVertexAICustomJobFromProto(g.MqlRuntime, job)
			if err != nil {
				return nil, false, err
			}
			items = append(items, mqlJob)
		}
		return items, false, nil
	})
}

// ---------------------------------------------------------------
// Indexes
// ---------------------------------------------------------------

func (g *mqlGcpProjectVertexaiServiceIndex) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) indexes() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("indexes", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewIndexClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListIndexes(ctx, &aiplatformpb.ListIndexesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			idx, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			var metadata any
			if idx.Metadata != nil {
				metadata = idx.Metadata.AsInterface()
			}
			encryptionSpec, err := protoToDict(idx.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}
			indexStats, err := protoToDict(idx.IndexStats)
			if err != nil {
				return nil, false, err
			}

			deployedIndexes := make([]any, 0, len(idx.DeployedIndexes))
			for _, di := range idx.DeployedIndexes {
				d, err := protoToDict(di)
				if err != nil {
					return nil, false, err
				}
				deployedIndexes = append(deployedIndexes, d)
			}

			mqlIdx, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.index", map[string]*llx.RawData{
				"name":              llx.StringData(idx.Name),
				"displayName":       llx.StringData(idx.DisplayName),
				"description":       llx.StringData(idx.Description),
				"metadataSchemaUri": llx.StringData(idx.MetadataSchemaUri),
				"metadata":          llx.DictData(metadata),
				"deployedIndexes":   llx.ArrayData(deployedIndexes, types.Dict),
				"labels":            llx.MapData(convert.MapToInterfaceMap(idx.Labels), types.String),
				"encryptionSpec":    llx.DictData(encryptionSpec),
				"indexUpdateMethod": llx.StringData(idx.IndexUpdateMethod.String()),
				"indexStats":        llx.DictData(indexStats),
				"created":           llx.TimeDataPtr(timestampAsTimePtr(idx.CreateTime)),
				"updated":           llx.TimeDataPtr(timestampAsTimePtr(idx.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlIdx.(*mqlGcpProjectVertexaiServiceIndex).cacheKmsKeyName = idx.GetEncryptionSpec().GetKmsKeyName()
			items = append(items, mqlIdx)
		}
		return items, false, nil
	})
}

// ---------------------------------------------------------------
// Index Endpoints
// ---------------------------------------------------------------

func (g *mqlGcpProjectVertexaiServiceIndexEndpoint) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) indexEndpoints() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("indexEndpoints", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewIndexEndpointClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListIndexEndpoints(ctx, &aiplatformpb.ListIndexEndpointsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			ep, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			encryptionSpec, err := protoToDict(ep.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			deployedIndexes := make([]any, 0, len(ep.DeployedIndexes))
			for _, di := range ep.DeployedIndexes {
				d, err := protoToDict(di)
				if err != nil {
					return nil, false, err
				}
				deployedIndexes = append(deployedIndexes, d)
			}

			mqlEP, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.indexEndpoint", map[string]*llx.RawData{
				"name":                     llx.StringData(ep.Name),
				"displayName":              llx.StringData(ep.DisplayName),
				"description":              llx.StringData(ep.Description),
				"deployedIndexes":          llx.ArrayData(deployedIndexes, types.Dict),
				"publicEndpointEnabled":    llx.BoolData(ep.PublicEndpointEnabled),
				"publicEndpointDomainName": llx.StringData(ep.PublicEndpointDomainName),
				"labels":                   llx.MapData(convert.MapToInterfaceMap(ep.Labels), types.String),
				"encryptionSpec":           llx.DictData(encryptionSpec),
				"created":                  llx.TimeDataPtr(timestampAsTimePtr(ep.CreateTime)),
				"updated":                  llx.TimeDataPtr(timestampAsTimePtr(ep.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlRef := mqlEP.(*mqlGcpProjectVertexaiServiceIndexEndpoint)
			mqlRef.cacheNetwork = ep.Network
			mqlEP.(*mqlGcpProjectVertexaiServiceIndexEndpoint).cacheKmsKeyName = ep.GetEncryptionSpec().GetKmsKeyName()
			items = append(items, mqlEP)
		}
		return items, false, nil
	})
}

// ---------------------------------------------------------------
// Metadata Stores
// ---------------------------------------------------------------

func (g *mqlGcpProjectVertexaiServiceMetadataStore) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) metadataStores() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("metadataStores", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewMetadataClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListMetadataStores(ctx, &aiplatformpb.ListMetadataStoresRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			store, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			state, err := protoToDict(store.State)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(store.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}
			dataplexConfig, err := protoToDict(store.DataplexConfig)
			if err != nil {
				return nil, false, err
			}

			mqlStore, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.metadataStore", map[string]*llx.RawData{
				"name":           llx.StringData(store.Name),
				"description":    llx.StringData(store.Description),
				"state":          llx.DictData(state),
				"encryptionSpec": llx.DictData(encryptionSpec),
				"dataplexConfig": llx.DictData(dataplexConfig),
				"created":        llx.TimeDataPtr(timestampAsTimePtr(store.CreateTime)),
				"updated":        llx.TimeDataPtr(timestampAsTimePtr(store.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlStore.(*mqlGcpProjectVertexaiServiceMetadataStore).cacheKmsKeyName = store.GetEncryptionSpec().GetKmsKeyName()
			items = append(items, mqlStore)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiService) notebookRuntimes() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("notebookRuntimes", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewNotebookClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListNotebookRuntimes(ctx, &aiplatformpb.ListNotebookRuntimesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			rt, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			machineSpec, err := protoToDict(rt.MachineSpec)
			if err != nil {
				return nil, false, err
			}
			networkSpec, err := protoToDict(rt.NetworkSpec)
			if err != nil {
				return nil, false, err
			}
			idleShutdownConfig, err := protoToDict(rt.IdleShutdownConfig)
			if err != nil {
				return nil, false, err
			}
			eucConfig, err := protoToDict(rt.EucConfig)
			if err != nil {
				return nil, false, err
			}
			shieldedVmConfig, err := protoToDict(rt.ShieldedVmConfig)
			if err != nil {
				return nil, false, err
			}
			softwareConfig, err := protoToDict(rt.SoftwareConfig)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(rt.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlRt, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.notebookRuntime", map[string]*llx.RawData{
				"name":                 llx.StringData(rt.Name),
				"displayName":          llx.StringData(rt.DisplayName),
				"description":          llx.StringData(rt.Description),
				"runtimeUser":          llx.StringData(rt.RuntimeUser),
				"proxyUri":             llx.StringData(rt.ProxyUri),
				"healthState":          llx.StringData(rt.HealthState.String()),
				"runtimeState":         llx.StringData(rt.RuntimeState.String()),
				"notebookRuntimeType":  llx.StringData(rt.NotebookRuntimeType.String()),
				"isUpgradable":         llx.BoolData(rt.IsUpgradable),
				"version":              llx.StringData(rt.Version),
				"networkTags":          llx.ArrayData(convert.SliceAnyToInterface(rt.NetworkTags), types.String),
				"machineSpec":          llx.DictData(machineSpec),
				"networkSpec":          llx.DictData(networkSpec),
				"enableInternetAccess": llx.BoolData(rt.GetNetworkSpec().GetEnableInternetAccess()),
				"idleShutdownConfig":   llx.DictData(idleShutdownConfig),
				"eucConfig":            llx.DictData(eucConfig),
				"eucDisabled":          llx.BoolData(rt.GetEucConfig().GetEucDisabled()),
				"bypassActasCheck":     llx.BoolData(rt.GetEucConfig().GetBypassActasCheck()),
				"shieldedVmConfig":     llx.DictData(shieldedVmConfig),
				"enableSecureBoot":     llx.BoolData(rt.GetShieldedVmConfig().GetEnableSecureBoot()),
				"softwareConfig":       llx.DictData(softwareConfig),
				"labels":               llx.MapData(convert.MapToInterfaceMap(rt.Labels), types.String),
				"encryptionSpec":       llx.DictData(encryptionSpec),
				"createdAt":            llx.TimeDataPtr(timestampAsTimePtr(rt.CreateTime)),
				"updatedAt":            llx.TimeDataPtr(timestampAsTimePtr(rt.UpdateTime)),
				"expirationTime":       llx.TimeDataPtr(timestampAsTimePtr(rt.ExpirationTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlRtTyped := mqlRt.(*mqlGcpProjectVertexaiServiceNotebookRuntime)
			mqlRtTyped.cacheKmsKeyName = rt.GetEncryptionSpec().GetKmsKeyName()
			mqlRtTyped.cacheServiceAccountEmail = rt.ServiceAccount
			mqlRtTyped.cacheProjectId = projectId
			mqlRtTyped.cacheNetwork = rt.GetNetworkSpec().GetNetwork()
			mqlRtTyped.cacheSubnetwork = rt.GetNetworkSpec().GetSubnetwork()
			items = append(items, mqlRt)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceNotebookRuntime) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) notebookRuntimeTemplates() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("notebookRuntimeTemplates", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewNotebookClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListNotebookRuntimeTemplates(ctx, &aiplatformpb.ListNotebookRuntimeTemplatesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			tmpl, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			mqlTmpl, err := newMqlVertexaiNotebookRuntimeTemplate(g.MqlRuntime, tmpl)
			if err != nil {
				return nil, false, err
			}
			items = append(items, mqlTmpl)
		}
		return items, false, nil
	})
}

// newMqlVertexaiNotebookRuntimeTemplate maps a Vertex AI
// NotebookRuntimeTemplate proto into an MQL resource. It is shared by the
// notebookRuntimeTemplates() lister and the
// initGcpProjectVertexaiServiceNotebookRuntimeTemplate single-instance resolver.
func newMqlVertexaiNotebookRuntimeTemplate(runtime *plugin.Runtime, tmpl *aiplatformpb.NotebookRuntimeTemplate) (*mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate, error) {
	machineSpec, err := protoToDict(tmpl.MachineSpec)
	if err != nil {
		return nil, err
	}
	networkSpec, err := protoToDict(tmpl.NetworkSpec)
	if err != nil {
		return nil, err
	}
	idleShutdownConfig, err := protoToDict(tmpl.IdleShutdownConfig)
	if err != nil {
		return nil, err
	}
	eucConfig, err := protoToDict(tmpl.EucConfig)
	if err != nil {
		return nil, err
	}
	shieldedVmConfig, err := protoToDict(tmpl.ShieldedVmConfig)
	if err != nil {
		return nil, err
	}
	softwareConfig, err := protoToDict(tmpl.SoftwareConfig)
	if err != nil {
		return nil, err
	}
	encryptionSpec, err := protoToDict(tmpl.EncryptionSpec)
	if err != nil {
		return nil, err
	}

	mqlTmpl, err := CreateResource(runtime, "gcp.project.vertexaiService.notebookRuntimeTemplate", map[string]*llx.RawData{
		"name":                 llx.StringData(tmpl.Name),
		"displayName":          llx.StringData(tmpl.DisplayName),
		"description":          llx.StringData(tmpl.Description),
		"isDefault":            llx.BoolData(tmpl.IsDefault),
		"notebookRuntimeType":  llx.StringData(tmpl.NotebookRuntimeType.String()),
		"networkTags":          llx.ArrayData(convert.SliceAnyToInterface(tmpl.NetworkTags), types.String),
		"machineSpec":          llx.DictData(machineSpec),
		"networkSpec":          llx.DictData(networkSpec),
		"enableInternetAccess": llx.BoolData(tmpl.GetNetworkSpec().GetEnableInternetAccess()),
		"idleShutdownConfig":   llx.DictData(idleShutdownConfig),
		"eucConfig":            llx.DictData(eucConfig),
		"eucDisabled":          llx.BoolData(tmpl.GetEucConfig().GetEucDisabled()),
		"bypassActasCheck":     llx.BoolData(tmpl.GetEucConfig().GetBypassActasCheck()),
		"shieldedVmConfig":     llx.DictData(shieldedVmConfig),
		"enableSecureBoot":     llx.BoolData(tmpl.GetShieldedVmConfig().GetEnableSecureBoot()),
		"softwareConfig":       llx.DictData(softwareConfig),
		"etag":                 llx.StringData(tmpl.Etag),
		"labels":               llx.MapData(convert.MapToInterfaceMap(tmpl.Labels), types.String),
		"encryptionSpec":       llx.DictData(encryptionSpec),
		"createdAt":            llx.TimeDataPtr(timestampAsTimePtr(tmpl.CreateTime)),
		"updatedAt":            llx.TimeDataPtr(timestampAsTimePtr(tmpl.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	res := mqlTmpl.(*mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate)
	res.cacheKmsKeyName = tmpl.GetEncryptionSpec().GetKmsKeyName()
	res.cacheServiceAccountEmail = tmpl.ServiceAccount
	res.cacheProjectId = vertexaiProjectFromName(tmpl.Name)
	res.cacheNetwork = tmpl.GetNetworkSpec().GetNetwork()
	res.cacheSubnetwork = tmpl.GetNetworkSpec().GetSubnetwork()
	return res, nil
}

func (g *mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) notebookExecutionJobs() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("notebookExecutionJobs", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewNotebookClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListNotebookExecutionJobs(ctx, &aiplatformpb.ListNotebookExecutionJobsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			job, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			encryptionSpec, err := protoToDict(job.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			var timeoutSeconds int64
			if job.ExecutionTimeout != nil {
				timeoutSeconds = int64(job.ExecutionTimeout.AsDuration().Seconds())
			}

			mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.notebookExecutionJob", map[string]*llx.RawData{
				"name":                    llx.StringData(job.Name),
				"displayName":             llx.StringData(job.DisplayName),
				"jobState":                llx.StringData(job.JobState.String()),
				"kernelName":              llx.StringData(job.KernelName),
				"executionUser":           llx.StringData(job.GetExecutionUser()),
				"executionTimeoutSeconds": llx.IntData(timeoutSeconds),
				"labels":                  llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
				"encryptionSpec":          llx.DictData(encryptionSpec),
				"createdAt":               llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
				"updatedAt":               llx.TimeDataPtr(timestampAsTimePtr(job.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlRef := mqlJob.(*mqlGcpProjectVertexaiServiceNotebookExecutionJob)
			mqlRef.cacheScheduleResourceName = job.ScheduleResourceName
			mqlNotebookJob := mqlJob.(*mqlGcpProjectVertexaiServiceNotebookExecutionJob)
			mqlNotebookJob.cacheKmsKeyName = job.GetEncryptionSpec().GetKmsKeyName()
			mqlNotebookJob.cacheServiceAccountEmail = job.GetServiceAccount()
			mqlNotebookJob.cacheProjectId = vertexaiProjectFromName(job.Name)
			mqlNotebookJob.cacheNotebookRuntimeTemplateName = job.GetNotebookRuntimeTemplateResourceName()
			items = append(items, mqlJob)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceNotebookExecutionJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) reasoningEngines() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("reasoningEngines", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewReasoningEngineClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListReasoningEngines(ctx, &aiplatformpb.ListReasoningEnginesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			engine, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			spec, err := protoToDict(engine.Spec)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(engine.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlEngine, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.reasoningEngine", map[string]*llx.RawData{
				"name":                llx.StringData(engine.Name),
				"displayName":         llx.StringData(engine.DisplayName),
				"description":         llx.StringData(engine.Description),
				"serviceAccountEmail": llx.StringData(engine.GetSpec().GetServiceAccount()),
				"agentFramework":      llx.StringData(engine.GetSpec().GetAgentFramework()),
				"spec":                llx.DictData(spec),
				"encryptionSpec":      llx.DictData(encryptionSpec),
				"labels":              llx.MapData(convert.MapToInterfaceMap(engine.Labels), types.String),
				"etag":                llx.StringData(engine.Etag),
				"createdAt":           llx.TimeDataPtr(timestampAsTimePtr(engine.CreateTime)),
				"updatedAt":           llx.TimeDataPtr(timestampAsTimePtr(engine.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlEngineRes := mqlEngine.(*mqlGcpProjectVertexaiServiceReasoningEngine)
			mqlEngineRes.cacheKmsKeyName = engine.GetEncryptionSpec().GetKmsKeyName()
			mqlEngineRes.cacheProjectId = projectId
			items = append(items, mqlEngine)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceReasoningEngine) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (a *mqlGcpProjectVertexaiServiceReasoningEngine) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if a.ServiceAccountEmail.Error != nil {
		return nil, a.ServiceAccountEmail.Error
	}
	email := a.ServiceAccountEmail.Data
	if email == "" || a.cacheProjectId == "" {
		a.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(a.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(a.cacheProjectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func (g *mqlGcpProjectVertexaiService) ragCorpora() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("ragCorpora", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewVertexRagDataClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListRagCorpora(ctx, &aiplatformpb.ListRagCorporaRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			corpus, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			corpusStatus, err := protoToDict(corpus.CorpusStatus)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(corpus.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlCorpus, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.ragCorpus", map[string]*llx.RawData{
				"name":           llx.StringData(corpus.Name),
				"displayName":    llx.StringData(corpus.DisplayName),
				"description":    llx.StringData(corpus.Description),
				"corpusStatus":   llx.DictData(corpusStatus),
				"encryptionSpec": llx.DictData(encryptionSpec),
				"createdAt":      llx.TimeDataPtr(timestampAsTimePtr(corpus.CreateTime)),
				"updatedAt":      llx.TimeDataPtr(timestampAsTimePtr(corpus.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlCorpus.(*mqlGcpProjectVertexaiServiceRagCorpus).cacheKmsKeyName = corpus.GetEncryptionSpec().GetKmsKeyName()
			items = append(items, mqlCorpus)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceRagCorpus) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) featureGroups() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("featureGroups", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewFeatureRegistryClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListFeatureGroups(ctx, &aiplatformpb.ListFeatureGroupsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			fg, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			bigQuery, err := protoToDict(fg.GetBigQuery())
			if err != nil {
				return nil, false, err
			}

			mqlFg, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.featureGroup", map[string]*llx.RawData{
				"name":        llx.StringData(fg.Name),
				"description": llx.StringData(fg.Description),
				"bigQuery":    llx.DictData(bigQuery),
				"etag":        llx.StringData(fg.Etag),
				"labels":      llx.MapData(convert.MapToInterfaceMap(fg.Labels), types.String),
				"createdAt":   llx.TimeDataPtr(timestampAsTimePtr(fg.CreateTime)),
				"updatedAt":   llx.TimeDataPtr(timestampAsTimePtr(fg.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			items = append(items, mqlFg)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceFeatureGroup) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) persistentResources() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("persistentResources", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewPersistentResourceClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListPersistentResources(ctx, &aiplatformpb.ListPersistentResourcesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			pr, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			resourcePools := make([]any, 0, len(pr.ResourcePools))
			for _, rp := range pr.ResourcePools {
				d, err := protoToDict(rp)
				if err != nil {
					return nil, false, err
				}
				resourcePools = append(resourcePools, d)
			}
			resourceRuntimeSpec, err := protoToDict(pr.ResourceRuntimeSpec)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(pr.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlPr, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.persistentResource", map[string]*llx.RawData{
				"name":                llx.StringData(pr.Name),
				"displayName":         llx.StringData(pr.DisplayName),
				"state":               llx.StringData(pr.State.String()),
				"reservedIpRanges":    llx.ArrayData(convert.SliceAnyToInterface(pr.ReservedIpRanges), types.String),
				"resourcePools":       llx.ArrayData(resourcePools, types.Dict),
				"resourceRuntimeSpec": llx.DictData(resourceRuntimeSpec),
				"labels":              llx.MapData(convert.MapToInterfaceMap(pr.Labels), types.String),
				"encryptionSpec":      llx.DictData(encryptionSpec),
				"createdAt":           llx.TimeDataPtr(timestampAsTimePtr(pr.CreateTime)),
				"startedAt":           llx.TimeDataPtr(timestampAsTimePtr(pr.StartTime)),
				"updatedAt":           llx.TimeDataPtr(timestampAsTimePtr(pr.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			prMql := mqlPr.(*mqlGcpProjectVertexaiServicePersistentResource)
			prMql.cacheKmsKeyName = pr.GetEncryptionSpec().GetKmsKeyName()
			prMql.cacheNetworkUrl = pr.Network
			items = append(items, mqlPr)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServicePersistentResource) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) schedules() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("schedules", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewScheduleClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListSchedules(ctx, &aiplatformpb.ListSchedulesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			sched, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			mqlSched, err := newMqlVertexaiSchedule(g.MqlRuntime, sched)
			if err != nil {
				return nil, false, err
			}
			items = append(items, mqlSched)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceSchedule) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// newMqlVertexaiSchedule maps a Vertex AI Schedule onto the MQL resource. It is
// shared by the schedules() collection and the single-schedule init so both
// paths populate the identical field set.
func newMqlVertexaiSchedule(runtime *plugin.Runtime, sched *aiplatformpb.Schedule) (plugin.Resource, error) {
	return CreateResource(runtime, "gcp.project.vertexaiService.schedule", map[string]*llx.RawData{
		"name":                  llx.StringData(sched.Name),
		"displayName":           llx.StringData(sched.DisplayName),
		"state":                 llx.StringData(sched.State.String()),
		"cron":                  llx.StringData(sched.GetCron()),
		"maxRunCount":           llx.IntData(sched.MaxRunCount),
		"startedRunCount":       llx.IntData(sched.StartedRunCount),
		"maxConcurrentRunCount": llx.IntData(sched.MaxConcurrentRunCount),
		"allowQueueing":         llx.BoolData(sched.AllowQueueing),
		"catchUp":               llx.BoolData(sched.CatchUp),
		"startedAt":             llx.TimeDataPtr(timestampAsTimePtr(sched.StartTime)),
		"endedAt":               llx.TimeDataPtr(timestampAsTimePtr(sched.EndTime)),
		"createdAt":             llx.TimeDataPtr(timestampAsTimePtr(sched.CreateTime)),
		"updatedAt":             llx.TimeDataPtr(timestampAsTimePtr(sched.UpdateTime)),
		"nextRunTime":           llx.TimeDataPtr(timestampAsTimePtr(sched.NextRunTime)),
	})
}

// initGcpProjectVertexaiServiceSchedule resolves a single Vertex AI schedule by
// its full resource name.
//
// Without an init, NewResource falls straight through to Create, so a typed
// scheduleRef() reference produced a resource carrying only `name` -- every
// other field unset, surfacing client-side as "primitive with no type
// information" with no attribution. Whether that was visible depended on
// whether schedules() had already run in the same session, so the same query
// passed or returned nulls depending on evaluation order.
func initGcpProjectVertexaiServiceSchedule(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.vertexaiService.schedule requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.vertexaiService.schedule requires a non-empty "name" argument`)
	}

	region := vertexaiRegionFromName(name)
	if region == "" {
		return nil, nil, errors.New("vertexai schedule init: could not determine region from name " + name)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. The answer is memoized per project, so this is free after the
	// first caller.
	projectId := parseProjectFromPath(name)
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_aiplatform); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Vertex AI API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := aiplatform.NewScheduleClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(region)),
	)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	sched, err := client.GetSchedule(ctx, &aiplatformpb.GetScheduleRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}

	res, err := newMqlVertexaiSchedule(runtime, sched)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (g *mqlGcpProjectVertexaiService) deploymentResourcePools() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("deploymentResourcePools", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewDeploymentResourcePoolClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListDeploymentResourcePools(ctx, &aiplatformpb.ListDeploymentResourcePoolsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			pool, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			dedicatedResources, err := protoToDict(pool.DedicatedResources)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(pool.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlPool, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.deploymentResourcePool", map[string]*llx.RawData{
				"name":                    llx.StringData(pool.Name),
				"disableContainerLogging": llx.BoolData(pool.DisableContainerLogging),
				"dedicatedResources":      llx.DictData(dedicatedResources),
				"encryptionSpec":          llx.DictData(encryptionSpec),
				"createdAt":               llx.TimeDataPtr(timestampAsTimePtr(pool.CreateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlPoolRes := mqlPool.(*mqlGcpProjectVertexaiServiceDeploymentResourcePool)
			mqlPoolRes.cacheKmsKeyName = pool.GetEncryptionSpec().GetKmsKeyName()
			mqlPoolRes.cacheProjectId = projectId
			mqlPoolRes.cacheServiceAccountEmail = pool.ServiceAccount
			items = append(items, mqlPool)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceDeploymentResourcePool) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) cachedContents() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("cachedContents", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewGenAiCacheClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListCachedContents(ctx, &aiplatformpb.ListCachedContentsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			cc, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			usageMetadata, err := protoToDict(cc.UsageMetadata)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(cc.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlCc, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.cachedContent", map[string]*llx.RawData{
				"name":           llx.StringData(cc.Name),
				"displayName":    llx.StringData(cc.DisplayName),
				"model":          llx.StringData(cc.Model),
				"usageMetadata":  llx.DictData(usageMetadata),
				"expireTime":     llx.TimeDataPtr(timestampAsTimePtr(cc.GetExpireTime())),
				"encryptionSpec": llx.DictData(encryptionSpec),
				"createdAt":      llx.TimeDataPtr(timestampAsTimePtr(cc.CreateTime)),
				"updatedAt":      llx.TimeDataPtr(timestampAsTimePtr(cc.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlCc.(*mqlGcpProjectVertexaiServiceCachedContent).cacheKmsKeyName = cc.GetEncryptionSpec().GetKmsKeyName()
			items = append(items, mqlCc)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceCachedContent) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) batchPredictionJobs() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("batchPredictionJobs", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewJobClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListBatchPredictionJobs(ctx, &aiplatformpb.ListBatchPredictionJobsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			job, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			inputConfig, err := protoToDict(job.InputConfig)
			if err != nil {
				return nil, false, err
			}
			outputConfig, err := protoToDict(job.OutputConfig)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(job.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.batchPredictionJob", map[string]*llx.RawData{
				"name":                    llx.StringData(job.Name),
				"displayName":             llx.StringData(job.DisplayName),
				"modelVersionId":          llx.StringData(job.ModelVersionId),
				"inputConfig":             llx.DictData(inputConfig),
				"outputConfig":            llx.DictData(outputConfig),
				"state":                   llx.StringData(job.State.String()),
				"generateExplanation":     llx.BoolData(job.GenerateExplanation),
				"disableContainerLogging": llx.BoolData(job.DisableContainerLogging),
				"labels":                  llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
				"encryptionSpec":          llx.DictData(encryptionSpec),
				"createdAt":               llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
				"startedAt":               llx.TimeDataPtr(timestampAsTimePtr(job.StartTime)),
				"endedAt":                 llx.TimeDataPtr(timestampAsTimePtr(job.EndTime)),
				"updatedAt":               llx.TimeDataPtr(timestampAsTimePtr(job.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlBatchJob := mqlJob.(*mqlGcpProjectVertexaiServiceBatchPredictionJob)
			mqlBatchJob.cacheKmsKeyName = job.GetEncryptionSpec().GetKmsKeyName()
			mqlBatchJob.cacheModelName = job.Model
			mqlBatchJob.cacheServiceAccountEmail = job.ServiceAccount
			mqlBatchJob.cacheProjectId = projectId
			items = append(items, mqlJob)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceBatchPredictionJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) tuningJobs() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("tuningJobs", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewGenAiTuningClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListTuningJobs(ctx, &aiplatformpb.ListTuningJobsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			job, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			tunedModel, err := protoToDict(job.TunedModel)
			if err != nil {
				return nil, false, err
			}
			tuningDataStats, err := protoToDict(job.TuningDataStats)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(job.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.tuningJob", map[string]*llx.RawData{
				"name":                  llx.StringData(job.Name),
				"tunedModelDisplayName": llx.StringData(job.TunedModelDisplayName),
				"description":           llx.StringData(job.Description),
				"baseModel":             llx.StringData(job.GetBaseModel()),
				"state":                 llx.StringData(job.State.String()),
				"experiment":            llx.StringData(job.Experiment),
				"tunedModel":            llx.DictData(tunedModel),
				"tuningDataStats":       llx.DictData(tuningDataStats),
				"labels":                llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
				"encryptionSpec":        llx.DictData(encryptionSpec),
				"createdAt":             llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
				"startedAt":             llx.TimeDataPtr(timestampAsTimePtr(job.StartTime)),
				"endedAt":               llx.TimeDataPtr(timestampAsTimePtr(job.EndTime)),
				"updatedAt":             llx.TimeDataPtr(timestampAsTimePtr(job.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlTuningJob := mqlJob.(*mqlGcpProjectVertexaiServiceTuningJob)
			mqlTuningJob.cacheKmsKeyName = job.GetEncryptionSpec().GetKmsKeyName()
			mqlTuningJob.cacheServiceAccountEmail = job.ServiceAccount
			mqlTuningJob.cacheProjectId = projectId
			mqlTuningJob.cacheTunedModelName = job.GetTunedModel().GetModel()
			items = append(items, mqlJob)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceTuningJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) trainingPipelines() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("trainingPipelines", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewPipelineClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListTrainingPipelines(ctx, &aiplatformpb.ListTrainingPipelinesRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			pipeline, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			inputDataConfig, err := protoToDict(pipeline.InputDataConfig)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(pipeline.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlPipeline, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.trainingPipeline", map[string]*llx.RawData{
				"name":                   llx.StringData(pipeline.Name),
				"displayName":            llx.StringData(pipeline.DisplayName),
				"trainingTaskDefinition": llx.StringData(pipeline.TrainingTaskDefinition),
				"inputDataConfig":        llx.DictData(inputDataConfig),
				"state":                  llx.StringData(pipeline.State.String()),
				"labels":                 llx.MapData(convert.MapToInterfaceMap(pipeline.Labels), types.String),
				"encryptionSpec":         llx.DictData(encryptionSpec),
				"createdAt":              llx.TimeDataPtr(timestampAsTimePtr(pipeline.CreateTime)),
				"startedAt":              llx.TimeDataPtr(timestampAsTimePtr(pipeline.StartTime)),
				"endedAt":                llx.TimeDataPtr(timestampAsTimePtr(pipeline.EndTime)),
				"updatedAt":              llx.TimeDataPtr(timestampAsTimePtr(pipeline.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			pipelineRes := mqlPipeline.(*mqlGcpProjectVertexaiServiceTrainingPipeline)
			pipelineRes.cacheKmsKeyName = pipeline.GetEncryptionSpec().GetKmsKeyName()
			pipelineRes.cacheParentModel = pipeline.ParentModel
			if pipeline.ModelId != "" {
				pipelineRes.cacheModelName = fmt.Sprintf("projects/%s/locations/%s/models/%s", projectId, region, pipeline.ModelId)
			}
			items = append(items, mqlPipeline)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceTrainingPipeline) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) hyperparameterTuningJobs() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("hyperparameterTuningJobs", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewJobClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListHyperparameterTuningJobs(ctx, &aiplatformpb.ListHyperparameterTuningJobsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			job, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			studySpec, err := protoToDict(job.StudySpec)
			if err != nil {
				return nil, false, err
			}
			trialJobSpec, err := protoToDict(job.TrialJobSpec)
			if err != nil {
				return nil, false, err
			}
			encryptionSpec, err := protoToDict(job.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.hyperparameterTuningJob", map[string]*llx.RawData{
				"name":                llx.StringData(job.Name),
				"displayName":         llx.StringData(job.DisplayName),
				"state":               llx.StringData(job.State.String()),
				"maxTrialCount":       llx.IntData(int64(job.MaxTrialCount)),
				"parallelTrialCount":  llx.IntData(int64(job.ParallelTrialCount)),
				"maxFailedTrialCount": llx.IntData(int64(job.MaxFailedTrialCount)),
				"studySpec":           llx.DictData(studySpec),
				"trialJobSpec":        llx.DictData(trialJobSpec),
				"labels":              llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
				"encryptionSpec":      llx.DictData(encryptionSpec),
				"createdAt":           llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
				"startedAt":           llx.TimeDataPtr(timestampAsTimePtr(job.StartTime)),
				"endedAt":             llx.TimeDataPtr(timestampAsTimePtr(job.EndTime)),
				"updatedAt":           llx.TimeDataPtr(timestampAsTimePtr(job.UpdateTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlHyperJob := mqlJob.(*mqlGcpProjectVertexaiServiceHyperparameterTuningJob)
			mqlHyperJob.cacheKmsKeyName = job.GetEncryptionSpec().GetKmsKeyName()
			if job.TrialJobSpec != nil {
				mqlHyperJob.cacheServiceAccountEmail = job.TrialJobSpec.GetServiceAccount()
				mqlHyperJob.cacheNetwork = job.TrialJobSpec.GetNetwork()
			}
			mqlHyperJob.cacheProjectId = vertexaiProjectFromName(job.Name)
			items = append(items, mqlJob)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceHyperparameterTuningJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectVertexaiService) modelDeploymentMonitoringJobs() ([]any, error) {
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
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	return g.listAcrossRegions("modelDeploymentMonitoringJobs", func(ctx context.Context, region string) ([]any, bool, error) {
		client, err := aiplatform.NewJobClient(ctx,
			option.WithCredentials(creds), connection.GRPCClientTraceOption(),
			option.WithEndpoint(vertexaiEndpoint(region)),
		)
		if err != nil {
			return nil, false, err
		}
		defer client.Close()

		it := client.ListModelDeploymentMonitoringJobs(ctx, &aiplatformpb.ListModelDeploymentMonitoringJobsRequest{
			Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region),
		})

		var items []any
		for {
			job, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isInapplicable(err) {
					// Keep what this region already yielded: the iterator
					// paginates lazily, so a skippable error on a later page
					// must not discard the pages that succeeded.
					return items, true, nil
				}
				return nil, false, err
			}

			encryptionSpec, err := protoToDict(job.EncryptionSpec)
			if err != nil {
				return nil, false, err
			}

			mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.vertexaiService.modelDeploymentMonitoringJob", map[string]*llx.RawData{
				"name":                         llx.StringData(job.Name),
				"displayName":                  llx.StringData(job.DisplayName),
				"state":                        llx.StringData(job.State.String()),
				"scheduleState":                llx.StringData(job.ScheduleState.String()),
				"enableMonitoringPipelineLogs": llx.BoolData(job.EnableMonitoringPipelineLogs),
				"labels":                       llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
				"encryptionSpec":               llx.DictData(encryptionSpec),
				"createdAt":                    llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
				"updatedAt":                    llx.TimeDataPtr(timestampAsTimePtr(job.UpdateTime)),
				"nextScheduleTime":             llx.TimeDataPtr(timestampAsTimePtr(job.NextScheduleTime)),
			})
			if err != nil {
				return nil, false, err
			}
			mqlMonJob := mqlJob.(*mqlGcpProjectVertexaiServiceModelDeploymentMonitoringJob)
			mqlMonJob.cacheKmsKeyName = job.GetEncryptionSpec().GetKmsKeyName()
			mqlMonJob.cacheEndpointName = job.Endpoint
			items = append(items, mqlJob)
		}
		return items, false, nil
	})
}

func (g *mqlGcpProjectVertexaiServiceModelDeploymentMonitoringJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// ---------------------------------------------------------------
// KMS key references
// ---------------------------------------------------------------

type mqlGcpProjectVertexaiServiceModelInternal struct {
	cacheKmsKeyName        string
	cacheOriginalModelName string
	cachePipelineJobName   string
}

func (a *mqlGcpProjectVertexaiServiceModel) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceModel) iamPolicy() ([]any, error) {
	if a.Name.Error != nil {
		return nil, a.Name.Error
	}
	name := a.Name.Data

	conn := a.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := aiplatform.NewModelClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(vertexaiRegionFromName(name))),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: name,
		Options:  &iampb.GetPolicyOptions{RequestedPolicyVersion: 3},
	})
	return vertexaiIamPolicyBindings(a.MqlRuntime, name, policy, err)
}

func (a *mqlGcpProjectVertexaiServiceModel) public() (bool, error) {
	bindings := a.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (a *mqlGcpProjectVertexaiServiceModel) originalModel() (*mqlGcpProjectVertexaiServiceModel, error) {
	return resolveVertexaiModelRef(a.MqlRuntime, &a.OriginalModel, a.cacheOriginalModelName)
}

func (a *mqlGcpProjectVertexaiServiceModel) pipelineJob() (*mqlGcpProjectVertexaiServicePipelineJob, error) {
	if a.cachePipelineJobName == "" {
		a.PipelineJob.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gcp.project.vertexaiService.pipelineJob", map[string]*llx.RawData{
		"name": llx.StringData(a.cachePipelineJobName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectVertexaiServicePipelineJob), nil
}

type mqlGcpProjectVertexaiServiceEndpointInternal struct {
	cacheKmsKeyName string
	cacheNetwork    string
}

func (a *mqlGcpProjectVertexaiServiceEndpoint) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServicePipelineJobInternal struct {
	cacheKmsKeyName     string
	cacheScheduleName   string
	cacheNetwork        string
	cacheServiceAccount string
}

func (a *mqlGcpProjectVertexaiServicePipelineJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServicePipelineJob) scheduleRef() (*mqlGcpProjectVertexaiServiceSchedule, error) {
	if a.cacheScheduleName == "" {
		a.ScheduleRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gcp.project.vertexaiService.schedule", map[string]*llx.RawData{
		"name": llx.StringData(a.cacheScheduleName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectVertexaiServiceSchedule), nil
}

func (a *mqlGcpProjectVertexaiServicePipelineJob) managedBy() (string, error) {
	return managedByFromLabels(a.GetLabels())
}

type mqlGcpProjectVertexaiServiceDatasetInternal struct {
	cacheKmsKeyName string
}

func (a *mqlGcpProjectVertexaiServiceDataset) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServiceFeatureOnlineStoreInternal struct {
	cacheKmsKeyName string
}

func (a *mqlGcpProjectVertexaiServiceFeatureOnlineStore) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServiceTensorboardInternal struct {
	cacheKmsKeyName string
}

func (a *mqlGcpProjectVertexaiServiceTensorboard) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServiceCustomJobInternal struct {
	cacheKmsKeyName     string
	cacheNetwork        string
	cacheServiceAccount string
}

func (a *mqlGcpProjectVertexaiServiceCustomJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceCustomJob) managedBy() (string, error) {
	return managedByFromLabels(a.GetLabels())
}

type mqlGcpProjectVertexaiServiceIndexInternal struct {
	cacheKmsKeyName string
}

func (a *mqlGcpProjectVertexaiServiceIndex) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServiceIndexEndpointInternal struct {
	cacheKmsKeyName string
	cacheNetwork    string
}

func (a *mqlGcpProjectVertexaiServiceIndexEndpoint) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServiceMetadataStoreInternal struct {
	cacheKmsKeyName string
}

func (a *mqlGcpProjectVertexaiServiceMetadataStore) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

// vertexaiServiceAccountRef resolves a cached service-account email (scoped to
// the given project) to a typed gcp.project.iamService.serviceAccount, marking
// the field null when either value is missing.
func vertexaiServiceAccountRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectIamServiceServiceAccount], projectId, email string) (*mqlGcpProjectIamServiceServiceAccount, error) {
	if email == "" || projectId == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

type mqlGcpProjectVertexaiServiceNotebookRuntimeInternal struct {
	cacheKmsKeyName          string
	cacheServiceAccountEmail string
	cacheProjectId           string
	cacheNetwork             string
	cacheSubnetwork          string
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntime) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntime) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	return vertexaiServiceAccountRef(a.MqlRuntime, &a.ServiceAccount, a.cacheProjectId, a.cacheServiceAccountEmail)
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntime) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	return vertexaiNetworkRef(a.MqlRuntime, &a.Network, a.cacheNetwork)
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntime) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	return vertexaiSubnetworkRef(a.MqlRuntime, &a.Subnetwork, a.cacheSubnetwork)
}

type mqlGcpProjectVertexaiServiceNotebookRuntimeTemplateInternal struct {
	cacheKmsKeyName          string
	cacheServiceAccountEmail string
	cacheProjectId           string
	cacheNetwork             string
	cacheSubnetwork          string
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate) iamPolicy() ([]any, error) {
	if a.Name.Error != nil {
		return nil, a.Name.Error
	}
	name := a.Name.Data

	conn := a.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(aiplatform.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := aiplatform.NewNotebookClient(ctx,
		option.WithCredentials(creds), connection.GRPCClientTraceOption(),
		option.WithEndpoint(vertexaiEndpoint(vertexaiRegionFromName(name))),
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: name,
		Options:  &iampb.GetPolicyOptions{RequestedPolicyVersion: 3},
	})
	return vertexaiIamPolicyBindings(a.MqlRuntime, name, policy, err)
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate) public() (bool, error) {
	bindings := a.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

// vertexaiIamPolicyBindings maps a fetched resource-level IAM policy to
// gcp.resourcemanager.binding resources. It handles the GetIamPolicy error
// (the Model and Notebook clients share the google.iam.v1 mixin), returning nil
// on access-denied so a scan without getIamPolicy permission degrades
// gracefully rather than erroring.
func vertexaiIamPolicyBindings(runtime *plugin.Runtime, name string, policy *iampb.Policy, err error) ([]any, error) {
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			return nil, nil
		}
		return nil, err
	}
	return iampbBindingsToMql(runtime, name, policy.Bindings)
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	return vertexaiServiceAccountRef(a.MqlRuntime, &a.ServiceAccount, a.cacheProjectId, a.cacheServiceAccountEmail)
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	return vertexaiNetworkRef(a.MqlRuntime, &a.Network, a.cacheNetwork)
}

func (a *mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	return vertexaiSubnetworkRef(a.MqlRuntime, &a.Subnetwork, a.cacheSubnetwork)
}

// vertexaiNetworkRef resolves a cached VPC network URL/name to the typed
// compute network, marking the field null when empty or unresolvable.
func vertexaiNetworkRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectComputeServiceNetwork], networkUrl string) (*mqlGcpProjectComputeServiceNetwork, error) {
	if networkUrl == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	n, err := getNetworkByUrl(networkUrl, runtime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

// vertexaiSubnetworkRef resolves a cached subnetwork URL/name to the typed
// compute subnetwork, marking the field null when empty or unresolvable.
func vertexaiSubnetworkRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectComputeServiceSubnetwork], subnetUrl string) (*mqlGcpProjectComputeServiceSubnetwork, error) {
	if subnetUrl == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	n, err := getSubnetworkByUrl(subnetUrl, runtime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

type mqlGcpProjectVertexaiServiceNotebookExecutionJobInternal struct {
	cacheKmsKeyName                  string
	cacheServiceAccountEmail         string
	cacheProjectId                   string
	cacheNotebookRuntimeTemplateName string
	cacheScheduleResourceName        string
}

func (a *mqlGcpProjectVertexaiServiceNotebookExecutionJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceNotebookExecutionJob) serviceAccountRef() (*mqlGcpProjectIamServiceServiceAccount, error) {
	return vertexaiServiceAccountRef(a.MqlRuntime, &a.ServiceAccountRef, a.cacheProjectId, a.cacheServiceAccountEmail)
}

func (a *mqlGcpProjectVertexaiServiceNotebookExecutionJob) notebookRuntimeTemplateRef() (*mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate, error) {
	if a.cacheNotebookRuntimeTemplateName == "" {
		a.NotebookRuntimeTemplateRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gcp.project.vertexaiService.notebookRuntimeTemplate", map[string]*llx.RawData{
		"name": llx.StringData(a.cacheNotebookRuntimeTemplateName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectVertexaiServiceNotebookRuntimeTemplate), nil
}

func (a *mqlGcpProjectVertexaiServiceNotebookExecutionJob) scheduleRef() (*mqlGcpProjectVertexaiServiceSchedule, error) {
	name := a.cacheScheduleResourceName
	if name == "" {
		a.ScheduleRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "gcp.project.vertexaiService.schedule", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectVertexaiServiceSchedule), nil
}

func (a *mqlGcpProjectVertexaiServiceNotebookExecutionJob) managedBy() (string, error) {
	return managedByFromLabels(a.GetLabels())
}

type mqlGcpProjectVertexaiServiceReasoningEngineInternal struct {
	cacheKmsKeyName string
	cacheProjectId  string
}

func (a *mqlGcpProjectVertexaiServiceReasoningEngine) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServiceRagCorpusInternal struct {
	cacheKmsKeyName string
}

func (a *mqlGcpProjectVertexaiServiceRagCorpus) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServicePersistentResourceInternal struct {
	cacheKmsKeyName string
	cacheNetworkUrl string
}

func (a *mqlGcpProjectVertexaiServicePersistentResource) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServicePersistentResource) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if a.cacheNetworkUrl == "" {
		a.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return getNetworkByUrl(a.cacheNetworkUrl, a.MqlRuntime)
}

type mqlGcpProjectVertexaiServiceDeploymentResourcePoolInternal struct {
	cacheKmsKeyName          string
	cacheProjectId           string
	cacheServiceAccountEmail string
}

func (a *mqlGcpProjectVertexaiServiceDeploymentResourcePool) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceDeploymentResourcePool) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if a.cacheServiceAccountEmail == "" || a.cacheProjectId == "" {
		a.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(a.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(a.cacheProjectId),
		"email":     llx.StringData(a.cacheServiceAccountEmail),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

type mqlGcpProjectVertexaiServiceCachedContentInternal struct {
	cacheKmsKeyName string
}

func (a *mqlGcpProjectVertexaiServiceCachedContent) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServiceBatchPredictionJobInternal struct {
	cacheKmsKeyName          string
	cacheModelName           string
	cacheServiceAccountEmail string
	cacheProjectId           string
}

func (a *mqlGcpProjectVertexaiServiceBatchPredictionJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceBatchPredictionJob) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	return vertexaiServiceAccountRef(a.MqlRuntime, &a.ServiceAccount, a.cacheProjectId, a.cacheServiceAccountEmail)
}

func (a *mqlGcpProjectVertexaiServiceBatchPredictionJob) model() (*mqlGcpProjectVertexaiServiceModel, error) {
	return resolveVertexaiModelRef(a.MqlRuntime, &a.Model, a.cacheModelName)
}

func (a *mqlGcpProjectVertexaiServiceBatchPredictionJob) managedBy() (string, error) {
	return managedByFromLabels(a.GetLabels())
}

type mqlGcpProjectVertexaiServiceTuningJobInternal struct {
	cacheKmsKeyName          string
	cacheServiceAccountEmail string
	cacheProjectId           string
	cacheTunedModelName      string
}

func (a *mqlGcpProjectVertexaiServiceTuningJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceTuningJob) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	return vertexaiServiceAccountRef(a.MqlRuntime, &a.ServiceAccount, a.cacheProjectId, a.cacheServiceAccountEmail)
}

func (a *mqlGcpProjectVertexaiServiceTuningJob) tunedModelRef() (*mqlGcpProjectVertexaiServiceModel, error) {
	return resolveVertexaiModelRef(a.MqlRuntime, &a.TunedModelRef, a.cacheTunedModelName)
}

func (a *mqlGcpProjectVertexaiServiceTuningJob) managedBy() (string, error) {
	return managedByFromLabels(a.GetLabels())
}

type mqlGcpProjectVertexaiServiceTrainingPipelineInternal struct {
	cacheKmsKeyName  string
	cacheModelName   string
	cacheParentModel string
}

func (a *mqlGcpProjectVertexaiServiceTrainingPipeline) model() (*mqlGcpProjectVertexaiServiceModel, error) {
	return resolveVertexaiModelRef(a.MqlRuntime, &a.Model, a.cacheModelName)
}

func (a *mqlGcpProjectVertexaiServiceTrainingPipeline) parentModel() (*mqlGcpProjectVertexaiServiceModel, error) {
	return resolveVertexaiModelRef(a.MqlRuntime, &a.ParentModel, a.cacheParentModel)
}

func (a *mqlGcpProjectVertexaiServiceTrainingPipeline) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

type mqlGcpProjectVertexaiServiceHyperparameterTuningJobInternal struct {
	cacheKmsKeyName          string
	cacheServiceAccountEmail string
	cacheNetwork             string
	cacheProjectId           string
}

func (a *mqlGcpProjectVertexaiServiceHyperparameterTuningJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceHyperparameterTuningJob) serviceAccountRef() (*mqlGcpProjectIamServiceServiceAccount, error) {
	return vertexaiServiceAccountRef(a.MqlRuntime, &a.ServiceAccountRef, a.cacheProjectId, a.cacheServiceAccountEmail)
}

func (a *mqlGcpProjectVertexaiServiceHyperparameterTuningJob) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	if a.cacheNetwork == "" {
		a.NetworkRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	n, err := getNetworkByUrl(a.cacheNetwork, a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		a.NetworkRef.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return n, nil
}

func (a *mqlGcpProjectVertexaiServiceHyperparameterTuningJob) managedBy() (string, error) {
	return managedByFromLabels(a.GetLabels())
}

type mqlGcpProjectVertexaiServiceModelDeploymentMonitoringJobInternal struct {
	cacheKmsKeyName   string
	cacheEndpointName string
}

func (a *mqlGcpProjectVertexaiServiceModelDeploymentMonitoringJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

func (a *mqlGcpProjectVertexaiServiceModelDeploymentMonitoringJob) managedBy() (string, error) {
	return managedByFromLabels(a.GetLabels())
}

func (a *mqlGcpProjectVertexaiServiceModelDeploymentMonitoringJob) endpoint() (*mqlGcpProjectVertexaiServiceEndpoint, error) {
	return resolveVertexaiEndpointRef(a.MqlRuntime, &a.Endpoint, a.cacheEndpointName)
}
