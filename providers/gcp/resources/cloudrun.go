// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	run "cloud.google.com/go/run/apiv2"
	runpb "cloud.google.com/go/run/apiv2/runpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	runv2 "google.golang.org/api/run/v2"
)

func (g *mqlGcpProjectCloudRunService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.cloudRunService", projectId), nil
}

func initGcpProjectCloudRunService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

type mqlGcpProjectCloudRunServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) cloudRun() (*mqlGcpProjectCloudRunService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.cloudRunService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_cloudrun)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectCloudRunService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_cloudrun).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func (g *mqlGcpProjectCloudRunServiceOperation) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	return fmt.Sprintf("gcp.project.cloudRunService.operation/%s/%s", projectId, name), nil
}

func (g *mqlGcpProjectCloudRunServiceService) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return fmt.Sprintf("gcp.project.cloudRunService.service/%s", id), nil
}

func initGcpProjectCloudRunServiceService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["region"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.cloudRunService.service requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.cloudRunService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlGcpProjectCloudRunService)
	services := svc.GetServices()
	if services.Error != nil {
		return nil, nil, services.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.cloudRunService.service requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	regionVal := ""
	if args["region"] != nil {
		regionVal, _ = args["region"].Value.(string)
	}
	for _, s := range services.Data {
		service := s.(*mqlGcpProjectCloudRunServiceService)
		if service.Name.Data == nameVal && (regionVal == "" || service.Region.Data == regionVal) {
			return args, service, nil
		}
	}

	return nil, nil, fmt.Errorf("cloud run service %q not found", nameVal)
}

type mqlGcpProjectCloudRunServiceServiceInternal struct {
	cacheEncryptionKey string
}

func (g *mqlGcpProjectCloudRunServiceService) encryptionKeyRef() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.EncryptionKeyRef, g.cacheEncryptionKey)
}

func (g *mqlGcpProjectCloudRunServiceService) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels(), g.GetAnnotations())
}

func (g *mqlGcpProjectCloudRunServiceJob) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return fmt.Sprintf("gcp.project.cloudRunService.job/%s", id), nil
}

func initGcpProjectCloudRunServiceJob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["region"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.cloudRunService.job requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.cloudRunService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlGcpProjectCloudRunService)
	jobs := svc.GetJobs()
	if jobs.Error != nil {
		return nil, nil, jobs.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.cloudRunService.job requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	regionVal := ""
	if args["region"] != nil {
		regionVal, _ = args["region"].Value.(string)
	}
	for _, j := range jobs.Data {
		job := j.(*mqlGcpProjectCloudRunServiceJob)
		if job.Name.Data == nameVal && (regionVal == "" || job.Region.Data == regionVal) {
			return args, job, nil
		}
	}

	return nil, nil, fmt.Errorf("cloud run job %q not found", nameVal)
}

type mqlGcpProjectCloudRunServiceJobInternal struct {
	cacheEncryptionKey string
}

func (g *mqlGcpProjectCloudRunServiceJob) encryptionKeyRef() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.EncryptionKeyRef, g.cacheEncryptionKey)
}

func (g *mqlGcpProjectCloudRunServiceJob) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels(), g.GetAnnotations())
}

func (g *mqlGcpProjectCloudRunServiceServiceRevisionTemplate) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectCloudRunServiceContainer) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectCloudRunServiceContainer) imageRepository() (*mqlGcpProjectArtifactRegistryServiceRepository, error) {
	if g.Image.Error != nil {
		return nil, g.Image.Error
	}
	project, location, repo := artifactRegistryRepoFromImage(g.Image.Data)
	ref, err := resolveArtifactRegistryRepoRef(g.MqlRuntime, project, location, repo)
	if err != nil {
		return nil, err
	}
	if ref == nil {
		g.ImageRepository.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return ref, nil
}

func (g *mqlGcpProjectCloudRunServiceContainerProbe) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectCloudRunServiceCondition) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectCloudRunServiceJobExecutionTemplate) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectCloudRunServiceJobExecutionTemplateTaskTemplate) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectCloudRunService) regions() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	client, err := conn.Client(run.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	regions, err := computeSvc.Regions.List(projectId).Do()
	if err != nil {
		return nil, err
	}

	regionNames := make([]any, 0, len(regions.Items))
	for _, region := range regions.Items {
		regionNames = append(regionNames, region.Name)
	}
	return regionNames, nil
}

func (g *mqlGcpProjectCloudRunService) operations() ([]any, error) {
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

	if g.Regions.Error != nil {
		return nil, g.Regions.Error
	}
	regions := g.Regions.Data
	if len(regions) == 0 {
		// regions data has not been fetched, we need to get it
		r, err := g.regions()
		if err != nil {
			return nil, err
		}
		regions = r
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(run.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	runSvc, err := run.NewServicesClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer runSvc.Close()

	var wg sync.WaitGroup
	var operations []any
	wg.Add(len(regions))
	mux := &sync.Mutex{}
	for _, region := range regions {
		go func(region string) {
			defer wg.Done()
			it := runSvc.ListOperations(ctx, &longrunningpb.ListOperationsRequest{Name: fmt.Sprintf("projects/%s/locations/%s", projectId, region)})
			for {
				t, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					log.Error().Err(err).Send()
					break
				}
				mqlOp, err := CreateResource(g.MqlRuntime, "gcp.project.cloudRunService.operation", map[string]*llx.RawData{
					"projectId": llx.StringData(projectId),
					"name":      llx.StringData(t.Name),
					"done":      llx.BoolData(t.Done),
				})
				if err != nil {
					log.Error().Err(err).Send()
					continue
				}
				mux.Lock()
				operations = append(operations, mqlOp)
				mux.Unlock()
			}
		}(region.(string))
	}
	wg.Wait()
	return operations, nil
}

func (g *mqlGcpProjectCloudRunService) services() ([]any, error) {
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

	creds, err := conn.Credentials(run.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	runSvc, err := run.NewServicesClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer runSvc.Close()

	type mqlRevisionScaling struct {
		MinInstanceCount int32 `json:"minInstanceCount"`
		MaxInstanceCount int32 `json:"maxInstanceCount"`
	}

	// One call for every region. Cloud Run v2 accepts "-" as the location, which
	// this provider previously fanned out over ~43 regions to achieve: verified
	// against the live API, projects/{p}/locations/-/services returns 200 with
	// services from every region. (ListJobs rejects the same wildcard with
	// INVALID_ARGUMENT, which is why the jobs lister below still fans out.)
	// Each service's own region is read back off its resource name.
	var services []any
	it := runSvc.ListServices(ctx, &runpb.ListServicesRequest{Parent: fmt.Sprintf("projects/%s/locations/-", projectId)})
	for {
		s, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Error().Err(err).Send()
			break
		}

		var mqlTemplate plugin.Resource
		if s.Template != nil {
			var scalingCfg map[string]any
			if s.Template.Scaling != nil {
				scalingCfg, err = convert.JsonToDict(mqlRevisionScaling{
					MinInstanceCount: s.Template.Scaling.MinInstanceCount,
					MaxInstanceCount: s.Template.Scaling.MaxInstanceCount,
				})
				if err != nil {
					log.Error().Err(err).Send()
				}
			}

			templateId := fmt.Sprintf("gcp.project.cloudRunService.service/%s/%s/revisionTemplate", projectId, s.Name)
			mqlVpcAccessCfg, err := mqlVpcAccessConfig(g.MqlRuntime, templateId+"/vpcAccess", s.Template.VpcAccess)
			if err != nil {
				log.Error().Err(err).Send()
			}

			mqlContainers, err := mqlContainers(g.MqlRuntime, s.Template.Containers, templateId)
			if err != nil {
				log.Error().Err(err).Send()
			}

			mqlTemplate, err = CreateResource(g.MqlRuntime, "gcp.project.cloudRunService.service.revisionTemplate", map[string]*llx.RawData{
				"id":                                   llx.StringData(templateId),
				"projectId":                            llx.StringData(projectId),
				"name":                                 llx.StringData(s.Template.Revision),
				"labels":                               llx.MapData(convert.MapToInterfaceMap(s.Template.Labels), types.String),
				"annotations":                          llx.MapData(convert.MapToInterfaceMap(s.Template.Annotations), types.String),
				"scaling":                              llx.DictData(scalingCfg),
				"vpcAccessConfig":                      llx.ResourceData(mqlVpcAccessCfg, "gcp.project.cloudRunService.vpcAccessConfig"),
				"timeout":                              llx.TimeData(llx.DurationToTime(s.Template.GetTimeout().GetSeconds())),
				"serviceAccountEmail":                  llx.StringData(s.Template.ServiceAccount),
				"containers":                           llx.ArrayData(mqlContainers, "gcp.project.cloudRunService.container"),
				"volumes":                              llx.ArrayData(mqlVolumes(s.Template.Volumes), types.Dict),
				"executionEnvironment":                 llx.StringData(s.Template.ExecutionEnvironment.String()),
				"encryptionKey":                        llx.StringData(s.Template.EncryptionKey),
				"maxInstanceRequestConcurrency":        llx.IntData(int64(s.Template.MaxInstanceRequestConcurrency)),
				"encryptionKeyRevocationAction":        llx.StringData(s.Template.GetEncryptionKeyRevocationAction().String()),
				"encryptionKeyShutdownDurationSeconds": llx.IntData(s.Template.GetEncryptionKeyShutdownDuration().GetSeconds()),
				"serviceMesh":                          llx.StringData(s.Template.GetServiceMesh().GetMesh()),
				"sessionAffinity":                      llx.BoolData(s.Template.GetSessionAffinity()),
				"healthCheckDisabled":                  llx.BoolData(s.Template.GetHealthCheckDisabled()),
				"nodeSelectorAccelerator":              llx.StringData(s.Template.GetNodeSelector().GetAccelerator()),
				"gpuZonalRedundancyDisabled":           llx.BoolData(s.Template.GetGpuZonalRedundancyDisabled()),
			})
			if err != nil {
				log.Error().Err(err).Send()
			}
		}

		mqlTraffic := make([]any, 0, len(s.Traffic))
		for _, t := range s.Traffic {
			mqlTraffic = append(mqlTraffic, map[string]any{
				"type":     t.Type.String(),
				"revision": t.Revision,
				"percent":  strconv.Itoa(int(t.Percent)),
				"tag":      t.Tag,
			})
		}

		mqlTerminalCondition, err := mqlCondition(g.MqlRuntime, s.TerminalCondition, s.Name, "terminal")
		if err != nil {
			log.Error().Err(err).Send()
		}

		mqlConditions := make([]any, 0, len(s.Conditions))
		for i, c := range s.Conditions {
			mqlCondition, err := mqlCondition(g.MqlRuntime, c, s.Name, fmt.Sprintf("%d", i))
			if err != nil {
				log.Error().Err(err).Send()
			}
			mqlConditions = append(mqlConditions, mqlCondition)
		}

		mqlTrafficStatuses := make([]any, 0, len(s.TrafficStatuses))
		for _, t := range s.TrafficStatuses {
			mqlTrafficStatuses = append(mqlTrafficStatuses, map[string]any{
				"type":     t.Type.String(),
				"revision": t.Revision,
				"percent":  strconv.Itoa(int(t.Percent)),
				"tag":      t.Tag,
				"uri":      t.Uri,
			})
		}

		baDict, err := protoToDict(s.BinaryAuthorization)
		if err != nil {
			log.Error().Err(err).Msg("failed to convert BinaryAuthorization to dict")
		}
		var baUseDefault bool
		var baBreakglass string
		if s.BinaryAuthorization != nil {
			baUseDefault = s.BinaryAuthorization.GetUseDefault()
			baBreakglass = s.BinaryAuthorization.GetBreakglassJustification()
		}
		// Only a service Cloud Run built from source carries a build
		// config. Leaving it null on image-deployed services keeps a
		// check on the base image or build identity from matching a
		// service that was never built here.
		buildConfigData := llx.NilData
		if bc := s.GetBuildConfig(); bc != nil {
			mqlBuild, err := CreateResource(g.MqlRuntime, "gcp.project.cloudRunService.service.buildSettings", map[string]*llx.RawData{
				"__id":                   llx.StringData(fmt.Sprintf("%s/buildConfig", s.Name)),
				"name":                   llx.StringData(bc.GetName()),
				"sourceLocation":         llx.StringData(bc.GetSourceLocation()),
				"functionTarget":         llx.StringData(bc.GetFunctionTarget()),
				"imageUri":               llx.StringData(bc.GetImageUri()),
				"baseImage":              llx.StringData(bc.GetBaseImage()),
				"enableAutomaticUpdates": llx.BoolData(bc.GetEnableAutomaticUpdates()),
				"workerPool":             llx.StringData(bc.GetWorkerPool()),
				"environmentVariables":   llx.MapData(convert.MapToInterfaceMap(bc.GetEnvironmentVariables()), types.String),
			})
			if err != nil {
				// Match the surrounding loop: one malformed build config
				// must not drop the whole service list. The field stays
				// null rather than reporting a build that was not read.
				log.Error().Err(err).Str("service", s.Name).Msg("failed to create cloud run build config")
			} else {
				mqlBuild.(*mqlGcpProjectCloudRunServiceServiceBuildSettings).cacheServiceAccount = bc.GetServiceAccount()
				buildConfigData = llx.ResourceData(mqlBuild, "gcp.project.cloudRunService.service.buildSettings")
			}
		}

		mqlS, err := CreateResource(g.MqlRuntime, "gcp.project.cloudRunService.service", map[string]*llx.RawData{
			"id":                            llx.StringData(s.Name),
			"projectId":                     llx.StringData(projectId),
			"region":                        llx.StringData(parseLocationFromPath(s.Name)),
			"name":                          llx.StringData(parseResourceName(s.Name)),
			"description":                   llx.StringData(s.Description),
			"generation":                    llx.IntData(s.Generation),
			"labels":                        llx.MapData(convert.MapToInterfaceMap(s.Labels), types.String),
			"annotations":                   llx.MapData(convert.MapToInterfaceMap(s.Annotations), types.String),
			"created":                       llx.TimeDataPtr(timestampAsTimePtr(s.CreateTime)),
			"updated":                       llx.TimeDataPtr(timestampAsTimePtr(s.UpdateTime)),
			"deleted":                       llx.TimeDataPtr(timestampAsTimePtr(s.DeleteTime)),
			"expired":                       llx.TimeDataPtr(timestampAsTimePtr(s.ExpireTime)),
			"creator":                       llx.StringData(s.Creator),
			"lastModifier":                  llx.StringData(s.LastModifier),
			"ingress":                       llx.StringData(s.Ingress.String()),
			"invokerIamDisabled":            llx.BoolData(s.InvokerIamDisabled),
			"iapEnabled":                    llx.BoolData(s.IapEnabled),
			"threatDetectionEnabled":        llx.BoolData(s.ThreatDetectionEnabled),
			"launchStage":                   llx.StringData(s.LaunchStage.String()),
			"template":                      llx.ResourceData(mqlTemplate, "gcp.project.cloudRunService.service.revisionTemplate"),
			"traffic":                       llx.ArrayData(mqlTraffic, types.Dict),
			"observedGeneration":            llx.IntData(s.ObservedGeneration),
			"terminalCondition":             llx.ResourceData(mqlTerminalCondition, "gcp.project.cloudRunService.condition"),
			"conditions":                    llx.ArrayData(mqlConditions, types.Resource("gcp.project.cloudRunService.condition")),
			"latestReadyRevision":           llx.StringData(s.LatestReadyRevision),
			"latestCreatedRevision":         llx.StringData(s.LatestCreatedRevision),
			"trafficStatuses":               llx.ArrayData(mqlTrafficStatuses, types.Dict),
			"uri":                           llx.StringData(s.Uri),
			"reconciling":                   llx.BoolData(s.Reconciling),
			"customAudiences":               llx.ArrayData(convert.SliceAnyToInterface(s.CustomAudiences), types.String),
			"defaultUriDisabled":            llx.BoolData(s.DefaultUriDisabled),
			"satisfiesPzs":                  llx.BoolData(s.SatisfiesPzs),
			"scalingMode":                   llx.StringData(s.GetScaling().GetScalingMode().String()),
			"minInstanceCount":              llx.IntData(int64(s.GetScaling().GetMinInstanceCount())),
			"maxInstanceCount":              llx.IntData(int64(s.GetScaling().GetMaxInstanceCount())),
			"manualInstanceCount":           llx.IntData(int64(s.GetScaling().GetManualInstanceCount())),
			"urls":                          llx.ArrayData(convert.SliceAnyToInterface(s.GetUrls()), types.String),
			"buildConfig":                   buildConfigData,
			"uid":                           llx.StringData(s.Uid),
			"etag":                          llx.StringData(s.Etag),
			"client":                        llx.StringData(s.Client),
			"clientVersion":                 llx.StringData(s.ClientVersion),
			"binaryAuthorization":           llx.DictData(baDict),
			"binaryAuthorizationUseDefault": llx.BoolData(baUseDefault),
			"binaryAuthorizationBreakglassJustification": llx.StringData(baBreakglass),
		})
		if err != nil {
			log.Error().Err(err).Send()
			continue
		}
		mqlS.(*mqlGcpProjectCloudRunServiceService).cacheEncryptionKey = s.GetTemplate().GetEncryptionKey()
		services = append(services, mqlS)
	}
	return services, nil
}

func cloudRunIamBindings(runtime *plugin.Runtime, resourcePath string, bindings []*runv2.GoogleIamV1Binding) ([]any, error) {
	res := make([]any, 0, len(bindings))
	for i, b := range bindings {
		condTitle, condExpr, condDesc := "", "", ""
		if b.Condition != nil {
			condTitle = b.Condition.Title
			condExpr = b.Condition.Expression
			condDesc = b.Condition.Description
		}

		mqlBinding, err := CreateResource(runtime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(resourcePath + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(condTitle),
			"conditionExpression":  llx.StringData(condExpr),
			"conditionDescription": llx.StringData(condDesc),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectCloudRunServiceService) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Region.Error != nil {
		return nil, g.Region.Error
	}
	region := g.Region.Data
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(runv2.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	runSvc, err := runv2.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	resourcePath := fmt.Sprintf("projects/%s/locations/%s/services/%s", projectId, region, name)
	policy, err := runSvc.Projects.Locations.Services.GetIamPolicy(resourcePath).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		if isSkippable(err) {
			return nil, nil
		}
		return nil, err
	}
	return cloudRunIamBindings(g.MqlRuntime, resourcePath, policy.Bindings)
}

func (g *mqlGcpProjectCloudRunServiceJob) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Region.Error != nil {
		return nil, g.Region.Error
	}
	region := g.Region.Data
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(runv2.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	runSvc, err := runv2.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	resourcePath := fmt.Sprintf("projects/%s/locations/%s/jobs/%s", projectId, region, name)
	policy, err := runSvc.Projects.Locations.Jobs.GetIamPolicy(resourcePath).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		if isSkippable(err) {
			return nil, nil
		}
		return nil, err
	}
	return cloudRunIamBindings(g.MqlRuntime, resourcePath, policy.Bindings)
}

func (g *mqlGcpProjectCloudRunServiceServiceRevisionTemplate) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" {
		// No SA on the template means it falls back to the compute/project
		// default; resolve to null rather than a husk keyed on an empty email.
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
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

func (g *mqlGcpProjectCloudRunServiceJobExecutionTemplateTaskTemplate) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" {
		// No SA on the template means it falls back to the compute/project
		// default; resolve to null rather than a husk keyed on an empty email.
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
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

func (g *mqlGcpProjectCloudRunService) jobs() ([]any, error) {
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

	if g.Regions.Error != nil {
		return nil, g.Regions.Error
	}
	regions := g.Regions.Data
	if len(regions) == 0 {
		// regions data has not been fetched, we need to get it
		r, err := g.regions()
		if err != nil {
			return nil, err
		}
		regions = r
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(run.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	runSvc, err := run.NewJobsClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer runSvc.Close()

	var wg sync.WaitGroup
	var jobs []any
	wg.Add(len(regions))
	mux := &sync.Mutex{}
	for _, region := range regions {
		go func(region string) {
			defer wg.Done()
			it := runSvc.ListJobs(ctx, &runpb.ListJobsRequest{Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, region)})
			for {
				j, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					log.Error().Err(err).Send()
					return
				}

				var mqlTemplate plugin.Resource
				if j.Template != nil {
					templateId := fmt.Sprintf("%s/executionTemplate", j.Name)
					var mqlTaskTemplate plugin.Resource
					if j.Template.Template != nil {
						taskTemplateId := fmt.Sprintf("%s/template", templateId)
						mqlVpcAccessCfg, err := mqlVpcAccessConfig(g.MqlRuntime, taskTemplateId+"/vpcAccess", j.Template.Template.VpcAccess)
						if err != nil {
							log.Error().Err(err).Send()
							return
						}

						mqlContainers, err := mqlContainers(g.MqlRuntime, j.Template.Template.Containers, templateId)
						if err != nil {
							log.Error().Err(err).Send()
							return
						}

						mqlTaskTemplate, err = CreateResource(g.MqlRuntime, "gcp.project.cloudRunService.job.executionTemplate.taskTemplate", map[string]*llx.RawData{
							"id":                   llx.StringData(taskTemplateId),
							"projectId":            llx.StringData(projectId),
							"vpcAccessConfig":      llx.ResourceData(mqlVpcAccessCfg, "gcp.project.cloudRunService.vpcAccessConfig"),
							"timeout":              llx.TimeData(llx.DurationToTime(j.Template.Template.GetTimeout().GetSeconds())),
							"serviceAccountEmail":  llx.StringData(j.Template.Template.ServiceAccount),
							"containers":           llx.ArrayData(mqlContainers, types.Resource("gcp.project.cloudRunService.container")),
							"volumes":              llx.ArrayData(mqlVolumes(j.Template.Template.Volumes), types.Dict),
							"executionEnvironment": llx.StringData(j.Template.Template.ExecutionEnvironment.String()),
							"encryptionKey":        llx.StringData(j.Template.Template.EncryptionKey),
							"maxRetries":           llx.IntData(int64(j.Template.Template.GetMaxRetries())),
						})
						if err != nil {
							log.Error().Err(err).Send()
							return
						}
					}

					mqlTemplate, err = CreateResource(g.MqlRuntime, "gcp.project.cloudRunService.job.executionTemplate", map[string]*llx.RawData{
						"id":          llx.StringData(templateId),
						"labels":      llx.MapData(convert.MapToInterfaceMap(j.Template.Labels), types.String),
						"annotations": llx.MapData(convert.MapToInterfaceMap(j.Template.Annotations), types.String),
						"parallelism": llx.IntData(int64(j.Template.Parallelism)),
						"taskCount":   llx.IntData(int64(j.Template.TaskCount)),
						"template":    llx.ResourceData(mqlTaskTemplate, "gcp.project.cloudRunService.job.executionTemplate.taskTemplate"),
					})
					if err != nil {
						log.Error().Err(err).Send()
						return
					}
				}

				mqlTerminalCondition, err := mqlCondition(g.MqlRuntime, j.TerminalCondition, j.Name, "terminal")
				if err != nil {
					log.Error().Err(err).Send()
					return
				}

				mqlConditions := make([]any, 0, len(j.Conditions))
				for i, c := range j.Conditions {
					mqlCondition, err := mqlCondition(g.MqlRuntime, c, j.Name, fmt.Sprintf("%d", i))
					if err != nil {
						log.Error().Err(err).Send()
						return
					}
					mqlConditions = append(mqlConditions, mqlCondition)
				}

				mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.cloudRunService.job", map[string]*llx.RawData{
					"id":                 llx.StringData(j.Name),
					"projectId":          llx.StringData(projectId),
					"region":             llx.StringData(region),
					"name":               llx.StringData(parseResourceName(j.Name)),
					"generation":         llx.IntData(j.Generation),
					"labels":             llx.MapData(convert.MapToInterfaceMap(j.Labels), types.String),
					"annotations":        llx.MapData(convert.MapToInterfaceMap(j.Annotations), types.String),
					"created":            llx.TimeDataPtr(timestampAsTimePtr(j.CreateTime)),
					"updated":            llx.TimeDataPtr(timestampAsTimePtr(j.UpdateTime)),
					"deleted":            llx.TimeDataPtr(timestampAsTimePtr(j.DeleteTime)),
					"expired":            llx.TimeDataPtr(timestampAsTimePtr(j.ExpireTime)),
					"creator":            llx.StringData(j.Creator),
					"lastModifier":       llx.StringData(j.LastModifier),
					"client":             llx.StringData(j.Client),
					"clientVersion":      llx.StringData(j.ClientVersion),
					"launchStage":        llx.StringData(j.LaunchStage.String()),
					"template":           llx.ResourceData(mqlTemplate, "gcp.project.cloudRunService.job.executionTemplate"),
					"observedGeneration": llx.IntData(j.ObservedGeneration),
					"terminalCondition":  llx.ResourceData(mqlTerminalCondition, "gcp.project.cloudRunService.condition"),
					"conditions":         llx.ArrayData(mqlConditions, types.Resource("gcp.project.cloudRunService.condition")),
					"executionCount":     llx.IntData(int64(j.ExecutionCount)),
					"reconciling":        llx.BoolData(j.Reconciling),
					"satisfiesPzs":       llx.BoolData(j.SatisfiesPzs),
					"uid":                llx.StringData(j.Uid),
					"etag":               llx.StringData(j.Etag),
				})
				if err != nil {
					log.Error().Err(err).Send()
					return
				}
				mqlJob.(*mqlGcpProjectCloudRunServiceJob).cacheEncryptionKey = j.GetTemplate().GetTemplate().GetEncryptionKey()
				mux.Lock()
				jobs = append(jobs, mqlJob)
				mux.Unlock()
			}
		}(region.(string))
	}
	wg.Wait()
	return jobs, nil
}

func mqlContainerProbe(runtime *plugin.Runtime, probe *runpb.Probe, containerId string, probeName string) (plugin.Resource, error) {
	if probe == nil {
		return nil, nil
	}
	var mqlHttpGet map[string]any
	if httpGet := probe.GetHttpGet(); httpGet != nil {
		mqlHttpHeaders := make([]any, 0, len(httpGet.HttpHeaders))
		for _, h := range httpGet.HttpHeaders {
			mqlHttpHeaders = append(mqlHttpHeaders, map[string]any{
				"name":  h.Name,
				"value": h.Value,
			})
		}
		mqlHttpGet = map[string]any{
			"path":        httpGet.Path,
			"httpHeaders": mqlHttpHeaders,
		}
	}

	var mqlTcpSocket map[string]any
	if tcpSocket := probe.GetTcpSocket(); tcpSocket != nil {
		mqlTcpSocket = map[string]any{
			// int32 is not JSON-native inside a dict.
			"port": int64(tcpSocket.Port),
		}
	}

	return CreateResource(runtime, "gcp.project.cloudRunService.container.probe", map[string]*llx.RawData{
		"id":                  llx.StringData(fmt.Sprintf("%s/%s", containerId, probeName)),
		"initialDelaySeconds": llx.IntData(int64(probe.InitialDelaySeconds)),
		"timeoutSeconds":      llx.IntData(int64(probe.TimeoutSeconds)),
		"periodSeconds":       llx.IntData(int64(probe.PeriodSeconds)),
		"failureThreshold":    llx.IntData(int64(probe.FailureThreshold)),
		"httpGet":             llx.DictData(mqlHttpGet),
		"tcpSocket":           llx.DictData(mqlTcpSocket),
	})
}

func mqlCondition(runtime *plugin.Runtime, c *runpb.Condition, parentId, suffix string) (plugin.Resource, error) {
	if c == nil {
		return nil, nil
	}
	return CreateResource(runtime, "gcp.project.cloudRunService.condition", map[string]*llx.RawData{
		"id":   llx.StringData(fmt.Sprintf("%s/condition/%s", parentId, suffix)),
		"type": llx.StringData(c.Type),
		// c.String() is the generated proto-message stringer, which renders the
		// whole message as protobuf TEXT (`type:"Ready" state:CONDITION_...`).
		// The state enum is c.State.
		"state":              llx.StringData(c.State.String()),
		"message":            llx.StringData(c.Message),
		"lastTransitionTime": llx.TimeDataPtr(timestampAsTimePtr(c.LastTransitionTime)),
		"severity":           llx.StringData(c.Severity.String()),
	})
}

// mqlVpcAccessConfig builds the typed gcp.project.cloudRunService.vpcAccessConfig
// resource shared by Cloud Run service revisions and Cloud Run job task
// templates. id should be a parent-qualified path so multiple instances of
// this sub-resource (one per revision or task template) do not collide in the
// runtime cache.
func mqlVpcAccessConfig(runtime *plugin.Runtime, id string, vpcAccess *runpb.VpcAccess) (plugin.Resource, error) {
	if vpcAccess == nil {
		return nil, nil
	}
	interfaces := make([]any, 0, len(vpcAccess.NetworkInterfaces))
	for _, ni := range vpcAccess.NetworkInterfaces {
		if ni == nil {
			continue
		}
		interfaces = append(interfaces, map[string]any{
			"network":    ni.Network,
			"subnetwork": ni.Subnetwork,
			"tags":       convert.SliceAnyToInterface(ni.Tags),
		})
	}
	return CreateResource(runtime, "gcp.project.cloudRunService.vpcAccessConfig", map[string]*llx.RawData{
		"__id":              llx.StringData(id),
		"connector":         llx.StringData(vpcAccess.Connector),
		"egress":            llx.StringData(vpcAccess.Egress.String()),
		"networkInterfaces": llx.ArrayData(interfaces, types.Dict),
	})
}

func mqlContainers(runtime *plugin.Runtime, containers []*runpb.Container, templateId string) ([]any, error) {
	mqlContainers := make([]any, 0, len(containers))
	for _, c := range containers {
		mqlEnvs := make([]any, 0, len(c.Env))
		for _, e := range c.Env {
			valueSource := e.GetValueSource()
			var mqlValueSource map[string]any
			if skr := valueSource.GetSecretKeyRef(); skr != nil {
				mqlValueSource = map[string]any{
					"secretKeyRef": map[string]any{
						"secret":  skr.Secret,
						"version": skr.Version,
					},
				}
			}
			mqlEnvs = append(mqlEnvs, map[string]any{
				"name":        e.Name,
				"value":       e.GetValue(),
				"valueSource": mqlValueSource,
			})
		}

		var mqlResources map[string]any
		if c.Resources != nil {
			mqlResources = map[string]any{
				"limits":  convert.MapToInterfaceMap(c.Resources.Limits),
				"cpuIdle": c.Resources.CpuIdle,
			}
		}

		mqlPorts := make([]any, 0, len(c.Ports))
		for _, p := range c.Ports {
			mqlPorts = append(mqlPorts, map[string]any{
				"name": p.Name,
				// int32 is not JSON-native inside a dict.
				"containerPort": int64(p.ContainerPort),
			})
		}

		mqlVolumeMounts := make([]any, 0, len(c.VolumeMounts))
		for _, v := range c.VolumeMounts {
			mqlVolumeMounts = append(mqlVolumeMounts, map[string]any{
				"name":      v.Name,
				"mountPath": v.MountPath,
			})
		}

		containerId := fmt.Sprintf("%s/container/%s", templateId, c.Name)
		mqlLivenessProbe, err := mqlContainerProbe(runtime, c.LivenessProbe, containerId, "livenessProbe")
		if err != nil {
			return nil, err
		}

		mqlReadinessProbe, err := mqlContainerProbe(runtime, c.ReadinessProbe, containerId, "readinessProbe")
		if err != nil {
			return nil, err
		}

		mqlStartupProbe, err := mqlContainerProbe(runtime, c.StartupProbe, containerId, "startupProbe")
		if err != nil {
			return nil, err
		}

		mqlContainer, err := CreateResource(runtime, "gcp.project.cloudRunService.container", map[string]*llx.RawData{
			"id":                  llx.StringData(containerId),
			"name":                llx.StringData(c.Name),
			"image":               llx.StringData(c.Image),
			"command":             llx.ArrayData(convert.SliceAnyToInterface(c.Command), types.String),
			"args":                llx.ArrayData(convert.SliceAnyToInterface(c.Args), types.String),
			"env":                 llx.ArrayData(mqlEnvs, types.Dict),
			"resources":           llx.DictData(mqlResources),
			"ports":               llx.ArrayData(mqlPorts, types.Dict),
			"volumeMounts":        llx.ArrayData(mqlVolumeMounts, types.Dict),
			"workingDir":          llx.StringData(c.WorkingDir),
			"livenessProbe":       llx.ResourceData(mqlLivenessProbe, "gcp.project.cloudRunService.container.probe"),
			"startupProbe":        llx.ResourceData(mqlStartupProbe, "gcp.project.cloudRunService.container.probe"),
			"readinessProbe":      llx.ResourceData(mqlReadinessProbe, "gcp.project.cloudRunService.container.probe"),
			"dependsOn":           llx.ArrayData(convert.SliceAnyToInterface(c.DependsOn), types.String),
			"baseImageUri":        llx.StringData(c.BaseImageUri),
			"buildFunctionTarget": llx.StringData(c.GetBuildInfo().GetFunctionTarget()),
			"buildSourceLocation": llx.StringData(c.GetBuildInfo().GetSourceLocation()),
		})
		if err != nil {
			return nil, err
		}
		mqlContainers = append(mqlContainers, mqlContainer)
	}
	return mqlContainers, nil
}

func (g *mqlGcpProjectCloudRunServiceService) publicInvocable() (bool, error) {
	if g.Ingress.Error != nil {
		return false, g.Ingress.Error
	}
	if g.Ingress.Data != "INGRESS_TRAFFIC_ALL" {
		return false, nil
	}
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func mqlVolumes(volumes []*runpb.Volume) []any {
	mqlVolumes := make([]any, 0, len(volumes))
	for _, v := range volumes {
		mqlVolumes = append(mqlVolumes, map[string]any{
			"name": v.Name,
		})
	}
	return mqlVolumes
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectCloudRunService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_cloudrun)
}

type mqlGcpProjectCloudRunServiceServiceBuildSettingsInternal struct {
	cacheServiceAccount string
}

func (g *mqlGcpProjectCloudRunServiceServiceBuildSettings) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	// Cloud Run reports a full "projects/{p}/serviceAccounts/{email}" path here,
	// so resolveServiceAccountRef derives the project and needs no fallback.
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheServiceAccount, "")
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}
