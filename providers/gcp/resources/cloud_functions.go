// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	functions "cloud.google.com/go/functions/apiv1"
	"cloud.google.com/go/functions/apiv1/functionspb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"go.mondoo.com/mql/llx"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (g *mqlGcpProject) cloudFunctions() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}

	serviceEnabled, err := g.isServiceEnabled(service_cloudfunctions)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_cloudfunctions).Msg("gcp service is not enabled, skipping")
		return nil, nil
	}

	projectId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(functions.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	cloudFuncSvc, err := functions.NewCloudFunctionsClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer cloudFuncSvc.Close()

	type mqlSecretEnvVar struct {
		ProjectId string `json:"projectId"`
		Secret    string `json:"secret"`
		Version   string `json:"version"`
	}
	type mqlSecretVolumeVersion struct {
		Version string `json:"version"`
		Path    string `json:"path"`
	}
	type mqlSecretVolume struct {
		MountPath string                   `json:"mountPath"`
		ProjectId string                   `json:"projectId"`
		Secret    string                   `json:"secret"`
		Versions  []mqlSecretVolumeVersion `json:"versions"`
	}
	type mqlSourceRepository struct {
		Url         string `json:"url"`
		DeployedUrl string `json:"deployedUrl"`
	}
	type mqlHttpsTrigger struct {
		Url           string `json:"url"`
		SecurityLevel string `json:"securityLevel"`
	}
	type mqlFailurePolicy struct {
		Retry string `json:"retry"`
	}
	type mqlEventTrigger struct {
		EventType     string           `json:"eventType"`
		Resource      string           `json:"resource"`
		Service       string           `json:"service"`
		FailurePolicy mqlFailurePolicy `json:"failurePolicy"`
	}

	it := cloudFuncSvc.ListFunctions(ctx, &functionspb.ListFunctionsRequest{Parent: fmt.Sprintf("projects/%s/locations/-", projectId)})
	var cloudFunctions []any
	for {
		f, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		secretEnvVars := make(map[string]any)
		for _, v := range f.SecretEnvironmentVariables {
			envVar, err := convert.JsonToDict(mqlSecretEnvVar{ProjectId: v.ProjectId, Secret: v.Secret, Version: v.Version})
			if err != nil {
				return nil, err
			}
			secretEnvVars[v.Key] = envVar
		}

		secretVolumes := make([]any, 0, len(f.SecretVolumes))
		for _, v := range f.SecretVolumes {
			versions := make([]mqlSecretVolumeVersion, 0, len(v.Versions))
			for _, vv := range v.Versions {
				versions = append(versions, mqlSecretVolumeVersion{Version: vv.Version, Path: vv.Path})
			}
			vol, err := convert.JsonToDict(mqlSecretVolume{MountPath: v.MountPath, ProjectId: v.ProjectId, Secret: v.Secret, Versions: versions})
			if err != nil {
				return nil, err
			}
			secretVolumes = append(secretVolumes, vol)
		}

		envBindings := make([]cloudFunctionSecretBinding, 0, len(f.SecretEnvironmentVariables))
		for _, v := range f.SecretEnvironmentVariables {
			envBindings = append(envBindings, cloudFunctionSecretBinding{
				key: v.Key, projectID: v.ProjectId, secret: v.Secret, version: v.Version,
			})
		}
		volumeBindings := make([]cloudFunctionSecretBinding, 0, len(f.SecretVolumes))
		for _, v := range f.SecretVolumes {
			paths := make(map[string]string, len(v.Versions))
			for _, vv := range v.Versions {
				paths[vv.Version] = vv.Path
			}
			volumeBindings = append(volumeBindings, cloudFunctionSecretBinding{
				mountPath: v.MountPath, projectID: v.ProjectId, secret: v.Secret, versionPaths: paths,
			})
		}
		boundSecretEnvVars, err := newMqlFunctionSecretEnvVars(g.MqlRuntime, f.Name, envBindings)
		if err != nil {
			return nil, err
		}
		boundSecretVolumes, err := newMqlFunctionSecretVolumes(g.MqlRuntime, f.Name, volumeBindings)
		if err != nil {
			return nil, err
		}

		var sourceUploadUrl, sourceArchiveUrl string
		var sourceRepository map[string]any
		switch f.SourceCode.(type) {
		case *functionspb.CloudFunction_SourceArchiveUrl:
			sourceArchiveUrl = f.GetSourceArchiveUrl()
		case *functionspb.CloudFunction_SourceRepository:
			pbSourceRepo := f.GetSourceRepository()
			sourceRepository, err = convert.JsonToDict(mqlSourceRepository{Url: pbSourceRepo.Url, DeployedUrl: pbSourceRepo.DeployedUrl})
			if err != nil {
				return nil, err
			}
		case *functionspb.CloudFunction_SourceUploadUrl:
			sourceUploadUrl = f.GetSourceUploadUrl()
		}

		var httpsTrigger, eventTrigger map[string]any
		var eventTriggerResource string
		switch f.Trigger.(type) {
		case *functionspb.CloudFunction_HttpsTrigger:
			pbHttpsTrigger := f.GetHttpsTrigger()
			httpsTrigger, err = convert.JsonToDict(mqlHttpsTrigger{Url: pbHttpsTrigger.Url, SecurityLevel: pbHttpsTrigger.SecurityLevel.String()})
			if err != nil {
				return nil, err
			}
		case *functionspb.CloudFunction_EventTrigger:
			pbEventTrigger := f.GetEventTrigger()
			eventTriggerResource = pbEventTrigger.Resource
			eventTrigger, err = convert.JsonToDict(mqlEventTrigger{
				EventType:     pbEventTrigger.EventType,
				Resource:      pbEventTrigger.Resource,
				Service:       pbEventTrigger.Service,
				FailurePolicy: mqlFailurePolicy{Retry: pbEventTrigger.FailurePolicy.GetRetry().String()},
			})
			if err != nil {
				return nil, err
			}
		}

		mqlCloudFuncs, err := CreateResource(g.MqlRuntime, "gcp.project.cloudFunction", map[string]*llx.RawData{
			"projectId":           llx.StringData(projectId),
			"location":            llx.StringData(parseLocationFromPath(f.Name)),
			"name":                llx.StringData(parseResourceName(f.Name)),
			"description":         llx.StringData(f.Description),
			"sourceArchiveUrl":    llx.StringData(sourceArchiveUrl),
			"sourceRepository":    llx.DictData(sourceRepository),
			"sourceUploadUrl":     llx.StringData(sourceUploadUrl),
			"httpsTrigger":        llx.DictData(httpsTrigger),
			"eventTrigger":        llx.DictData(eventTrigger),
			"status":              llx.StringData(f.Status.String()),
			"entryPoint":          llx.StringData(f.EntryPoint),
			"runtime":             llx.StringData(f.Runtime),
			"timeout":             llx.TimeData(llx.DurationToTime(f.GetTimeout().GetSeconds())),
			"availableMemoryMb":   llx.IntData(int64(f.AvailableMemoryMb)),
			"serviceAccountEmail": llx.StringData(f.ServiceAccountEmail),
			"updated":             llx.TimeDataPtr(timestampAsTimePtr(f.UpdateTime)),
			"versionId":           llx.IntData(f.VersionId),
			"labels":              llx.MapData(convert.MapToInterfaceMap(f.Labels), types.String),
			"envVars":             llx.MapData(convert.MapToInterfaceMap(f.EnvironmentVariables), types.String),
			"buildEnvVars":        llx.MapData(convert.MapToInterfaceMap(f.BuildEnvironmentVariables), types.String),
			"maxInstances":        llx.IntData(int64(f.MaxInstances)),
			"minInstances":        llx.IntData(int64(f.MinInstances)),
			"vpcConnector":        llx.StringData(f.VpcConnector),
			"egressSettings":      llx.StringData(f.VpcConnectorEgressSettings.String()),
			"ingressSettings":     llx.StringData(f.IngressSettings.String()),
			"kmsKeyName":          llx.StringData(f.KmsKeyName),
			"buildWorkerPool":     llx.StringData(f.BuildWorkerPool),
			"buildId":             llx.StringData(f.BuildId),
			"buildName":           llx.StringData(f.BuildName),
			"secretEnvVars":       llx.MapData(secretEnvVars, types.Dict),
			"secretVolumes":       llx.ArrayData(secretVolumes, types.Dict),
			"boundSecretEnvVars":  llx.ArrayData(boundSecretEnvVars, types.Resource("gcp.project.cloudFunction.secretEnvVar")),
			"boundSecretVolumes":  llx.ArrayData(boundSecretVolumes, types.Resource("gcp.project.cloudFunction.secretVolume")),
			"dockerRegistry":      llx.StringData(f.DockerRegistry.String()),
		})
		if err != nil {
			return nil, err
		}
		mqlRef := mqlCloudFuncs.(*mqlGcpProjectCloudFunction)
		mqlRef.cacheNetwork = f.Network
		mqlRef.cacheDockerRepository = f.DockerRepository
		mqlFunc := mqlCloudFuncs.(*mqlGcpProjectCloudFunction)
		mqlFunc.cacheKmsKeyName = f.KmsKeyName
		mqlFunc.cacheBuildServiceAccount = f.BuildServiceAccount
		mqlFunc.cacheEventTriggerResource = eventTriggerResource
		cloudFunctions = append(cloudFunctions, mqlCloudFuncs)
	}
	return cloudFunctions, nil
}

type mqlGcpProjectCloudFunctionInternal struct {
	cacheKmsKeyName           string
	cacheBuildServiceAccount  string
	cacheEventTriggerResource string
	cacheDockerRepository     string
	cacheNetwork              string
}

func (g *mqlGcpProjectCloudFunction) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func (g *mqlGcpProjectCloudFunction) dockerRepositoryRef() (*mqlGcpProjectArtifactRegistryServiceRepository, error) {
	project, location, repo := artifactRegistryRepoFromPath(g.cacheDockerRepository)
	ref, err := resolveArtifactRegistryRepoRef(g.MqlRuntime, project, location, repo)
	if err != nil {
		return nil, err
	}
	if ref == nil {
		g.DockerRepositoryRef.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return ref, nil
}

func (g *mqlGcpProjectCloudFunction) eventTriggerTopic() (*mqlGcpProjectPubsubServiceTopic, error) {
	resource := g.cacheEventTriggerResource
	if !strings.Contains(resource, "/topics/") {
		g.EventTriggerTopic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	projectId := projectFromResourceName(resource)
	if projectId == "" && g.ProjectId.Error == nil {
		projectId = g.ProjectId.Data
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.pubsubService.topic", map[string]*llx.RawData{
		"name":      llx.StringData(parseResourceName(resource)),
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectPubsubServiceTopic), nil
}

func (g *mqlGcpProjectCloudFunction) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

// iampbBindingsToMql converts IAM policy bindings (from the cloud.google.com/go
// iampb package) into gcp.resourcemanager.binding resources, preserving any
// IAM condition attached to each binding. Shared by the Cloud Functions,
// Cloud Tasks, KMS, and service-account IAM accessors.
//
// Keep in sync with dataprocBindingsToMql (dataproc.go), which does the same
// mapping for the REST client's *dataproc.Binding type — if a field is added
// to gcp.resourcemanager.binding, update both.
func iampbBindingsToMql(runtime *plugin.Runtime, resourcePath string, bindings []*iampb.Binding) ([]any, error) {
	res := make([]any, 0, len(bindings))
	for i, b := range bindings {
		mqlBinding, err := CreateResource(runtime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(resourcePath + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(b.GetCondition().GetTitle()),
			"conditionExpression":  llx.StringData(b.GetCondition().GetExpression()),
			"conditionDescription": llx.StringData(b.GetCondition().GetDescription()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectCloudFunction) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Location.Error != nil {
		return nil, g.Location.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	location := g.Location.Data
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(functions.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	cloudFuncSvc, err := functions.NewCloudFunctionsClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer cloudFuncSvc.Close()

	resourcePath := fmt.Sprintf("projects/%s/locations/%s/functions/%s", projectId, location, name)
	policy, err := cloudFuncSvc.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resourcePath, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			log.Warn().Str("project", projectId).Str("function", name).Err(err).Msg("could not retrieve cloud function IAM policy")
			return nil, nil
		}
		return nil, err
	}
	return iampbBindingsToMql(g.MqlRuntime, resourcePath, policy.Bindings)
}

func (g *mqlGcpProjectCloudFunction) allowsUnauthenticated() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectCloudFunction) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" {
		g.ServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount",
		map[string]*llx.RawData{
			"email":     llx.StringData(email),
			"projectId": llx.StringData(g.ProjectId.Data),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func (g *mqlGcpProjectCloudFunction) buildServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	projectId := ""
	if g.ProjectId.Error == nil {
		projectId = g.ProjectId.Data
	}
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheBuildServiceAccount, projectId)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.BuildServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectCloudFunction) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cacheNetwork, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.NetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func (g *mqlGcpProjectCloudFunction) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	if g.Location.Error != nil {
		return "", g.Location.Error
	}
	// Cloud Functions v1 names are unique within a location, not within a
	// project, and this resource's own init matches on name + location. Without
	// the location a function deployed to two regions collapses onto one row.
	return fmt.Sprintf("%s/%s/%s", projectId, g.Location.Data, name), nil
}

func initGcpProjectCloudFunction(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["location"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.cloudFunction requires a \"projectId\" argument")
	}

	// NewResource, not CreateResource: CreateResource would cache a gcp.project
	// carrying nothing but an id, and initGcpProject returns whatever is already
	// cached -- so that husk would win for every later caller, and its name,
	// state, parentId, labels, createTime and number are computed fields
	// implemented as placeholders that only ever return "not implemented".
	// servicegate.go spells out the same reasoning for the enablement lookup.
	obj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	proj := obj.(*mqlGcpProject)
	funcs := proj.GetCloudFunctions()
	if funcs.Error != nil {
		return nil, nil, funcs.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.cloudFunction requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	locationVal := ""
	if args["location"] != nil {
		locationVal, _ = args["location"].Value.(string)
	}
	for _, f := range funcs.Data {
		fn := f.(*mqlGcpProjectCloudFunction)
		if fn.Name.Data == nameVal && (locationVal == "" || fn.Location.Data == locationVal) {
			return args, fn, nil
		}
	}

	return nil, nil, fmt.Errorf("cloud function %q not found", nameVal)
}
