// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	functions "cloud.google.com/go/functions/apiv2"
	"cloud.google.com/go/functions/apiv2/functionspb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mqlGcpProjectCloudFunctionV2BuildConfigInternal struct {
	cacheDockerRepository string
	cacheServiceAccount   string
}

func (g *mqlGcpProject) cloudFunctionsV2() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(functions.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := functions.NewFunctionClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListFunctions(ctx, &functionspb.ListFunctionsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		fn, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			// Gracefully skip when the Cloud Functions API is disabled or access
			// is denied (matches the gRPC-based sibling resources), instead of
			// failing the whole query with a hard error.
			if isSkippable(err) {
				break
			}
			return nil, err
		}

		var createTime, updateTime *time.Time
		if fn.CreateTime != nil {
			t := fn.CreateTime.AsTime()
			createTime = &t
		}
		if fn.UpdateTime != nil {
			t := fn.UpdateTime.AsTime()
			updateTime = &t
		}

		var labels map[string]any
		if len(fn.Labels) > 0 {
			labels = make(map[string]any, len(fn.Labels))
			for k, v := range fn.Labels {
				labels[k] = v
			}
		}

		buildConfig, err := fnV2BuildConfig(g.MqlRuntime, fn.Name, fn.BuildConfig)
		if err != nil {
			return nil, err
		}

		serviceConfig, err := fnV2ServiceConfig(g.MqlRuntime, fn.Name, projectId, fn.ServiceConfig)
		if err != nil {
			return nil, err
		}

		eventTrigger, err := fnV2EventTrigger(g.MqlRuntime, fn.Name, projectId, fn.EventTrigger)
		if err != nil {
			return nil, err
		}

		args := map[string]*llx.RawData{
			"projectId":   llx.StringData(projectId),
			"name":        llx.StringData(fn.Name),
			"description": llx.StringData(fn.Description),
			"state":       llx.StringData(fn.State.String()),
			"environment": llx.StringData(fn.Environment.String()),
			"url":         llx.StringData(fn.Url),
			"labels":      llx.MapData(labels, types.String),
			"kmsKeyName":  llx.StringData(fn.KmsKeyName),
			"createTime":  llx.TimeDataPtr(createTime),
			"updateTime":  llx.TimeDataPtr(updateTime),
		}
		if buildConfig != nil {
			args["buildConfig"] = llx.ResourceData(buildConfig, "gcp.project.cloudFunctionV2.buildConfig")
		}
		if serviceConfig != nil {
			args["serviceConfig"] = llx.ResourceData(serviceConfig, "gcp.project.cloudFunctionV2.serviceConfig")
		}
		if eventTrigger != nil {
			args["eventTrigger"] = llx.ResourceData(eventTrigger, "gcp.project.cloudFunctionV2.eventTrigger")
		}

		mqlFn, err := CreateResource(g.MqlRuntime, "gcp.project.cloudFunctionV2", args)
		if err != nil {
			return nil, err
		}
		fnRes := mqlFn.(*mqlGcpProjectCloudFunctionV2)
		fnRes.cacheKmsKeyName = fn.KmsKeyName
		if buildConfig == nil {
			fnRes.BuildConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}
		if serviceConfig == nil {
			fnRes.ServiceConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}
		if eventTrigger == nil {
			fnRes.EventTrigger.State = plugin.StateIsNull | plugin.StateIsSet
		}
		res = append(res, mqlFn)
	}

	return res, nil
}

type mqlGcpProjectCloudFunctionV2Internal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProjectCloudFunctionV2) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudFunctionV2/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectCloudFunctionV2) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	keyName := g.cacheKmsKeyName
	if keyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey", map[string]*llx.RawData{
		"resourcePath": llx.StringData(keyName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectCloudFunctionV2) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func (g *mqlGcpProjectCloudFunctionV2) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	resourcePath := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(functions.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := functions.NewFunctionClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resourcePath, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			log.Warn().Str("function", resourcePath).Err(err).Msg("could not retrieve cloud function IAM policy")
			return nil, nil
		}
		return nil, err
	}
	return iampbBindingsToMql(g.MqlRuntime, resourcePath, policy.Bindings)
}

func (g *mqlGcpProjectCloudFunctionV2) allowsUnauthenticated() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func fnV2BuildConfig(runtime *plugin.Runtime, parentName string, cfg *functionspb.BuildConfig) (*mqlGcpProjectCloudFunctionV2BuildConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	sourceDict, err := protoToDict(cfg.GetSource())
	if err != nil {
		return nil, err
	}

	sourceProvenanceDict, err := protoToDict(cfg.GetSourceProvenance())
	if err != nil {
		return nil, err
	}

	var gitUri string
	if cfg.GetSourceProvenance() != nil {
		gitUri = cfg.GetSourceProvenance().GetGitUri()
	}

	var envVars map[string]any
	if len(cfg.EnvironmentVariables) > 0 {
		envVars = make(map[string]any, len(cfg.EnvironmentVariables))
		for k, v := range cfg.EnvironmentVariables {
			envVars[k] = v
		}
	}

	res, err := CreateResource(runtime, "gcp.project.cloudFunctionV2.buildConfig", map[string]*llx.RawData{
		"id":                   llx.StringData(parentName + "/buildConfig"),
		"runtime":              llx.StringData(cfg.Runtime),
		"entryPoint":           llx.StringData(cfg.EntryPoint),
		"source":               llx.DictData(sourceDict),
		"buildWorkerPool":      llx.StringData(cfg.WorkerPool),
		"environmentVariables": llx.MapData(envVars, types.String),
		"build":                llx.StringData(cfg.Build),
		"sourceProvenance":     llx.DictData(sourceProvenanceDict),
		"gitUri":               llx.StringData(gitUri),
	})
	if err != nil {
		return nil, err
	}
	mqlRef := res.(*mqlGcpProjectCloudFunctionV2BuildConfig)
	mqlRef.cacheDockerRepository = cfg.DockerRepository
	mqlRef.cacheServiceAccount = cfg.ServiceAccount
	return res.(*mqlGcpProjectCloudFunctionV2BuildConfig), nil
}

func (g *mqlGcpProjectCloudFunctionV2BuildConfig) serviceAccountRef() (*mqlGcpProjectIamServiceServiceAccount, error) {
	// buildConfig.serviceAccount is a full "projects/{p}/serviceAccounts/{email}"
	// path, so resolveServiceAccountRef derives the project — no fallback needed.
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheServiceAccount, "")
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.ServiceAccountRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectCloudFunctionV2BuildConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectCloudFunctionV2BuildConfig) dockerRepositoryRef() (*mqlGcpProjectArtifactRegistryServiceRepository, error) {
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

func fnV2ServiceConfig(runtime *plugin.Runtime, parentName string, projectId string, cfg *functionspb.ServiceConfig) (*mqlGcpProjectCloudFunctionV2ServiceConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	var envVars map[string]any
	if len(cfg.EnvironmentVariables) > 0 {
		envVars = make(map[string]any, len(cfg.EnvironmentVariables))
		for k, v := range cfg.EnvironmentVariables {
			envVars[k] = v
		}
	}

	var secretEnvVars []any
	for _, sev := range cfg.SecretEnvironmentVariables {
		d, err := protoToDict(sev)
		if err != nil {
			return nil, err
		}
		secretEnvVars = append(secretEnvVars, d)
	}

	var secretVolumes []any
	for _, sv := range cfg.SecretVolumes {
		d, err := protoToDict(sv)
		if err != nil {
			return nil, err
		}
		secretVolumes = append(secretVolumes, d)
	}

	envBindings := make([]cloudFunctionSecretBinding, 0, len(cfg.SecretEnvironmentVariables))
	for _, v := range cfg.SecretEnvironmentVariables {
		envBindings = append(envBindings, cloudFunctionSecretBinding{
			key: v.Key, projectID: v.ProjectId, secret: v.Secret, version: v.Version,
		})
	}
	volumeBindings := make([]cloudFunctionSecretBinding, 0, len(cfg.SecretVolumes))
	for _, v := range cfg.SecretVolumes {
		paths := make(map[string]string, len(v.Versions))
		for _, vv := range v.Versions {
			paths[vv.Version] = vv.Path
		}
		volumeBindings = append(volumeBindings, cloudFunctionSecretBinding{
			mountPath: v.MountPath, projectID: v.ProjectId, secret: v.Secret, versionPaths: paths,
		})
	}
	boundSecretEnvVars, err := newMqlFunctionSecretEnvVars(runtime, parentName+"/serviceConfig", envBindings)
	if err != nil {
		return nil, err
	}
	boundSecretVolumes, err := newMqlFunctionSecretVolumes(runtime, parentName+"/serviceConfig", volumeBindings)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.cloudFunctionV2.serviceConfig", map[string]*llx.RawData{
		"id":                         llx.StringData(parentName + "/serviceConfig"),
		"service":                    llx.StringData(cfg.Service),
		"timeoutSeconds":             llx.IntData(int64(cfg.TimeoutSeconds)),
		"availableMemory":            llx.StringData(cfg.AvailableMemory),
		"availableCpu":               llx.StringData(cfg.AvailableCpu),
		"environmentVariables":       llx.MapData(envVars, types.String),
		"maxInstanceCount":           llx.IntData(int64(cfg.MaxInstanceCount)),
		"minInstanceCount":           llx.IntData(int64(cfg.MinInstanceCount)),
		"vpcConnector":               llx.StringData(cfg.VpcConnector),
		"vpcConnectorEgressSettings": llx.StringData(cfg.VpcConnectorEgressSettings.String()),
		"ingressSettings":            llx.StringData(cfg.IngressSettings.String()),
		"securityLevel":              llx.StringData(cfg.SecurityLevel.String()),
		"binaryAuthorizationPolicy":  llx.StringData(cfg.BinaryAuthorizationPolicy),
		"serviceAccountEmail":        llx.StringData(cfg.ServiceAccountEmail),
		"allTrafficOnLatestRevision": llx.BoolData(cfg.AllTrafficOnLatestRevision),
		"secretEnvironmentVariables": llx.ArrayData(secretEnvVars, types.Dict),
		"secretVolumes":              llx.ArrayData(secretVolumes, types.Dict),
		"boundSecretEnvVars":         llx.ArrayData(boundSecretEnvVars, types.Resource("gcp.project.cloudFunction.secretEnvVar")),
		"boundSecretVolumes":         llx.ArrayData(boundSecretVolumes, types.Resource("gcp.project.cloudFunction.secretVolume")),
	})
	if err != nil {
		return nil, err
	}

	// Populate Internal struct for cross-reference
	sc := res.(*mqlGcpProjectCloudFunctionV2ServiceConfig)
	sc.cacheServiceAccountEmail = cfg.ServiceAccountEmail
	sc.cacheProjectId = projectId

	return sc, nil
}

func (g *mqlGcpProjectCloudFunctionV2ServiceConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectCloudFunctionV2ServiceConfig) serviceRef() (*mqlGcpProjectCloudRunServiceService, error) {
	if g.Service.Error != nil {
		return nil, g.Service.Error
	}
	service := g.Service.Data
	if service == "" {
		g.ServiceRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	projectId := parseProjectFromPath(service)
	if projectId == "" {
		projectId = g.cacheProjectId
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.cloudRunService.service", map[string]*llx.RawData{
		"name":      llx.StringData(parseResourceName(service)),
		"region":    llx.StringData(parseLocationFromPath(service)),
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudRunServiceService), nil
}

type mqlGcpProjectCloudFunctionV2ServiceConfigInternal struct {
	cacheServiceAccountEmail string
	cacheProjectId           string
}

func (g *mqlGcpProjectCloudFunctionV2ServiceConfig) iamServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	email := g.cacheServiceAccountEmail
	if email == "" {
		g.IamServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"email":     llx.StringData(email),
		"projectId": llx.StringData(g.cacheProjectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func fnV2EventTrigger(runtime *plugin.Runtime, parentName string, projectId string, cfg *functionspb.EventTrigger) (*mqlGcpProjectCloudFunctionV2EventTrigger, error) {
	if cfg == nil {
		return nil, nil
	}

	var eventFilters []any
	for _, ef := range cfg.EventFilters {
		d, err := protoToDict(ef)
		if err != nil {
			return nil, err
		}
		eventFilters = append(eventFilters, d)
	}

	res, err := CreateResource(runtime, "gcp.project.cloudFunctionV2.eventTrigger", map[string]*llx.RawData{
		"id":                  llx.StringData(parentName + "/eventTrigger"),
		"trigger":             llx.StringData(cfg.Trigger),
		"triggerRegion":       llx.StringData(cfg.TriggerRegion),
		"eventType":           llx.StringData(cfg.EventType),
		"eventFilters":        llx.ArrayData(eventFilters, types.Dict),
		"pubsubTopic":         llx.StringData(cfg.PubsubTopic),
		"serviceAccountEmail": llx.StringData(cfg.ServiceAccountEmail),
		"retryPolicy":         llx.StringData(cfg.RetryPolicy.String()),
		"channel":             llx.StringData(cfg.Channel),
	})
	if err != nil {
		return nil, err
	}

	// Populate Internal struct for cross-reference
	et := res.(*mqlGcpProjectCloudFunctionV2EventTrigger)
	et.cachePubsubTopic = cfg.PubsubTopic
	et.cacheProjectId = projectId

	return et, nil
}

func (g *mqlGcpProjectCloudFunctionV2EventTrigger) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

type mqlGcpProjectCloudFunctionV2EventTriggerInternal struct {
	cachePubsubTopic string
	cacheProjectId   string
}

func (g *mqlGcpProjectCloudFunctionV2EventTrigger) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" {
		g.ServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount",
		map[string]*llx.RawData{
			"email":     llx.StringData(email),
			"projectId": llx.StringData(g.cacheProjectId),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func (g *mqlGcpProjectCloudFunctionV2EventTrigger) topic() (*mqlGcpProjectPubsubServiceTopic, error) {
	ref, err := resolvePubsubTopicRef(g.MqlRuntime, g.cachePubsubTopic, "")
	if err != nil {
		return nil, err
	}
	if ref == nil {
		g.Topic.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return ref, nil
}
