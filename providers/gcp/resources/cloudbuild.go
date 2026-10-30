// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"time"

	cloudbuild "cloud.google.com/go/cloudbuild/apiv1/v2"
	"cloud.google.com/go/cloudbuild/apiv1/v2/cloudbuildpb"
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

type mqlGcpProjectCloudBuildServiceWorkerPoolNetworkConfigInternal struct {
	cachePeeredNetwork string
}

func (g *mqlGcpProject) cloudBuild() (*mqlGcpProjectCloudBuildService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.cloudBuildService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudBuildService), nil
}

func (g *mqlGcpProjectCloudBuildService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudBuildService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectCloudBuildService) triggers() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(cloudbuild.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := cloudbuild.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// NOTE: The Cloud Build ListBuildTriggers API does not support the
	// locations/- wildcard (returns InvalidArgument). This means only global
	// triggers are returned; regional triggers require enumerating locations
	// individually, which is not yet implemented.
	it := client.ListBuildTriggers(ctx, &cloudbuildpb.ListBuildTriggersRequest{
		Parent:    fmt.Sprintf("projects/%s/locations/global", projectId),
		ProjectId: projectId,
	})

	var res []any
	for {
		trigger, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		var createTime *time.Time
		if trigger.CreateTime != nil {
			t := trigger.CreateTime.AsTime()
			createTime = &t
		}

		// Convert tags to []any
		tags := make([]any, len(trigger.Tags))
		for i, t := range trigger.Tags {
			tags[i] = t
		}

		// Convert substitutions to map[string]any
		var substitutions map[string]any
		if len(trigger.Substitutions) > 0 {
			substitutions = make(map[string]any, len(trigger.Substitutions))
			for k, v := range trigger.Substitutions {
				substitutions[k] = v
			}
		}

		// Build GitHub events config sub-resource
		github, err := buildTriggerGithubConfig(g.MqlRuntime, trigger.Id, trigger.GetGithub())
		if err != nil {
			return nil, err
		}

		// Build Pub/Sub config sub-resource
		pubsubConfig, err := buildTriggerPubsubConfig(g.MqlRuntime, trigger.Id, projectId, trigger.GetPubsubConfig())
		if err != nil {
			return nil, err
		}

		// Build webhook config sub-resource
		webhookConfig, err := buildTriggerWebhookConfig(g.MqlRuntime, trigger.Id, trigger.GetWebhookConfig())
		if err != nil {
			return nil, err
		}

		// Build repository event config sub-resource
		repoEventConfig, err := buildTriggerRepoEventConfig(g.MqlRuntime, trigger.Id, trigger.GetRepositoryEventConfig())
		if err != nil {
			return nil, err
		}

		args := map[string]*llx.RawData{
			"projectId":      llx.StringData(projectId),
			"name":           llx.StringData(trigger.Name),
			"triggerId":      llx.StringData(trigger.Id),
			"description":    llx.StringData(trigger.Description),
			"disabled":       llx.BoolData(trigger.Disabled),
			"tags":           llx.ArrayData(tags, types.String),
			"filename":       llx.StringData(trigger.GetFilename()),
			"filter":         llx.StringData(trigger.Filter),
			"substitutions":  llx.MapData(substitutions, types.String),
			"serviceAccount": llx.StringData(trigger.ServiceAccount),
			"createTime":     llx.TimeDataPtr(createTime),
		}
		if github != nil {
			args["github"] = llx.ResourceData(github, "gcp.project.cloudBuildService.trigger.githubEventsConfig")
		}
		if pubsubConfig != nil {
			args["pubsubConfig"] = llx.ResourceData(pubsubConfig, "gcp.project.cloudBuildService.trigger.pubsubConfig")
		}
		if webhookConfig != nil {
			args["webhookConfig"] = llx.ResourceData(webhookConfig, "gcp.project.cloudBuildService.trigger.webhookConfig")
		}
		if repoEventConfig != nil {
			args["repositoryEventConfig"] = llx.ResourceData(repoEventConfig, "gcp.project.cloudBuildService.trigger.repositoryEventConfig")
		}

		mqlTrigger, err := CreateResource(g.MqlRuntime, "gcp.project.cloudBuildService.trigger", args)
		if err != nil {
			return nil, err
		}

		// Populate Internal struct cache and set null state for absent sub-resources
		t := mqlTrigger.(*mqlGcpProjectCloudBuildServiceTrigger)
		t.cacheServiceAccount = trigger.ServiceAccount
		if github == nil {
			t.Github.State = plugin.StateIsNull | plugin.StateIsSet
		}
		if pubsubConfig == nil {
			t.PubsubConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}
		if webhookConfig == nil {
			t.WebhookConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}
		if repoEventConfig == nil {
			t.RepositoryEventConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}

		res = append(res, mqlTrigger)
	}

	return res, nil
}

func (g *mqlGcpProjectCloudBuildServiceTrigger) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	// BuildTrigger.Name is user-assigned, optional, and unique only within a
	// project; Id is the service-generated unique identifier. Keying on the
	// name aliased same-named triggers across projects (and collapsed every
	// unnamed, Terraform-created trigger onto one row).
	if g.TriggerId.Error != nil {
		return "", g.TriggerId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudBuildService.trigger/%s", g.ProjectId.Data, g.TriggerId.Data), nil
}

type mqlGcpProjectCloudBuildServiceTriggerInternal struct {
	cacheServiceAccount string
}

func (g *mqlGcpProjectCloudBuildServiceTrigger) iamServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa := g.cacheServiceAccount
	if sa == "" {
		g.IamServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// Extract email from resource name: projects/{project}/serviceAccounts/{email}
	email := sa
	if _, after, ok := strings.CutLast(sa, "/"); ok {
		email = after
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"email":     llx.StringData(email),
		"projectId": llx.StringData(g.ProjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func buildTriggerGithubConfig(runtime *plugin.Runtime, parentName string, cfg *cloudbuildpb.GitHubEventsConfig) (*mqlGcpProjectCloudBuildServiceTriggerGithubEventsConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	pushDict, err := protoToDict(cfg.GetPush())
	if err != nil {
		return nil, err
	}
	prDict, err := protoToDict(cfg.GetPullRequest())
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.cloudBuildService.trigger.githubEventsConfig", map[string]*llx.RawData{
		"id":             llx.StringData(parentName + "/github"),
		"owner":          llx.StringData(cfg.Owner),
		"name":           llx.StringData(cfg.Name),
		"installationId": llx.IntData(cfg.InstallationId),
		"push":           llx.DictData(pushDict),
		"pullRequest":    llx.DictData(prDict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudBuildServiceTriggerGithubEventsConfig), nil
}

func (g *mqlGcpProjectCloudBuildServiceTriggerGithubEventsConfig) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return g.Id.Data, nil
}

func buildTriggerPubsubConfig(runtime *plugin.Runtime, parentName string, projectId string, cfg *cloudbuildpb.PubsubConfig) (*mqlGcpProjectCloudBuildServiceTriggerPubsubConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	res, err := CreateResource(runtime, "gcp.project.cloudBuildService.trigger.pubsubConfig", map[string]*llx.RawData{
		"id":                  llx.StringData(parentName + "/pubsubConfig"),
		"topic":               llx.StringData(cfg.Topic),
		"subscription":        llx.StringData(cfg.Subscription),
		"serviceAccountEmail": llx.StringData(cfg.ServiceAccountEmail),
		"state":               llx.StringData(cfg.State.String()),
	})
	if err != nil {
		return nil, err
	}

	// Populate Internal struct cache for cross-reference
	pc := res.(*mqlGcpProjectCloudBuildServiceTriggerPubsubConfig)
	pc.cacheTopic = cfg.Topic
	pc.cacheProjectId = projectId

	return pc, nil
}

func (g *mqlGcpProjectCloudBuildServiceTriggerPubsubConfig) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return g.Id.Data, nil
}

type mqlGcpProjectCloudBuildServiceTriggerPubsubConfigInternal struct {
	cacheTopic     string
	cacheProjectId string
}

func (g *mqlGcpProjectCloudBuildServiceTriggerPubsubConfig) pubsubTopic() (*mqlGcpProjectPubsubServiceTopic, error) {
	ref, err := resolvePubsubTopicRef(g.MqlRuntime, g.cacheTopic, "")
	if err != nil {
		return nil, err
	}
	if ref == nil {
		g.PubsubTopic.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return ref, nil
}

func (g *mqlGcpProjectCloudBuildServiceTriggerPubsubConfig) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
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

func buildTriggerWebhookConfig(runtime *plugin.Runtime, parentName string, cfg *cloudbuildpb.WebhookConfig) (*mqlGcpProjectCloudBuildServiceTriggerWebhookConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	res, err := CreateResource(runtime, "gcp.project.cloudBuildService.trigger.webhookConfig", map[string]*llx.RawData{
		"id":    llx.StringData(parentName + "/webhookConfig"),
		"state": llx.StringData(cfg.State.String()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudBuildServiceTriggerWebhookConfig), nil
}

func (g *mqlGcpProjectCloudBuildServiceTriggerWebhookConfig) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return g.Id.Data, nil
}

func buildTriggerRepoEventConfig(runtime *plugin.Runtime, parentName string, cfg *cloudbuildpb.RepositoryEventConfig) (*mqlGcpProjectCloudBuildServiceTriggerRepositoryEventConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	pushDict, err := protoToDict(cfg.GetPush())
	if err != nil {
		return nil, err
	}
	prDict, err := protoToDict(cfg.GetPullRequest())
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.cloudBuildService.trigger.repositoryEventConfig", map[string]*llx.RawData{
		"id":             llx.StringData(parentName + "/repositoryEventConfig"),
		"repository":     llx.StringData(cfg.Repository),
		"repositoryType": llx.StringData(cfg.RepositoryType.String()),
		"push":           llx.DictData(pushDict),
		"pullRequest":    llx.DictData(prDict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudBuildServiceTriggerRepositoryEventConfig), nil
}

func (g *mqlGcpProjectCloudBuildServiceTriggerRepositoryEventConfig) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return g.Id.Data, nil
}

func (g *mqlGcpProjectCloudBuildService) workerPools() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(cloudbuild.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := cloudbuild.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListWorkerPools(ctx, &cloudbuildpb.ListWorkerPoolsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		wp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			// The wildcard location "-" may not be supported; treat InvalidArgument as empty
			if s, ok := status.FromError(err); ok && s.Code() == codes.InvalidArgument {
				break
			}
			if isSkippable(err) {
				break
			}
			return nil, err
		}

		var createTime, updateTime *time.Time
		if wp.CreateTime != nil {
			t := wp.CreateTime.AsTime()
			createTime = &t
		}
		if wp.UpdateTime != nil {
			t := wp.UpdateTime.AsTime()
			updateTime = &t
		}

		var annotations map[string]any
		if len(wp.Annotations) > 0 {
			annotations = make(map[string]any, len(wp.Annotations))
			for k, v := range wp.Annotations {
				annotations[k] = v
			}
		}

		workerConfig, err := buildWorkerPoolWorkerConfig(g.MqlRuntime, wp.Name, wp.GetPrivatePoolV1Config())
		if err != nil {
			return nil, err
		}

		networkConfig, err := buildWorkerPoolNetworkConfig(g.MqlRuntime, wp.Name, wp.GetPrivatePoolV1Config())
		if err != nil {
			return nil, err
		}

		wpArgs := map[string]*llx.RawData{
			"projectId":   llx.StringData(projectId),
			"name":        llx.StringData(wp.Name),
			"displayName": llx.StringData(wp.DisplayName),
			"state":       llx.StringData(wp.State.String()),
			"annotations": llx.MapData(annotations, types.String),
			"createTime":  llx.TimeDataPtr(createTime),
			"updateTime":  llx.TimeDataPtr(updateTime),
		}
		if workerConfig != nil {
			wpArgs["workerConfig"] = llx.ResourceData(workerConfig, "gcp.project.cloudBuildService.workerPool.workerConfig")
		}
		if networkConfig != nil {
			wpArgs["networkConfig"] = llx.ResourceData(networkConfig, "gcp.project.cloudBuildService.workerPool.networkConfig")
		}

		mqlWP, err := CreateResource(g.MqlRuntime, "gcp.project.cloudBuildService.workerPool", wpArgs)
		if err != nil {
			return nil, err
		}
		wpRes := mqlWP.(*mqlGcpProjectCloudBuildServiceWorkerPool)
		if workerConfig == nil {
			wpRes.WorkerConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}
		if networkConfig == nil {
			wpRes.NetworkConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}
		res = append(res, mqlWP)
	}

	return res, nil
}

func (g *mqlGcpProjectCloudBuildServiceWorkerPool) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudBuildService.workerPool/%s", g.ProjectId.Data, g.Name.Data), nil
}

func buildWorkerPoolWorkerConfig(runtime *plugin.Runtime, parentName string, cfg *cloudbuildpb.PrivatePoolV1Config) (*mqlGcpProjectCloudBuildServiceWorkerPoolWorkerConfig, error) {
	if cfg == nil || cfg.WorkerConfig == nil {
		return nil, nil
	}
	wc := cfg.WorkerConfig
	res, err := CreateResource(runtime, "gcp.project.cloudBuildService.workerPool.workerConfig", map[string]*llx.RawData{
		"id":                         llx.StringData(parentName + "/workerConfig"),
		"machineType":                llx.StringData(wc.MachineType),
		"diskSizeGb":                 llx.IntData(wc.DiskSizeGb),
		"enableNestedVirtualization": llx.BoolDataPtr(wc.EnableNestedVirtualization),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudBuildServiceWorkerPoolWorkerConfig), nil
}

func (g *mqlGcpProjectCloudBuildServiceWorkerPoolWorkerConfig) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return g.Id.Data, nil
}

func buildWorkerPoolNetworkConfig(runtime *plugin.Runtime, parentName string, cfg *cloudbuildpb.PrivatePoolV1Config) (*mqlGcpProjectCloudBuildServiceWorkerPoolNetworkConfig, error) {
	if cfg == nil || cfg.NetworkConfig == nil {
		return nil, nil
	}
	nc := cfg.NetworkConfig
	res, err := CreateResource(runtime, "gcp.project.cloudBuildService.workerPool.networkConfig", map[string]*llx.RawData{
		"id":                   llx.StringData(parentName + "/networkConfig"),
		"peeredNetworkIpRange": llx.StringData(nc.PeeredNetworkIpRange),
		"egressOption":         llx.StringData(nc.EgressOption.String()),
	})
	if err != nil {
		return nil, err
	}
	mqlRef := res.(*mqlGcpProjectCloudBuildServiceWorkerPoolNetworkConfig)
	mqlRef.cachePeeredNetwork = nc.PeeredNetwork
	return res.(*mqlGcpProjectCloudBuildServiceWorkerPoolNetworkConfig), nil
}

func (g *mqlGcpProjectCloudBuildServiceWorkerPoolNetworkConfig) peeredNetworkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cachePeeredNetwork, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.PeeredNetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func (g *mqlGcpProjectCloudBuildServiceWorkerPoolNetworkConfig) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return g.Id.Data, nil
}

func (g *mqlGcpProjectCloudBuildService) builds() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(cloudbuild.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := cloudbuild.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// NOTE: Like ListBuildTriggers, the project-scoped ListBuilds returns only
	// builds in the global region. Regional builds require enumerating
	// locations individually, which is not yet implemented.
	it := client.ListBuilds(ctx, &cloudbuildpb.ListBuildsRequest{
		ProjectId: projectId,
		PageSize:  maxCloudBuilds,
	})

	// ListBuilds returns builds newest-first and is unbounded — active projects
	// can accumulate tens of thousands of builds. Cap at the most recent
	// maxCloudBuilds and warn when truncated rather than silently paging the
	// entire history (which would make the query very slow).
	var res []any
	for {
		b, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				break
			}
			return nil, err
		}

		mqlBuild, err := newCloudBuild(g.MqlRuntime, projectId, b)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBuild)

		if len(res) >= maxCloudBuilds {
			log.Warn().
				Str("project", projectId).
				Int("limit", maxCloudBuilds).
				Msg("reached Cloud Build history limit; returning only the most recent builds")
			break
		}
	}

	return res, nil
}

// maxCloudBuilds bounds how many of the most recent builds builds() returns, to
// keep the query responsive on projects with very long build histories.
const maxCloudBuilds = 500

func newCloudBuild(runtime *plugin.Runtime, projectId string, b *cloudbuildpb.Build) (*mqlGcpProjectCloudBuildServiceBuild, error) {
	source, err := protoToDict(b.GetSource())
	if err != nil {
		return nil, err
	}
	sourceProvenance, err := protoToDict(b.GetSourceProvenance())
	if err != nil {
		return nil, err
	}
	results, err := protoToDict(b.GetResults())
	if err != nil {
		return nil, err
	}

	images := make([]any, len(b.Images))
	for i, img := range b.Images {
		images[i] = img
	}
	tags := make([]any, len(b.Tags))
	for i, t := range b.Tags {
		tags[i] = t
	}
	var substitutions map[string]any
	if len(b.Substitutions) > 0 {
		substitutions = make(map[string]any, len(b.Substitutions))
		for k, v := range b.Substitutions {
			substitutions[k] = v
		}
	}

	res, err := CreateResource(runtime, "gcp.project.cloudBuildService.build", map[string]*llx.RawData{
		"projectId":        llx.StringData(projectId),
		"buildId":          llx.StringData(b.Id),
		"status":           llx.StringData(b.Status.String()),
		"statusDetail":     llx.StringData(b.StatusDetail),
		"source":           llx.DictData(source),
		"sourceProvenance": llx.DictData(sourceProvenance),
		"createTime":       llx.TimeDataPtr(timestampAsTimePtr(b.CreateTime)),
		"startTime":        llx.TimeDataPtr(timestampAsTimePtr(b.StartTime)),
		"finishTime":       llx.TimeDataPtr(timestampAsTimePtr(b.FinishTime)),
		"images":           llx.ArrayData(images, types.String),
		"results":          llx.DictData(results),
		"buildTriggerId":   llx.StringData(b.BuildTriggerId),
		"logUrl":           llx.StringData(b.LogUrl),
		"logsBucket":       llx.StringData(b.LogsBucket),
		"substitutions":    llx.MapData(substitutions, types.String),
		"tags":             llx.ArrayData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlBuild := res.(*mqlGcpProjectCloudBuildServiceBuild)
	mqlBuild.cacheProjectId = projectId
	mqlBuild.cacheBuildTriggerId = b.BuildTriggerId
	mqlBuild.cacheServiceAccount = b.ServiceAccount
	return mqlBuild, nil
}

func (g *mqlGcpProjectCloudBuildServiceBuild) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.BuildId.Error != nil {
		return "", g.BuildId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudBuildService.build/%s", g.ProjectId.Data, g.BuildId.Data), nil
}

type mqlGcpProjectCloudBuildServiceBuildInternal struct {
	cacheProjectId      string
	cacheBuildTriggerId string
	cacheServiceAccount string
}

func (g *mqlGcpProjectCloudBuildServiceBuild) trigger() (*mqlGcpProjectCloudBuildServiceTrigger, error) {
	triggerId := g.cacheBuildTriggerId
	if triggerId == "" {
		g.Trigger.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	svc, err := NewResource(g.MqlRuntime, "gcp.project.cloudBuildService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.cacheProjectId),
	})
	if err != nil {
		return nil, err
	}
	triggers := svc.(*mqlGcpProjectCloudBuildService).GetTriggers()
	if triggers.Error != nil {
		return nil, triggers.Error
	}
	for _, t := range triggers.Data {
		trigger := t.(*mqlGcpProjectCloudBuildServiceTrigger)
		if trigger.TriggerId.Data == triggerId {
			return trigger, nil
		}
	}

	// Trigger not found (deleted, or a regional trigger absent from the
	// global ListBuildTriggers result).
	g.Trigger.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (g *mqlGcpProjectCloudBuildServiceBuild) iamServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa := g.cacheServiceAccount
	if sa == "" {
		g.IamServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// Extract email from resource name: projects/{project}/serviceAccounts/{email}
	email := sa
	if _, after, ok := strings.CutLast(sa, "/"); ok {
		email = after
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
