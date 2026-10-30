// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"cloud.google.com/go/pubsub/v2"
	pubsubadmin "cloud.google.com/go/pubsub/v2/apiv1"
	"cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
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
	"google.golang.org/protobuf/types/known/durationpb"
)

type mqlGcpProjectPubsubServiceTopicConfigInternal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProjectPubsubService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.pubsubService", projectId), nil
}

func initGcpProjectPubsubService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

type mqlGcpProjectPubsubServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) pubsub() (*mqlGcpProjectPubsubService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_pubsub)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectPubsubService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_pubsub).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func (g *mqlGcpProjectPubsubServiceTopic) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	return fmt.Sprintf("%s/%s", projectId, name), nil
}

func initGcpProjectPubsubServiceTopic(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.pubsubService.topic requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.pubsubService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlGcpProjectPubsubService)
	topics := svc.GetTopics()
	if topics.Error != nil {
		return nil, nil, topics.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.pubsubService.topic requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	for _, t := range topics.Data {
		topic := t.(*mqlGcpProjectPubsubServiceTopic)
		if topic.Name.Data == nameVal {
			return args, topic, nil
		}
	}

	return nil, nil, fmt.Errorf("pubsub topic %q not found", nameVal)
}

func (g *mqlGcpProjectPubsubServiceTopicConfig) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.TopicName.Error != nil {
		return "", g.TopicName.Error
	}
	topicName := g.TopicName.Data
	return pubsubConfigId(projectId, topicName), nil
}

func (g *mqlGcpProjectPubsubServiceTopicConfigMessagestoragepolicy) id() (string, error) {
	if g.ConfigId.Error != nil {
		return "", g.ConfigId.Error
	}
	configId := g.ConfigId.Data
	return fmt.Sprintf("%s/messageStoragePolicy", configId), nil
}

func (g *mqlGcpProjectPubsubServiceSubscription) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	return fmt.Sprintf("%s/%s", projectId, name), nil
}

func initGcpProjectPubsubServiceSubscription(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.pubsubService.subscription requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.pubsubService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlGcpProjectPubsubService)
	subs := svc.GetSubscriptions()
	if subs.Error != nil {
		return nil, nil, subs.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.pubsubService.subscription requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	for _, s := range subs.Data {
		sub := s.(*mqlGcpProjectPubsubServiceSubscription)
		if sub.Name.Data == nameVal {
			return args, sub, nil
		}
	}

	return nil, nil, fmt.Errorf("pubsub subscription %q not found", nameVal)
}

func (g *mqlGcpProjectPubsubServiceSubscriptionConfig) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.SubscriptionName.Error != nil {
		return "", g.SubscriptionName.Error
	}
	subscriptionName := g.SubscriptionName.Data
	return pubsubConfigId(projectId, subscriptionName), nil
}

func (g *mqlGcpProjectPubsubServiceSubscriptionConfigPushconfig) id() (string, error) {
	if g.ConfigId.Error != nil {
		return "", g.ConfigId.Error
	}
	configId := g.ConfigId.Data
	return fmt.Sprintf("%s/pushConfig", configId), nil
}

func (g *mqlGcpProjectPubsubServiceSnapshot) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	return fmt.Sprintf("%s/%s", projectId, name), nil
}

func initGcpProjectPubsubServiceSnapshot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.pubsubService.snapshot requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.pubsubService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlGcpProjectPubsubService)
	snapshots := svc.GetSnapshots()
	if snapshots.Error != nil {
		return nil, nil, snapshots.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.pubsubService.snapshot requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	for _, s := range snapshots.Data {
		snap := s.(*mqlGcpProjectPubsubServiceSnapshot)
		if snap.Name.Data == nameVal {
			return args, snap, nil
		}
	}

	return nil, nil, fmt.Errorf("pubsub snapshot %q not found", nameVal)
}

func (g *mqlGcpProjectPubsubService) topics() ([]any, error) {
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

	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	pubsubSvc, err := pubsub.NewClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer pubsubSvc.Close()

	var topics []any

	it := pubsubSvc.TopicAdminClient.ListTopics(ctx, &pubsubpb.ListTopicsRequest{
		Project: projectPath(projectId),
	})
	for {
		t, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlTopic, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.topic", map[string]*llx.RawData{
			"projectId": llx.StringData(projectId),
			"name":      llx.StringData(lastPathSegment(t.Name)),
		})
		if err != nil {
			return nil, err
		}
		topics = append(topics, mqlTopic)
	}

	return topics, nil
}

func (g *mqlGcpProjectPubsubServiceTopic) config() (*mqlGcpProjectPubsubServiceTopicConfig, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	pubsubSvc, err := pubsub.NewClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer pubsubSvc.Close()

	cfg, err := pubsubSvc.TopicAdminClient.GetTopic(ctx, &pubsubpb.GetTopicRequest{
		Topic: topicPath(projectId, name),
	})
	if err != nil {
		return nil, err
	}

	configId := pubsubConfigId(projectId, name)

	var allowedRegions []string
	var enforceInTransit bool
	if cfg.MessageStoragePolicy != nil {
		allowedRegions = cfg.MessageStoragePolicy.AllowedPersistenceRegions
		enforceInTransit = cfg.MessageStoragePolicy.EnforceInTransit
	}
	messageStoragePolicy, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.topic.config.messagestoragepolicy", map[string]*llx.RawData{
		"configId":                  llx.StringData(configId),
		"allowedPersistenceRegions": llx.ArrayData(convert.SliceAnyToInterface(allowedRegions), types.String),
		"enforceInTransit":          llx.BoolData(enforceInTransit),
	})
	if err != nil {
		return nil, err
	}
	schemaSettings, err := buildTopicSchemaSettings(g.MqlRuntime, configId, cfg.SchemaSettings)
	if err != nil {
		return nil, err
	}

	var ingestionSettings any
	if cfg.IngestionDataSourceSettings != nil {
		ingestionSettings, err = convert.JsonToDict(cfg.IngestionDataSourceSettings)
		if err != nil {
			return nil, err
		}
	}

	messageTransforms := make([]any, 0, len(cfg.MessageTransforms))
	for _, mt := range cfg.MessageTransforms {
		d, err := convert.JsonToDict(mt)
		if err != nil {
			return nil, err
		}
		messageTransforms = append(messageTransforms, d)
	}

	args := map[string]*llx.RawData{
		"projectId":                   llx.StringData(projectId),
		"topicName":                   llx.StringData(name),
		"labels":                      llx.MapData(convert.MapToInterfaceMap(cfg.Labels), types.String),
		"messageStoragePolicy":        llx.ResourceData(messageStoragePolicy, "gcp.project.pubsubService.topic.config.messagestoragepolicy"),
		"state":                       llx.StringData(topicStateToString(cfg.State)),
		"retentionDuration":           llx.TimeData(pbDurationToTime(cfg.MessageRetentionDuration)),
		"satisfiesPzs":                llx.BoolData(cfg.SatisfiesPzs),
		"ingestionDataSourceSettings": llx.DictData(ingestionSettings),
		"messageTransforms":           llx.ArrayData(messageTransforms, types.Dict),
	}
	if schemaSettings != nil {
		args["schemaSettings"] = llx.ResourceData(schemaSettings, "gcp.project.pubsubService.topic.config.schemaSettings")
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.topic.config", args)
	if err != nil {
		return nil, err
	}
	tc := res.(*mqlGcpProjectPubsubServiceTopicConfig)
	tc.cacheKmsKeyName = cfg.KmsKeyName
	if schemaSettings == nil {
		tc.SchemaSettings.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return tc, nil
}

func (g *mqlGcpProjectPubsubService) subscriptions() ([]any, error) {
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

	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	pubsubSvc, err := pubsub.NewClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer pubsubSvc.Close()

	var subs []any

	it := pubsubSvc.SubscriptionAdminClient.ListSubscriptions(ctx, &pubsubpb.ListSubscriptionsRequest{
		Project: projectPath(projectId),
	})
	for {
		s, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlSub, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.subscription", map[string]*llx.RawData{
			"projectId": llx.StringData(projectId),
			"name":      llx.StringData(lastPathSegment(s.Name)),
		})
		if err != nil {
			return nil, err
		}
		subs = append(subs, mqlSub)
	}

	return subs, nil
}

func (g *mqlGcpProjectPubsubServiceSubscription) config() (*mqlGcpProjectPubsubServiceSubscriptionConfig, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	pubsubSvc, err := pubsub.NewClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer pubsubSvc.Close()

	cfg, err := pubsubSvc.SubscriptionAdminClient.GetSubscription(ctx, &pubsubpb.GetSubscriptionRequest{
		Subscription: subscriptionPath(projectId, name),
	})
	if err != nil {
		return nil, err
	}

	// A subscription may reference a topic in a different project; key the topic
	// ref on the topic's own project (from its resource path), not the local one.
	topicProjectId := projectFromResourceName(cfg.Topic)
	if topicProjectId == "" {
		topicProjectId = projectId
	}
	topic, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.topic", map[string]*llx.RawData{
		"projectId": llx.StringData(topicProjectId),
		"name":      llx.StringData(lastPathSegment(cfg.Topic)),
	})
	if err != nil {
		return nil, err
	}

	var pushEndpoint, oidcServiceAccountEmail, oidcAudience, pushWrapper string
	var pushAttributes map[string]string
	if cfg.PushConfig != nil {
		pushEndpoint = cfg.PushConfig.PushEndpoint
		pushAttributes = cfg.PushConfig.Attributes
		if oidc := cfg.PushConfig.GetOidcToken(); oidc != nil {
			oidcServiceAccountEmail = oidc.ServiceAccountEmail
			oidcAudience = oidc.Audience
		}
		switch cfg.PushConfig.Wrapper.(type) {
		case *pubsubpb.PushConfig_PubsubWrapper_:
			pushWrapper = "PUBSUB"
		case *pubsubpb.PushConfig_NoWrapper_:
			pushWrapper = "NONE"
		}
	}
	pushConfig, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.subscription.config.pushconfig", map[string]*llx.RawData{
		"configId":                     llx.StringData(pubsubConfigId(projectId, name)),
		"endpoint":                     llx.StringData(pushEndpoint),
		"attributes":                   llx.MapData(convert.MapToInterfaceMap(pushAttributes), types.String),
		"oidcTokenServiceAccountEmail": llx.StringData(oidcServiceAccountEmail),
		"oidcTokenAudience":            llx.StringData(oidcAudience),
		"wrapper":                      llx.StringData(pushWrapper),
	})
	if err != nil {
		return nil, err
	}

	var expPolicy time.Time
	if cfg.ExpirationPolicy != nil && cfg.ExpirationPolicy.Ttl != nil {
		expPolicy = llx.DurationToTime(int64(cfg.ExpirationPolicy.Ttl.AsDuration().Seconds()))
	}

	var deadLetterDict map[string]any
	if cfg.DeadLetterPolicy != nil {
		deadLetterDict = map[string]any{
			"deadLetterTopic":     cfg.DeadLetterPolicy.DeadLetterTopic,
			"maxDeliveryAttempts": int64(cfg.DeadLetterPolicy.MaxDeliveryAttempts),
		}
	}

	var retryDict map[string]any
	if cfg.RetryPolicy != nil {
		var minBackoff, maxBackoff string
		if cfg.RetryPolicy.MinimumBackoff != nil {
			minBackoff = cfg.RetryPolicy.MinimumBackoff.AsDuration().String()
		}
		if cfg.RetryPolicy.MaximumBackoff != nil {
			maxBackoff = cfg.RetryPolicy.MaximumBackoff.AsDuration().String()
		}
		retryDict = map[string]any{
			"minimumBackoff": minBackoff,
			"maximumBackoff": maxBackoff,
		}
	}

	var bigqueryConfigDict, cloudStorageConfigDict, bigtableConfigDict map[string]any
	var bigqueryTable, cloudStorageBucket, bigtableServiceAccount string
	if bq := cfg.GetBigqueryConfig(); bq != nil {
		bigqueryConfigDict, err = protoToDict(bq)
		if err != nil {
			return nil, err
		}
		bigqueryTable = bq.GetTable()
	}
	if cs := cfg.GetCloudStorageConfig(); cs != nil {
		cloudStorageConfigDict, err = protoToDict(cs)
		if err != nil {
			return nil, err
		}
		cloudStorageBucket = cs.GetBucket()
	}
	if bt := cfg.GetBigtableConfig(); bt != nil {
		bigtableConfigDict, err = protoToDict(bt)
		if err != nil {
			return nil, err
		}
		bigtableServiceAccount = bt.GetServiceAccountEmail()
	}

	deadLetterTopic := ""
	if cfg.DeadLetterPolicy != nil {
		deadLetterTopic = cfg.DeadLetterPolicy.DeadLetterTopic
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.subscription.config", map[string]*llx.RawData{
		"projectId":                     llx.StringData(projectId),
		"subscriptionName":              llx.StringData(name),
		"topic":                         llx.ResourceData(topic, "gcp.project.pubsubService.topic"),
		"pushConfig":                    llx.ResourceData(pushConfig, "gcp.project.pubsubService.subscription.config.pushconfig"),
		"ackDeadline":                   llx.TimeData(llx.DurationToTime(int64(cfg.AckDeadlineSeconds))),
		"retainAckedMessages":           llx.BoolData(cfg.RetainAckedMessages),
		"retentionDuration":             llx.TimeData(pbDurationToTime(cfg.MessageRetentionDuration)),
		"expirationPolicy":              llx.TimeData(expPolicy),
		"labels":                        llx.MapData(convert.MapToInterfaceMap(cfg.Labels), types.String),
		"enableMessageOrdering":         llx.BoolData(cfg.EnableMessageOrdering),
		"enableExactlyOnceDelivery":     llx.BoolData(cfg.EnableExactlyOnceDelivery),
		"filter":                        llx.StringData(cfg.Filter),
		"detached":                      llx.BoolData(cfg.Detached),
		"state":                         llx.StringData(subscriptionStateToString(cfg.State)),
		"topicMessageRetentionDuration": llx.TimeData(pbDurationToTime(cfg.TopicMessageRetentionDuration)),
		"deadLetterPolicy":              llx.DictData(deadLetterDict),
		"retryPolicy":                   llx.DictData(retryDict),
		"bigqueryConfig":                llx.DictData(bigqueryConfigDict),
		"cloudStorageConfig":            llx.DictData(cloudStorageConfigDict),
		"bigtableConfig":                llx.DictData(bigtableConfigDict),
	})
	if err != nil {
		return nil, err
	}
	cfgRes := res.(*mqlGcpProjectPubsubServiceSubscriptionConfig)
	cfgRes.cacheDeadLetterTopic = deadLetterTopic
	cfgRes.cacheOidcServiceAccount = oidcServiceAccountEmail
	cfgRes.cacheBigqueryTable = bigqueryTable
	cfgRes.cacheCloudStorageBucket = cloudStorageBucket
	cfgRes.cacheBigtableServiceAccount = bigtableServiceAccount
	return cfgRes, nil
}

func (g *mqlGcpProjectPubsubService) snapshots() ([]any, error) {
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

	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	pubsubSvc, err := pubsub.NewClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer pubsubSvc.Close()

	var subs []any

	it := pubsubSvc.SubscriptionAdminClient.ListSnapshots(ctx, &pubsubpb.ListSnapshotsRequest{
		Project: projectPath(projectId),
	})
	for {
		s, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		snapshotName := lastPathSegment(s.Name)
		topicName := lastPathSegment(s.Topic)

		// A snapshot may reference a topic in a different project; key the topic
		// ref on the topic's own project (from its resource path).
		topicProjectId := projectFromResourceName(s.Topic)
		if topicProjectId == "" {
			topicProjectId = projectId
		}
		topic, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.topic", map[string]*llx.RawData{
			"projectId": llx.StringData(topicProjectId),
			"name":      llx.StringData(topicName),
		})
		if err != nil {
			return nil, err
		}

		var expiration time.Time
		if s.ExpireTime != nil {
			expiration = s.ExpireTime.AsTime()
		}

		mqlSub, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.snapshot", map[string]*llx.RawData{
			"projectId":  llx.StringData(projectId),
			"name":       llx.StringData(snapshotName),
			"topic":      llx.ResourceData(topic, "gcp.project.pubsubService.topic"),
			"expiration": llx.TimeData(expiration),
			"labels":     llx.MapData(convert.MapToInterfaceMap(s.Labels), types.String),
		})
		if err != nil {
			return nil, err
		}
		subs = append(subs, mqlSub)
	}

	return subs, nil
}

func (g *mqlGcpProjectPubsubServiceTopic) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	pubsubSvc, err := pubsub.NewClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer pubsubSvc.Close()

	resourcePath := topicPath(projectId, name)
	policy, err := pubsubSvc.TopicAdminClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resourcePath, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			log.Warn().Str("project", projectId).Str("topic", name).Err(err).Msg("could not retrieve topic IAM policy")
			return nil, nil
		}
		return nil, err
	}

	// Share the standard binding mapper. The inline copy this replaces omitted
	// conditionTitle/conditionExpression/conditionDescription, which are plain
	// (non-computed) fields, so they crossed the plugin boundary UNSET -- and a
	// conditional allUsers grant read as an unconditional one even though the
	// request already asks for policy schema v3.
	return iampbBindingsToMql(g.MqlRuntime, resourcePath, policy.Bindings)
}

func (g *mqlGcpProjectPubsubServiceSubscription) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	pubsubSvc, err := pubsub.NewClient(ctx, projectId, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer pubsubSvc.Close()

	resourcePath := subscriptionPath(projectId, name)
	policy, err := pubsubSvc.SubscriptionAdminClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resourcePath, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.PermissionDenied {
			log.Warn().Str("project", projectId).Str("subscription", name).Err(err).Msg("could not retrieve subscription IAM policy")
			return nil, nil
		}
		return nil, err
	}

	// Share the standard binding mapper. The inline copy this replaces omitted
	// conditionTitle/conditionExpression/conditionDescription, which are plain
	// (non-computed) fields, so they crossed the plugin boundary UNSET -- and a
	// conditional allUsers grant read as an unconditional one even though the
	// request already asks for policy schema v3.
	return iampbBindingsToMql(g.MqlRuntime, resourcePath, policy.Bindings)
}

func topicStateToString(state pubsubpb.Topic_State) string {
	switch state {
	case pubsubpb.Topic_ACTIVE:
		return "ACTIVE"
	case pubsubpb.Topic_INGESTION_RESOURCE_ERROR:
		return "INGESTION_RESOURCE_ERROR"
	default:
		return "STATE_UNSPECIFIED"
	}
}

func subscriptionStateToString(state pubsubpb.Subscription_State) string {
	switch state {
	case pubsubpb.Subscription_ACTIVE:
		return "ACTIVE"
	case pubsubpb.Subscription_RESOURCE_ERROR:
		return "RESOURCE_ERROR"
	default:
		return "STATE_UNSPECIFIED"
	}
}

func pbDurationToTime(d *durationpb.Duration) time.Time {
	if d == nil {
		return llx.DurationToTime(0)
	}
	return llx.DurationToTime(int64(d.AsDuration().Seconds()))
}

func pubsubConfigId(projectId, parentName string) string {
	return fmt.Sprintf("%s/%s/config", projectId, parentName)
}

func projectPath(projectID string) string {
	return "projects/" + projectID
}

func topicPath(projectID, name string) string {
	return fmt.Sprintf("projects/%s/topics/%s", projectID, name)
}

func subscriptionPath(projectID, name string) string {
	return fmt.Sprintf("projects/%s/subscriptions/%s", projectID, name)
}

func lastPathSegment(s string) string {
	if _, after, ok := strings.CutLast(s, "/"); ok {
		return after
	}
	return s
}

func (g *mqlGcpProjectPubsubService) schemas() ([]any, error) {
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
	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	schemaClient, err := pubsubadmin.NewSchemaClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer schemaClient.Close()

	it := schemaClient.ListSchemas(ctx, &pubsubpb.ListSchemasRequest{
		Parent: projectPath(projectId),
		View:   pubsubpb.SchemaView_FULL,
	})

	var res []any
	for {
		schema, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
				break
			}
			return nil, err
		}

		var revisionCreateTime *time.Time
		if schema.RevisionCreateTime != nil {
			t := schema.RevisionCreateTime.AsTime()
			revisionCreateTime = &t
		}

		mqlSchema, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.schema", map[string]*llx.RawData{
			"projectId":          llx.StringData(projectId),
			"name":               llx.StringData(schema.Name),
			"type":               llx.StringData(pubsubSchemaTypeString(schema.Type)),
			"definition":         llx.StringData(schema.Definition),
			"revisionId":         llx.StringData(schema.RevisionId),
			"revisionCreateTime": llx.TimeDataPtr(revisionCreateTime),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSchema)
	}

	return res, nil
}

func pubsubSchemaTypeString(t pubsubpb.Schema_Type) string {
	switch t {
	case pubsubpb.Schema_PROTOCOL_BUFFER:
		return "PROTOCOL_BUFFER"
	case pubsubpb.Schema_AVRO:
		return "AVRO"
	default:
		return "TYPE_UNSPECIFIED"
	}
}

func (g *mqlGcpProjectPubsubServiceSchema) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/pubsubService.schema/%s", g.ProjectId.Data, g.Name.Data), nil
}

// initGcpProjectPubsubServiceSchema resolves a schema reference by fetching it
// from the Pub/Sub API. Required so typed references (e.g. topic.config.
// schemaSettings.schemaResource) work without first listing every schema in
// the project.
func initGcpProjectPubsubServiceSchema(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if args == nil {
		args = make(map[string]*llx.RawData)
	}
	// Already fully populated (e.g. from the schemas() listing) — nothing to do.
	if _, ok := args["definition"]; ok {
		return args, nil, nil
	}

	nameArg, ok := args["name"]
	if !ok || nameArg == nil {
		return nil, nil, errors.New("gcp.project.pubsubService.schema requires a name")
	}
	fullName, ok := nameArg.Value.(string)
	if !ok || fullName == "" {
		return nil, nil, errors.New("gcp.project.pubsubService.schema requires a name")
	}

	// Schema names are always projects/{project}/schemas/{schema}.
	parts := strings.Split(fullName, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != "schemas" {
		return nil, nil, fmt.Errorf("invalid pubsub schema name %q (want projects/<project>/schemas/<schema>)", fullName)
	}
	projectId := parts[1]

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. Memoized per project, so this is free after the first caller.
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_pubsub); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Pub/Sub API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(pubsub.ScopePubSub)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	schemaClient, err := pubsubadmin.NewSchemaClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}
	defer schemaClient.Close()

	schema, err := schemaClient.GetSchema(ctx, &pubsubpb.GetSchemaRequest{
		Name: fullName,
		View: pubsubpb.SchemaView_FULL,
	})
	if err != nil {
		return nil, nil, err
	}

	var revisionCreateTime *time.Time
	if schema.RevisionCreateTime != nil {
		t := schema.RevisionCreateTime.AsTime()
		revisionCreateTime = &t
	}

	args["projectId"] = llx.StringData(projectId)
	args["name"] = llx.StringData(schema.Name)
	args["type"] = llx.StringData(pubsubSchemaTypeString(schema.Type))
	args["definition"] = llx.StringData(schema.Definition)
	args["revisionId"] = llx.StringData(schema.RevisionId)
	args["revisionCreateTime"] = llx.TimeDataPtr(revisionCreateTime)
	return args, nil, nil
}

func pubsubSchemaEncodingString(e pubsubpb.Encoding) string {
	switch e {
	case pubsubpb.Encoding_JSON:
		return "JSON"
	case pubsubpb.Encoding_BINARY:
		return "BINARY"
	default:
		return "ENCODING_UNSPECIFIED"
	}
}

func buildTopicSchemaSettings(runtime *plugin.Runtime, parentId string, ss *pubsubpb.SchemaSettings) (*mqlGcpProjectPubsubServiceTopicConfigSchemaSettings, error) {
	if ss == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "gcp.project.pubsubService.topic.config.schemaSettings", map[string]*llx.RawData{
		"id":              llx.StringData(parentId + "/schemaSettings"),
		"schema":          llx.StringData(ss.Schema),
		"encoding":        llx.StringData(pubsubSchemaEncodingString(ss.Encoding)),
		"firstRevisionId": llx.StringData(ss.FirstRevisionId),
		"lastRevisionId":  llx.StringData(ss.LastRevisionId),
	})
	if err != nil {
		return nil, err
	}
	pc := res.(*mqlGcpProjectPubsubServiceTopicConfigSchemaSettings)
	pc.cacheSchema = ss.Schema
	return pc, nil
}

func (g *mqlGcpProjectPubsubServiceTopicConfigSchemaSettings) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

type mqlGcpProjectPubsubServiceTopicConfigSchemaSettingsInternal struct {
	cacheSchema string
}

func (g *mqlGcpProjectPubsubServiceTopicConfigSchemaSettings) schemaResource() (*mqlGcpProjectPubsubServiceSchema, error) {
	schema := g.cacheSchema
	if schema == "" {
		g.SchemaResource.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	args := map[string]*llx.RawData{
		"name": llx.StringData(schema),
	}
	// Schema names are always projects/{project}/schemas/{schema} — extract the
	// project so the resource's id() can resolve without listing all schemas first.
	if parts := strings.Split(schema, "/"); len(parts) == 4 && parts[0] == "projects" && parts[2] == "schemas" {
		args["projectId"] = llx.StringData(parts[1])
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.pubsubService.schema", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectPubsubServiceSchema), nil
}

func (g *mqlGcpProjectPubsubServiceTopic) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectPubsubServiceSubscription) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectPubsubServiceTopicConfig) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

type mqlGcpProjectPubsubServiceSubscriptionConfigInternal struct {
	cacheDeadLetterTopic        string
	cacheOidcServiceAccount     string
	cacheBigqueryTable          string
	cacheCloudStorageBucket     string
	cacheBigtableServiceAccount string
}

func (g *mqlGcpProjectPubsubServiceSubscriptionConfig) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

func (g *mqlGcpProjectPubsubServiceSubscriptionConfig) deadLetterTopic() (*mqlGcpProjectPubsubServiceTopic, error) {
	if g.cacheDeadLetterTopic == "" {
		g.DeadLetterTopic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	projectId := projectFromResourceName(g.cacheDeadLetterTopic)
	if projectId == "" && g.ProjectId.Error == nil {
		projectId = g.ProjectId.Data
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.pubsubService.topic", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"name":      llx.StringData(lastPathSegment(g.cacheDeadLetterTopic)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectPubsubServiceTopic), nil
}

func (g *mqlGcpProjectPubsubServiceSubscriptionConfig) oidcTokenServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	projectId := ""
	if g.ProjectId.Error == nil {
		projectId = g.ProjectId.Data
	}
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheOidcServiceAccount, projectId)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.OidcTokenServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return sa, nil
}

func (g *mqlGcpProjectPubsubServiceSubscriptionConfig) bigtableServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	projectId := ""
	if g.ProjectId.Error == nil {
		projectId = g.ProjectId.Data
	}
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheBigtableServiceAccount, projectId)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.BigtableServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return sa, nil
}

func (g *mqlGcpProjectPubsubServiceSubscriptionConfig) bigqueryTable() (*mqlGcpProjectBigqueryServiceTable, error) {
	// Pub/Sub carries the destination as "{projectId}.{datasetId}.{tableId}".
	parts := strings.SplitN(g.cacheBigqueryTable, ".", 3)
	if g.cacheBigqueryTable == "" || len(parts) != 3 {
		g.BigqueryTable.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.bigqueryService.table", map[string]*llx.RawData{
		"id":        llx.StringData(parts[2]),
		"projectId": llx.StringData(parts[0]),
		"datasetId": llx.StringData(parts[1]),
		"name":      llx.StringData(parts[2]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectBigqueryServiceTable), nil
}

func (g *mqlGcpProjectPubsubServiceSubscriptionConfig) cloudStorageBucket() (*mqlGcpProjectStorageServiceBucket, error) {
	if g.cacheCloudStorageBucket == "" {
		g.CloudStorageBucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.storageService.bucket", map[string]*llx.RawData{
		"name": llx.StringData(g.cacheCloudStorageBucket),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectStorageServiceBucket), nil
}

func (g *mqlGcpProjectPubsubServiceSnapshot) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

func (g *mqlGcpProjectPubsubServiceTopicConfig) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
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

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectPubsubService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_pubsub)
}
