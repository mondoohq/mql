// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	eventarc "cloud.google.com/go/eventarc/apiv1"
	"cloud.google.com/go/eventarc/apiv1/eventarcpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectEventarcServiceChannelInternal struct {
	cacheCryptoKeyName string
}

type mqlGcpProjectEventarcServiceTriggerInternal struct {
	cacheServiceAccount string
}

type mqlGcpProjectEventarcServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) eventarc() (*mqlGcpProjectEventarcService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.eventarcService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_eventarc)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectEventarcService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_eventarc).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectEventarcService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (g *mqlGcpProjectEventarcService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.eventarcService", g.ProjectId.Data), nil
}

// ---------------------------------------------------------------
// Triggers
// ---------------------------------------------------------------

func (g *mqlGcpProjectEventarcServiceTrigger) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectEventarcServiceTrigger) serviceAccountRef() (*mqlGcpProjectIamServiceServiceAccount, error) {
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

// eventFilterID returns a cache-stable identifier for an Eventarc trigger
// event filter. A trigger can declare multiple filters that share an
// attribute key but match different values, so both must participate in
// the id to avoid runtime-cache collisions.
func eventFilterID(triggerName, attribute, value string) string {
	return fmt.Sprintf("%s/eventFilters/%s/%s", triggerName, attribute, value)
}

func (g *mqlGcpProjectEventarcServiceTriggerEventFilter) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectEventarcService) triggers() ([]any, error) {
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
	creds, err := conn.Credentials(eventarc.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := eventarc.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListTriggers(ctx, &eventarcpb.ListTriggersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		trigger, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Eventarc triggers")
				break
			}
			return nil, err
		}

		eventFilters := make([]any, 0, len(trigger.EventFilters))
		for _, ef := range trigger.EventFilters {
			mqlEF, err := CreateResource(g.MqlRuntime, "gcp.project.eventarcService.trigger.eventFilter", map[string]*llx.RawData{
				"id":        llx.StringData(eventFilterID(trigger.Name, ef.Attribute, ef.Value)),
				"attribute": llx.StringData(ef.Attribute),
				"value":     llx.StringData(ef.Value),
				"operator":  llx.StringData(ef.Operator),
			})
			if err != nil {
				return nil, err
			}
			eventFilters = append(eventFilters, mqlEF)
		}

		destination, err := protoToDict(trigger.Destination)
		if err != nil {
			return nil, err
		}

		transport, err := protoToDict(trigger.Transport)
		if err != nil {
			return nil, err
		}

		conditions := make(map[string]any)
		for k, v := range trigger.Conditions {
			if v != nil {
				msg := v.Code.String()
				if v.Message != "" {
					msg += ": " + v.Message
				}
				conditions[k] = msg
			}
		}

		mqlTrigger, err := CreateResource(g.MqlRuntime, "gcp.project.eventarcService.trigger", map[string]*llx.RawData{
			"name":                 llx.StringData(trigger.Name),
			"uid":                  llx.StringData(trigger.Uid),
			"eventFilters":         llx.ArrayData(eventFilters, types.Resource("gcp.project.eventarcService.trigger.eventFilter")),
			"destination":          llx.DictData(destination),
			"transport":            llx.DictData(transport),
			"channelName":          llx.StringData(trigger.Channel),
			"labels":               llx.MapData(convert.MapToInterfaceMap(trigger.Labels), types.String),
			"conditions":           llx.MapData(conditions, types.String),
			"eventDataContentType": llx.StringData(trigger.EventDataContentType),
			"created":              llx.TimeDataPtr(timestampAsTimePtr(trigger.CreateTime)),
			"updated":              llx.TimeDataPtr(timestampAsTimePtr(trigger.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlRef := mqlTrigger.(*mqlGcpProjectEventarcServiceTrigger)
		mqlRef.cacheServiceAccount = trigger.ServiceAccount
		res = append(res, mqlTrigger)
	}

	return res, nil
}

// ---------------------------------------------------------------
// Channels
// ---------------------------------------------------------------

func (g *mqlGcpProjectEventarcServiceChannel) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectEventarcServiceChannel) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, g.cacheCryptoKeyName)
}

func (g *mqlGcpProjectEventarcService) channels() ([]any, error) {
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
	creds, err := conn.Credentials(eventarc.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := eventarc.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListChannels(ctx, &eventarcpb.ListChannelsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		channel, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Eventarc channels")
				break
			}
			return nil, err
		}

		mqlChannel, err := CreateResource(g.MqlRuntime, "gcp.project.eventarcService.channel", map[string]*llx.RawData{
			"name":        llx.StringData(channel.Name),
			"uid":         llx.StringData(channel.Uid),
			"provider":    llx.StringData(channel.Provider),
			"pubsubTopic": llx.StringData(channel.GetPubsubTopic()),
			"state":       llx.StringData(channel.State.String()),
			"labels":      llx.MapData(convert.MapToInterfaceMap(channel.GetLabels()), types.String),
			"created":     llx.TimeDataPtr(timestampAsTimePtr(channel.CreateTime)),
			"updated":     llx.TimeDataPtr(timestampAsTimePtr(channel.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlRef := mqlChannel.(*mqlGcpProjectEventarcServiceChannel)
		mqlRef.cacheCryptoKeyName = channel.GetCryptoKeyName()
		res = append(res, mqlChannel)
	}

	return res, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectEventarcService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_eventarc)
}
