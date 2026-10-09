// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/ons"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciOns) id() (string, error) {
	return "oci.ons", nil
}

func (o *mqlOciOns) topics() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Notification topics are created next to the alarms and connectors that
	// publish to them, which puts them in child compartments. ListTopics has no
	// subtree option, so a root-only sweep reported no topics and broke the alarm
	// and Connector Hub destination references that point at them.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			svc, err := conn.NotificationControlPlaneClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			topics, err := o.getTopicsForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range topics {
				topic := topics[i]

				var created *time.Time
				if topic.TimeCreated != nil {
					created = &topic.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.ons.topic", stringValue(topic.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(topic.TopicId),
					"name":         llx.StringDataPtr(topic.Name),
					"description":  llx.StringDataPtr(topic.Description),
					"state":        llx.StringData(string(topic.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(topic.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(topic.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}

				mqlTopic := mqlInstance.(*mqlOciOnsTopic)
				mqlTopic.cacheRegion = region

				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (o *mqlOciOns) getTopicsForRegion(ctx context.Context, client *ons.NotificationControlPlaneClient, compartmentID string) ([]ons.NotificationTopicSummary, error) {
	topics, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]ons.NotificationTopicSummary, *string, error) {
		request := ons.ListTopicsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := client.ListTopics(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return topics, nil
}

type mqlOciOnsTopicInternal struct {
	ociCompartmentRef
	cacheRegion string
}

func initOciOnsTopic(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.ons.topic")
	}

	obj, err := CreateResource(runtime, "oci.ons", nil)
	if err != nil {
		return nil, nil, err
	}
	o := obj.(*mqlOciOns)

	rawTopics := o.GetTopics()
	if rawTopics.Error != nil {
		return nil, nil, rawTopics.Error
	}

	for _, raw := range rawTopics.Data {
		topic := raw.(*mqlOciOnsTopic)
		if topic.Id.Data == idVal {
			return args, topic, nil
		}
	}

	return nil, nil, fmt.Errorf("%w: %s", errOciOnsTopicNotFound, idVal)
}

// errOciOnsTopicNotFound marks a topic OCID that is not in the listing, which
// normally means the topic was deleted while something that points at it - a
// Connector Hub target, a monitoring alarm destination - outlived it.
//
// It is a sentinel rather than a bare errors.New so callers holding a single
// such reference can tell "the referent is gone" (answer null) apart from "the
// lookup itself failed" (answer with the error). See ociReferentGone.
var errOciOnsTopicNotFound = errors.New("oci.ons.topic not found")

func (o *mqlOciOnsTopic) id() (string, error) {
	return "oci.ons.topic/" + o.Id.Data, nil
}

func (o *mqlOciOnsTopic) subscriptions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.NotificationDataPlaneClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	topicId := o.Id.Data
	ctx := context.Background()

	// Subscriptions are listed in the topic's compartment, not the tenancy
	// root, which held none for a topic created in a child compartment.
	compartmentID := o.cacheCompartmentID
	if compartmentID == "" {
		compartmentID = conn.TenantID()
	}

	subs, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]ons.SubscriptionSummary, *string, error) {
		request := ons.ListSubscriptionsRequest{
			CompartmentId: common.String(compartmentID),
			TopicId:       common.String(topicId),
			Page:          page,
		}

		response, err := client.ListSubscriptions(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(subs))
	for i := range subs {
		sub := subs[i]

		var created *time.Time
		if sub.CreatedTime != nil {
			t := time.UnixMilli(*sub.CreatedTime)
			created = &t
		}

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.ons.subscription", map[string]*llx.RawData{
			"id":           llx.StringDataPtr(sub.Id),
			"protocol":     llx.StringDataPtr(sub.Protocol),
			"endpoint":     llx.StringDataPtr(sub.Endpoint),
			"state":        llx.StringData(string(sub.LifecycleState)),
			"created":      llx.TimeDataPtr(created),
			"freeformTags": llx.MapData(strMapToAny(sub.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(sub.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlInstance.(*mqlOciOnsSubscription).cacheTopicID = stringValue(sub.TopicId)
		res = append(res, mqlInstance)
	}

	return res, nil
}

type mqlOciOnsSubscriptionInternal struct {
	cacheTopicID string
}

func (o *mqlOciOnsSubscription) id() (string, error) {
	return "oci.ons.subscription/" + o.Id.Data, nil
}

func (o *mqlOciOnsSubscription) topic() (*mqlOciOnsTopic, error) {
	if o.cacheTopicID == "" {
		o.Topic.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlTopic, err := NewResource(o.MqlRuntime, "oci.ons.topic", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheTopicID),
	})
	if err != nil {
		return nil, err
	}
	return mqlTopic.(*mqlOciOnsTopic), nil
}
