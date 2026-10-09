// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/events"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciEvents) id() (string, error) {
	return "oci.events", nil
}

func (o *mqlOciEvents) rules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			svc, err := conn.EventsClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			rules, err := o.getEventRulesForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range rules {
				rule := rules[i]

				var created *time.Time
				if rule.TimeCreated != nil {
					created = &rule.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.events.rule", stringValue(rule.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(rule.Id),
					"name":         llx.StringDataPtr(rule.DisplayName),
					"description":  llx.StringDataPtr(rule.Description),
					"condition":    llx.StringDataPtr(rule.Condition),
					"isEnabled":    llx.BoolDataPtr(rule.IsEnabled),
					"state":        llx.StringData(string(rule.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(rule.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(rule.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}

				mqlRule := mqlInstance.(*mqlOciEventsRule)
				mqlRule.cacheRegion = region

				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (o *mqlOciEvents) getEventRulesForRegion(ctx context.Context, client *events.EventsClient, compartmentID string) ([]events.RuleSummary, error) {
	rules, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]events.RuleSummary, *string, error) {
		request := events.ListRulesRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := client.ListRules(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return rules, nil
}

type mqlOciEventsRuleInternal struct {
	ociCompartmentRef
	rule        ociRetryLazy[*events.Rule]
	cacheRegion string
}

func (o *mqlOciEventsRule) id() (string, error) {
	return "oci.events.rule/" + o.Id.Data, nil
}

// getRuleDetails lazily loads the rule detail, which carries the actions the
// list call omits.
func (o *mqlOciEventsRule) getRuleDetails() (*events.Rule, error) {
	return o.rule.get(func() (*events.Rule, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)

		client, err := conn.EventsClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}

		response, err := client.GetRule(context.Background(), events.GetRuleRequest{
			RuleId: common.String(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &response.Rule, nil
	})
}

func (o *mqlOciEventsRule) actions() ([]any, error) {
	rule, err := o.getRuleDetails()
	if err != nil {
		return nil, err
	}

	if rule.Actions == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(rule.Actions.Actions))
	for _, action := range rule.Actions.Actions {
		// The SDK stores a nil entry for any action whose JSON is null
		// (events/action_list.go), and calling a method on that nil interface
		// panics - which in a provider accessor takes down the whole scan.
		if action == nil {
			continue
		}

		m := map[string]any{
			"id":        stringValue(action.GetId()),
			"isEnabled": boolValue(action.GetIsEnabled()),
			"state":     string(action.GetLifecycleState()),
		}

		switch a := action.(type) {
		case events.NotificationServiceAction:
			m["actionType"] = "ONS"
			m["topicId"] = stringValue(a.TopicId)
			m["description"] = stringValue(a.Description)
		case events.StreamingServiceAction:
			m["actionType"] = "OSS"
			m["streamId"] = stringValue(a.StreamId)
			m["description"] = stringValue(a.Description)
		case events.FaaSAction:
			m["actionType"] = "FAAS"
			m["functionId"] = stringValue(a.FunctionId)
			m["description"] = stringValue(a.Description)
		default:
			// An action type newer than the pinned SDK. Without this branch the
			// entry carried no actionType at all and silently dropped out of
			// any `actions.where(actionType == ...)` filter.
			m["actionType"] = "UNKNOWN"
			m["description"] = stringValue(action.GetDescription())
		}

		res = append(res, m)
	}

	return res, nil
}
