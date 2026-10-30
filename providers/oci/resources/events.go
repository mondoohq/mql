// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/oracle/oci-go-sdk/v65/events"
	"github.com/oracle/oci-go-sdk/v65/ons"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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
			CompartmentId: new(compartmentID),
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
			RuleId: new(o.Id.Data),
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

// ociEventsCondition is the subset of an Events rule condition that names what
// the rule matches. OCI accepts eventType as either a string or a list.
type ociEventsCondition struct {
	EventType json.RawMessage `json:"eventType"`
	Data      map[string]any  `json:"data"`
}

// parseOciEventsCondition decodes a rule condition into its event types and
// its data filter. An empty condition matches every event, so it yields no
// event types and no data filter rather than an error.
func parseOciEventsCondition(condition string) ([]string, map[string]any, error) {
	if condition == "" {
		return []string{}, nil, nil
	}

	var cond ociEventsCondition
	if err := json.Unmarshal([]byte(condition), &cond); err != nil {
		return nil, nil, err
	}

	eventTypes := []string{}
	if len(cond.EventType) > 0 && string(cond.EventType) != "null" {
		var single string
		if err := json.Unmarshal(cond.EventType, &single); err == nil {
			eventTypes = append(eventTypes, single)
		} else if err := json.Unmarshal(cond.EventType, &eventTypes); err != nil {
			return nil, nil, fmt.Errorf("eventType is neither a string nor a list of strings: %w", err)
		}
	}

	return eventTypes, cond.Data, nil
}

func (o *mqlOciEventsRule) eventTypes() ([]any, error) {
	eventTypes, _, err := parseOciEventsCondition(o.Condition.Data)
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse condition of oci.events.rule %s: %w", o.Id.Data, err))
	}
	return stringsToAny(eventTypes), nil
}

func (o *mqlOciEventsRule) conditionData() (map[string]any, error) {
	_, data, err := parseOciEventsCondition(o.Condition.Data)
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse condition of oci.events.rule %s: %w", o.Id.Data, err))
	}
	if data == nil {
		o.ConditionData.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return data, nil
}

// ociOnsActionTopicIDs returns the distinct topic OCIDs of a rule's ONS
// actions, in the order the rule lists them. activeOnly keeps only actions
// that are enabled and ACTIVE.
func ociOnsActionTopicIDs(rule *events.Rule, activeOnly bool) []string {
	ids := []string{}
	if rule == nil || rule.Actions == nil {
		return ids
	}

	seen := map[string]struct{}{}
	for _, action := range rule.Actions.Actions {
		onsAction, ok := action.(events.NotificationServiceAction)
		if !ok {
			continue
		}
		if activeOnly && (!boolValue(onsAction.IsEnabled) || onsAction.LifecycleState != events.ActionLifecycleStateActive) {
			continue
		}
		id := stringValue(onsAction.TopicId)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

func (o *mqlOciEventsRule) topics() ([]any, error) {
	rule, err := o.getRuleDetails()
	if err != nil {
		return nil, err
	}
	return resolveOciTopics(o.MqlRuntime, stringsToAny(ociOnsActionTopicIDs(rule, false)))
}

// ociTopicDelivery is what decides whether a topic delivers: its own state and
// the states of its subscriptions.
type ociTopicDelivery struct {
	topicState         string
	subscriptionStates []string
}

// ociEventsRuleNotifies reports whether any of topicIDs is an ACTIVE topic with
// an ACTIVE subscription. A topic that no longer exists does not count. A topic
// that cannot be read is an error only when no other topic answers true, since
// one readable delivering topic settles the question.
func ociEventsRuleNotifies(topicIDs []string, lookup func(topicID string) (ociTopicDelivery, error)) (bool, error) {
	var firstErr error
	for _, id := range topicIDs {
		delivery, err := lookup(id)
		if err != nil {
			if ociReferentGone(err) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if delivery.topicState != string(ons.NotificationTopicSummaryLifecycleStateActive) {
			continue
		}
		if slices.Contains(delivery.subscriptionStates, string(ons.SubscriptionSummaryLifecycleStateActive)) {
			return true, nil
		}
	}
	return false, firstErr
}

func (o *mqlOciEventsRule) hasActiveNotification() (bool, error) {
	if !o.IsEnabled.Data || o.State.Data != string(events.RuleLifecycleStateActive) {
		return false, nil
	}

	rule, err := o.getRuleDetails()
	if err != nil {
		return false, err
	}

	return ociEventsRuleNotifies(ociOnsActionTopicIDs(rule, true), func(topicID string) (ociTopicDelivery, error) {
		res, err := NewResource(o.MqlRuntime, "oci.ons.topic", map[string]*llx.RawData{
			"id": llx.StringData(topicID),
		})
		if err != nil {
			return ociTopicDelivery{}, err
		}
		topic := res.(*mqlOciOnsTopic)

		subs := topic.GetSubscriptions()
		if subs.Error != nil {
			return ociTopicDelivery{}, subs.Error
		}

		delivery := ociTopicDelivery{topicState: topic.State.Data}
		for _, raw := range subs.Data {
			delivery.subscriptionStates = append(delivery.subscriptionStates, raw.(*mqlOciOnsSubscription).State.Data)
		}
		return delivery, nil
	})
}
