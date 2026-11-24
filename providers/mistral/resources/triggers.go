// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mistral/internal/mistralai"
)

// mqlMistralTriggerInternal carries the id of the agent a trigger starts a
// session with.
type mqlMistralTriggerInternal struct {
	agentID string
}

func (r *mqlMistral) webhooks() ([]any, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	webhooks, err := client.ListWebhooks(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(webhooks))
	for _, w := range webhooks {
		mqlWebhook, err := newMqlWebhook(r.MqlRuntime, w)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlWebhook)
	}
	return res, nil
}

// newMqlWebhook maps one webhook record onto a mistral.webhook resource. It is
// shared by the webhook listing and by triggers, which embed the full webhook
// they listen on, so both paths build the same cached resource.
func newMqlWebhook(runtime *plugin.Runtime, w mistralai.Webhook) (*mqlMistralWebhook, error) {
	res, err := CreateResource(runtime, "mistral.webhook", map[string]*llx.RawData{
		"__id":                   llx.StringData(w.ID),
		"id":                     llx.StringData(w.ID),
		"name":                   llx.StringData(w.Name),
		"provider":               llx.StringData(w.Provider),
		"url":                    llx.StringData(w.URL),
		"urlVerified":            llx.BoolDataPtr(w.URLVerified),
		"signatureHashAlgorithm": llx.StringDataPtr(w.SignatureHashAlgorithm),
		"validityPeriodSeconds":  llx.IntDataPtr(w.ValidityPeriodSecond),
		"ownerType":              llx.StringData(w.OwnerType),
		"expiresAt":              llx.TimeDataPtr(w.ExpiresAt),
		"createdAt":              llx.TimeDataPtr(w.CreatedAt),
		"updatedAt":              llx.TimeDataPtr(w.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMistralWebhook), nil
}

func (r *mqlMistral) triggers() ([]any, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	triggers, err := client.ListTriggers(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(triggers))
	for _, t := range triggers {
		eventSource := llx.NilData
		if t.EventSource != nil && t.EventSource.ID != "" {
			webhook, err := newMqlWebhook(r.MqlRuntime, *t.EventSource)
			if err != nil {
				return nil, err
			}
			eventSource = llx.ResourceData(webhook, "mistral.webhook")
		}

		agentID, targetID := triggerTarget(t.Action)

		mqlTrigger, err := CreateResource(r.MqlRuntime, "mistral.trigger", map[string]*llx.RawData{
			"__id":           llx.StringData(t.ID),
			"id":             llx.StringData(t.ID),
			"title":          llx.StringData(t.Title),
			"eventSource":    eventSource,
			"handler":        llx.StringData(t.Handler),
			"actionType":     llx.StringData(t.Action.Type),
			"actionTargetId": llx.StringDataPtr(targetID),
			"filters":        llx.StringDataPtr(t.Filters),
			"ownerType":      llx.StringData(t.OwnerType),
		})
		if err != nil {
			return nil, err
		}
		trigger := mqlTrigger.(*mqlMistralTrigger)
		trigger.agentID = agentID
		res = append(res, trigger)
	}
	return res, nil
}

// triggerTarget splits a trigger action's target into the agent it starts a
// session with and the raw id of any other target. Only an agent is modeled,
// so the raw id is reported only for workflows and apps.
func triggerTarget(a mistralai.TriggerAction) (agentID string, targetID *string) {
	if a.PrimitiveID == "" {
		return "", nil
	}
	if a.Type == mistralai.TriggerActionStartAgentSession {
		return a.PrimitiveID, nil
	}
	id := a.PrimitiveID
	return "", &id
}

func (r *mqlMistralWebhook) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlMistralTrigger) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlMistralTrigger) agent() (*mqlMistralAgent, error) {
	a, err := listedAgent(r.MqlRuntime, r.agentID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		r.Agent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return a, nil
}
