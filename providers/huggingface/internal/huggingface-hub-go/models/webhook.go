// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
)

type Webhook struct {
	ID       string          `json:"id"`
	Watched  []Watched       `json:"watched"`
	URL      string          `json:"url"`
	Domains  []string        `json:"domains"`
	Disabled WebhookDisabled `json:"disabled"`
	// HasSecret reports only whether a secret is set; the Hub never returns
	// the secret itself. Nil when the field was absent.
	HasSecret     *bool       `json:"hasSecret"`
	LastTriggerAt string      `json:"lastTriggerAt"`
	Job           *WebhookJob `json:"job"`
}

// WebhookJob is the job a webhook launches. Exactly one of DockerImage and
// SpaceID names what the job runs. Environment, secrets and the command are
// not decoded.
type WebhookJob struct {
	DockerImage string `json:"dockerImage"`
	SpaceID     string `json:"spaceId"`
}

// WebhookDisabled is true for a webhook that does not deliver. The Hub reports
// either a boolean or the string "suspended-after-failure" for a webhook it
// stopped after repeated delivery failures; both mean the webhook is off.
type WebhookDisabled bool

func (d *WebhookDisabled) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*d = WebhookDisabled(b)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*d = WebhookDisabled(s != "")
	return nil
}

type Watched struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type WebhookList []Webhook

func (wl *WebhookList) UnmarshalJSON(data []byte) error {
	var webhooks []Webhook
	if err := json.Unmarshal(data, &webhooks); err == nil {
		*wl = webhooks
		return nil
	}

	var obj struct {
		Webhooks []Webhook `json:"webhooks"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*wl = obj.Webhooks
	return nil
}

type WebhookListOptions struct {
	Search        string
	Filter        string
	SortBy        string
	SortDirection string
	Limit         int
	Full          bool
}

func NewWebhookListOptions() *WebhookListOptions {
	return &WebhookListOptions{
		SortDirection: "1",
		Limit:         20,
		Full:          false,
	}
}
