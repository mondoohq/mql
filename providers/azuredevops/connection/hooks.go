// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/url"
	"strings"
)

// Subscription is one entry of GET /_apis/hooks/subscriptions, a service hook
// that sends the events of a publisher to a consumer such as a web hook.
type Subscription struct {
	ID          string `json:"id"`
	EventType   string `json:"eventType"`
	PublisherID string `json:"publisherId"`
	ConsumerID  string `json:"consumerId"`
	// Status is enabled, onProbation, disabledByUser, disabledBySystem, or
	// disabledByInactiveIdentity.
	Status          string            `json:"status"`
	PublisherInputs map[string]string `json:"publisherInputs"`
	ConsumerInputs  map[string]string `json:"consumerInputs"`
}

// Active reports a subscription that still sends events. One on probation
// failed recently but is still retried.
func (s Subscription) Active() bool {
	return strings.EqualFold(s.Status, "enabled") || strings.EqualFold(s.Status, "onProbation")
}

// URL is the absolute address the subscription sends events to, or nil when
// its consumer has none.
func (s Subscription) URL() *url.URL {
	raw := strings.TrimSpace(s.ConsumerInputs["url"])
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	return u
}

// AppliesToRepository reports a subscription that fires for the repository: one
// whose project is the project of the repository, or that names no project,
// and that names the repository, or names no repository and publishes code
// events, which then fire for every repository of the project.
func (s Subscription) AppliesToRepository(projectID, repoID string) bool {
	if p := s.PublisherInputs["projectId"]; p != "" && !strings.EqualFold(p, projectID) {
		return false
	}
	if repo := s.PublisherInputs["repository"]; repo != "" {
		return strings.EqualFold(repo, repoID)
	}
	ev := strings.ToLower(s.EventType)
	return strings.HasPrefix(ev, "git.") || strings.HasPrefix(ev, "ms.vss-code.")
}

// Subscriptions lists the service hook subscriptions of the organization.
// Every repository reads the same list, so it is fetched once per client.
func (c *Client) Subscriptions(ctx context.Context) ([]Subscription, error) {
	return c.subscriptions.get("", func() ([]Subscription, error) {
		return listAll[Subscription](ctx, c, request{
			segments: []string{"_apis", "hooks", "subscriptions"},
		}, 0)
	})
}
