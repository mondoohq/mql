// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"time"
)

// AdvSecEnablement is the answer of GET advsec
// /{project}/_apis/management/repositories/{repo}/enablement.
type AdvSecEnablement struct {
	Enabled bool `json:"advSecEnabled"`
	// LastChangedRaw is kept as text, because Azure DevOps sends some dates
	// without a zone, which time.Time cannot decode. LastChanged parses it.
	LastChangedRaw string `json:"advSecEnablementLastChangedDate"`
}

// LastChanged is when Advanced Security was last turned on or off, or nil when
// it never was.
func (e AdvSecEnablement) LastChanged() *time.Time {
	return parseDate(e.LastChangedRaw)
}

// parseDate reads an Azure DevOps date. A date without a zone is UTC. An empty
// date, a date that does not parse, and the year-one date Azure DevOps sends
// for "never" give nil.
func parseDate(s string) *time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
		t, err := time.Parse(layout, s)
		if err != nil {
			continue
		}
		if t.Year() <= 1 {
			return nil
		}
		t = t.UTC()
		return &t
	}
	return nil
}

// Alert is one entry of GET advsec /{project}/_apis/alert/repositories/{repo}/alerts.
type Alert struct {
	ID int64 `json:"alertId"`
	// AlertType is dependency, secret, or code.
	AlertType string `json:"alertType"`
	// Severity is critical, high, medium, low, note, warning, error, or undefined.
	Severity string `json:"severity"`
	// State is active, dismissed, fixed, or autoDismissed.
	State  string `json:"state"`
	Title  string `json:"title"`
	GitRef string `json:"gitRef"`
	// FirstSeenRaw is kept as text for the reason given on AdvSecEnablement.
	FirstSeenRaw string `json:"firstSeenDate"`
}

// FirstSeen is when the alert was first detected.
func (a Alert) FirstSeen() *time.Time {
	return parseDate(a.FirstSeenRaw)
}

// AdvSecEnablement reads whether Advanced Security is on for one repository.
// Each repository is read once per client.
func (c *Client) AdvSecEnablement(ctx context.Context, project, repoID string) (*AdvSecEnablement, error) {
	return c.enablements.get(project+"/"+repoID, func() (*AdvSecEnablement, error) {
		out := &AdvSecEnablement{}
		if _, err := c.getJSON(ctx, request{
			host:       hostAdvSec,
			segments:   []string{project, "_apis", "management", "repositories", repoID, "enablement"},
			apiVersion: AdvSecAPIVersion,
		}, out); err != nil {
			return nil, err
		}
		return out, nil
	})
}

// Alerts lists the Advanced Security alerts of one repository. A repository
// without Advanced Security answers 400 VS2150009, which IsAdvSecDisabled
// recognizes.
func (c *Client) Alerts(ctx context.Context, project, repoID string) ([]Alert, error) {
	return listAll[Alert](ctx, c, request{
		host:       hostAdvSec,
		segments:   []string{project, "_apis", "alert", "repositories", repoID, "alerts"},
		apiVersion: AdvSecAPIVersion,
	}, 0)
}
