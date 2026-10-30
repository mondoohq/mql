// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
)

// --- dev servers ----------------------------------------------------------

type devServerRecord struct {
	ID        string      `json:"id"`
	SiteID    string      `json:"site_id"`
	Branch    string      `json:"branch"`
	URL       string      `json:"url"`
	State     string      `json:"state"`
	Title     string      `json:"title"`
	CreatedAt netlifyTime `json:"created_at"`
	UpdatedAt netlifyTime `json:"updated_at"`
	LiveAt    netlifyTime `json:"live_at"`
	DoneAt    netlifyTime `json:"done_at"`
}

func (s *mqlNetlifySite) devServers() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[devServerRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/dev_servers", nil)
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			// Development servers are plan-gated, and a site on a plan without
			// them answers 403 or 404 rather than with an empty list.
			s.DevServers = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		server, err := CreateResource(s.MqlRuntime, "netlify.site.devServer", map[string]*llx.RawData{
			"__id":      llx.StringData(s.Id.Data + "/devServer/" + rec.ID),
			"id":        llx.StringData(rec.ID),
			"branch":    llx.StringData(rec.Branch),
			"url":       llx.StringData(rec.URL),
			"state":     llx.StringData(rec.State),
			"title":     llx.StringData(rec.Title),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt": llx.TimeDataPtr(rec.UpdatedAt.Time()),
			"liveAt":    llx.TimeDataPtr(rec.LiveAt.Time()),
			"doneAt":    llx.TimeDataPtr(rec.DoneAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, server)
	}
	return res, nil
}

func (d *mqlNetlifySiteDevServer) id() (string, error) {
	return d.Id.Data, d.Id.Error
}

// --- agent runners --------------------------------------------------------

// mqlNetlifySiteAgentRunnerInternal caches the site the run works on, which its
// site reference resolves against.
type mqlNetlifySiteAgentRunnerInternal struct {
	cacheSiteID string
}

type agentRunnerRecord struct {
	ID           string      `json:"id"`
	SiteID       string      `json:"site_id"`
	State        string      `json:"state"`
	Title        string      `json:"title"`
	Branch       string      `json:"branch"`
	ResultBranch string      `json:"result_branch"`
	PrURL        string      `json:"pr_url"`
	PrBranch     string      `json:"pr_branch"`
	PrState      string      `json:"pr_state"`
	PrNumber     *int64      `json:"pr_number"`
	CurrentTask  string      `json:"current_task"`
	CreatedAt    netlifyTime `json:"created_at"`
	UpdatedAt    netlifyTime `json:"updated_at"`
	DoneAt       netlifyTime `json:"done_at"`
}

// agentRunners lists the agent runs against the site's repository. The endpoint
// is keyed on both the account and the site, so a site whose account is not
// readable with this token cannot be asked.
func (s *mqlNetlifySite) agentRunners() ([]any, error) {
	if s.cacheAccountID == "" {
		s.AgentRunners = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	c := netlifyConn(s.MqlRuntime)

	query := url.Values{}
	query.Set("account_id", s.cacheAccountID)
	query.Set("site_id", s.Id.Data)

	records, err := connection.GetPaged[agentRunnerRecord](context.Background(), c, "/agent_runners", query)
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			// Agent runners are plan-gated, and an account on a plan without
			// them answers 403 or 404 rather than with an empty list.
			s.AgentRunners = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		// The run's diff and the files attached to it are the code it wrote,
		// which belongs in the repository rather than in scan results.
		runner, err := CreateResource(s.MqlRuntime, "netlify.site.agentRunner", map[string]*llx.RawData{
			"__id":         llx.StringData(s.Id.Data + "/agentRunner/" + rec.ID),
			"id":           llx.StringData(rec.ID),
			"state":        llx.StringData(rec.State),
			"title":        llx.StringData(rec.Title),
			"branch":       llx.StringData(rec.Branch),
			"resultBranch": llx.StringData(rec.ResultBranch),
			"prUrl":        llx.StringData(rec.PrURL),
			"prBranch":     llx.StringData(rec.PrBranch),
			"prState":      llx.StringData(rec.PrState),
			"prNumber":     optionalInt(rec.PrNumber),
			"currentTask":  llx.StringData(rec.CurrentTask),
			"createdAt":    llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":    llx.TimeDataPtr(rec.UpdatedAt.Time()),
			"doneAt":       llx.TimeDataPtr(rec.DoneAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		mqlRunner := runner.(*mqlNetlifySiteAgentRunner)
		mqlRunner.cacheSiteID = s.Id.Data
		res = append(res, mqlRunner)
	}
	return res, nil
}

func (r *mqlNetlifySiteAgentRunner) id() (string, error) {
	return r.Id.Data, r.Id.Error
}

func (r *mqlNetlifySiteAgentRunner) site() (*mqlNetlifySite, error) {
	return resolveSiteByID(r.MqlRuntime, r.cacheSiteID, &r.Site)
}
