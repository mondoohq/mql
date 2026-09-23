// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

func (g *mqlGithubOrganizationCopilot) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubOrganizationCopilotSeat) id() (string, error) {
	return g.__id, nil
}

func initGithubOrganizationCopilot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	org, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	copilot := org.(*mqlGithubOrganization).GetCopilot()
	if copilot.Error != nil {
		return nil, nil, copilot.Error
	}
	if copilot.Data == nil {
		return nil, nil, errors.New("Copilot configuration is not available for this organization (requires Copilot admin access)")
	}
	return args, copilot.Data, nil
}

func (g *mqlGithubOrganization) copilot() (*mqlGithubOrganizationCopilot, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	details, _, err := conn.Client().Copilot.GetCopilotBilling(conn.Context(), orgLogin)
	if err != nil {
		switch githubResponseStatus(err) {
		case 404, 403, 401:
			log.Debug().Err(err).Msg("Copilot configuration not accessible")
			g.Copilot.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if details == nil {
		g.Copilot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	args := map[string]*llx.RawData{
		"__id":                  llx.StringData("github.organization.copilot/" + orgLogin),
		"seatManagementSetting": llx.StringData(details.SeatManagementSetting),
		"publicCodeSuggestions": llx.StringData(details.PublicCodeSuggestions),
		"copilotChat":           llx.StringData(details.CopilotChat),
	}
	if b := details.SeatBreakdown; b != nil {
		args["seatsTotal"] = llx.IntData(int64(b.Total))
		args["seatsAddedThisCycle"] = llx.IntData(int64(b.AddedThisCycle))
		args["seatsPendingCancellation"] = llx.IntData(int64(b.PendingCancellation))
		args["seatsPendingInvitation"] = llx.IntData(int64(b.PendingInvitation))
		args["seatsActiveThisCycle"] = llx.IntData(int64(b.ActiveThisCycle))
		args["seatsInactiveThisCycle"] = llx.IntData(int64(b.InactiveThisCycle))
	} else {
		args["seatsTotal"] = llx.IntData(0)
		args["seatsAddedThisCycle"] = llx.IntData(0)
		args["seatsPendingCancellation"] = llx.IntData(0)
		args["seatsPendingInvitation"] = llx.IntData(0)
		args["seatsActiveThisCycle"] = llx.IntData(0)
		args["seatsInactiveThisCycle"] = llx.IntData(0)
	}

	res, err := CreateResource(g.MqlRuntime, "github.organization.copilot", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubOrganizationCopilot), nil
}

func (g *mqlGithubOrganizationCopilot) contentExclusion() (any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	orgLogin, err := copilotOrgLogin(g)
	if err != nil {
		return nil, err
	}

	details, _, err := conn.Client().Copilot.GetOrganizationContentExclusionDetails(conn.Context(), orgLogin)
	if err != nil {
		switch githubResponseStatus(err) {
		case 404, 403, 401:
			log.Debug().Err(err).Msg("Copilot content exclusion not accessible")
			g.ContentExclusion.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	out := map[string]any{}
	for k, v := range details {
		patterns := make([]any, 0, len(v))
		for _, p := range v {
			patterns = append(patterns, p)
		}
		out[k] = patterns
	}
	return out, nil
}

func (g *mqlGithubOrganizationCopilot) seats() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	orgLogin, err := copilotOrgLogin(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var allSeats []*github.CopilotSeatDetails
	for {
		page, resp, err := conn.Client().Copilot.ListCopilotSeats(conn.Context(), orgLogin, listOpts)
		if err != nil {
			switch githubResponseStatus(err) {
			case 404, 403, 401:
				log.Debug().Err(err).Msg("Copilot seats not accessible")
				return []any{}, nil
			}
			return nil, err
		}
		if page != nil {
			allSeats = append(allSeats, page.Seats...)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := make([]any, 0, len(allSeats))
	for _, seat := range allSeats {
		if seat == nil {
			continue
		}
		mqlSeat, err := newMqlCopilotSeat(g.MqlRuntime, orgLogin, seat)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSeat)
	}
	return res, nil
}

func copilotOrgLogin(g *mqlGithubOrganizationCopilot) (string, error) {
	// __id format: github.organization.copilot/<orgLogin>
	if after, ok := strings.CutPrefix(g.__id, "github.organization.copilot/"); ok && after != "" {
		return after, nil
	}
	return "", errors.New("github.organization.copilot has invalid id")
}

func newMqlCopilotSeat(runtime *plugin.Runtime, orgLogin string, seat *github.CopilotSeatDetails) (plugin.Resource, error) {
	assigneeLogin := ""
	assigneeType := ""
	assigningTeamName := ""
	var userRes *mqlGithubUser

	if user, ok := seat.GetUser(); ok && user != nil {
		assigneeType = "User"
		assigneeLogin = user.GetLogin()
		ur, err := CreateResource(runtime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntData(user.GetID()),
			"login": llx.StringData(user.GetLogin()),
		})
		if err != nil {
			return nil, err
		}
		userRes = ur.(*mqlGithubUser)
	} else if team, ok := seat.GetTeam(); ok && team != nil {
		assigneeType = "Team"
		assigneeLogin = team.GetSlug()
	} else if o, ok := seat.GetOrganization(); ok && o != nil {
		assigneeType = "Organization"
		assigneeLogin = o.GetLogin()
	}
	if at := seat.AssigningTeam; at != nil {
		assigningTeamName = at.GetSlug()
	}

	pending := ""
	if seat.PendingCancellationDate != nil {
		pending = *seat.PendingCancellationDate
	}

	args := map[string]*llx.RawData{
		"__id":                    llx.StringData("github.organization.copilot.seat/" + orgLogin + "/" + assigneeType + "/" + assigneeLogin),
		"assigneeLogin":           llx.StringData(assigneeLogin),
		"assigneeType":            llx.StringData(assigneeType),
		"assigningTeamName":       llx.StringData(assigningTeamName),
		"pendingCancellationDate": llx.StringData(pending),
		"lastActivityAt":          llx.TimeDataPtr(githubTimestamp(seat.LastActivityAt)),
		"lastActivityEditor":      llx.StringDataPtr(seat.LastActivityEditor),
		"createdAt":               llx.TimeDataPtr(githubTimestamp(seat.CreatedAt)),
		"updatedAt":               llx.TimeDataPtr(githubTimestamp(seat.UpdatedAt)),
		"planType":                llx.StringDataPtr(seat.PlanType),
	}
	if userRes != nil {
		args["user"] = llx.ResourceData(userRes, "github.user")
	} else {
		// Team/Org-level seats have no user; NilData sets StateIsSet|StateIsNull
		// on the field so `.user` reads as null rather than panicking.
		args["user"] = llx.NilData
	}
	return CreateResource(runtime, "github.organization.copilot.seat", args)
}

func (g *mqlGithubRepositoryCopilotCloudAgent) id() (string, error) {
	if g.__id == "" {
		return "", errors.New("github.repository.copilotCloudAgent requires __id set by the creator")
	}
	return g.__id, nil
}

func initGithubRepositoryCopilotCloudAgent(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	repo, err := NewResource(runtime, "github.repository", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	cfg := repo.(*mqlGithubRepository).GetCopilotCloudAgent()
	if cfg.Error != nil {
		return nil, nil, cfg.Error
	}
	if cfg.Data == nil {
		return nil, nil, errors.New("Copilot coding agent configuration is not available for this repository")
	}
	return args, cfg.Data, nil
}

func (g *mqlGithubRepository) copilotCloudAgent() (*mqlGithubRepositoryCopilotCloudAgent, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	cfg, _, err := conn.Client().Copilot.GetCloudAgentConfiguration(conn.Context(), ownerLogin, repoName)
	if err != nil {
		switch githubResponseStatus(err) {
		case 404, 403, 401:
			log.Debug().Err(err).Msg("Copilot coding agent configuration not accessible")
			g.CopilotCloudAgent.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if cfg == nil {
		g.CopilotCloudAgent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	args := map[string]*llx.RawData{
		"__id":                                  llx.StringData("github.repository.copilotCloudAgent/" + ownerLogin + "/" + repoName),
		"isFirewallEnabled":                     llx.BoolData(cfg.IsFirewallEnabled),
		"isFirewallRecommendedAllowlistEnabled": llx.BoolData(cfg.IsFirewallRecommendedAllowlistEnabled),
		"customAllowlist":                       llx.ArrayData(convert.SliceAnyToInterface[string](cfg.CustomAllowlist), types.String),
		"requireActionsWorkflowApproval":        llx.BoolData(cfg.RequireActionsWorkflowApproval),
		"mcpConfiguration":                      llx.DictData(cfg.MCPConfiguration),
	}
	if t := cfg.EnabledTools; t != nil {
		args["codeqlEnabled"] = llx.BoolData(t.Codeql)
		args["copilotCodeReviewEnabled"] = llx.BoolData(t.CopilotCodeReview)
		args["secretScanningEnabled"] = llx.BoolData(t.SecretScanning)
		args["dependencyVulnerabilityChecksEnabled"] = llx.BoolData(t.DependencyVulnerabilityChecks)
	} else {
		args["codeqlEnabled"] = llx.BoolData(false)
		args["copilotCodeReviewEnabled"] = llx.BoolData(false)
		args["secretScanningEnabled"] = llx.BoolData(false)
		args["dependencyVulnerabilityChecksEnabled"] = llx.BoolData(false)
	}

	res, err := CreateResource(g.MqlRuntime, "github.repository.copilotCloudAgent", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubRepositoryCopilotCloudAgent), nil
}
