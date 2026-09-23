// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// ghRunnerExt mirrors the Runner JSON returned by GitHub plus architecture,
// which go-github does not expose on its Runner struct.
type ghRunnerExt struct {
	ID           *int64                 `json:"id,omitempty"`
	Name         *string                `json:"name,omitempty"`
	OS           *string                `json:"os,omitempty"`
	Status       *string                `json:"status,omitempty"`
	Busy         *bool                  `json:"busy,omitempty"`
	Ephemeral    *bool                  `json:"ephemeral,omitempty"`
	Architecture *string                `json:"architecture,omitempty"`
	Labels       []*github.RunnerLabels `json:"labels,omitempty"`
}

// idValue returns the runner id, or 0 when the API omitted it.
func (r *ghRunnerExt) idValue() int64 {
	if r == nil || r.ID == nil {
		return 0
	}
	return *r.ID
}

type ghRunnersListResp struct {
	TotalCount int            `json:"total_count"`
	Runners    []*ghRunnerExt `json:"runners"`
}

// listRunnersRaw paginates through a self-hosted runners endpoint (org or repo)
// using the raw API so we can read architecture, which go-github does not expose.
func listRunnersRaw(ctx context.Context, client *github.Client, basePath string) ([]*ghRunnerExt, error) {
	var all []*ghRunnerExt
	page := 1
	for {
		var body ghRunnersListResp
		url := fmt.Sprintf("%s?per_page=%d&page=%d", basePath, paginationPerPage, page)
		resp, err := doRawJSON(ctx, client, url, &body)
		if err != nil {
			return nil, err
		}
		all = append(all, body.Runners...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return all, nil
}

func (g *mqlGithubRunner) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.runner/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func (g *mqlGithubRunnerLabel) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.runnerLabel/" + strconv.FormatInt(g.Id.Data, 10), nil
}

// runners returns the self-hosted runners for an organization.
func (g *mqlGithubOrganization) runners() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	scope := "orgs/" + orgLogin
	allRunners, err := listRunnersRaw(conn.Context(), conn.Client(), fmt.Sprintf("orgs/%s/actions/runners", orgLogin))
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		if strings.Contains(err.Error(), "403") {
			log.Debug().Msg("Self-hosted runners are not accessible for this organization")
			return nil, nil
		}
		return nil, err
	}

	return runnersToMql(g.MqlRuntime, scope, allRunners)
}

// runners returns the self-hosted runners for a repository.
func (g *mqlGithubRepository) runners() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	scope := "repos/" + ownerLogin + "/" + repoName
	allRunners, err := listRunnersRaw(conn.Context(), conn.Client(), fmt.Sprintf("repos/%s/%s/actions/runners", ownerLogin, repoName))
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return nil, nil
		}
		if strings.Contains(err.Error(), "403") {
			log.Debug().Msg("Self-hosted runners are not accessible for this repository")
			return nil, nil
		}
		return nil, err
	}

	return runnersToMql(g.MqlRuntime, scope, allRunners)
}

// runnerKey identifies a runner within its scope. The id is the natural key, but
// it is a pointer in the API payload: falling back to a shared zero would alias
// every id-less runner onto one resource, so the name (unique per scope) and
// finally the listing position stand in for it.
func runnerKey(runner *ghRunnerExt, idx int) string {
	if id := runner.idValue(); id != 0 {
		return strconv.FormatInt(id, 10)
	}
	if name := runner.Name; name != nil && *name != "" {
		return "name/" + *name
	}
	log.Warn().Int("position", idx).Msg("github runner has neither an id nor a name, keying it by listing position")
	return "position/" + strconv.Itoa(idx)
}

// runnerID keys a runner by the scope that registered it. Organization and
// repository runners are numbered independently, so an unqualified id aliased an
// org runner with a repository runner that happened to share a number.
func runnerID(scope string, key string) string {
	return "github.runner/" + scope + "/" + key
}

// runnerLabelID keys a label by runner and name. Read-only labels ("self-hosted",
// "linux", ...) share fixed ids across every runner, and the API omits the id for
// some custom labels, which collapsed those labels onto a single resource.
func runnerLabelID(scope string, runnerKey string, name string) string {
	return "github.runnerLabel/" + scope + "/" + runnerKey + "/" + name
}

// runnersToMql converts a list of GitHub runners to MQL resources. scope is the
// API path prefix the runners were listed from, used to key them.
func runnersToMql(runtime *plugin.Runtime, scope string, runners []*ghRunnerExt) ([]any, error) {
	res := []any{}
	for idx, runner := range runners {
		key := runnerKey(runner, idx)

		labels := []any{}
		for _, label := range runner.Labels {
			labelRes, err := CreateResource(runtime, "github.runnerLabel", map[string]*llx.RawData{
				"__id": llx.StringData(runnerLabelID(scope, key, label.GetName())),
				"id":   llx.IntDataDefault(label.ID, 0),
				"name": llx.StringDataPtr(label.Name),
				"type": llx.StringDataPtr(label.Type),
			})
			if err != nil {
				return nil, err
			}
			labels = append(labels, labelRes)
		}

		r, err := CreateResource(runtime, "github.runner", map[string]*llx.RawData{
			"__id":         llx.StringData(runnerID(scope, key)),
			"id":           llx.IntDataDefault(runner.ID, 0),
			"name":         llx.StringDataPtr(runner.Name),
			"os":           llx.StringDataPtr(runner.OS),
			"status":       llx.StringDataPtr(runner.Status),
			"busy":         llx.BoolDataPtr(runner.Busy),
			"ephemeral":    llx.BoolDataPtr(runner.Ephemeral),
			"architecture": llx.StringDataPtr(runner.Architecture),
			"labels":       llx.ArrayData(labels, types.Resource("github.runnerLabel")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}
