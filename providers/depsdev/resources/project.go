// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/depsdev/connection"
	"go.mondoo.com/mql/types"
)

type mqlDepsdevProjectInternal struct {
	fetched         atomic.Bool
	lock            sync.Mutex
	archivedFetched atomic.Bool
	archivedLock    sync.Mutex
}

type mqlDepsdevScorecardInternal struct {
	projectID string
}

type mqlDepsdevScorecardCheckInternal struct {
	projectID string
}

func initDepsdevProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["id"]; !ok {
		return nil, nil, errors.New("missing required argument 'id'")
	}

	return args, nil, nil
}

func (r *mqlDepsdevProject) id() (string, error) {
	return "depsdev.project/" + r.Id.Data, nil
}

// fetchProjectInfo fetches project data from deps.dev and populates all fields.
func (r *mqlDepsdevProject) fetchProjectInfo() error {
	if r.fetched.Load() {
		return nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return nil
	}

	conn := r.MqlRuntime.Connection.(*connection.DepsDevConnection)

	proj, err := fetchProject(conn.HttpClient, r.Id.Data)
	if err != nil {
		return err
	}

	r.OpenIssuesCount = plugin.TValue[int64]{Data: int64(proj.OpenIssuesCount), State: plugin.StateIsSet}
	r.StarsCount = plugin.TValue[int64]{Data: int64(proj.StarsCount), State: plugin.StateIsSet}
	r.ForksCount = plugin.TValue[int64]{Data: int64(proj.ForksCount), State: plugin.StateIsSet}
	r.License = plugin.TValue[string]{Data: proj.License, State: plugin.StateIsSet}
	r.Description = plugin.TValue[string]{Data: proj.Description, State: plugin.StateIsSet}
	r.Homepage = plugin.TValue[string]{Data: proj.Homepage, State: plugin.StateIsSet}

	if proj.Scorecard != nil {
		sc, err := r.buildScorecard(proj.Scorecard)
		if err != nil {
			return err
		}
		r.Scorecard = plugin.TValue[*mqlDepsdevScorecard]{Data: sc, State: plugin.StateIsSet}
	} else {
		r.Scorecard = plugin.TValue[*mqlDepsdevScorecard]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	}

	r.fetched.Store(true)
	return nil
}

func (r *mqlDepsdevProject) buildScorecard(sc *depsDevScorecardResponse) (*mqlDepsdevScorecard, error) {
	var checks []any
	for _, c := range sc.Checks {
		docURL := c.Documentation.URL
		if docURL == "" {
			docURL = c.Documentation.ShortDescription
		}

		// Pass __id explicitly: CreateResource calls id() before projectID is set
		// below, so id() would otherwise build a key with an empty project id and
		// collide across projects that share a check name (the OpenSSF check names
		// are a fixed set, identical across every project).
		check, err := CreateResource(r.MqlRuntime, "depsdev.scorecardCheck", map[string]*llx.RawData{
			"__id":          llx.StringData("depsdev.scorecardCheck/" + r.Id.Data + "/" + c.Name),
			"name":          llx.StringData(c.Name),
			"score":         llx.IntData(int64(c.Score)),
			"reason":        llx.StringData(c.Reason),
			"documentation": llx.StringData(docURL),
		})
		if err != nil {
			return nil, err
		}
		mqlCheck := check.(*mqlDepsdevScorecardCheck)
		mqlCheck.projectID = r.Id.Data
		checks = append(checks, check)
	}

	scorecardDate := sc.Date
	// Pass __id explicitly for the same reason as the checks above: projectID is
	// assigned after CreateResource returns, so id() cannot build the key from it.
	res, err := CreateResource(r.MqlRuntime, "depsdev.scorecard", map[string]*llx.RawData{
		"__id":         llx.StringData("depsdev.scorecard/" + r.Id.Data + "/" + scorecardDate.Format(time.RFC3339)),
		"overallScore": llx.FloatData(sc.OverallScore),
		"date":         llx.TimeData(scorecardDate),
		"checks":       llx.ArrayData(checks, types.Resource("depsdev.scorecardCheck")),
	})
	if err != nil {
		return nil, err
	}

	mqlSc := res.(*mqlDepsdevScorecard)
	mqlSc.projectID = r.Id.Data

	return mqlSc, nil
}

func (r *mqlDepsdevProject) openIssuesCount() (int64, error) {
	return 0, r.fetchProjectInfo()
}

func (r *mqlDepsdevProject) starsCount() (int64, error) {
	return 0, r.fetchProjectInfo()
}

func (r *mqlDepsdevProject) forksCount() (int64, error) {
	return 0, r.fetchProjectInfo()
}

func (r *mqlDepsdevProject) license() (string, error) {
	return "", r.fetchProjectInfo()
}

func (r *mqlDepsdevProject) description() (string, error) {
	return "", r.fetchProjectInfo()
}

func (r *mqlDepsdevProject) homepage() (string, error) {
	return "", r.fetchProjectInfo()
}

func (r *mqlDepsdevProject) scorecard() (*mqlDepsdevScorecard, error) {
	return nil, r.fetchProjectInfo()
}

func (r *mqlDepsdevProject) archived() (bool, error) {
	if r.archivedFetched.Load() {
		return r.Archived.Data, nil
	}
	r.archivedLock.Lock()
	defer r.archivedLock.Unlock()
	if r.archivedFetched.Load() {
		return r.Archived.Data, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.DepsDevConnection)

	repo, err := fetchGitHubRepo(conn.HttpClient, r.Id.Data)
	if err != nil {
		if !errors.Is(err, errNotGitHubProject) {
			// A real GitHub API failure (rate limit, 5xx, network). Surface it
			// rather than silently reporting the dependency as "not archived":
			// unauthenticated GitHub is limited to 60 requests/hour, so a large
			// go.mod without GITHUB_TOKEN would otherwise mask every lookup.
			return false, err
		}
		// Not a github.com project (e.g. GitLab, Bitbucket): the archived state is
		// genuinely unavailable here, so degrade to null.
		log.Debug().Str("project", r.Id.Data).Msg("archived status unavailable for non-GitHub project")
		r.Archived = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet | plugin.StateIsNull}
		r.archivedFetched.Store(true)
		return false, nil
	}

	// Set the field before the flag so the unlocked fast-path above observes a
	// populated value once it sees archivedFetched == true.
	r.Archived = plugin.TValue[bool]{Data: repo.Archived, State: plugin.StateIsSet}
	r.archivedFetched.Store(true)
	return repo.Archived, nil
}

// depsdev.scorecard

func (r *mqlDepsdevScorecard) id() (string, error) {
	return "depsdev.scorecard/" + r.projectID + "/" + r.Date.Data.Format(time.RFC3339), nil
}

func (r *mqlDepsdevScorecard) checks() ([]any, error) {
	// checks are always set at creation time via CreateResource
	return nil, errors.New("checks should be set at creation time")
}

// depsdev.scorecardCheck

func (r *mqlDepsdevScorecardCheck) id() (string, error) {
	return "depsdev.scorecardCheck/" + r.projectID + "/" + r.Name.Data, nil
}
