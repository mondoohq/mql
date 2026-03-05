// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"time"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/depsdev/connection"
)

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
	conn := r.MqlRuntime.Connection.(*connection.DepsDevConnection)

	// Set defaults
	r.OpenIssuesCount = plugin.TValue[int64]{Data: 0, State: plugin.StateIsSet | plugin.StateIsNull}
	r.StarsCount = plugin.TValue[int64]{Data: 0, State: plugin.StateIsSet | plugin.StateIsNull}
	r.ForksCount = plugin.TValue[int64]{Data: 0, State: plugin.StateIsSet | plugin.StateIsNull}
	r.License = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
	r.Description = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
	r.Homepage = plugin.TValue[string]{Data: "", State: plugin.StateIsSet | plugin.StateIsNull}
	r.Scorecard = plugin.TValue[*mqlDepsdevScorecard]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}

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
	}

	return nil
}

func (r *mqlDepsdevProject) buildScorecard(sc *depsDevScorecardResponse) (*mqlDepsdevScorecard, error) {
	var checks []any
	for _, c := range sc.Checks {
		docURL := c.Documentation.URL
		if docURL == "" {
			docURL = c.Documentation.ShortDescription
		}

		check, err := CreateResource(r.MqlRuntime, "depsdev.scorecardCheck", map[string]*llx.RawData{
			"name":          llx.StringData(c.Name),
			"score":         llx.IntData(int64(c.Score)),
			"reason":        llx.StringData(c.Reason),
			"documentation": llx.StringData(docURL),
		})
		if err != nil {
			return nil, err
		}
		checks = append(checks, check)
	}

	scorecardDate := sc.Date
	res, err := CreateResource(r.MqlRuntime, "depsdev.scorecard", map[string]*llx.RawData{
		"overallScore": llx.FloatData(sc.OverallScore),
		"date":         llx.TimeData(scorecardDate),
		"checks":       llx.ArrayData(checks, "\x12depsdev.scorecardCheck"),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlDepsdevScorecard), nil
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

// depsdev.scorecard

func (r *mqlDepsdevScorecard) id() (string, error) {
	return "depsdev.scorecard/" + r.Date.Data.Format(time.RFC3339), nil
}

func (r *mqlDepsdevScorecard) checks() ([]any, error) {
	// checks are always set at creation time via CreateResource
	return nil, errors.New("checks should be set at creation time")
}

// depsdev.scorecardCheck

func (r *mqlDepsdevScorecardCheck) id() (string, error) {
	return "depsdev.scorecardCheck/" + r.Name.Data, nil
}
