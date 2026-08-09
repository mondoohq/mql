// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// mqlJenkinsJobInternal caches the raw node name the job's last build ran on
// (and whether the job has built at all) so the node accessor can resolve a
// typed jenkins.node reference without an extra API call.
type mqlJenkinsJobInternal struct {
	cacheHasLastBuild bool
	cacheBuiltOn      string
}

// jenkinsJobData is the shape fetched from the Jenkins root job tree, scoped
// with a tree query to a single deep fetch (Jenkins list endpoints return
// their full result in one response; there is no pagination to follow).
type jenkinsJobData struct {
	Name        string `json:"name"`
	FullName    string `json:"fullName"`
	URL         string `json:"url"`
	Class       string `json:"_class"`
	Buildable   bool   `json:"buildable"`
	Disabled    bool   `json:"disabled"`
	Description string `json:"description"`
	LastBuild   struct {
		Number  int64  `json:"number"`
		BuiltOn string `json:"builtOn"`
	} `json:"lastBuild"`
	LastSuccessfulBuild struct {
		Number int64 `json:"number"`
	} `json:"lastSuccessfulBuild"`
	LastFailedBuild struct {
		Number int64 `json:"number"`
	} `json:"lastFailedBuild"`
}

// jobs lists every configured job, pipeline, and folder in a single deep
// fetch against the root job tree.
func (r *mqlJenkins) jobs() ([]any, error) {
	conn := r.conn()

	var resp struct {
		Jobs []jenkinsJobData `json:"jobs"`
	}
	_, err := conn.Client().Requester.GetJSON(context.Background(), "/", &resp, map[string]string{
		"tree": "jobs[name,fullName,url,_class,buildable,disabled,description," +
			"lastBuild[number,builtOn],lastSuccessfulBuild[number],lastFailedBuild[number]]",
	})
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(resp.Jobs))
	for _, j := range resp.Jobs {
		res, err := newMqlJenkinsJob(r.MqlRuntime, j)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// newMqlJenkinsJob maps a single job's fetched data to its MQL resource.
func newMqlJenkinsJob(runtime *plugin.Runtime, j jenkinsJobData) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "jenkins.job", map[string]*llx.RawData{
		"__id":                      llx.StringData(j.URL),
		"name":                      llx.StringData(j.Name),
		"fullName":                  llx.StringData(j.FullName),
		"url":                       llx.StringData(j.URL),
		"class":                     llx.StringData(j.Class),
		"buildable":                 llx.BoolData(j.Buildable),
		"disabled":                  llx.BoolData(j.Disabled),
		"lastBuildNumber":           llx.IntData(j.LastBuild.Number),
		"lastSuccessfulBuildNumber": llx.IntData(j.LastSuccessfulBuild.Number),
		"lastFailedBuildNumber":     llx.IntData(j.LastFailedBuild.Number),
		"description":               llx.StringData(j.Description),
	})
	if err != nil {
		return nil, err
	}

	mqlJob := res.(*mqlJenkinsJob)
	mqlJob.cacheHasLastBuild = j.LastBuild.Number != 0
	mqlJob.cacheBuiltOn = j.LastBuild.BuiltOn
	return res, nil
}

// node resolves the agent (or the built-in controller node) the job's last
// build ran on into a typed jenkins.node reference.
func (j *mqlJenkinsJob) node() (*mqlJenkinsNode, error) {
	if !j.cacheHasLastBuild {
		j.Node.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	name := builtInNodeDisplayName
	if j.cacheBuiltOn != "" {
		name = j.cacheBuiltOn
	}

	r, err := NewResource(j.MqlRuntime, "jenkins.node", map[string]*llx.RawData{"name": llx.StringData(name)})
	if err != nil {
		// A node that has since been removed from the controller should not
		// fail the whole job query.
		j.Node.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return r.(*mqlJenkinsNode), nil
}
