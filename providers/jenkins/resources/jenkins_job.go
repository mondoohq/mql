// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jenkins/connection"
)

// jobRecursionDepth bounds how deeply the job tree is walked into nested
// folders. Folder nesting this deep is exceptional; the bound keeps the single
// tree query finite while covering realistic Jenkins layouts.
const jobRecursionDepth = 10

// jobTreeFields is the set of per-job fields requested for every level of the
// job tree.
const jobTreeFields = "name,fullName,url,_class,buildable,disabled,description," +
	"lastBuild[number,builtOn],lastSuccessfulBuild[number],lastFailedBuild[number]"

// jobsTreeQuery builds a nested `jobs[...]` tree query that descends depth
// levels of folders, so jobs inside com.cloudbees.hudson.plugins.folder.Folder
// containers are returned by the same single fetch as top-level jobs.
func jobsTreeQuery(depth int) string {
	inner := jobTreeFields
	for i := 0; i < depth; i++ {
		inner = jobTreeFields + ",jobs[" + inner + "]"
	}
	return "jobs[" + inner + "]"
}

// mqlJenkinsJobInternal caches the raw node name the job's last build ran on
// (and whether the job has built at all) so the node accessor can resolve a
// typed jenkins.node reference without an extra API call.
type mqlJenkinsJobInternal struct {
	cacheHasLastBuild bool
	cacheBuiltOn      *string
}

// jenkinsJobData is the shape fetched from the Jenkins job tree, scoped with a
// tree query to a single deep fetch (Jenkins list endpoints return their full
// result in one response; there is no pagination to follow). The nested Jobs
// slice holds the children of folder-type jobs, populated by the recursive
// tree query.
type jenkinsJobData struct {
	Name        string `json:"name"`
	FullName    string `json:"fullName"`
	URL         string `json:"url"`
	Class       string `json:"_class"`
	Buildable   *bool  `json:"buildable"`
	Disabled    *bool  `json:"disabled"`
	Description string `json:"description"`
	LastBuild   struct {
		Number int64 `json:"number"`
		// BuiltOn is a pointer because the two cases are otherwise
		// indistinguishable: a freestyle build that ran on the controller
		// reports it as the empty string, while a pipeline build does not
		// export the field at all.
		BuiltOn *string `json:"builtOn"`
	} `json:"lastBuild"`
	LastSuccessfulBuild struct {
		Number int64 `json:"number"`
	} `json:"lastSuccessfulBuild"`
	LastFailedBuild struct {
		Number int64 `json:"number"`
	} `json:"lastFailedBuild"`
	Jobs []jenkinsJobData `json:"jobs"`
}

// fetchJobTree fetches the whole job tree, descending folders in a single
// nested tree query. The result is memoized on the connection so that querying
// both jenkins.jobs and jenkins.credentials (which enumerates folders) does not
// fetch the tree twice.
func fetchJobTree(conn *connection.JenkinsConnection) ([]jenkinsJobData, error) {
	v, err := conn.CachedJobTree(func() (any, error) {
		var resp struct {
			Jobs []jenkinsJobData `json:"jobs"`
		}
		_, err := conn.Client().Requester.GetJSON(context.Background(), "/", &resp, map[string]string{
			"tree": jobsTreeQuery(jobRecursionDepth),
		})
		if err != nil {
			return nil, err
		}
		return resp.Jobs, nil
	})
	if err != nil {
		return nil, err
	}
	jobs, ok := v.([]jenkinsJobData)
	if !ok {
		return nil, fmt.Errorf("unexpected cached job tree type %T", v)
	}
	return jobs, nil
}

// isFolderClass reports whether a job class is a folder container that can hold
// nested jobs and its own credential store.
func isFolderClass(class string) bool {
	return strings.Contains(class, "hudson.plugins.folder.Folder") ||
		strings.Contains(class, "OrganizationFolder")
}

// fetchFolders returns every folder job in the tree, flattened, for callers
// that enumerate folder-scoped resources (e.g. folder credential stores).
func fetchFolders(conn *connection.JenkinsConnection) ([]jenkinsJobData, error) {
	jobs, err := fetchJobTree(conn)
	if err != nil {
		return nil, err
	}
	var folders []jenkinsJobData
	var walk func([]jenkinsJobData)
	walk = func(js []jenkinsJobData) {
		for _, j := range js {
			if isFolderClass(j.Class) {
				folders = append(folders, j)
			}
			if len(j.Jobs) > 0 {
				walk(j.Jobs)
			}
		}
	}
	walk(jobs)
	return folders, nil
}

// jobs lists every configured job, pipeline, and folder, including those nested
// inside folders, in a single deep fetch against the root job tree. Jobs inside
// folders carry a path-qualified fullName (e.g. "team-a/deploy-service").
func (r *mqlJenkins) jobs() ([]any, error) {
	conn := r.conn()

	jobs, err := fetchJobTree(conn)
	if err != nil {
		return nil, err
	}

	all := []any{}
	if err := r.appendJobs(jobs, &all); err != nil {
		return nil, err
	}
	return all, nil
}

// appendJobs maps each job to its MQL resource and recurses into folder
// children so the returned list is a flat view of the whole job tree.
func (r *mqlJenkins) appendJobs(jobs []jenkinsJobData, all *[]any) error {
	for _, j := range jobs {
		res, err := newMqlJenkinsJob(r.MqlRuntime, j)
		if err != nil {
			return err
		}
		*all = append(*all, res)
		if len(j.Jobs) > 0 {
			if err := r.appendJobs(j.Jobs, all); err != nil {
				return err
			}
		}
	}
	return nil
}

// newMqlJenkinsJob maps a single job's fetched data to its MQL resource.
func newMqlJenkinsJob(runtime *plugin.Runtime, j jenkinsJobData) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "jenkins.job", map[string]*llx.RawData{
		"__id":                      llx.StringData(j.URL),
		"name":                      llx.StringData(j.Name),
		"fullName":                  llx.StringData(j.FullName),
		"url":                       llx.StringData(j.URL),
		"class":                     llx.StringData(j.Class),
		"buildable":                 llx.BoolDataPtr(j.Buildable),
		"disabled":                  llx.BoolDataPtr(j.Disabled),
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

	// A pipeline build does not export builtOn at all, so the node it ran on
	// is genuinely unknown rather than the controller.
	if j.cacheBuiltOn == nil {
		j.Node.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	// Present but empty means the build really did run on the controller.
	name := builtInNodeDisplayName
	if *j.cacheBuiltOn != "" {
		name = *j.cacheBuiltOn
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
