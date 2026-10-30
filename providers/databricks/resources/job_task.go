// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/databricks/databricks-sdk-go/service/compute"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mqlDatabricksJobTaskInternal keeps the references a task declares so each one
// resolves to a full resource without re-reading the job. The compute a task
// creates for its own runs is kept as the source specification, because it has
// no identity of its own and is only ever mapped through the owning task.
type mqlDatabricksJobTaskInternal struct {
	jobId                  string
	cacheExistingClusterId string
	cachePipelineId        string
	newClusterSpec         *compute.ClusterSpec
}

// existingCluster resolves the long-lived cluster the task runs on. Tasks that
// create compute for each run declare no existing cluster.
func (r *mqlDatabricksJobTask) existingCluster() (*mqlDatabricksCluster, error) {
	if r.cacheExistingClusterId == "" {
		r.ExistingCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "databricks.cluster", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheExistingClusterId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksCluster), nil
}

// newCluster maps the compute the task creates for each run. A task that runs on
// a job cluster or an existing cluster declares none.
func (r *mqlDatabricksJobTask) newCluster() (*mqlDatabricksClusterSpec, error) {
	if r.newClusterSpec == nil {
		r.NewCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDatabricksClusterSpec(r.MqlRuntime,
		"databricks.job/"+r.jobId+"/task/"+r.TaskKey.Data,
		jobClusterSpecFields("", *r.newClusterSpec))
}

// pipeline resolves the pipeline a pipeline task triggers. Tasks of every other
// kind declare none.
func (r *mqlDatabricksJobTask) pipeline() (*mqlDatabricksPipeline, error) {
	if r.cachePipelineId == "" {
		r.Pipeline.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "databricks.pipeline", map[string]*llx.RawData{
		"id": llx.StringData(r.cachePipelineId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksPipeline), nil
}
