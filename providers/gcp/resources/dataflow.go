// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	dataflow "google.golang.org/api/dataflow/v1b3"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) dataflow() (*mqlGcpProjectDataflowService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.dataflowService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDataflowService), nil
}

func (g *mqlGcpProjectDataflowService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/dataflowService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectDataflowService) jobs() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(dataflow.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	svc, err := dataflow.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	// The aggregated list returns only the summary view: no environment,
	// labels or pipeline description, whatever view is requested. Those are
	// fetched per job, on first use, by jobDescription.
	call := svc.Projects.Jobs.Aggregated(projectId)
	if err := call.Pages(ctx, func(page *dataflow.ListJobsResponse) error {
		for _, job := range page.Jobs {
			mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.dataflowService.job", map[string]*llx.RawData{
				"projectId":        llx.StringData(projectId),
				"id":               llx.StringData(job.Id),
				"name":             llx.StringData(job.Name),
				"type":             llx.StringData(job.Type),
				"currentState":     llx.StringData(job.CurrentState),
				"createTime":       llx.TimeDataPtr(parseTime(job.CreateTime)),
				"location":         llx.StringData(job.Location),
				"currentStateTime": llx.TimeDataPtr(parseTime(job.CurrentStateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlJob)
		}
		return nil
	}); err != nil {
		// Dataflow is not enabled on most projects, and an unused API answers
		// 403 "has not been used ... or it is disabled" rather than with an
		// empty list. Left to propagate, that error renders as the value of the
		// enclosing collection, so selecting jobs inside a gcp.project block
		// costs every other field in it.
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list dataflow jobs")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

type mqlGcpProjectDataflowServiceJobInternal struct {
	descLock    sync.Mutex
	descFetched bool
	desc        *dataflow.Job
	descErr     error
}

// jobDescription fetches the job with JOB_VIEW_DESCRIPTION, which carries the
// environment, labels and pipeline description the aggregated list omits. It
// returns nil when the job is no longer retained (NotFound) or not readable.
func (g *mqlGcpProjectDataflowServiceJob) jobDescription() (*dataflow.Job, error) {
	g.descLock.Lock()
	defer g.descLock.Unlock()
	if g.descFetched {
		return g.desc, g.descErr
	}
	g.descFetched = true

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(dataflow.CloudPlatformScope)
	if err != nil {
		g.descErr = err
		return nil, err
	}
	ctx := context.Background()
	svc, err := dataflow.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		g.descErr = err
		return nil, err
	}

	job, err := svc.Projects.Locations.Jobs.Get(g.ProjectId.Data, g.Location.Data, g.Id.Data).View("JOB_VIEW_DESCRIPTION").Context(ctx).Do()
	if err != nil {
		if isSkippable(err) {
			log.Debug().Err(err).Str("job", g.Id.Data).Msg("could not describe dataflow job")
			return nil, nil
		}
		g.descErr = err
		return nil, err
	}
	g.desc = job
	return job, nil
}

func (g *mqlGcpProjectDataflowServiceJob) labels() (map[string]any, error) {
	job, err := g.jobDescription()
	if err != nil {
		return nil, err
	}
	if job == nil {
		g.Labels.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return convert.MapToInterfaceMap(job.Labels), nil
}

func (g *mqlGcpProjectDataflowServiceJob) environment() (map[string]any, error) {
	job, err := g.jobDescription()
	if err != nil {
		return nil, err
	}
	if job == nil || job.Environment == nil {
		g.Environment.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return convert.JsonToDict(dataflowEnvironmentSummary(job.Environment))
}

func (g *mqlGcpProjectDataflowServiceJob) pipelineDescription() (map[string]any, error) {
	job, err := g.jobDescription()
	if err != nil {
		return nil, err
	}
	if job == nil || job.PipelineDescription == nil {
		g.PipelineDescription.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return convert.JsonToDict(dataflowPipelineSummary(job.PipelineDescription))
}

// The job description carries the arguments the pipeline was launched with:
// environment.sdkPipelineOptions, environment.userAgent,
// environment.internalExperiments, worker pool metadata and pool arguments,
// and displayData on the pipeline and on each transform. Those routinely hold
// connection strings, passwords and tokens, so the dicts below are built from
// an allowlist of the settings that describe how the job runs, and none of
// those fields is read.

type dataflowEnvironmentAllowlist struct {
	ServiceAccountEmail        string                        `json:"serviceAccountEmail,omitempty"`
	ServiceKmsKeyName          string                        `json:"serviceKmsKeyName,omitempty"`
	WorkerRegion               string                        `json:"workerRegion,omitempty"`
	WorkerZone                 string                        `json:"workerZone,omitempty"`
	TempStoragePrefix          string                        `json:"tempStoragePrefix,omitempty"`
	ShuffleMode                string                        `json:"shuffleMode,omitempty"`
	StreamingMode              string                        `json:"streamingMode,omitempty"`
	FlexResourceSchedulingGoal string                        `json:"flexResourceSchedulingGoal,omitempty"`
	WorkerPools                []dataflowWorkerPoolAllowlist `json:"workerPools,omitempty"`
}

type dataflowWorkerPoolAllowlist struct {
	Kind            string `json:"kind,omitempty"`
	MachineType     string `json:"machineType,omitempty"`
	NumWorkers      int64  `json:"numWorkers,omitempty"`
	IpConfiguration string `json:"ipConfiguration,omitempty"`
	Network         string `json:"network,omitempty"`
	Subnetwork      string `json:"subnetwork,omitempty"`
	Zone            string `json:"zone,omitempty"`
	DiskSizeGb      int64  `json:"diskSizeGb,omitempty"`
	DiskType        string `json:"diskType,omitempty"`
}

func dataflowEnvironmentSummary(env *dataflow.Environment) dataflowEnvironmentAllowlist {
	out := dataflowEnvironmentAllowlist{
		ServiceAccountEmail:        env.ServiceAccountEmail,
		ServiceKmsKeyName:          env.ServiceKmsKeyName,
		WorkerRegion:               env.WorkerRegion,
		WorkerZone:                 env.WorkerZone,
		TempStoragePrefix:          env.TempStoragePrefix,
		ShuffleMode:                env.ShuffleMode,
		StreamingMode:              env.StreamingMode,
		FlexResourceSchedulingGoal: env.FlexResourceSchedulingGoal,
	}
	for _, wp := range env.WorkerPools {
		if wp == nil {
			continue
		}
		out.WorkerPools = append(out.WorkerPools, dataflowWorkerPoolAllowlist{
			Kind:            wp.Kind,
			MachineType:     wp.MachineType,
			NumWorkers:      wp.NumWorkers,
			IpConfiguration: wp.IpConfiguration,
			Network:         wp.Network,
			Subnetwork:      wp.Subnetwork,
			Zone:            wp.Zone,
			DiskSizeGb:      wp.DiskSizeGb,
			DiskType:        wp.DiskType,
		})
	}
	return out
}

type dataflowPipelineAllowlist struct {
	StepNamesHash             string                  `json:"stepNamesHash,omitempty"`
	OriginalPipelineTransform []dataflowStepAllowlist `json:"originalPipelineTransform,omitempty"`
	ExecutionPipelineStage    []dataflowStepAllowlist `json:"executionPipelineStage,omitempty"`
}

type dataflowStepAllowlist struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

func dataflowPipelineSummary(pd *dataflow.PipelineDescription) dataflowPipelineAllowlist {
	out := dataflowPipelineAllowlist{StepNamesHash: pd.StepNamesHash}
	for _, t := range pd.OriginalPipelineTransform {
		if t != nil {
			out.OriginalPipelineTransform = append(out.OriginalPipelineTransform, dataflowStepAllowlist{Id: t.Id, Name: t.Name, Kind: t.Kind})
		}
	}
	for _, st := range pd.ExecutionPipelineStage {
		if st != nil {
			out.ExecutionPipelineStage = append(out.ExecutionPipelineStage, dataflowStepAllowlist{Id: st.Id, Name: st.Name, Kind: st.Kind})
		}
	}
	return out
}

func (g *mqlGcpProjectDataflowServiceJob) workerIpConfiguration() (string, error) {
	job, err := g.jobDescription()
	if err != nil {
		return "", err
	}
	if job == nil {
		g.WorkerIpConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return dataflowWorkerIpConfiguration(job.Environment), nil
}

// dataflowWorkerIpConfiguration returns the first IP configuration set on a
// worker pool, or "" when none is: the API omits it for the default, public
// worker IPs.
func dataflowWorkerIpConfiguration(env *dataflow.Environment) string {
	if env == nil {
		return ""
	}
	for _, wp := range env.WorkerPools {
		if wp != nil && wp.IpConfiguration != "" {
			return wp.IpConfiguration
		}
	}
	return ""
}

func (g *mqlGcpProjectDataflowServiceJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	job, err := g.jobDescription()
	if err != nil {
		return nil, err
	}
	keyName := ""
	if job != nil && job.Environment != nil {
		keyName = job.Environment.ServiceKmsKeyName
	}
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, keyName)
}

func (g *mqlGcpProjectDataflowServiceJob) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return fmt.Sprintf("gcp.project/%s/dataflowService.job/%s", g.ProjectId.Data, g.Id.Data), nil
}
