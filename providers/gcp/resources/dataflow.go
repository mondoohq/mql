// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
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
	// Use aggregated list to get jobs across all locations
	call := svc.Projects.Jobs.Aggregated(projectId)
	if err := call.Pages(ctx, func(page *dataflow.ListJobsResponse) error {
		for _, job := range page.Jobs {
			env, _ := convert.JsonToDict(job.Environment)
			pipelineDesc, _ := convert.JsonToDict(job.PipelineDescription)

			workerIpConfiguration := ""
			if job.Environment != nil {
				for _, wp := range job.Environment.WorkerPools {
					if wp != nil && wp.IpConfiguration != "" {
						workerIpConfiguration = wp.IpConfiguration
						break
					}
				}
			}

			mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.dataflowService.job", map[string]*llx.RawData{
				"projectId":             llx.StringData(projectId),
				"id":                    llx.StringData(job.Id),
				"name":                  llx.StringData(job.Name),
				"type":                  llx.StringData(job.Type),
				"currentState":          llx.StringData(job.CurrentState),
				"createTime":            llx.TimeDataPtr(parseTime(job.CreateTime)),
				"location":              llx.StringData(job.Location),
				"labels":                llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
				"environment":           llx.DictData(env),
				"workerIpConfiguration": llx.StringData(workerIpConfiguration),
				"pipelineDescription":   llx.DictData(pipelineDesc),
				"currentStateTime":      llx.TimeDataPtr(parseTime(job.CurrentStateTime)),
			})
			if err != nil {
				return err
			}
			if job.Environment != nil {
				mqlJob.(*mqlGcpProjectDataflowServiceJob).cacheKmsKeyName = job.Environment.ServiceKmsKeyName
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
	cacheKmsKeyName string
}

func (g *mqlGcpProjectDataflowServiceJob) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, g.cacheKmsKeyName)
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
