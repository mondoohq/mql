// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2"
	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) cloudTasks() (*mqlGcpProjectCloudTasksService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.cloudTasksService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudTasksService), nil
}

func (g *mqlGcpProjectCloudTasksService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudTasksService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectCloudTasksService) queues() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(cloudtasks.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := cloudtasks.NewClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListQueues(ctx, &cloudtaskspb.ListQueuesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		queue, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		rateLimits, err := cloudTasksConvertRateLimits(queue.RateLimits)
		if err != nil {
			return nil, err
		}
		retryConfig, err := cloudTasksRetryConfig(g.MqlRuntime, queue.Name, queue.RetryConfig)
		if err != nil {
			return nil, err
		}
		appEngineRouting, err := cloudTasksConvertAppEngineRouting(queue.AppEngineRoutingOverride)
		if err != nil {
			return nil, err
		}

		mqlQueue, err := CreateResource(g.MqlRuntime, "gcp.project.cloudTasksService.queue", map[string]*llx.RawData{
			"projectId":                llx.StringData(projectId),
			"name":                     llx.StringData(queue.Name),
			"state":                    llx.StringData(queue.State.String()),
			"rateLimits":               llx.DictData(rateLimits),
			"retryConfig":              llx.ResourceData(retryConfig, "gcp.retryConfig"),
			"appEngineRoutingOverride": llx.DictData(appEngineRouting),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlQueue)
	}

	return res, nil
}

func (g *mqlGcpProjectCloudTasksServiceQueue) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudTasksService.queue/%s", g.ProjectId.Data, g.Name.Data), nil
}

func cloudTasksConvertRateLimits(rl *cloudtaskspb.RateLimits) (map[string]any, error) {
	if rl == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		MaxDispatchesPerSecond  float64 `json:"maxDispatchesPerSecond"`
		MaxBurstSize            int32   `json:"maxBurstSize"`
		MaxConcurrentDispatches int32   `json:"maxConcurrentDispatches"`
	}{
		MaxDispatchesPerSecond:  rl.MaxDispatchesPerSecond,
		MaxBurstSize:            rl.MaxBurstSize,
		MaxConcurrentDispatches: rl.MaxConcurrentDispatches,
	})
}

func cloudTasksRetryConfig(runtime *plugin.Runtime, parentName string, rc *cloudtaskspb.RetryConfig) (*mqlGcpRetryConfig, error) {
	if rc == nil {
		return nil, nil
	}
	var minBackoff, maxBackoff, maxRetryDuration string
	if rc.MinBackoff != nil {
		minBackoff = rc.MinBackoff.AsDuration().String()
	}
	if rc.MaxBackoff != nil {
		maxBackoff = rc.MaxBackoff.AsDuration().String()
	}
	if rc.MaxRetryDuration != nil {
		maxRetryDuration = rc.MaxRetryDuration.AsDuration().String()
	}
	return newRetryConfigResource(runtime, parentName,
		int64(rc.MaxAttempts), minBackoff, maxBackoff, int64(rc.MaxDoublings), maxRetryDuration)
}

func cloudTasksConvertAppEngineRouting(r *cloudtaskspb.AppEngineRouting) (map[string]any, error) {
	if r == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		Service  string `json:"service"`
		Version  string `json:"version"`
		Instance string `json:"instance"`
		Host     string `json:"host"`
	}{
		Service:  r.Service,
		Version:  r.Version,
		Instance: r.Instance,
		Host:     r.Host,
	})
}
