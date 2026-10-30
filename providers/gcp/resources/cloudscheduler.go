// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"time"

	scheduler "cloud.google.com/go/scheduler/apiv1"
	"cloud.google.com/go/scheduler/apiv1/schedulerpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// initGcpProjectCloudSchedulerService fills in the project the service belongs to when the
// resource is reached by its own type name rather than through the
// gcp.project accessor. Without it the resource is built with an empty
// projectId, and the serviceEnabled gate then asks Service Usage about
// "projects/", which fails the whole query with an InvalidArgument.
func initGcpProjectCloudSchedulerService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	args["projectId"] = llx.StringData(conn.ResourceID())

	return args, nil, nil
}

type mqlGcpProjectCloudSchedulerServiceInternal struct {
	serviceGate
}

type mqlGcpProjectCloudSchedulerServiceJobInternal struct {
	cacheOauthServiceAccountEmail string
	cacheOidcServiceAccountEmail  string
}

func (g *mqlGcpProject) cloudScheduler() (*mqlGcpProjectCloudSchedulerService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.cloudSchedulerService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_cloudscheduler)
	if err != nil {
		return nil, err
	}
	schedulerService := res.(*mqlGcpProjectCloudSchedulerService)
	schedulerService.recordEnabled(serviceEnabled)
	return schedulerService, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectCloudSchedulerService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_cloudscheduler)
}

func (g *mqlGcpProjectCloudSchedulerService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudSchedulerService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectCloudSchedulerService) jobs() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	// A project that never turned Cloud Scheduler on answers ListJobs with
	// PermissionDenied "API has not been used in project ... or it is disabled",
	// which failed the field outright. Not having enabled a service is the
	// ordinary state of most projects, and the answer it deserves is "no jobs",
	// not an error, so the gate every other service resource uses applies here
	// too.
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		log.Debug().Str("service", service_cloudscheduler).Msg("gcp service is not enabled, skipping")
		return []any{}, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(scheduler.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := scheduler.NewCloudSchedulerClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListJobs(ctx, &schedulerpb.ListJobsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		job, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		retryConfig, err := schedulerRetryConfig(g.MqlRuntime, job.Name, job.RetryConfig)
		if err != nil {
			return nil, err
		}

		targetType := ""
		oidcServiceAccountEmail := ""
		oauthServiceAccountEmail := ""
		switch t := job.Target.(type) {
		case *schedulerpb.Job_HttpTarget:
			targetType = "httpTarget"
			if oidc := t.HttpTarget.GetOidcToken(); oidc != nil {
				oidcServiceAccountEmail = oidc.GetServiceAccountEmail()
			}
			if oauth := t.HttpTarget.GetOauthToken(); oauth != nil {
				oauthServiceAccountEmail = oauth.GetServiceAccountEmail()
			}
		case *schedulerpb.Job_PubsubTarget:
			targetType = "pubsubTarget"
		case *schedulerpb.Job_AppEngineHttpTarget:
			targetType = "appEngineHttpTarget"
		}

		var lastAttemptTime, scheduleTime, userUpdateTime *time.Time
		if job.LastAttemptTime != nil {
			t := job.LastAttemptTime.AsTime()
			lastAttemptTime = &t
		}
		if job.ScheduleTime != nil {
			t := job.ScheduleTime.AsTime()
			scheduleTime = &t
		}
		if job.UserUpdateTime != nil {
			t := job.UserUpdateTime.AsTime()
			userUpdateTime = &t
		}

		jobArgs := map[string]*llx.RawData{
			"projectId":       llx.StringData(projectId),
			"name":            llx.StringData(job.Name),
			"schedule":        llx.StringData(job.Schedule),
			"timeZone":        llx.StringData(job.TimeZone),
			"state":           llx.StringData(job.State.String()),
			"description":     llx.StringData(job.Description),
			"lastAttemptTime": llx.TimeDataPtr(lastAttemptTime),
			"scheduleTime":    llx.TimeDataPtr(scheduleTime),
			"userUpdateTime":  llx.TimeDataPtr(userUpdateTime),
			"targetType":      llx.StringData(targetType),
		}
		if retryConfig != nil {
			jobArgs["retryConfig"] = llx.ResourceData(retryConfig, "gcp.retryConfig")
		}
		mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.cloudSchedulerService.job", jobArgs)
		if err != nil {
			return nil, err
		}
		mqlJ := mqlJob.(*mqlGcpProjectCloudSchedulerServiceJob)
		mqlJ.cacheOidcServiceAccountEmail = oidcServiceAccountEmail
		mqlJ.cacheOauthServiceAccountEmail = oauthServiceAccountEmail
		if retryConfig == nil {
			mqlJ.RetryConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}
		res = append(res, mqlJob)
	}

	return res, nil
}

func (g *mqlGcpProjectCloudSchedulerServiceJob) oidcServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheOidcServiceAccountEmail, g.ProjectId.Data)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.OidcServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectCloudSchedulerServiceJob) oauthServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheOauthServiceAccountEmail, g.ProjectId.Data)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.OauthServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectCloudSchedulerServiceJob) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudSchedulerService.job/%s", g.ProjectId.Data, g.Name.Data), nil
}

func schedulerRetryConfig(runtime *plugin.Runtime, parentName string, rc *schedulerpb.RetryConfig) (*mqlGcpRetryConfig, error) {
	if rc == nil {
		return nil, nil
	}
	var minBackoff, maxBackoff, maxRetryDuration string
	if rc.MinBackoffDuration != nil {
		minBackoff = rc.MinBackoffDuration.AsDuration().String()
	}
	if rc.MaxBackoffDuration != nil {
		maxBackoff = rc.MaxBackoffDuration.AsDuration().String()
	}
	if rc.MaxRetryDuration != nil {
		maxRetryDuration = rc.MaxRetryDuration.AsDuration().String()
	}
	return newRetryConfigResource(runtime, parentName,
		int64(rc.RetryCount), minBackoff, maxBackoff, int64(rc.MaxDoublings), maxRetryDuration)
}
