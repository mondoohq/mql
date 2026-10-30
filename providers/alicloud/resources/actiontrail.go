// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	actiontrailclient "github.com/alibabacloud-go/actiontrail-20200706/v3/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

func (r *mqlAlicloudActiontrail) id() (string, error) {
	return "alicloud.actiontrail", nil
}

// parseSlsProjectArn extracts the region and project name from a Log Service
// project ARN of the form acs:log:<region>:<account>:project/<name>. Returns
// empty strings when the ARN is not in that shape.
func parseSlsProjectArn(arn string) (region, project string) {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 || parts[1] != "log" {
		return "", ""
	}
	region = parts[2]
	resource := parts[4]
	project = strings.TrimPrefix(resource, "project/")
	if project == resource {
		return region, ""
	}
	return region, project
}

func (r *mqlAlicloudActiontrail) trails() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ActionTrailClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.DescribeTrails(&actiontrailclient.DescribeTrailsRequest{
		IncludeOrganizationTrail: new(true),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, t := range resp.Body.TrailList {
		if t == nil || t.Name == nil {
			continue
		}
		resource, err := CreateResource(r.MqlRuntime, "alicloud.actiontrail.trail", map[string]*llx.RawData{
			"__id":                llx.StringDataPtr(t.Name),
			"name":                llx.StringDataPtr(t.Name),
			"status":              llx.StringDataPtr(t.Status),
			"eventRW":             llx.StringDataPtr(t.EventRW),
			"homeRegion":          llx.StringDataPtr(t.HomeRegion),
			"trailRegion":         llx.StringDataPtr(t.TrailRegion),
			"trailArn":            llx.StringDataPtr(t.TrailArn),
			"isOrganizationTrail": llx.BoolDataPtr(t.IsOrganizationTrail),
			"organizationId":      llx.StringDataPtr(t.OrganizationId),
			"ossBucketName":       llx.StringDataPtr(t.OssBucketName),
			"ossBucketLocation":   llx.StringDataPtr(t.OssBucketLocation),
			"ossKeyPrefix":        llx.StringDataPtr(t.OssKeyPrefix),
			"ossWriteRoleArn":     llx.StringDataPtr(t.OssWriteRoleArn),
			"slsProjectArn":       llx.StringDataPtr(t.SlsProjectArn),
			"slsWriteRoleArn":     llx.StringDataPtr(t.SlsWriteRoleArn),
			"createTime":          llx.TimeDataPtr(alicloudParseTime(t.CreateTime)),
			"updateTime":          llx.TimeDataPtr(alicloudParseTime(t.UpdateTime)),
			"startLoggingTime":    llx.TimeDataPtr(alicloudParseTime(t.StartLoggingTime)),
			"stopLoggingTime":     llx.TimeDataPtr(alicloudParseTime(t.StopLoggingTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlTrail := resource.(*mqlAlicloudActiontrailTrail)
		mqlTrail.cacheOssBucketName = tea.StringValue(t.OssBucketName)
		mqlTrail.cacheSlsProjectArn = tea.StringValue(t.SlsProjectArn)
		res = append(res, resource)
	}
	return res, nil
}

// mqlAlicloudActiontrailTrailInternal caches the delivery-target identifiers for
// the typed ossBucket()/slsProject() references and memoizes the trail status.
type mqlAlicloudActiontrailTrailInternal struct {
	cacheOssBucketName string
	cacheSlsProjectArn string

	statusLock    sync.Mutex
	statusFetched atomic.Bool
	status        *actiontrailclient.GetTrailStatusResponseBody
}

func (r *mqlAlicloudActiontrailTrail) id() (string, error) {
	return r.Name.Data, nil
}

func (r *mqlAlicloudActiontrailTrail) ossBucket() (*mqlAlicloudOssBucket, error) {
	if r.cacheOssBucketName == "" {
		r.OssBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	bucket, err := resolveOssBucket(r.MqlRuntime, r.cacheOssBucketName)
	if err != nil || bucket == nil {
		r.OssBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return bucket, nil
}

func (r *mqlAlicloudActiontrailTrail) slsProject() (*mqlAlicloudLogProject, error) {
	region, project := parseSlsProjectArn(r.cacheSlsProjectArn)
	if project == "" {
		r.SlsProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	p, err := resolveLogProject(r.MqlRuntime, region, project)
	if err != nil || p == nil {
		r.SlsProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return p, nil
}

// trailStatus lazily fetches and caches the GetTrailStatus response, shared by
// the live logging and delivery accessors. A transient error is not cached
// (statusFetched is set only on success) and is returned so dependent fields
// surface the failure rather than a fabricated "not logging" value.
func (r *mqlAlicloudActiontrailTrail) trailStatus() (*actiontrailclient.GetTrailStatusResponseBody, error) {
	if r.statusFetched.Load() {
		return r.status, nil
	}
	r.statusLock.Lock()
	defer r.statusLock.Unlock()
	if r.statusFetched.Load() {
		return r.status, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ActionTrailClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.GetTrailStatus(&actiontrailclient.GetTrailStatusRequest{
		Name:                new(r.Name.Data),
		IsOrganizationTrail: new(r.IsOrganizationTrail.Data),
	})
	if err != nil {
		// Surface the failure so operators can tell a genuinely non-logging
		// trail apart from an API/permission error that left status unknown.
		log.Warn().Err(err).Str("trail", r.Name.Data).Msg("alicloud: failed to fetch ActionTrail status")
		return nil, err
	}
	if resp != nil {
		r.status = resp.Body
	}
	r.statusFetched.Store(true)
	return r.status, nil
}

func (r *mqlAlicloudActiontrailTrail) isLogging() (bool, error) {
	st, err := r.trailStatus()
	if err != nil || st == nil {
		return false, err
	}
	return tea.BoolValue(st.IsLogging), nil
}

func (r *mqlAlicloudActiontrailTrail) latestDeliveryTime() (*time.Time, error) {
	st, err := r.trailStatus()
	if err != nil || st == nil {
		return nil, err
	}
	return alicloudParseTime(st.LatestDeliveryTime), nil
}

func (r *mqlAlicloudActiontrailTrail) latestDeliveryError() (string, error) {
	st, err := r.trailStatus()
	if err != nil || st == nil {
		return "", err
	}
	return tea.StringValue(st.LatestDeliveryError), nil
}

func (r *mqlAlicloudActiontrailTrail) latestDeliveryLogServiceTime() (*time.Time, error) {
	st, err := r.trailStatus()
	if err != nil || st == nil {
		return nil, err
	}
	return alicloudParseTime(st.LatestDeliveryLogServiceTime), nil
}

func (r *mqlAlicloudActiontrailTrail) latestDeliveryLogServiceError() (string, error) {
	st, err := r.trailStatus()
	if err != nil || st == nil {
		return "", err
	}
	return tea.StringValue(st.LatestDeliveryLogServiceError), nil
}
