// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"time"

	slsclient "github.com/alibabacloud-go/sls-20201230/v6/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// slsAlertPageSize is the per-request alert count for the offset-paged
// ListAlerts API.
const slsAlertPageSize int32 = 100

// slsAlertEnabled reports whether an alert rule is evaluated. The API reports
// ENABLED or DISABLED; anything else, including an absent status, reads as off
// so a rule nobody could classify fails an "alerting is configured" check
// rather than passing it.
func slsAlertEnabled(status *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(status)), "enabled")
}

// slsEpochSeconds converts an SLS timestamp, which is seconds since the epoch,
// to a time. Zero and negative values stay null rather than becoming 1 January
// 1970, which would read as a real creation date.
func slsEpochSeconds(v *int64) *time.Time {
	secs := tea.Int64Value(v)
	if secs <= 0 {
		return nil
	}
	t := time.Unix(secs, 0).UTC()
	return &t
}

// slsAlertTags flattens an alert's labels or annotations into a map. Entries
// without a key are dropped rather than collapsing onto a shared empty key,
// where the last one would overwrite the rest.
func slsAlertTags(tags []*slsclient.AlertTag) map[string]any {
	res := map[string]any{}
	for _, tag := range tags {
		if tag == nil || tag.Key == nil || *tag.Key == "" {
			continue
		}
		res[*tag.Key] = tea.StringValue(tag.Value)
	}
	return res
}

// alerts lists the project's alert rules.
//
// ListAlerts returns the whole rule, not just its name, so the queries and the
// schedule come back with the listing and no per-rule GetAlert is needed.
func (r *mqlAlicloudLogProject) alerts() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlsClient(r.region)
	if err != nil {
		return nil, err
	}
	projectName := r.Name.Data

	res := []any{}
	offset := int32(0)
	firstPage := true
	for {
		resp, err := client.ListAlerts(new(projectName), &slsclient.ListAlertsRequest{
			Offset: new(offset),
			Size:   new(slsAlertPageSize),
		})
		if err != nil {
			// Same split as the logstore listing: a first-page failure means
			// this project's rules cannot be read, so skip it rather than
			// failing the whole scan. A later page failing is a real error and
			// must not be reported as a shorter list of rules, which would read
			// as "these are all the alerts" on an account that has more.
			if firstPage {
				log.Debug().Err(err).Str("project", projectName).
					Msg("alicloud> could not list Log Service alert rules")
				break
			}
			return nil, err
		}
		firstPage = false
		if resp == nil || resp.Body == nil {
			break
		}

		items := resp.Body.Results
		for _, alert := range items {
			if alert == nil {
				continue
			}
			name := tea.StringValue(alert.Name)
			if name == "" {
				// the name is half the cache key; an entry without one would
				// collide with every other unnamed rule in the project and
				// report the first one's values
				log.Debug().Str("project", projectName).
					Msg("alicloud> skipping Log Service alert rule with no name")
				continue
			}
			mqlAlert, err := newLogAlert(r.MqlRuntime, r.region, projectName, alert)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAlert)
		}

		total := tea.Int32Value(resp.Body.Total)
		offset += int32(len(items))
		if len(items) == 0 || len(items) < int(slsAlertPageSize) || (total > 0 && offset >= total) {
			break
		}
	}
	return res, nil
}

// mqlAlicloudLogAlertInternal keeps the queries from the listing, so reading
// them costs nothing beyond the call that already returned them.
type mqlAlicloudLogAlertInternal struct {
	cacheQueries []*slsclient.AlertQuery
}

func newLogAlert(runtime *plugin.Runtime, region, projectName string, alert *slsclient.Alert) (*mqlAlicloudLogAlert, error) {
	name := tea.StringValue(alert.Name)

	// Schedule and configuration are both optional on the wire even though the
	// API documents them as required, so every read below goes through a nil
	// guard rather than assuming they arrived.
	var schedule *slsclient.Schedule
	if alert.Schedule != nil {
		schedule = alert.Schedule
	}
	cfg := alert.Configuration

	labels := map[string]any{}
	annotations := map[string]any{}
	threshold := int64(0)
	noDataFire := false
	var muteUntil *time.Time
	var queries []*slsclient.AlertQuery
	if cfg != nil {
		labels = slsAlertTags(cfg.Labels)
		annotations = slsAlertTags(cfg.Annotations)
		threshold = int64(tea.Int32Value(cfg.Threshold))
		noDataFire = tea.BoolValue(cfg.NoDataFire)
		muteUntil = slsEpochSeconds(cfg.MuteUntil)
		queries = cfg.QueryList
	}

	resource, err := CreateResource(runtime, "alicloud.log.alert", map[string]*llx.RawData{
		"__id":                   llx.StringData(logAlertID(region, projectName, name)),
		"regionId":               llx.StringData(region),
		"projectName":            llx.StringData(projectName),
		"name":                   llx.StringData(name),
		"displayName":            llx.StringDataPtr(alert.DisplayName),
		"description":            llx.StringDataPtr(alert.Description),
		"enabled":                llx.BoolData(slsAlertEnabled(alert.Status)),
		"status":                 llx.StringDataPtr(alert.Status),
		"scheduleType":           llx.StringData(scheduleString(schedule, func(s *slsclient.Schedule) *string { return s.Type })),
		"scheduleInterval":       llx.StringData(scheduleString(schedule, func(s *slsclient.Schedule) *string { return s.Interval })),
		"scheduleCronExpression": llx.StringData(scheduleString(schedule, func(s *slsclient.Schedule) *string { return s.CronExpression })),
		"scheduleTimeZone":       llx.StringData(scheduleString(schedule, func(s *slsclient.Schedule) *string { return s.TimeZone })),
		"scheduleRunImmediately": llx.BoolData(schedule != nil && tea.BoolValue(schedule.RunImmediately)),
		"threshold":              llx.IntData(threshold),
		"noDataFire":             llx.BoolData(noDataFire),
		"muteUntil":              llx.TimeDataPtr(muteUntil),
		"labels":                 llx.MapData(labels, types.String),
		"annotations":            llx.MapData(annotations, types.String),
		"createTime":             llx.TimeDataPtr(slsEpochSeconds(alert.CreateTime)),
		"lastModifiedTime":       llx.TimeDataPtr(slsEpochSeconds(alert.LastModifiedTime)),
	})
	if err != nil {
		return nil, err
	}

	mqlAlert := resource.(*mqlAlicloudLogAlert)
	mqlAlert.cacheQueries = queries
	return mqlAlert, nil
}

// scheduleString reads one optional field off a possibly-absent schedule.
func scheduleString(schedule *slsclient.Schedule, get func(*slsclient.Schedule) *string) string {
	if schedule == nil {
		return ""
	}
	return tea.StringValue(get(schedule))
}

// logAlertID builds the alert cache key. A rule name is unique within a
// project, and a project name is unique within a region, so all three are
// needed: two projects may each hold a rule of the same name.
func logAlertID(region, projectName, name string) string {
	return region + "/" + projectName + "/" + name
}

func (r *mqlAlicloudLogAlert) id() (string, error) {
	return logAlertID(r.RegionId.Data, r.ProjectName.Data, r.Name.Data), nil
}

// project resolves the project the rule belongs to.
func (r *mqlAlicloudLogAlert) project() (*mqlAlicloudLogProject, error) {
	project, err := resolveLogProject(r.MqlRuntime, r.RegionId.Data, r.ProjectName.Data)
	if err != nil || project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

// queries builds the rule's queries from the listing response, which already
// carried them.
func (r *mqlAlicloudLogAlert) queries() ([]any, error) {
	alertID := logAlertID(r.RegionId.Data, r.ProjectName.Data, r.Name.Data)

	res := []any{}
	for i, query := range r.cacheQueries {
		if query == nil {
			continue
		}
		// A rule may read the same store twice with different searches, and a
		// query has no id of its own, so the position within the rule is what
		// keeps two entries apart. The key stays internal rather than being
		// exposed as a field.
		resource, err := CreateResource(r.MqlRuntime, "alicloud.log.alert.query", map[string]*llx.RawData{
			"__id":        llx.StringData(alertID + "/" + strconv.Itoa(i)),
			"projectName": llx.StringDataPtr(query.Project),
			"store":       llx.StringDataPtr(query.Store),
			"query":       llx.StringDataPtr(query.Query),
			"start":       llx.StringDataPtr(query.Start),
			"end":         llx.StringDataPtr(query.End),
			"regionId":    llx.StringDataPtr(query.Region),
			"roleArn":     llx.StringDataPtr(query.RoleArn),
		})
		if err != nil {
			return nil, err
		}
		mqlQuery := resource.(*mqlAlicloudLogAlertQuery)
		// A query may omit the project and region when it reads a store in the
		// rule's own project, so fall back to the rule's own placement rather
		// than leaving the logstore reference unresolvable.
		mqlQuery.cacheRegion = firstNonEmpty(tea.StringValue(query.Region), r.RegionId.Data)
		mqlQuery.cacheProject = firstNonEmpty(tea.StringValue(query.Project), r.ProjectName.Data)
		res = append(res, mqlQuery)
	}
	return res, nil
}

// mqlAlicloudLogAlertQueryInternal carries the resolved placement of the store
// the query reads, which the query itself may leave implicit.
type mqlAlicloudLogAlertQueryInternal struct {
	cacheRegion  string
	cacheProject string
}

// logstore resolves the store the query reads. A query pointing at another
// account's store (it carries a roleArn) or at a store that no longer exists
// degrades to null rather than failing the rule, and store still names it.
func (r *mqlAlicloudLogAlertQuery) logstore() (*mqlAlicloudLogLogstore, error) {
	if r.Store.Data == "" || r.RoleArn.Data != "" {
		r.Logstore.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	store, err := resolveLogStore(r.MqlRuntime, r.cacheRegion, r.cacheProject, r.Store.Data)
	if err != nil || store == nil {
		r.Logstore.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return store, nil
}

// firstNonEmpty returns the first non-empty value, used to fall back to the
// rule's placement when a query leaves its own implicit.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
