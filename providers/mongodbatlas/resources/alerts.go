// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// mqlMongodbatlasAlertConfigInternal keeps the notification targets that
// arrived with the configuration listing, so expanding them costs no second
// call.
type mqlMongodbatlasAlertConfigInternal struct {
	cacheAlertID       string
	cacheNotifications []admin.AlertsNotificationRootForGroup
}

// alertConfigs lists the project's alert rules. The set is the project's
// detection coverage: an event type that no enabled configuration names is one
// that fires without telling anybody.
func (r *mqlMongodbatlas) alertConfigs() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	err = forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.AlertConfigurationsAPI.
			ListAlertConfigs(ctx, pid).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// An empty configuration set is exactly the finding this reports,
			// so a denied read must not render as one.
			if isAccessDenied(httpResp) {
				r.AlertConfigs.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasAlertConfig(r.MqlRuntime, pid, results[i])
			if err != nil {
				return 0, err
			}
			out = append(out, res)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func newMqlMongodbatlasAlertConfig(runtime *plugin.Runtime, pid string, c admin.GroupAlertsConfig) (*mqlMongodbatlasAlertConfig, error) {
	matchers := []any{}
	for _, m := range c.GetMatchers() {
		matchers = append(matchers, map[string]any{
			"fieldName": m.GetFieldName(),
			"operator":  m.GetOperator(),
			"value":     m.GetValue(),
		})
	}

	// Atlas carries the same threshold under two names: metricThreshold for a
	// host or disk metric alert, threshold for the rest. Only one is populated.
	threshold := c.MetricThreshold
	if threshold == nil {
		threshold = c.Threshold
	}
	var metricName, operator, units *string
	var value *float64
	if threshold != nil {
		metricName = threshold.MetricName
		operator = threshold.Operator
		units = threshold.Units
		value = threshold.Threshold
	}

	res, err := CreateResource(runtime, "mongodbatlas.alertConfig", map[string]*llx.RawData{
		// An alert configuration id is unique within its project, and an
		// organization-wide scan walks several projects in one run.
		"__id":                llx.StringData("mongodbatlas.alertConfig/" + pid + "/" + c.GetId()),
		"id":                  llx.StringData(c.GetId()),
		"eventTypeName":       llx.StringDataPtr(c.EventTypeName),
		"enabled":             llx.BoolDataPtr(c.Enabled),
		"severityOverride":    llx.StringDataPtr(c.SeverityOverride),
		"matchers":            llx.ArrayData(matchers, types.Dict),
		"thresholdMetricName": llx.StringDataPtr(metricName),
		"thresholdOperator":   llx.StringDataPtr(operator),
		"thresholdValue":      llx.FloatDataPtr(value),
		"thresholdUnits":      llx.StringDataPtr(units),
		"created":             llx.TimeDataPtr(c.Created),
		"updated":             llx.TimeDataPtr(c.Updated),
	})
	if err != nil {
		return nil, err
	}
	cfg := res.(*mqlMongodbatlasAlertConfig)
	cfg.cacheAlertID = pid + "/" + c.GetId()
	cfg.cacheNotifications = c.GetNotifications()
	return cfg, nil
}

// notifications expands the configuration's delivery targets. Only
// non-credential fields are read: the Atlas notification record carries a Slack
// API token, a Datadog key, an Opsgenie key, a PagerDuty service key, a Splunk
// On-Call key, and a webhook secret inline, and none of those belong in a
// schema.
func (r *mqlMongodbatlasAlertConfig) notifications() ([]any, error) {
	out := []any{}
	for i := range r.cacheNotifications {
		n := r.cacheNotifications[i]
		res, err := CreateResource(r.MqlRuntime, "mongodbatlas.alertNotification", map[string]*llx.RawData{
			// A notification carries an Atlas-assigned notifierId only once it
			// has been through a third-party integration, so the position
			// within the configuration is the fallback dimension. Two EMAIL
			// targets on one configuration are otherwise the same key.
			"__id":             llx.StringData("mongodbatlas.alertNotification/" + r.cacheAlertID + "/" + int64ToString(int64(i)) + "/" + n.GetNotifierId()),
			"typeName":         llx.StringDataPtr(n.TypeName),
			"emailAddress":     llx.StringDataPtr(n.EmailAddress),
			"emailEnabled":     llx.BoolDataPtr(n.EmailEnabled),
			"smsEnabled":       llx.BoolDataPtr(n.SmsEnabled),
			"roles":            llx.ArrayData(strSlice(n.GetRoles()), types.String),
			"channelName":      llx.StringDataPtr(n.ChannelName),
			"teamName":         llx.StringDataPtr(n.TeamName),
			"username":         llx.StringDataPtr(n.Username),
			"delayMin":         llx.IntDataPtr(n.DelayMin),
			"intervalMin":      llx.IntDataPtr(n.IntervalMin),
			"integrationId":    llx.StringDataPtr(n.IntegrationId),
			"notifierId":       llx.StringDataPtr(n.NotifierId),
			"webhookUrlHost":   llx.StringDataPtr(hostPtrOf(n.WebhookUrl)),
			"hasWebhookSecret": llx.BoolData(isSet(n.WebhookSecret)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
