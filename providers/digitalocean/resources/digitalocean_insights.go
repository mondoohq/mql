// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"
	"strings"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// ----- notification channels -----

// splitEmailRecipients splits an email channel's recipient list, which the
// API keeps as one string separated by commas, semicolons, or spaces.
func splitEmailRecipients(to string) []any {
	out := []any{}
	for _, addr := range strings.FieldsFunc(to, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		out = append(out, addr)
	}
	return out
}

// webhookScheme returns the lower-cased scheme of a webhook URL, or "" when
// the URL has none. Only the scheme leaves this function: the rest of the URL
// can carry a path or query token that authenticates deliveries.
func webhookScheme(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}

// notificationChannelArgs maps a notification channel to its MQL fields.
// Slack webhook URLs, webhook URLs, headers, and credentials are never
// surfaced; for a webhook only the URL scheme and whether a signature or
// authentication is configured are reported. The API masks the credential
// values on read, so presence of the block is what is reported.
func notificationChannelArgs(c *godo.NotificationChannel) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.insights.notificationChannel", c.ID)
	if err != nil {
		return nil, err
	}
	emailTo := []any{}
	if c.Email != nil {
		emailTo = splitEmailRecipients(c.Email.To)
	}
	slackChannel := ""
	if c.Slack != nil {
		slackChannel = c.Slack.Channel
	}
	scheme := ""
	hasSignature, hasAuth := llx.NilData, llx.NilData
	if c.Webhook != nil {
		scheme = webhookScheme(c.Webhook.URL)
		hasSignature = llx.BoolData(c.Webhook.Signature != nil)
		hasAuth = llx.BoolData(c.Webhook.BasicAuth != nil || c.Webhook.BearerToken != nil)
	}
	ruleCount := llx.NilData
	if c.Usage != nil {
		ruleCount = llx.IntData(int64(c.Usage.RuleCount))
	}
	return map[string]*llx.RawData{
		"__id":                llx.StringData(id),
		"id":                  llx.StringData(c.ID),
		"name":                llx.StringData(c.Name),
		"type":                llx.StringData(c.ChannelType),
		"emailTo":             llx.ArrayData(emailTo, types.String),
		"slackChannel":        llx.StringData(slackChannel),
		"webhookScheme":       llx.StringData(scheme),
		"webhookHasSignature": hasSignature,
		"webhookHasAuth":      hasAuth,
		"ruleCount":           ruleCount,
		"createdAt":           llx.TimeDataPtr(timePtr(c.CreatedAt)),
		"updatedAt":           llx.TimeDataPtr(timePtr(c.UpdatedAt)),
	}, nil
}

func (r *mqlDigitalocean) insightsNotificationChannels() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	channels, err := paginate(context.Background(), client.Insights.ListNotificationChannels)
	if err != nil {
		return nil, classifyDoError(err)
	}
	out := make([]any, 0, len(channels))
	for i := range channels {
		args, err := notificationChannelArgs(&channels[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.insights.notificationChannel", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanInsightsNotificationChannel) id() (string, error) {
	return resourceID("digitalocean.insights.notificationChannel", r.Id.Data)
}

// insightsChannelByID resolves a notification channel from the account's
// channel listing, read once per scan.
func (r *mqlDigitalocean) insightsChannelByID(id string) (*mqlDigitaloceanInsightsNotificationChannel, error) {
	r.insightsChannelIndexOnce.Do(func() {
		channels := r.GetInsightsNotificationChannels()
		if channels.Error != nil {
			r.insightsChannelIndexErr = channels.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanInsightsNotificationChannel, len(channels.Data))
		for _, c := range channels.Data {
			mc := c.(*mqlDigitaloceanInsightsNotificationChannel)
			idx[mc.Id.Data] = mc
		}
		r.insightsChannelIndex = idx
	})
	if r.insightsChannelIndexErr != nil {
		return nil, r.insightsChannelIndexErr
	}
	return r.insightsChannelIndex[id], nil
}

// ----- alert rules -----

// listInsightsAlertRules walks every alert rule. The endpoint takes its own
// options type, so the shared page cursor is copied into it.
func listInsightsAlertRules(ctx context.Context, svc godo.InsightsService) ([]godo.AlertRule, error) {
	return paginate(ctx, func(ctx context.Context, opt *godo.ListOptions) ([]godo.AlertRule, *godo.Response, error) {
		return svc.ListAlertRules(ctx, &godo.AlertRuleListOptions{Page: opt.Page, PerPage: opt.PerPage})
	})
}

// alertRuleChannelIDs returns the ids of the channels an alert rule
// notifies, in order and without duplicates.
func alertRuleChannelIDs(rule *godo.AlertRule) []string {
	if rule.Spec.NotificationChannels == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, b := range *rule.Spec.NotificationChannels {
		if b.NotificationChannelID == "" {
			continue
		}
		if _, ok := seen[b.NotificationChannelID]; ok {
			continue
		}
		seen[b.NotificationChannelID] = struct{}{}
		out = append(out, b.NotificationChannelID)
	}
	return out
}

func alertRuleArgs(rule *godo.AlertRule) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.insights.alertRule", rule.ID)
	if err != nil {
		return nil, err
	}
	return map[string]*llx.RawData{
		"__id":            llx.StringData(id),
		"id":              llx.StringData(rule.ID),
		"name":            llx.StringData(rule.Spec.Name),
		"status":          llx.StringData(rule.Status),
		"metric":          llx.StringData(rule.Spec.Query.Metric),
		"reAlertDuration": llx.StringData(rule.Spec.ReAlertDuration),
		"createdAt":       llx.TimeDataPtr(timePtr(rule.CreatedAt)),
		"updatedAt":       llx.TimeDataPtr(timePtr(rule.UpdatedAt)),
	}, nil
}

// mqlDigitaloceanInsightsAlertRuleInternal keeps the ids of the channels the
// rule notifies, which channels() resolves from the channel listing.
type mqlDigitaloceanInsightsAlertRuleInternal struct {
	cacheChannelIDs []string
}

func (r *mqlDigitalocean) insightsAlertRules() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	rules, err := listInsightsAlertRules(context.Background(), conn.Client().Insights)
	if err != nil {
		return nil, classifyDoError(err)
	}
	out := make([]any, 0, len(rules))
	for i := range rules {
		args, err := alertRuleArgs(&rules[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.insights.alertRule", args)
		if err != nil {
			return nil, err
		}
		res.(*mqlDigitaloceanInsightsAlertRule).cacheChannelIDs = alertRuleChannelIDs(&rules[i])
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanInsightsAlertRule) id() (string, error) {
	return resourceID("digitalocean.insights.alertRule", r.Id.Data)
}

// channels resolves the rule's channels. A binding to a channel the listing
// does not hold (deleted since) is skipped rather than reported as a
// channel with no fields.
func (r *mqlDigitaloceanInsightsAlertRule) channels() ([]any, error) {
	out := []any{}
	if len(r.cacheChannelIDs) == 0 {
		return out, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	for _, id := range r.cacheChannelIDs {
		c, err := parent.insightsChannelByID(id)
		if err != nil {
			return nil, err
		}
		if c != nil {
			out = append(out, c)
		}
	}
	return out, nil
}
