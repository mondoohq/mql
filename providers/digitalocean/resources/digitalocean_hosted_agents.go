// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// hostedAgentPageSize is the page size requested from the hosted agents
// list endpoints.
const hostedAgentPageSize = 100

// hostedAgentTime returns nil for an absent timestamp so the field resolves
// to null instead of 1 January year 1.
func hostedAgentTime(t godo.Timestamp) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t.Time
}

// ----- configs -----

func listHostedAgentConfigs(ctx context.Context, svc godo.HostedAgentsService) ([]godo.HostedAgentConfigSummary, error) {
	return paginateToken(ctx, func(ctx context.Context, token string) ([]godo.HostedAgentConfigSummary, string, error) {
		page, _, err := svc.ListAgentConfigs(ctx, &godo.HostedAgentConfigListOptions{PageToken: token, PageSize: hostedAgentPageSize})
		if err != nil {
			return nil, "", err
		}
		if page == nil {
			return nil, "", nil
		}
		return page.Configs, page.NextPageToken, nil
	})
}

func hostedAgentConfigArgs(c *godo.HostedAgentConfigSummary) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.hostedAgentConfig", c.ID)
	if err != nil {
		return nil, err
	}
	return map[string]*llx.RawData{
		"__id":                   llx.StringData(id),
		"id":                     llx.StringData(c.ID),
		"name":                   llx.StringData(c.Name),
		"agentSpecSchemaVersion": llx.StringData(c.AgentSpecSchemaVersion),
		"contentHash":            llx.StringData(c.ContentHash),
		"createdBy":              llx.StringData(c.CreatedBy),
		"createdAt":              llx.TimeDataPtr(hostedAgentTime(c.CreatedAt)),
		"updatedAt":              llx.TimeDataPtr(hostedAgentTime(c.UpdatedAt)),
	}, nil
}

func (r *mqlDigitalocean) hostedAgentConfigs() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	configs, err := listHostedAgentConfigs(context.Background(), conn.Client().HostedAgents)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(configs))
	for i := range configs {
		args, err := hostedAgentConfigArgs(&configs[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.hostedAgentConfig", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanHostedAgentConfig) id() (string, error) {
	return r.Id.Data, nil
}

// credentials reads the config's credential slots. The list endpoint
// returns summaries only, so this is fetched per config when queried.
func (r *mqlDigitaloceanHostedAgentConfig) credentials() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	cfg, _, err := conn.Client().HostedAgents.GetAgentConfig(context.Background(), r.Id.Data)
	if err != nil {
		return nil, err
	}
	return hostedAgentCredentialDicts(cfg.Credentials), nil
}

// hostedAgentCredentialDicts converts credential slots to dicts. The slots
// carry declaration metadata only; the API never returns secret values.
func hostedAgentCredentialDicts(slots []godo.HostedAgentConfigCredentialSlot) []any {
	out := make([]any, 0, len(slots))
	for _, s := range slots {
		out = append(out, map[string]any{
			"name":     s.Name,
			"source":   s.Source,
			"provider": s.Provider,
		})
	}
	return out
}

// ----- triggers -----

func listHostedAgentTriggers(ctx context.Context, svc godo.HostedAgentTriggersService) ([]godo.HostedAgentTrigger, error) {
	return paginateToken(ctx, func(ctx context.Context, token string) ([]godo.HostedAgentTrigger, string, error) {
		page, _, err := svc.List(ctx, &godo.HostedAgentTriggerListOptions{PageToken: token, PageSize: hostedAgentPageSize})
		if err != nil {
			return nil, "", err
		}
		if page == nil {
			return nil, "", nil
		}
		return page.Triggers, page.NextPageToken, nil
	})
}

// hostedAgentTriggerArgs maps a trigger to its MQL fields. The prompt and
// session templates, the bound session, and the webhook URL are left out:
// they carry workload content or delivery endpoints, not configuration an
// audit reads.
func hostedAgentTriggerArgs(t *godo.HostedAgentTrigger) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.hostedAgentTrigger", t.TriggerID)
	if err != nil {
		return nil, err
	}

	webhookProvider := ""
	if t.Webhook != nil {
		webhookProvider = string(t.Webhook.Provider)
	}

	cronExpression, cronTimezone := "", ""
	nextRunAt := llx.NilData
	if t.Cron != nil {
		cronExpression = t.Cron.CronExpr
		cronTimezone = t.Cron.Timezone
		nextRunAt = llx.TimeDataPtr(hostedAgentTime(t.Cron.NextRunAt))
	}

	// Output is omitted by the API when no delivery is configured, which is
	// the none mode with no destination.
	outputMode := string(godo.HostedAgentTriggerOutputModeNone)
	emailConfigured, slackConfigured := false, false
	if t.Output != nil {
		if t.Output.Mode != "" {
			outputMode = string(t.Output.Mode)
		}
		emailConfigured = t.Output.EmailConfigured
		slackConfigured = t.Output.SlackConfigured
	}

	return map[string]*llx.RawData{
		"__id":                  llx.StringData(id),
		"id":                    llx.StringData(t.TriggerID),
		"name":                  llx.StringData(t.Name),
		"kind":                  llx.StringData(string(t.Kind)),
		"status":                llx.StringData(string(t.Status)),
		"sessionMode":           llx.StringData(string(t.SessionMode)),
		"agentKind":             llx.StringData(string(t.AgentKind)),
		"webhookProvider":       llx.StringData(webhookProvider),
		"cronExpression":        llx.StringData(cronExpression),
		"cronTimezone":          llx.StringData(cronTimezone),
		"nextRunAt":             nextRunAt,
		"outputMode":            llx.StringData(outputMode),
		"outputEmailConfigured": llx.BoolData(emailConfigured),
		"outputSlackConfigured": llx.BoolData(slackConfigured),
		"createdAt":             llx.TimeDataPtr(hostedAgentTime(t.CreatedAt)),
		"updatedAt":             llx.TimeDataPtr(hostedAgentTime(t.UpdatedAt)),
	}, nil
}

func (r *mqlDigitalocean) hostedAgentTriggers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	triggers, err := listHostedAgentTriggers(context.Background(), conn.Client().HostedAgentTriggers)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(triggers))
	for i := range triggers {
		args, err := hostedAgentTriggerArgs(&triggers[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.hostedAgentTrigger", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanHostedAgentTrigger) id() (string, error) {
	return r.Id.Data, nil
}
