// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/digitalocean/godo"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
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
		"region":                 hostedAgentRegion(c.Region),
	}, nil
}

// hostedAgentRegion returns null when the API reports no region. It omits
// the field for teams without regional placement and for configs created
// before it, and an empty string would read as a region that matched
// nothing.
func hostedAgentRegion(region string) *llx.RawData {
	if region == "" {
		return llx.NilData
	}
	return llx.StringData(region)
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

// ----- connections -----

// hostedAgentConnectionPageSize is the largest page the connection list
// endpoint accepts.
const hostedAgentConnectionPageSize = 100

// hostedAgentConnectionProviders returns the external providers whose
// connections are listed. The connection API is keyed by provider and has no
// endpoint that enumerates them, so the webhook provider registry supplies
// the set. "custom" is a signature scheme, not a provider an agent connects
// to, so it is left out.
func hostedAgentConnectionProviders(ctx context.Context, svc godo.HostedAgentTriggersService) ([]string, error) {
	resp, _, err := svc.ListWebhookProviders(ctx)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(resp.Providers))
	for _, p := range resp.Providers {
		key := string(p.Key)
		if key == "" || p.Key == godo.HostedAgentWebhookProviderCustom {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out, nil
}

// listHostedAgentConnections walks the page/per_page pagination of one
// provider's connection list. It stops on an empty page or once the reported
// total is reached. A page that adds no connection not already seen means the
// endpoint ignores the page parameter, which would otherwise loop forever.
func listHostedAgentConnections(ctx context.Context, svc godo.HostedAgentsService, provider string) ([]godo.HostedAgentConnection, error) {
	var all []godo.HostedAgentConnection
	seen := map[string]struct{}{}
	for page := 1; ; page++ {
		resp, _, err := svc.ListConnections(ctx, provider, &godo.HostedAgentConnectionListOptions{Page: page, PerPage: hostedAgentConnectionPageSize})
		if err != nil {
			return nil, err
		}
		if resp == nil || len(resp.Connections) == 0 {
			return all, nil
		}
		added := 0
		for _, c := range resp.Connections {
			if _, ok := seen[c.ID]; ok {
				continue
			}
			seen[c.ID] = struct{}{}
			all = append(all, c)
			added++
		}
		if added == 0 {
			return nil, fmt.Errorf("hosted agent connections for %s: page %d repeated earlier connections, so the endpoint is repeating a page", provider, page)
		}
		if len(all) >= int(resp.Pagination.Total) {
			return all, nil
		}
	}
}

// hostedAgentConnectionArgs maps a connection to its MQL fields. The API
// exposes no token or authorization handle on this surface.
func hostedAgentConnectionArgs(c *godo.HostedAgentConnection) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.hostedAgentConnection", c.Provider, c.ID)
	if err != nil {
		return nil, err
	}
	scopes := []any{}
	grantedAt := llx.NilData
	if c.OAuth != nil {
		for _, s := range c.OAuth.Scopes {
			scopes = append(scopes, s)
		}
		grantedAt = llx.TimeDataPtr(gradientaiTime(c.OAuth.GrantedAt))
	}
	return map[string]*llx.RawData{
		"__id":                llx.StringData(id),
		"id":                  llx.StringData(c.ID),
		"provider":            llx.StringData(c.Provider),
		"providerDisplayName": llx.StringData(c.ProviderDisplayName),
		"actorId":             llx.StringData(c.ActorID),
		"status":              llx.StringData(c.Status),
		"owningUserUuid":      llx.StringData(c.OwningUserID),
		"deletionProtected":   llx.BoolData(c.DeletionProtected),
		"oauthScopes":         llx.ArrayData(scopes, types.String),
		"grantedAt":           grantedAt,
		"createdAt":           llx.TimeDataPtr(gradientaiTime(c.CreatedAt)),
		"updatedAt":           llx.TimeDataPtr(gradientaiTime(c.UpdatedAt)),
	}, nil
}

func (r *mqlDigitalocean) hostedAgentConnections() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	ctx := context.Background()

	providers, err := hostedAgentConnectionProviders(ctx, client.HostedAgentTriggers)
	if err != nil {
		if isDoForbidden(err) {
			return nil, llx.Forbidden(err)
		}
		return nil, err
	}

	out := []any{}
	for _, provider := range providers {
		conns, err := listHostedAgentConnections(ctx, client.HostedAgents, provider)
		if err != nil {
			// One provider's list failing is a partial result: a provider
			// without connection support answers 404, and a denied read
			// for one provider should not hide the others.
			if isDoNotFound(err) || isDoForbidden(err) {
				log.Debug().Err(err).Str("provider", provider).Msg("digitalocean> skipping hosted agent connections")
				continue
			}
			return nil, err
		}
		for i := range conns {
			args, err := hostedAgentConnectionArgs(&conns[i])
			if err != nil {
				return nil, err
			}
			res, err := CreateResource(r.MqlRuntime, "digitalocean.hostedAgentConnection", args)
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func (r *mqlDigitaloceanHostedAgentConnection) id() (string, error) {
	return resourceID("digitalocean.hostedAgentConnection", r.Provider.Data, r.Id.Data)
}
