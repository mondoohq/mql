// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/packages/pagination"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

func (c *mqlCloudflareOneCasbPosturePolicy) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOneCasbPosturePolicyRemediation) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareOneCasbPosturePolicyWebhook) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// nextCasbCursor returns the cursor for the page after page, or "" when page
// is the last one. The endpoint documents the cursor as `result_info.cursor`
// while the SDK paginator reads `result_info.cursors.after`; both are
// accepted so a response using either spelling is walked to the end. A cursor
// equal to the one that produced this page is treated as the end, so a server
// that repeats its cursor cannot loop the walk forever.
func nextCasbCursor(page *pagination.CursorPaginationAfter[zero_trust.CasbPosturePolicyListResponse], current string) string {
	if page == nil || len(page.Result) == 0 {
		return ""
	}
	next := page.ResultInfo.Cursors.After
	if next == "" {
		var info struct {
			Cursor string `json:"cursor"`
		}
		if raw := page.JSON.ResultInfo.Raw(); raw != "" {
			_ = json.Unmarshal([]byte(raw), &info)
		}
		next = info.Cursor
	}
	if next == current {
		return ""
	}
	return next
}

func (c *mqlCloudflareOne) casbPosturePolicies() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	result := []any{}
	cursor := ""
	for {
		params := zero_trust.CasbPosturePolicyListParams{
			AccountID: cloudflare.F(c.AccountID),
		}
		if cursor != "" {
			params.Cursor = cloudflare.F(cursor)
		}
		page, err := conn.Cf.ZeroTrust.Casb.Posture.Policies.List(context.TODO(), params)
		if err != nil {
			return degradedList(err)
		}
		if page == nil {
			break
		}

		for _, rec := range page.Result {
			res, err := newCasbPosturePolicy(c, rec)
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}

		cursor = nextCasbCursor(page, cursor)
		if cursor == "" {
			break
		}
	}

	return result, nil
}

func newCasbPosturePolicy(c *mqlCloudflareOne, rec zero_trust.CasbPosturePolicyListResponse) (any, error) {
	remediations := make([]any, 0, len(rec.Actions.RemediationTypes))
	for _, rt := range rec.Actions.RemediationTypes {
		r, err := CreateResource(c.MqlRuntime, "cloudflare.one.casbPosturePolicy.remediation", map[string]*llx.RawData{
			"__id":        llx.StringData("cloudflare.one.casbPosturePolicy.remediation@" + rec.ID + "/" + rt.RemediationTypeID),
			"id":          llx.StringData(rt.RemediationTypeID),
			"type":        llx.StringData(rt.RemediationType),
			"displayName": llx.StringData(rt.DisplayName),
		})
		if err != nil {
			return nil, err
		}
		remediations = append(remediations, r)
	}

	webhooks := make([]any, 0, len(rec.Actions.WebhookConfigs))
	for _, wh := range rec.Actions.WebhookConfigs {
		r, err := CreateResource(c.MqlRuntime, "cloudflare.one.casbPosturePolicy.webhook", map[string]*llx.RawData{
			"__id":        llx.StringData("cloudflare.one.casbPosturePolicy.webhook@" + rec.ID + "/" + wh.WebhookConfigID),
			"id":          llx.StringData(wh.WebhookConfigID),
			"displayName": llx.StringData(wh.DisplayName),
		})
		if err != nil {
			return nil, err
		}
		webhooks = append(webhooks, r)
	}

	integrationIDs := make([]any, 0, len(rec.IntegrationIDs))
	for _, id := range rec.IntegrationIDs {
		integrationIDs = append(integrationIDs, id)
	}

	return CreateResource(c.MqlRuntime, "cloudflare.one.casbPosturePolicy", map[string]*llx.RawData{
		"__id":                     llx.StringData("cloudflare.one.casbPosturePolicy@" + rec.ID),
		"id":                       llx.StringData(rec.ID),
		"displayName":              llx.StringData(rec.DisplayName),
		"description":              llx.StringData(rec.Description),
		"enabled":                  llx.BoolData(rec.Enabled),
		"findingTypeId":            llx.StringData(rec.FindingTypeID),
		"appliesToAllIntegrations": llx.BoolData(rec.AppliesToAllIntegrations),
		"integrationIds":           llx.ArrayData(integrationIDs, types.String),
		"remediations":             llx.ArrayData(remediations, types.Resource("cloudflare.one.casbPosturePolicy.remediation")),
		"webhooks":                 llx.ArrayData(webhooks, types.Resource("cloudflare.one.casbPosturePolicy.webhook")),
		"lastTriggeredAt":          timeOrNil(rec.LastTriggeredAt),
		"createdAt":                timeOrNil(rec.CreatedAt),
		"updatedAt":                timeOrNil(rec.UpdatedAt),
	})
}
