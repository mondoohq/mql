// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

func (c *mqlCloudflareZoneRateLimitRule) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

// rateLimitRule is the response shape of the legacy zone rate-limits endpoint
// (`/zones/{id}/rate_limits`). cloudflare-go marks its typed RateLimitService
// as deprecated and its typed response drops fields we expose (the per-rule
// response status filter), so we read the endpoint via the client's generic Get
// and decode the full payload ourselves to preserve the MQL schema.
type rateLimitRule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Disabled    bool   `json:"disabled"`
	Threshold   int64  `json:"threshold"`
	Period      int64  `json:"period"`
	Action      struct {
		Mode     string `json:"mode"`
		Timeout  int64  `json:"timeout"`
		Response *struct {
			ContentType string `json:"content_type"`
			Body        string `json:"body"`
		} `json:"response"`
	} `json:"action"`
	Match struct {
		Request struct {
			URL     string   `json:"url"`
			Methods []string `json:"methods"`
			Schemes []string `json:"schemes"`
		} `json:"request"`
		Response struct {
			Status []int64 `json:"status"`
		} `json:"response"`
	} `json:"match"`
}

func (c *mqlCloudflareZone) rateLimitRules() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	page := 1
	for {
		var env struct {
			Result     []rateLimitRule `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		uri := fmt.Sprintf("zones/%s/rate_limits?page=%d&per_page=100", c.Id.Data, page)
		if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
			return nil, err
		}

		for i := range env.Result {
			l := env.Result[i]

			action := map[string]any{
				"mode":    l.Action.Mode,
				"timeout": l.Action.Timeout,
			}
			if l.Action.Response != nil {
				action["response"] = map[string]any{
					"contentType": l.Action.Response.ContentType,
					"body":        l.Action.Response.Body,
				}
			}

			statuses := make([]any, 0, len(l.Match.Response.Status))
			for _, s := range l.Match.Response.Status {
				statuses = append(statuses, s)
			}

			res, err := CreateResource(c.MqlRuntime, "cloudflare.zone.rateLimitRule", map[string]*llx.RawData{
				"__id":             llx.StringData("cloudflare.zone.rateLimitRule@" + c.Id.Data + "/" + l.ID),
				"id":               llx.StringData(l.ID),
				"description":      llx.StringData(l.Description),
				"disabled":         llx.BoolData(l.Disabled),
				"threshold":        llx.IntData(l.Threshold),
				"period":           llx.IntData(l.Period),
				"action":           llx.DictData(action),
				"urlPattern":       llx.StringData(l.Match.Request.URL),
				"methods":          llx.ArrayData(convert.SliceAnyToInterface(l.Match.Request.Methods), types.String),
				"schemes":          llx.ArrayData(convert.SliceAnyToInterface(l.Match.Request.Schemes), types.String),
				"responseStatuses": llx.ArrayData(statuses, types.Int),
			})
			if err != nil {
				return nil, err
			}

			result = append(result, res)
		}

		// Terminate on the local page counter, not the server-echoed
		// ResultInfo.Page, so a page:0 echo with total_pages>0 can't loop forever.
		if env.ResultInfo.TotalPages == 0 || page >= env.ResultInfo.TotalPages {
			break
		}
		page++
	}

	return result, nil
}
