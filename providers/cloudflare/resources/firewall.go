// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/page_rules"
	"github.com/cloudflare/cloudflare-go/v7/rulesets"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

func (c *mqlCloudflareZoneRuleset) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareZone) rulesets() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.Rulesets.ListAutoPaging(context.TODO(), rulesets.RulesetListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.ruleset", map[string]*llx.RawData{
			"id":          llx.StringData(rec.ID),
			"name":        llx.StringData(rec.Name),
			"description": llx.StringData(rec.Description),
			"kind":        llx.StringData(string(rec.Kind)),
			"phase":       llx.StringData(string(rec.Phase)),
			"version":     llx.StringData(rec.Version),
			"updatedAt":   timeOrNil(rec.LastUpdated),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *mqlCloudflareZonePageRule) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareZone) pageRules() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	records, err := conn.Cf.PageRules.List(context.TODO(), page_rules.PageRuleListParams{
		ZoneID: cloudflare.F(c.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	var result []any
	for i := range *records {
		rec := (*records)[i]

		res, err := NewResource(c.MqlRuntime, "cloudflare.zone.pageRule", map[string]*llx.RawData{
			"id":        llx.StringData(rec.ID),
			"status":    llx.StringData(string(rec.Status)),
			"priority":  llx.IntData(rec.Priority),
			"createdAt": llx.TimeData(rec.CreatedOn),
			"updatedAt": llx.TimeData(rec.ModifiedOn),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}

	return result, nil
}
