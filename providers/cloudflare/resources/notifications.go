// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// notificationPolicy mirrors an account alerting (v3) policy, decoded via the
// client's generic Get.
type notificationPolicy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	AlertType   string    `json:"alert_type"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"modified"`
	Mechanisms  map[string][]struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"mechanisms"`
	Conditions map[string]any      `json:"conditions"`
	Filters    map[string][]string `json:"filters"`
}

func (c *mqlCloudflareNotificationPolicy) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return "cloudflare/notificationPolicy/" + c.Id.Data, nil
}

func (c *mqlCloudflareAccount) notificationPolicies() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	policies, err := cfGetPaged[notificationPolicy](conn, fmt.Sprintf("accounts/%s/alerting/v3/policies", c.Id.Data))
	if err != nil {
		return nil, err
	}

	results := []any{}
	for i := range policies {
		p := policies[i]

		mechanisms := map[string]any{}
		for name, integrations := range p.Mechanisms {
			list := make([]any, 0, len(integrations))
			for _, m := range integrations {
				list = append(list, map[string]any{
					"id":   m.ID,
					"name": m.Name,
				})
			}
			mechanisms[name] = list
		}

		filters := map[string]any{}
		for k, v := range p.Filters {
			vv := make([]any, 0, len(v))
			for _, s := range v {
				vv = append(vv, s)
			}
			filters[k] = vv
		}

		res, err := NewResource(c.MqlRuntime, "cloudflare.notificationPolicy", map[string]*llx.RawData{
			"id":          llx.StringData(p.ID),
			"name":        llx.StringData(p.Name),
			"description": llx.StringData(p.Description),
			"enabled":     llx.BoolData(p.Enabled),
			"alertType":   llx.StringData(p.AlertType),
			"mechanisms":  llx.DictData(mechanisms),
			"conditions":  llx.DictData(dictValue(p.Conditions)),
			"filters":     llx.DictData(filters),
			"created":     llx.TimeData(p.Created),
			"modified":    llx.TimeData(p.Modified),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
