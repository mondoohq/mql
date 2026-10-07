// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
)

func (r *mqlAzuredevopsRepository) webhooks() ([]any, error) {
	subs, err := connectionOf(r.MqlRuntime).Client().Subscriptions(apiContext())
	if err != nil {
		return nil, classifyForbidden(err)
	}

	out := []any{}
	for _, s := range subs {
		if !s.AppliesToRepository(r.ProjectId.Data, r.Id.Data) {
			continue
		}
		u := s.URL()
		if u == nil {
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		res, err := CreateResource(r.MqlRuntime, "azuredevops.webhook", map[string]*llx.RawData{
			"__id":       llx.StringData("azuredevops.webhook/" + s.ID),
			"id":         llx.StringData(s.ID),
			"eventType":  llx.StringData(s.EventType),
			"consumerId": llx.StringData(s.ConsumerID),
			"status":     llx.StringData(s.Status),
			"active":     llx.BoolData(s.Active()),
			"scheme":     llx.StringData(scheme),
			"host":       llx.StringData(u.Host),
			"isHttps":    llx.BoolData(scheme == "https"),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
