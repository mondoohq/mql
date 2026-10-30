// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// grafanaRoleJSON mirrors one element of /api/access-control/roles.
type grafanaRoleJSON struct {
	UID         string                  `json:"uid"`
	Name        string                  `json:"name"`
	DisplayName string                  `json:"displayName"`
	Description string                  `json:"description"`
	Group       string                  `json:"group"`
	Global      bool                    `json:"global"`
	Hidden      bool                    `json:"hidden"`
	Version     int                     `json:"version"`
	Permissions []grafanaRolePermission `json:"permissions"`
	Created     string                  `json:"created"`
	Updated     string                  `json:"updated"`
}

type grafanaRolePermission struct {
	Action string `json:"action"`
	Scope  string `json:"scope"`
}

// roles queries /api/access-control/roles, which is RBAC-enabled. The endpoint
// is only available on Grafana Enterprise/Cloud. On unsupported instances, an
// empty list is returned rather than an error so MQL queries don't fail.
func (g *mqlGrafana) roles() ([]any, error) {
	conn, err := grafanaConnection(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	resp, err := conn.Get(context.Background(), "/api/access-control/roles?includeHidden=true")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return []any{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET /api/access-control/roles returned status %d", resp.StatusCode)
	}

	var raw []grafanaRoleJSON
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("grafana: decoding /api/access-control/roles response: %w", err)
	}

	list := make([]any, 0, len(raw))
	for _, r := range raw {
		grouped := map[string][]any{}
		for _, p := range r.Permissions {
			grouped[p.Action] = append(grouped[p.Action], p.Scope)
		}
		permsMap := make(map[string]any, len(grouped))
		for k, v := range grouped {
			permsMap[k] = v
		}

		res, err := CreateResource(g.MqlRuntime, "grafana.role", map[string]*llx.RawData{
			"uid":         llx.StringData(r.UID),
			"name":        llx.StringData(r.Name),
			"displayName": llx.StringData(r.DisplayName),
			"description": llx.StringData(r.Description),
			"group":       llx.StringData(r.Group),
			"global":      llx.BoolData(r.Global),
			"hidden":      llx.BoolData(r.Hidden),
			"version":     llx.IntData(int64(r.Version)),
			"permissions": llx.MapData(permsMap, types.Array(types.String)),
			"created":     llx.TimeData(parseGrafanaTime(r.Created)),
			"updated":     llx.TimeData(parseGrafanaTime(r.Updated)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlGrafanaRole) id() (string, error) {
	return "grafana-role/" + r.Uid.Data, nil
}
