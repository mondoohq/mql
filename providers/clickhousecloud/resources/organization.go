// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/clickhousecloud/connection"
)

func initClickhousecloudOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := clickhousecloudConn(runtime)
	var org struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"createdAt"`
	}
	if err := conn.Get(conn.Context(), "", &org); err != nil {
		return nil, nil, fmt.Errorf("clickhousecloud: cannot read organization: %w", err)
	}

	args["__id"] = llx.StringData(connection.NewClickhousecloudOrgIdentifier(conn.OrgID()))
	args["id"] = llx.StringData(conn.OrgID())
	args["name"] = llx.StringData(org.Name)
	args["createdAt"] = timeData(org.CreatedAt)
	return args, nil, nil
}

type apiMember struct {
	UserID string `json:"userId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

func (r *mqlClickhousecloudOrganization) members() ([]any, error) {
	conn := clickhousecloudConn(r.MqlRuntime)
	var members []apiMember
	if err := conn.Get(conn.Context(), "/members", &members); err != nil {
		if connection.IsPermissionError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	orgID := conn.OrgID()
	list := []any{}
	for _, m := range members {
		res, err := CreateResource(r.MqlRuntime, "clickhousecloud.member", map[string]*llx.RawData{
			"__id":   llx.StringData(orgID + "/member/" + m.UserID),
			"userId": llx.StringData(m.UserID),
			"email":  llx.StringData(m.Email),
			"name":   llx.StringData(m.Name),
			"role":   llx.StringData(m.Role),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// apiAssignedRole is a role assignment as returned for both keys and members.
type apiAssignedRole struct {
	RoleName string `json:"roleName"`
}

type apiKey struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	State         string            `json:"state"`
	KeySuffix     string            `json:"keySuffix"`
	AssignedRoles []apiAssignedRole `json:"assignedRoles"`
	ExpireAt      string            `json:"expireAt"`
	UsedAt        string            `json:"usedAt"`
	CreatedAt     string            `json:"createdAt"`
}

func (r *mqlClickhousecloudOrganization) apiKeys() ([]any, error) {
	conn := clickhousecloudConn(r.MqlRuntime)
	var keys []apiKey
	if err := conn.Get(conn.Context(), "/keys", &keys); err != nil {
		if connection.IsPermissionError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	orgID := conn.OrgID()
	list := []any{}
	for _, k := range keys {
		res, err := CreateResource(r.MqlRuntime, "clickhousecloud.apiKey", map[string]*llx.RawData{
			"__id":         llx.StringData(orgID + "/key/" + k.ID),
			"id":           llx.StringData(k.ID),
			"name":         llx.StringData(k.Name),
			"state":        llx.StringData(k.State),
			"roles":        llx.ArrayData(toAnySlice(roleNames(k.AssignedRoles)), "string"),
			"neverExpires": llx.BoolData(k.ExpireAt == ""),
			"expiresAt":    timeData(k.ExpireAt),
			"usedAt":       timeData(k.UsedAt),
			"createdAt":    timeData(k.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// roleNames extracts the role names from a set of assigned roles.
func roleNames(roles []apiAssignedRole) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if r.RoleName != "" {
			out = append(out, r.RoleName)
		}
	}
	return out
}
