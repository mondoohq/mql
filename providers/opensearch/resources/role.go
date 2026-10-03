// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// osRole is one role from the security roles API.
type osRole struct {
	Reserved           bool     `json:"reserved"`
	Hidden             bool     `json:"hidden"`
	Static             bool     `json:"static"`
	Description        string   `json:"description"`
	ClusterPermissions []string `json:"cluster_permissions"`
	IndexPermissions   []struct {
		IndexPatterns  []string `json:"index_patterns"`
		FLS            []string `json:"fls"`
		MaskedFields   []string `json:"masked_fields"`
		AllowedActions []string `json:"allowed_actions"`
	} `json:"index_permissions"`
}

func (r *mqlOpensearchCluster) roles() ([]any, error) {
	conn := osConnection(r.MqlRuntime)
	var resp map[string]osRole
	if err := conn.Get("/_plugins/_security/api/roles", &resp); err != nil {
		return refusedList(err, permSecurityAPI)
	}

	names := make([]string, 0, len(resp))
	for name := range resp {
		names = append(names, name)
	}
	sort.Strings(names)

	list := []any{}
	for _, name := range names {
		role := resp[name]
		res, err := CreateResource(r.MqlRuntime, "opensearch.role", map[string]*llx.RawData{
			"__id":               llx.StringData(r.__id + "/role/" + name),
			"name":               llx.StringData(name),
			"isReserved":         llx.BoolData(role.Reserved),
			"isHidden":           llx.BoolData(role.Hidden),
			"isStatic":           llx.BoolData(role.Static),
			"description":        llx.StringData(role.Description),
			"clusterPermissions": llx.ArrayData(toStringSlice(role.ClusterPermissions), types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlRole := res.(*mqlOpensearchRole)
		roleCopy := role
		mqlRole.cacheRole = &roleCopy
		list = append(list, mqlRole)
	}
	return list, nil
}

func (r *mqlOpensearchRole) indexPermissions() ([]any, error) {
	if r.cacheRole == nil {
		return []any{}, nil
	}
	list := []any{}
	for i, ip := range r.cacheRole.IndexPermissions {
		res, err := CreateResource(r.MqlRuntime, "opensearch.role.indexPermission", map[string]*llx.RawData{
			"__id":                  llx.StringData(r.__id + "/idx/" + strconv.Itoa(i)),
			"indexPatterns":         llx.ArrayData(toStringSlice(ip.IndexPatterns), types.String),
			"allowedActions":        llx.ArrayData(toStringSlice(ip.AllowedActions), types.String),
			"hasFieldLevelSecurity": llx.BoolData(len(ip.FLS) > 0),
			"hasFieldMasking":       llx.BoolData(len(ip.MaskedFields) > 0),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
