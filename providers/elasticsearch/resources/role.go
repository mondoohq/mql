// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// jsonHasContent reports whether a raw JSON value carries a real restriction,
// i.e. it is present and not one of the "no restriction" forms. Elasticsearch
// returns field_security as {} and query as "" (or null, or omits them) when a
// role has no field- or document-level security, all of which must read as no
// restriction rather than a false positive.
func jsonHasContent(raw json.RawMessage, emptyForms ...string) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return false
	}
	for _, e := range emptyForms {
		if s == e {
			return false
		}
	}
	return true
}

// esRole is one role from GET /_security/role. Field- and document-level
// security are decoded as raw JSON so their presence can be reported without
// depending on their (licensed) internal shape.
type esRole struct {
	Cluster      []string `json:"cluster"`
	RunAs        []string `json:"run_as"`
	Applications []struct {
		Application string `json:"application"`
	} `json:"applications"`
	Indices []struct {
		Names                  []string        `json:"names"`
		Privileges             []string        `json:"privileges"`
		FieldSecurity          json.RawMessage `json:"field_security"`
		Query                  json.RawMessage `json:"query"`
		AllowRestrictedIndices bool            `json:"allow_restricted_indices"`
	} `json:"indices"`
	Metadata map[string]any `json:"metadata"`
}

func (r *mqlElasticsearchCluster) roles() ([]any, error) {
	conn := esConnection(r.MqlRuntime)
	var resp map[string]esRole
	if err := conn.Get("/_security/role", &resp); err != nil {
		return refusedList(err, "read_security")
	}

	names := make([]string, 0, len(resp))
	for name := range resp {
		names = append(names, name)
	}
	sort.Strings(names)

	list := []any{}
	for _, name := range names {
		role := resp[name]
		appNames := make([]any, 0, len(role.Applications))
		for _, a := range role.Applications {
			appNames = append(appNames, a.Application)
		}

		res, err := CreateResource(r.MqlRuntime, "elasticsearch.role", map[string]*llx.RawData{
			"__id":              llx.StringData(r.__id + "/role/" + name),
			"name":              llx.StringData(name),
			"isReserved":        llx.BoolData(isReserved(role.Metadata)),
			"clusterPrivileges": llx.ArrayData(toStringSlice(role.Cluster), types.String),
			"applicationNames":  llx.ArrayData(appNames, types.String),
			"runAs":             llx.ArrayData(toStringSlice(role.RunAs), types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlRole := res.(*mqlElasticsearchRole)
		mqlRole.cacheRole = &role
		list = append(list, mqlRole)
	}
	return list, nil
}

func (r *mqlElasticsearchRole) indexPrivileges() ([]any, error) {
	if r.cacheRole == nil {
		return []any{}, nil
	}
	list := []any{}
	for i, idx := range r.cacheRole.Indices {
		// Field-level security is the field_security object, empty ({}) when
		// unset; document-level security is the query string, empty ("") when
		// unset. Both, plus null/absent, must read as no restriction.
		hasFLS := jsonHasContent(idx.FieldSecurity, "{}")
		hasDLS := jsonHasContent(idx.Query, `""`)
		res, err := CreateResource(r.MqlRuntime, "elasticsearch.role.indexPrivilege", map[string]*llx.RawData{
			"__id":                   llx.StringData(r.__id + "/idx/" + intToStr(int64(i))),
			"names":                  llx.ArrayData(toStringSlice(idx.Names), types.String),
			"privileges":             llx.ArrayData(toStringSlice(idx.Privileges), types.String),
			"hasFieldSecurity":       llx.BoolData(hasFLS),
			"hasDocumentSecurity":    llx.BoolData(hasDLS),
			"allowRestrictedIndices": llx.BoolData(idx.AllowRestrictedIndices),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
