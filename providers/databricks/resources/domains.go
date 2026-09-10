// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	sdktime "github.com/databricks/databricks-sdk-go/common/types/time"
	"github.com/databricks/databricks-sdk-go/service/domains"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlDatabricksDomainInternal struct {
	cacheParentDomainId string
}

// sdkTime converts the SDK's protobuf-backed timestamp to a Go time, returning
// nil when the API sent none. The SDK's own accessor returns the zero time for
// a nil pointer, which MQL would render as a real date in the year 1.
func sdkTime(t *sdktime.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime()
	if v.IsZero() {
		return nil
	}
	return &v
}

// int64Slice converts the SDK's principal id lists to the []any form
// llx.ArrayData expects.
func int64Slice(vals []int64) []any {
	out := make([]any, 0, len(vals))
	for _, v := range vals {
		out = append(out, v)
	}
	return out
}

// domainFields maps one domain record to its MQL fields. Kept apart from the
// API call so the absent cases can be asserted directly: a domain the API
// reports without timestamps arrives as null rather than as the zero time, and
// a domain without owners reports an empty list, which is a fact the API
// stated, not a read that failed.
func domainFields(d domains.Domain) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":              llx.StringData("databricks.domain/" + d.DomainId),
		"id":                llx.StringData(d.DomainId),
		"name":              llx.StringData(d.Name),
		"subtitle":          llx.StringData(d.Subtitle),
		"description":       llx.StringData(d.Description),
		"tagKey":            llx.StringData(d.TagKey),
		"effectiveDraft":    llx.BoolData(d.EffectiveDraft),
		"businessOwnerIds":  llx.ArrayData(int64Slice(d.BusinessOwnerIds), types.Int),
		"technicalOwnerIds": llx.ArrayData(int64Slice(d.TechnicalOwnerIds), types.Int),
		"createTime":        llx.TimeDataPtr(sdkTime(d.CreateTime)),
		"updateTime":        llx.TimeDataPtr(sdkTime(d.UpdateTime)),
	}
}

// childDomains returns the domains whose parent is parentID, in list order.
func childDomains(list []domains.Domain, parentID string) []domains.Domain {
	out := []domains.Domain{}
	for i := range list {
		if list[i].ParentDomainId == parentID {
			out = append(out, list[i])
		}
	}
	return out
}

// cachedDomains lists the workspace domains at most once per scan, caching them
// on the root databricks resource so the domain list, each domain's parent, and
// each domain's subdomains all come from a single ListDomains call rather than
// one Get per reference.
func cachedDomains(runtime *plugin.Runtime) ([]domains.Domain, map[string]domains.Domain, error) {
	rootRes, err := NewResource(runtime, "databricks", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	root := rootRes.(*mqlDatabricks)
	root.domainsOnce.Do(func() {
		ws, err := workspaceClient(runtime)
		if err != nil {
			root.domainsErr = err
			return
		}
		list, err := ws.Domains.ListDomainsAll(context.Background(), domains.ListDomainsRequest{})
		if err != nil {
			root.domainsErr = err
			return
		}
		byID := make(map[string]domains.Domain, len(list))
		for i := range list {
			byID[list[i].DomainId] = list[i]
		}
		root.domainList = list
		root.domainsByID = byID
	})
	return root.domainList, root.domainsByID, root.domainsErr
}

func newMqlDatabricksDomain(runtime *plugin.Runtime, d domains.Domain) (*mqlDatabricksDomain, error) {
	res, err := CreateResource(runtime, "databricks.domain", domainFields(d))
	if err != nil {
		return nil, err
	}
	dom := res.(*mqlDatabricksDomain)
	dom.cacheParentDomainId = d.ParentDomainId
	return dom, nil
}

// domains lists the workspace's data domains. A caller who may not read them
// gets null rather than an empty list, and a workspace where the feature is
// not served reports none.
func (r *mqlDatabricks) domains() ([]any, error) {
	list, _, err := cachedDomains(r.MqlRuntime)
	if err != nil {
		if isDatabricksUnreadable(err) {
			r.Domains = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		if isDatabricksFeatureUnavailable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	out := []any{}
	for i := range list {
		res, err := newMqlDatabricksDomain(r.MqlRuntime, list[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricksDomain) parentDomain() (*mqlDatabricksDomain, error) {
	if r.cacheParentDomainId == "" {
		r.ParentDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	_, byID, err := cachedDomains(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	parent, ok := byID[r.cacheParentDomainId]
	if !ok {
		// The parent was deleted after this domain recorded it; there is no
		// domain to point at.
		r.ParentDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDatabricksDomain(r.MqlRuntime, parent)
}

func (r *mqlDatabricksDomain) subdomains() ([]any, error) {
	list, _, err := cachedDomains(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	out := []any{}
	for _, child := range childDomains(list, r.Id.Data) {
		res, err := newMqlDatabricksDomain(r.MqlRuntime, child)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
