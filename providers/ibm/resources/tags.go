// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// searchPageSize is the largest page Global Search returns.
const searchPageSize = 1000

// resourceTags are the user and access management tags attached to one CRN.
type resourceTags struct {
	user   []string
	access []string
}

// tagIndex reads the tags of every resource in the account once per
// connection through Global Search, keyed by CRN. IBM Cloud's resource APIs
// do not return tags, and Global Search answers for the whole account in a
// few pages instead of one tagging call per resource.
func tagIndex(runtime *plugin.Runtime) (map[string]resourceTags, error) {
	c := conn(runtime)
	v, err := c.Memo("tags", func() (any, error) {
		return searchTags(func(cursor *string) (*globalsearchv2.ScanResult, error) {
			res, _, err := c.GlobalSearch().Search(&globalsearchv2.SearchOptions{
				Query:        core.StringPtr("*"),
				Fields:       []string{"crn", "tags", "access_tags"},
				Limit:        core.Int64Ptr(searchPageSize),
				SearchCursor: cursor,
			})
			return res, err
		})
	})
	if err != nil {
		return nil, classifyError(err, "")
	}
	return v.(map[string]resourceTags), nil
}

// searchTags walks the Global Search pages. A page shorter than the page size
// is the last one; a cursor that does not move would loop forever, so it ends
// the walk with an error.
func searchTags(page func(cursor *string) (*globalsearchv2.ScanResult, error)) (map[string]resourceTags, error) {
	out := map[string]resourceTags{}
	var cursor *string
	for {
		res, err := page(cursor)
		if err != nil {
			return nil, err
		}
		if res == nil {
			return out, nil
		}
		for i := range res.Items {
			it := &res.Items[i]
			crn := derefStr(it.CRN)
			if crn == "" {
				continue
			}
			out[crn] = resourceTags{
				user:   anyStrings(it.GetProperty("tags")),
				access: anyStrings(it.GetProperty("access_tags")),
			}
		}
		if len(res.Items) < searchPageSize || res.SearchCursor == nil || *res.SearchCursor == "" {
			return out, nil
		}
		if cursor != nil && *cursor == *res.SearchCursor {
			return nil, errors.New("ibm: global search returned the same cursor twice")
		}
		cursor = res.SearchCursor
	}
}

// anyStrings reads a JSON string array; anything else is an empty list.
func anyStrings(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// tagsOf returns the tags of a CRN. A resource Global Search has not indexed
// carries no tags.
func tagsOf(runtime *plugin.Runtime, crn string) (resourceTags, error) {
	idx, err := tagIndex(runtime)
	if err != nil {
		return resourceTags{}, err
	}
	return idx[crn], nil
}

// allTags is the user and access tags together, which --filters matches.
func (t resourceTags) all() []string {
	return append(append([]string{}, t.user...), t.access...)
}

// filteredOut reports whether --filters drops the resource with this CRN. The
// tag index is only read when a filter is set.
func filteredOut(runtime *plugin.Runtime, crn string) (bool, error) {
	f := conn(runtime).Filters
	if !f.HasFilters() {
		return false, nil
	}
	t, err := tagsOf(runtime, crn)
	if err != nil {
		return false, err
	}
	return f.IsFilteredOut(t.all()), nil
}

func userTags(runtime *plugin.Runtime, crn string) ([]any, error) {
	t, err := tagsOf(runtime, crn)
	if err != nil {
		return nil, err
	}
	return tagList(t.user), nil
}

func accessTags(runtime *plugin.Runtime, crn string) ([]any, error) {
	t, err := tagsOf(runtime, crn)
	if err != nil {
		return nil, err
	}
	return tagList(t.access), nil
}

func tagList(in []string) []any {
	out := make([]any, 0, len(in))
	for _, t := range in {
		out = append(out, t)
	}
	return out
}

func (r *mqlIbmResourceGroup) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmResourceGroup) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmResourceInstance) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmResourceInstance) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpc) tags() ([]any, error)             { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpc) accessTags() ([]any, error)       { return accessTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcSubnet) tags() ([]any, error)       { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcSubnet) accessTags() ([]any, error) { return accessTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcInstance) tags() ([]any, error)     { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcInstance) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpcSecurityGroup) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcSecurityGroup) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpcNetworkAcl) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcNetworkAcl) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpcFloatingIp) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcFloatingIp) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpcPublicGateway) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcPublicGateway) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpcLoadBalancer) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcLoadBalancer) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpcVolume) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcVolume) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpcSshKey) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcSshKey) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmVpcFlowLogCollector) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcFlowLogCollector) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmPowerWorkspace) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmPowerWorkspace) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmPowerInstance) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmPowerInstance) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmPowerNetwork) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmPowerNetwork) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmPowerVolume) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmPowerVolume) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
func (r *mqlIbmPowerImage) tags() ([]any, error) { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmPowerImage) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Crn.Data)
}
