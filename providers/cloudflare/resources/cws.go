// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"slices"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/packages/pagination"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// cwsPageSize is the largest page the Cloud Web Security list endpoints accept.
const cwsPageSize = 100

type mqlCloudflareOneCwsInternal struct {
	AccountID string
}

type mqlCloudflareOneCwsDeploymentInternal struct {
	accountID              string
	policySetIDs           []string
	domainACLID            string
	basicAuthCredentialIDs []string
}

type mqlCloudflareOneCwsPolicySetInternal struct {
	accountID          string
	memberRecs         []zero_trust.PolicySetPolicy
	includeWorkloadIDs []string
	excludeWorkloadIDs []string
}

type mqlCloudflareOneCwsPolicySetMemberInternal struct {
	accountID string
	policyID  string
}

type mqlCloudflareOneCwsPolicyInternal struct {
	accountID string
}

type mqlCloudflareOneCwsDomainAclInternal struct {
	accountID string
}

type mqlCloudflareOneCwsBasicAuthCredentialInternal struct {
	accountID string
}

func (c *mqlCloudflareOne) cws() (*mqlCloudflareOneCws, error) {
	return newCws(c.MqlRuntime, c.AccountID)
}

// newCws returns the account's Cloud Web Security namespace. The resource is
// cached by account, so every caller shares one set of list results.
func newCws(runtime *plugin.Runtime, accountID string) (*mqlCloudflareOneCws, error) {
	res, err := CreateResource(runtime, "cloudflare.one.cws", map[string]*llx.RawData{
		"__id": llx.StringData("cloudflare.one.cws@" + accountID),
	})
	if err != nil {
		return nil, err
	}
	cws := res.(*mqlCloudflareOneCws)
	cws.AccountID = accountID
	return cws, nil
}

// cwsListAll walks a cursor-paginated Cloud Web Security list endpoint. It
// stops on an empty page, an empty cursor, or a cursor it has already
// followed, so a server that repeats a cursor cannot loop the walk forever.
func cwsListAll[T any](fetch func(cursor string) (*pagination.CursorPagination[T], error)) ([]T, error) {
	var all []T
	seen := map[string]struct{}{}
	cursor := ""
	for {
		page, err := fetch(cursor)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Result) == 0 {
			break
		}
		all = append(all, page.Result...)

		next := page.ResultInfo.Cursor
		if next == "" {
			break
		}
		if _, ok := seen[next]; ok {
			break
		}
		seen[next] = struct{}{}
		cursor = next
	}
	return all, nil
}

// optionalString reports an optional string the API omits or leaves empty as
// null rather than as an empty string.
func optionalString(s string) *llx.RawData {
	if s == "" {
		return llx.NilData
	}
	return llx.StringData(s)
}

func cwsTags(tags map[string]string) *llx.RawData {
	return llx.MapData(convert.MapToInterfaceMap(tags), types.String)
}

// cwsResolve returns the resources in list whose id is in ids, in the order of
// ids. An id with no matching resource is skipped: the API reports references
// by id, and a reference to something the token cannot list says nothing about
// the resource it points to.
func cwsResolve(ids []string, list []any, idOf func(any) string) []any {
	byID := make(map[string]any, len(list))
	for _, r := range list {
		byID[idOf(r)] = r
	}
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		if r, ok := byID[id]; ok {
			out = append(out, r)
		}
	}
	return out
}

func (c *mqlCloudflareOneCws) deployments() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	records, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.Deployment], error) {
		p := zero_trust.CWSDeploymentListParams{
			AccountID: cloudflare.F(c.AccountID),
			PerPage:   cloudflare.F(int64(cwsPageSize)),
		}
		if cursor != "" {
			p.Cursor = cloudflare.F(cursor)
		}
		return conn.Cf.ZeroTrust.CWS.Deployments.List(context.TODO(), p)
	})
	if err != nil {
		return degradedList(err)
	}

	result := make([]any, 0, len(records))
	for _, rec := range records {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.one.cws.deployment", map[string]*llx.RawData{
			"__id":           llx.StringData("cloudflare.one.cws.deployment@" + c.AccountID + "/" + rec.ID),
			"id":             llx.StringData(rec.ID),
			"name":           llx.StringData(rec.Name),
			"description":    optionalString(rec.Description),
			"defaultMode":    llx.StringData(string(rec.DefaultMode)),
			"onErrorAction":  llx.StringData(string(rec.OnErrorAction)),
			"regoRaiseError": llx.BoolData(rec.RegoRaiseError),
			"tags":           cwsTags(rec.Tags),
			"createdAt":      timeOrNil(rec.CreatedAt),
			"updatedAt":      timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		d := res.(*mqlCloudflareOneCwsDeployment)
		d.accountID = c.AccountID
		d.policySetIDs = rec.PolicySetIDs
		d.domainACLID = rec.DomainACLID
		d.basicAuthCredentialIDs = rec.BasicAuthCredentialIDs
		result = append(result, d)
	}
	return result, nil
}

func (c *mqlCloudflareOneCws) policySets() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	records, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.PolicySet], error) {
		p := zero_trust.CWSPolicySetListParams{
			AccountID: cloudflare.F(c.AccountID),
			PerPage:   cloudflare.F(int64(cwsPageSize)),
		}
		if cursor != "" {
			p.Cursor = cloudflare.F(cursor)
		}
		return conn.Cf.ZeroTrust.CWS.PolicySets.List(context.TODO(), p)
	})
	if err != nil {
		return degradedList(err)
	}

	result := make([]any, 0, len(records))
	for _, rec := range records {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.one.cws.policySet", map[string]*llx.RawData{
			"__id":        llx.StringData("cloudflare.one.cws.policySet@" + c.AccountID + "/" + rec.ID),
			"id":          llx.StringData(rec.ID),
			"name":        llx.StringData(rec.Name),
			"description": optionalString(rec.Description),
			"tags":        cwsTags(rec.Tags),
			"createdAt":   timeOrNil(rec.CreatedAt),
			"updatedAt":   timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		s := res.(*mqlCloudflareOneCwsPolicySet)
		s.accountID = c.AccountID
		s.memberRecs = rec.Policies
		s.includeWorkloadIDs = rec.IncludeWorkloadIDs
		s.excludeWorkloadIDs = rec.ExcludeWorkloadIDs
		result = append(result, s)
	}
	return result, nil
}

func (c *mqlCloudflareOneCws) policies() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	records, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.Policy], error) {
		p := zero_trust.CWSPolicyListParams{
			AccountID: cloudflare.F(c.AccountID),
			PerPage:   cloudflare.F(int64(cwsPageSize)),
		}
		if cursor != "" {
			p.Cursor = cloudflare.F(cursor)
		}
		return conn.Cf.ZeroTrust.CWS.Policies.List(context.TODO(), p)
	})
	if err != nil {
		return degradedList(err)
	}

	result := make([]any, 0, len(records))
	for _, rec := range records {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.one.cws.policy", map[string]*llx.RawData{
			"__id":        llx.StringData("cloudflare.one.cws.policy@" + c.AccountID + "/" + rec.ID),
			"id":          llx.StringData(rec.ID),
			"name":        llx.StringData(rec.Name),
			"description": optionalString(rec.Description),
			"entrypoint":  llx.StringData(rec.Entrypoint),
			"filter":      llx.StringData(rec.Filter),
			"packagePath": llx.StringData(rec.PackagePath),
			"regoSource":  llx.StringData(rec.RegoSource),
			"tags":        cwsTags(rec.Tags),
			"createdAt":   timeOrNil(rec.CreatedAt),
			"updatedAt":   timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		p := res.(*mqlCloudflareOneCwsPolicy)
		p.accountID = c.AccountID
		result = append(result, p)
	}
	return result, nil
}

func (c *mqlCloudflareOneCws) workloads() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	records, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.Workload], error) {
		p := zero_trust.CWSWorkloadListParams{
			AccountID: cloudflare.F(c.AccountID),
			PerPage:   cloudflare.F(int64(cwsPageSize)),
		}
		if cursor != "" {
			p.Cursor = cloudflare.F(cursor)
		}
		return conn.Cf.ZeroTrust.CWS.Workloads.List(context.TODO(), p)
	})
	if err != nil {
		return degradedList(err)
	}

	result := make([]any, 0, len(records))
	for _, rec := range records {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.one.cws.workload", map[string]*llx.RawData{
			"__id":        llx.StringData("cloudflare.one.cws.workload@" + c.AccountID + "/" + rec.ID),
			"id":          llx.StringData(rec.ID),
			"name":        llx.StringData(rec.Name),
			"description": optionalString(rec.Description),
			"filter":      llx.StringData(rec.Filter),
			"tags":        cwsTags(rec.Tags),
			"createdAt":   timeOrNil(rec.CreatedAt),
			"updatedAt":   timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

// cwsDomainACLEntries maps each listed domain to its action. The API allows a
// domain at most once per ACL, so the map loses nothing.
func cwsDomainACLEntries(entries []zero_trust.DomainACLEntry) map[string]any {
	out := make(map[string]any, len(entries))
	for _, e := range entries {
		out[e.Domain] = string(e.Action)
	}
	return out
}

func (c *mqlCloudflareOneCws) domainAcls() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	records, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.DomainACL], error) {
		p := zero_trust.CWSDomainACLListParams{
			AccountID: cloudflare.F(c.AccountID),
			PerPage:   cloudflare.F(int64(cwsPageSize)),
		}
		if cursor != "" {
			p.Cursor = cloudflare.F(cursor)
		}
		return conn.Cf.ZeroTrust.CWS.DomainACLs.List(context.TODO(), p)
	})
	if err != nil {
		return degradedList(err)
	}

	result := make([]any, 0, len(records))
	for _, rec := range records {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.one.cws.domainAcl", map[string]*llx.RawData{
			"__id":          llx.StringData("cloudflare.one.cws.domainAcl@" + c.AccountID + "/" + rec.ID),
			"id":            llx.StringData(rec.ID),
			"name":          llx.StringData(rec.Name),
			"defaultAction": llx.StringData(string(rec.DefaultAction)),
			"entries":       llx.MapData(cwsDomainACLEntries(rec.Entries), types.String),
			"createdAt":     timeOrNil(rec.CreatedAt),
			"updatedAt":     timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		a := res.(*mqlCloudflareOneCwsDomainAcl)
		a.accountID = c.AccountID
		result = append(result, a)
	}
	return result, nil
}

// basicAuthCredentials lists credential metadata only. The secrets endpoint
// under each credential is never called.
func (c *mqlCloudflareOneCws) basicAuthCredentials() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	records, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.BasicAuthCredential], error) {
		p := zero_trust.CWSBasicAuthCredentialListParams{
			AccountID: cloudflare.F(c.AccountID),
			PerPage:   cloudflare.F(int64(cwsPageSize)),
		}
		if cursor != "" {
			p.Cursor = cloudflare.F(cursor)
		}
		return conn.Cf.ZeroTrust.CWS.BasicAuthCredentials.List(context.TODO(), p)
	})
	if err != nil {
		return degradedList(err)
	}

	result := make([]any, 0, len(records))
	for _, rec := range records {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.one.cws.basicAuthCredential", map[string]*llx.RawData{
			"__id":      llx.StringData("cloudflare.one.cws.basicAuthCredential@" + c.AccountID + "/" + rec.ID),
			"id":        llx.StringData(rec.ID),
			"username":  llx.StringData(rec.Username),
			"createdAt": timeOrNil(rec.CreatedAt),
			"updatedAt": timeOrNil(rec.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		b := res.(*mqlCloudflareOneCwsBasicAuthCredential)
		b.accountID = c.AccountID
		result = append(result, b)
	}
	return result, nil
}

func cwsDeploymentID(r any) string                        { return r.(*mqlCloudflareOneCwsDeployment).Id.Data }
func cwsPolicySetID(r any) string                         { return r.(*mqlCloudflareOneCwsPolicySet).Id.Data }
func cwsPolicyID(r any) string                            { return r.(*mqlCloudflareOneCwsPolicy).Id.Data }
func cwsWorkloadID(r any) string                          { return r.(*mqlCloudflareOneCwsWorkload).Id.Data }
func cwsDomainACLID(r any) string                         { return r.(*mqlCloudflareOneCwsDomainAcl).Id.Data }
func cwsCredentialID(r any) string                        { return r.(*mqlCloudflareOneCwsBasicAuthCredential).Id.Data }
func cwsListOrErr(v *plugin.TValue[[]any]) ([]any, error) { return v.Data, v.Error }

// cwsDeploymentsWhere returns the account's deployments for which match is
// true, read from the cached deployment list.
func cwsDeploymentsWhere(runtime *plugin.Runtime, accountID string, match func(*mqlCloudflareOneCwsDeployment) bool) ([]any, error) {
	ns, err := newCws(runtime, accountID)
	if err != nil {
		return nil, err
	}
	all, err := cwsListOrErr(ns.GetDeployments())
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, r := range all {
		if d := r.(*mqlCloudflareOneCwsDeployment); match(d) {
			out = append(out, d)
		}
	}
	return out, nil
}

func (c *mqlCloudflareOneCwsDeployment) policySets() ([]any, error) {
	ns, err := newCws(c.MqlRuntime, c.accountID)
	if err != nil {
		return nil, err
	}
	all, err := cwsListOrErr(ns.GetPolicySets())
	if err != nil {
		return nil, err
	}
	return cwsResolve(c.policySetIDs, all, cwsPolicySetID), nil
}

func (c *mqlCloudflareOneCwsDeployment) domainAcl() (*mqlCloudflareOneCwsDomainAcl, error) {
	if c.domainACLID != "" {
		ns, err := newCws(c.MqlRuntime, c.accountID)
		if err != nil {
			return nil, err
		}
		all, err := cwsListOrErr(ns.GetDomainAcls())
		if err != nil {
			return nil, err
		}
		if found := cwsResolve([]string{c.domainACLID}, all, cwsDomainACLID); len(found) == 1 {
			return found[0].(*mqlCloudflareOneCwsDomainAcl), nil
		}
	}
	c.DomainAcl.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (c *mqlCloudflareOneCwsDeployment) basicAuthCredentials() ([]any, error) {
	ns, err := newCws(c.MqlRuntime, c.accountID)
	if err != nil {
		return nil, err
	}
	all, err := cwsListOrErr(ns.GetBasicAuthCredentials())
	if err != nil {
		return nil, err
	}
	return cwsResolve(c.basicAuthCredentialIDs, all, cwsCredentialID), nil
}

func (c *mqlCloudflareOneCwsPolicySet) members() ([]any, error) {
	out := make([]any, 0, len(c.memberRecs))
	for _, m := range c.memberRecs {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.one.cws.policySetMember", map[string]*llx.RawData{
			"__id":    llx.StringData("cloudflare.one.cws.policySetMember@" + c.accountID + "/" + c.Id.Data + "/" + m.PolicyID),
			"enforce": llx.BoolData(m.Enforce),
		})
		if err != nil {
			return nil, err
		}
		member := res.(*mqlCloudflareOneCwsPolicySetMember)
		member.accountID = c.accountID
		member.policyID = m.PolicyID
		out = append(out, member)
	}
	return out, nil
}

func (c *mqlCloudflareOneCwsPolicySet) workloadsByID(ids []string) ([]any, error) {
	ns, err := newCws(c.MqlRuntime, c.accountID)
	if err != nil {
		return nil, err
	}
	all, err := cwsListOrErr(ns.GetWorkloads())
	if err != nil {
		return nil, err
	}
	return cwsResolve(ids, all, cwsWorkloadID), nil
}

func (c *mqlCloudflareOneCwsPolicySet) includeWorkloads() ([]any, error) {
	return c.workloadsByID(c.includeWorkloadIDs)
}

func (c *mqlCloudflareOneCwsPolicySet) excludeWorkloads() ([]any, error) {
	return c.workloadsByID(c.excludeWorkloadIDs)
}

func (c *mqlCloudflareOneCwsPolicySet) deployments() ([]any, error) {
	id := c.Id.Data
	return cwsDeploymentsWhere(c.MqlRuntime, c.accountID, func(d *mqlCloudflareOneCwsDeployment) bool {
		return slices.Contains(d.policySetIDs, id)
	})
}

func (c *mqlCloudflareOneCwsPolicySetMember) policy() (*mqlCloudflareOneCwsPolicy, error) {
	ns, err := newCws(c.MqlRuntime, c.accountID)
	if err != nil {
		return nil, err
	}
	all, err := cwsListOrErr(ns.GetPolicies())
	if err != nil {
		return nil, err
	}
	if found := cwsResolve([]string{c.policyID}, all, cwsPolicyID); len(found) == 1 {
		return found[0].(*mqlCloudflareOneCwsPolicy), nil
	}
	c.Policy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (c *mqlCloudflareOneCwsPolicy) policySets() ([]any, error) {
	ns, err := newCws(c.MqlRuntime, c.accountID)
	if err != nil {
		return nil, err
	}
	all, err := cwsListOrErr(ns.GetPolicySets())
	if err != nil {
		return nil, err
	}
	id := c.Id.Data
	out := []any{}
	for _, r := range all {
		s := r.(*mqlCloudflareOneCwsPolicySet)
		if slices.ContainsFunc(s.memberRecs, func(m zero_trust.PolicySetPolicy) bool { return m.PolicyID == id }) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (c *mqlCloudflareOneCwsDomainAcl) deployments() ([]any, error) {
	id := c.Id.Data
	return cwsDeploymentsWhere(c.MqlRuntime, c.accountID, func(d *mqlCloudflareOneCwsDeployment) bool {
		return d.domainACLID == id
	})
}

func (c *mqlCloudflareOneCwsBasicAuthCredential) deployments() ([]any, error) {
	id := c.Id.Data
	return cwsDeploymentsWhere(c.MqlRuntime, c.accountID, func(d *mqlCloudflareOneCwsDeployment) bool {
		return slices.Contains(d.basicAuthCredentialIDs, id)
	})
}
