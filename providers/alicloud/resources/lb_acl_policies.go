// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	albclient "github.com/alibabacloud-go/alb-20200616/v2/client"
	nlbclient "github.com/alibabacloud-go/nlb-20220430/v4/client"
	slbclient "github.com/alibabacloud-go/slb-20140515/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// lbPageSize is the page size used for the load balancer ACL and security
// policy listings.
const lbPageSize = 100

// tlsLegacyVersions are the TLS versions that are deprecated and carry known
// weaknesses. A policy permitting either accepts connections a current client
// would refuse to make.
var tlsLegacyVersions = map[string]struct{}{
	"tlsv1.0": {},
	"tlsv1":   {},
	"tlsv1.1": {},
}

// tlsAllowsLegacy reports whether a TLS version list still admits TLS 1.0 or
// 1.1. Versions are compared case-insensitively, and both the "TLSv1" and
// "TLSv1.0" spellings of the oldest version are recognized.
func tlsAllowsLegacy(versions []string) bool {
	for _, v := range versions {
		if _, legacy := tlsLegacyVersions[strings.ToLower(strings.TrimSpace(v))]; legacy {
			return true
		}
	}
	return false
}

// splitCommaList splits a comma-separated API value, dropping blank entries.
// NLB returns a security policy's cipher suites this way where ALB returns a
// repeated field, so the two are normalized to the same list shape.
func splitCommaList(raw *string) []string {
	value := strings.TrimSpace(tea.StringValue(raw))
	if value == "" {
		return nil
	}
	res := []string{}
	for entry := range strings.SplitSeq(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		res = append(res, entry)
	}
	return res
}

// aclCoversAllAddresses reports whether an access control list admits every
// address. Only the two default routes count: a /0 in either address family
// covers the whole internet, while any narrower prefix restricts something.
func aclCoversAllAddresses(entries []any) bool {
	for _, entry := range entries {
		cidr, ok := entry.(string)
		if !ok {
			continue
		}
		switch strings.TrimSpace(cidr) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// alicloud.slb.acl
// ---------------------------------------------------------------------------

// mqlAlicloudSlbAclInternal memoizes the list's address entries, which the
// entries, entryCount and allowsAllAddresses fields all read.
type mqlAlicloudSlbAclInternal struct {
	entriesOnce sync.Once
	entryList   []any
	entriesErr  error
}

func (r *mqlAlicloudSlbAcl) id() (string, error) {
	return r.RegionId.Data + "/" + r.AclId.Data, nil
}

func (r *mqlAlicloudSlbAcl) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// acls enumerates the account's CLB access control lists across every scanned
// region. A region that is not activated, or that the credentials may not read,
// is skipped rather than failing the whole listing.
func (r *mqlAlicloudSlb) acls() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.SlbClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		collected := int32(0)
		for {
			resp, err := client.DescribeAccessControlLists(&slbclient.DescribeAccessControlListsRequest{
				RegionId:   new(region),
				PageNumber: new(pageNumber),
				PageSize:   tea.Int32(lbPageSize),
			})
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list CLB access control lists")
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.Acls == nil {
				break
			}
			items := resp.Body.Acls.Acl
			for _, acl := range items {
				if acl == nil || acl.AclId == nil {
					continue
				}
				tags := map[string]any{}
				if acl.Tags != nil {
					for _, t := range acl.Tags.Tag {
						if t == nil || t.TagKey == nil {
							continue
						}
						tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
					}
				}
				resource, err := CreateResource(r.MqlRuntime, "alicloud.slb.acl", map[string]*llx.RawData{
					"__id":             llx.StringData(region + "/" + tea.StringValue(acl.AclId)),
					"regionId":         llx.StringData(region),
					"aclId":            llx.StringDataPtr(acl.AclId),
					"aclName":          llx.StringDataPtr(acl.AclName),
					"addressIPVersion": llx.StringDataPtr(acl.AddressIPVersion),
					"resourceGroupId":  llx.StringDataPtr(acl.ResourceGroupId),
					"tags":             llx.MapData(tags, types.String),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			collected += int32(len(items))
			if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// aclEntries reads the list's address entries once. The entries come from a
// separate paged endpoint, so the three fields that read them share one walk.
func (r *mqlAlicloudSlbAcl) aclEntries() ([]any, error) {
	r.entriesOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.SlbClient(r.RegionId.Data)
		if err != nil {
			r.entriesErr = err
			return
		}

		entries := []any{}
		page := int32(1)
		collected := int32(0)
		for {
			resp, err := client.DescribeAccessControlListAttribute(&slbclient.DescribeAccessControlListAttributeRequest{
				RegionId: new(r.RegionId.Data),
				AclId:    new(r.AclId.Data),
				Page:     new(page),
				PageSize: tea.Int32(lbPageSize),
			})
			if err != nil {
				r.entriesErr = err
				return
			}
			if resp == nil || resp.Body == nil || resp.Body.AclEntrys == nil {
				break
			}
			items := resp.Body.AclEntrys.AclEntry
			for _, e := range items {
				if e == nil || e.AclEntryIP == nil {
					continue
				}
				entries = append(entries, tea.StringValue(e.AclEntryIP))
			}
			collected += int32(len(items))
			if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalAclEntry) {
				break
			}
			page++
		}
		r.entryList = entries
	})
	return r.entryList, r.entriesErr
}

func (r *mqlAlicloudSlbAcl) entries() ([]any, error) {
	return r.aclEntries()
}

func (r *mqlAlicloudSlbAcl) entryCount() (int64, error) {
	entries, err := r.aclEntries()
	if err != nil {
		return 0, err
	}
	return int64(len(entries)), nil
}

func (r *mqlAlicloudSlbAcl) allowsAllAddresses() (bool, error) {
	entries, err := r.aclEntries()
	if err != nil {
		return false, err
	}
	return aclCoversAllAddresses(entries), nil
}

// acls resolves the access control lists a CLB listener names. The lists are
// resolved by scanning alicloud.slb.acls, which is fetched once for the whole
// scan, rather than by a lookup per listener.
func (r *mqlAlicloudSlbListener) acls() ([]any, error) {
	wanted := map[string]struct{}{}
	if id := r.AclId.Data; id != "" {
		wanted[id] = struct{}{}
	}
	for _, entry := range r.AclIds.Data {
		if id, ok := entry.(string); ok && id != "" {
			wanted[id] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return []any{}, nil
	}

	slb, err := CreateResource(r.MqlRuntime, "alicloud.slb", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	acls := slb.(*mqlAlicloudSlb).GetAcls()
	if acls.Error != nil {
		log.Debug().Err(acls.Error).Msg("alicloud> could not resolve the ACLs bound to a CLB listener")
		return []any{}, nil
	}

	res := []any{}
	for _, entry := range acls.Data {
		acl, ok := entry.(*mqlAlicloudSlbAcl)
		if !ok {
			continue
		}
		if _, match := wanted[acl.AclId.Data]; match {
			res = append(res, acl)
		}
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// alicloud.alb.securityPolicy
// ---------------------------------------------------------------------------

func (r *mqlAlicloudAlbSecurityPolicy) id() (string, error) {
	return r.RegionId.Data + "/" + r.SecurityPolicyId.Data, nil
}

func (r *mqlAlicloudAlbSecurityPolicy) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

func (r *mqlAlicloudAlb) securityPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.AlbClient(region)
		if err != nil {
			return nil, err
		}

		req := &albclient.ListSecurityPoliciesRequest{MaxResults: tea.Int32(lbPageSize)}
		for {
			resp, err := client.ListSecurityPolicies(req)
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list ALB security policies")
				break
			}
			if resp == nil || resp.Body == nil {
				break
			}
			for _, p := range resp.Body.SecurityPolicies {
				if p == nil || p.SecurityPolicyId == nil {
					continue
				}
				tags := map[string]any{}
				for _, t := range p.Tags {
					if t == nil || t.Key == nil {
						continue
					}
					tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
				}
				versions := strPtrsToStrings(p.TLSVersions)
				resource, err := CreateResource(r.MqlRuntime, "alicloud.alb.securityPolicy", map[string]*llx.RawData{
					"__id":               llx.StringData(region + "/" + tea.StringValue(p.SecurityPolicyId)),
					"regionId":           llx.StringData(region),
					"securityPolicyId":   llx.StringDataPtr(p.SecurityPolicyId),
					"securityPolicyName": llx.StringDataPtr(p.SecurityPolicyName),
					"status":             llx.StringDataPtr(p.SecurityPolicyStatus),
					"tlsVersions":        llx.ArrayData(strsToAny(versions), types.String),
					"ciphers":            llx.ArrayData(strPtrsToAny(p.Ciphers), types.String),
					"allowsLegacyTls":    llx.BoolData(tlsAllowsLegacy(versions)),
					"resourceGroupId":    llx.StringDataPtr(p.ResourceGroupId),
					"tags":               llx.MapData(tags, types.String),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			if tea.StringValue(resp.Body.NextToken) == "" {
				break
			}
			req.NextToken = resp.Body.NextToken
		}
	}
	return res, nil
}

// securityPolicy resolves the custom TLS policy an ALB listener names, by
// scanning alicloud.alb.securityPolicies, which is fetched once for the scan.
// A listener using one of the built-in policies resolves to null, because those
// are not enumerable; securityPolicyId names them.
func (r *mqlAlicloudAlbListener) securityPolicy() (*mqlAlicloudAlbSecurityPolicy, error) {
	wanted := r.SecurityPolicyId.Data
	if wanted == "" {
		r.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	alb, err := CreateResource(r.MqlRuntime, "alicloud.alb", map[string]*llx.RawData{})
	if err != nil {
		r.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	policies := alb.(*mqlAlicloudAlb).GetSecurityPolicies()
	if policies.Error != nil {
		log.Debug().Err(policies.Error).Msg("alicloud> could not resolve an ALB listener security policy")
		r.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, entry := range policies.Data {
		policy, ok := entry.(*mqlAlicloudAlbSecurityPolicy)
		if ok && policy.SecurityPolicyId.Data == wanted {
			return policy, nil
		}
	}
	r.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ---------------------------------------------------------------------------
// alicloud.nlb.securityPolicy
// ---------------------------------------------------------------------------

func (r *mqlAlicloudNlbSecurityPolicy) id() (string, error) {
	return r.RegionId.Data + "/" + r.SecurityPolicyId.Data, nil
}

func (r *mqlAlicloudNlbSecurityPolicy) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// securityPolicies enumerates the account's custom NLB TLS policies. The
// operation is ListSecurityPolicy, singular: NLB has no plural form, unlike
// ALB.
func (r *mqlAlicloudNlb) securityPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.NlbClient(region)
		if err != nil {
			return nil, err
		}

		req := &nlbclient.ListSecurityPolicyRequest{
			RegionId:   new(region),
			MaxResults: tea.Int32(lbPageSize),
		}
		for {
			resp, err := client.ListSecurityPolicy(req)
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list NLB security policies")
				break
			}
			if resp == nil || resp.Body == nil {
				break
			}
			for _, p := range resp.Body.SecurityPolicies {
				if p == nil || p.SecurityPolicyId == nil {
					continue
				}
				tags := map[string]any{}
				for _, t := range p.Tags {
					if t == nil || t.Key == nil {
						continue
					}
					tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
				}
				// NLB returns both members as comma-separated strings where ALB
				// returns repeated fields
				versions := splitCommaList(p.TlsVersion)
				resource, err := CreateResource(r.MqlRuntime, "alicloud.nlb.securityPolicy", map[string]*llx.RawData{
					"__id":               llx.StringData(region + "/" + tea.StringValue(p.SecurityPolicyId)),
					"regionId":           llx.StringData(region),
					"securityPolicyId":   llx.StringDataPtr(p.SecurityPolicyId),
					"securityPolicyName": llx.StringDataPtr(p.SecurityPolicyName),
					"status":             llx.StringDataPtr(p.SecurityPolicyStatus),
					"tlsVersions":        llx.ArrayData(strsToAny(versions), types.String),
					"ciphers":            llx.ArrayData(strsToAny(splitCommaList(p.Ciphers)), types.String),
					"allowsLegacyTls":    llx.BoolData(tlsAllowsLegacy(versions)),
					"resourceGroupId":    llx.StringDataPtr(p.ResourceGroupId),
					"tags":               llx.MapData(tags, types.String),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			if tea.StringValue(resp.Body.NextToken) == "" {
				break
			}
			req.NextToken = resp.Body.NextToken
		}
	}
	return res, nil
}

// securityPolicy resolves the custom TLS policy an NLB listener names, by
// scanning alicloud.nlb.securityPolicies, which is fetched once for the scan.
func (r *mqlAlicloudNlbListener) securityPolicy() (*mqlAlicloudNlbSecurityPolicy, error) {
	wanted := r.SecurityPolicyId.Data
	if wanted == "" {
		r.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	nlb, err := CreateResource(r.MqlRuntime, "alicloud.nlb", map[string]*llx.RawData{})
	if err != nil {
		r.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	policies := nlb.(*mqlAlicloudNlb).GetSecurityPolicies()
	if policies.Error != nil {
		log.Debug().Err(policies.Error).Msg("alicloud> could not resolve an NLB listener security policy")
		r.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, entry := range policies.Data {
		policy, ok := entry.(*mqlAlicloudNlbSecurityPolicy)
		if ok && policy.SecurityPolicyId.Data == wanted {
			return policy, nil
		}
	}
	r.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
