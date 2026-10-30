// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/networkfirewall"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
)

// The lists a network firewall policy's rules are written against.
//
// A security rule does not carry addresses, ports or URL patterns: it carries
// the *names* of lists that hold them. Without those lists a rule reads as
// "allow from corp-ranges" with no way to learn whether corp-ranges is a pair
// of office prefixes or 0.0.0.0/0, which is the difference between a policy
// that constrains traffic and one that does not.
//
// Every list here is enumerated by a call that returns names and counts only;
// the members come from a per-item Get. So the membership fields are computed
// and fetched on demand, which keeps listing a policy's lists cheap and pays
// for contents only where a query asks for them.

// ----- address lists -----

type mqlOciNetworkFirewallPolicyAddressListInternal struct {
	cachePolicyID string
	cacheRegion   string
	detail        ociRetryLazy[*networkfirewall.AddressList]
}

func (o *mqlOciNetworkFirewallPolicyAddressList) fetchDetail() (*networkfirewall.AddressList, error) {
	return o.detail.get(func() (*networkfirewall.AddressList, error) {
		svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetAddressList(context.Background(), networkfirewall.GetAddressListRequest{
			NetworkFirewallPolicyId: new(o.cachePolicyID),
			AddressListName:         new(o.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.AddressList, nil
	})
}

func (o *mqlOciNetworkFirewallPolicyAddressList) addresses() ([]any, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	return stringsToAny(detail.Addresses), nil
}

func (o *mqlOciNetworkFirewallPolicy) addressLists() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.AddressListSummary, *string, error) {
		resp, err := svc.ListAddressLists(ctx, networkfirewall.ListAddressListsRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.AddressListSummaryCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		a := items[i]
		name := stringValue(a.Name)

		mqlList, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.addressList", map[string]*llx.RawData{
			"__id":           llx.StringData(o.Id.Data + "/addressList/" + name),
			"name":           llx.StringData(name),
			"type":           llx.StringData(string(a.Type)),
			"description":    llx.StringDataPtr(a.Description),
			"totalAddresses": llx.IntData(intValue(a.TotalAddresses)),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlList.(*mqlOciNetworkFirewallPolicyAddressList)
		typed.cachePolicyID = o.Id.Data
		typed.cacheRegion = o.cacheRegion
		res = append(res, typed)
	}
	return res, nil
}

// ----- URL lists -----

type mqlOciNetworkFirewallPolicyUrlListInternal struct {
	cachePolicyID string
	cacheRegion   string
	detail        ociRetryLazy[*networkfirewall.UrlList]
}

func (o *mqlOciNetworkFirewallPolicyUrlList) urls() ([]any, error) {
	detail, err := o.detail.get(func() (*networkfirewall.UrlList, error) {
		svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetUrlList(context.Background(), networkfirewall.GetUrlListRequest{
			NetworkFirewallPolicyId: new(o.cachePolicyID),
			UrlListName:             new(o.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.UrlList, nil
	})
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(detail.Urls)
}

func (o *mqlOciNetworkFirewallPolicy) urlLists() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.UrlListSummary, *string, error) {
		resp, err := svc.ListUrlLists(ctx, networkfirewall.ListUrlListsRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.UrlListSummaryCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		u := items[i]
		name := stringValue(u.Name)

		mqlList, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.urlList", map[string]*llx.RawData{
			"__id":        llx.StringData(o.Id.Data + "/urlList/" + name),
			"name":        llx.StringData(name),
			"description": llx.StringDataPtr(u.Description),
			"totalUrls":   llx.IntData(intValue(u.TotalUrls)),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlList.(*mqlOciNetworkFirewallPolicyUrlList)
		typed.cachePolicyID = o.Id.Data
		typed.cacheRegion = o.cacheRegion
		res = append(res, typed)
	}
	return res, nil
}

// ----- services and service lists -----

type mqlOciNetworkFirewallPolicyServiceInternal struct {
	cachePolicyID string
	cacheRegion   string
	detail        ociRetryLazy[networkfirewall.Service]
}

// portRanges returns the port ranges the service covers.
//
// The listing reports only the service's name and transport, so the ranges -
// the part that decides what the service actually admits - come from a Get.
func (o *mqlOciNetworkFirewallPolicyService) portRanges() ([]any, error) {
	detail, err := o.detail.get(func() (networkfirewall.Service, error) {
		svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetService(context.Background(), networkfirewall.GetServiceRequest{
			NetworkFirewallPolicyId: new(o.cachePolicyID),
			ServiceName:             new(o.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		return resp.Service, nil
	})
	if err != nil {
		return nil, err
	}

	// Service is a union over the transports. Both members carry port ranges,
	// but they are separate fields on separate structs rather than a shared
	// accessor, so each has to be named.
	//
	// An unhandled member is an error rather than an empty list. Returning no
	// ranges would render as `[]`, which reads as "this service covers no
	// ports" - a wrong answer that looks like a real one, and the exact shape
	// of silent under-reporting this provider treats as worse than failing.
	// TestNetworkFirewallServiceUnionMembers catches a new transport at build
	// time; this catches it at runtime if that test is ever bypassed.
	switch s := detail.(type) {
	case networkfirewall.TcpService:
		return convert.JsonToDictSlice(s.PortRanges)
	case networkfirewall.UdpService:
		return convert.JsonToDictSlice(s.PortRanges)
	default:
		return nil, fmt.Errorf(
			"oci.networkFirewall.policy.service %q: unhandled service type %T", o.Name.Data, detail)
	}
}

func (o *mqlOciNetworkFirewallPolicy) services() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.ServiceSummary, *string, error) {
		resp, err := svc.ListServices(ctx, networkfirewall.ListServicesRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.ServiceSummaryCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		s := items[i]
		name := stringValue(s.Name)

		mqlService, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.service", map[string]*llx.RawData{
			"__id":        llx.StringData(o.Id.Data + "/service/" + name),
			"name":        llx.StringData(name),
			"type":        llx.StringData(string(s.Type)),
			"description": llx.StringDataPtr(s.Description),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlService.(*mqlOciNetworkFirewallPolicyService)
		typed.cachePolicyID = o.Id.Data
		typed.cacheRegion = o.cacheRegion
		res = append(res, typed)
	}
	return res, nil
}

type mqlOciNetworkFirewallPolicyServiceListInternal struct {
	cachePolicyID string
	cacheRegion   string
	detail        ociRetryLazy[*networkfirewall.ServiceList]
}

func (o *mqlOciNetworkFirewallPolicyServiceList) services() ([]any, error) {
	detail, err := o.detail.get(func() (*networkfirewall.ServiceList, error) {
		svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetServiceList(context.Background(), networkfirewall.GetServiceListRequest{
			NetworkFirewallPolicyId: new(o.cachePolicyID),
			ServiceListName:         new(o.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.ServiceList, nil
	})
	if err != nil {
		return nil, err
	}
	return stringsToAny(detail.Services), nil
}

func (o *mqlOciNetworkFirewallPolicy) serviceLists() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.ServiceListSummary, *string, error) {
		resp, err := svc.ListServiceLists(ctx, networkfirewall.ListServiceListsRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.ServiceListSummaryCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		s := items[i]
		name := stringValue(s.Name)

		mqlList, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.serviceList", map[string]*llx.RawData{
			"__id":          llx.StringData(o.Id.Data + "/serviceList/" + name),
			"name":          llx.StringData(name),
			"description":   llx.StringDataPtr(s.Description),
			"totalServices": llx.IntData(intValue(s.TotalServices)),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlList.(*mqlOciNetworkFirewallPolicyServiceList)
		typed.cachePolicyID = o.Id.Data
		typed.cacheRegion = o.cacheRegion
		res = append(res, typed)
	}
	return res, nil
}

// ----- applications and application groups -----

func (o *mqlOciNetworkFirewallPolicy) applications() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.ApplicationSummary, *string, error) {
		resp, err := svc.ListApplications(ctx, networkfirewall.ListApplicationsRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.ApplicationSummaryCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		fields := ociFirewallApplicationFields(items[i])
		if fields == nil {
			// Skipping would drop the application from the policy's list
			// entirely, so a rule naming it would resolve to nothing and read
			// as matching no traffic.
			return nil, fmt.Errorf(
				"oci.networkFirewall.policy %q: unhandled application type %T", o.Id.Data, items[i])
		}
		fields["__id"] = llx.StringData(o.Id.Data + "/application/" + fields["name"].Value.(string))

		mqlApp, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.application", fields)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlApp)
	}
	return res, nil
}

// ociFirewallApplicationFields flattens one member of the ApplicationSummary
// union into resource fields, or returns nil for a member it does not know.
//
// Both current members describe an ICMP message, differing only in the protocol
// they belong to, so the discriminator is carried as a `type` field rather than
// each becoming its own resource. Returning nil for an unrecognised member drops
// it rather than reporting it as an ICMP application with zeroed codes.
//
// This union is the one the sibling drift tests cannot cover: the SDK gives it
// no discriminator enum, so TestNetworkFirewallApplicationUnionMembers pins the
// known members rather than deriving them. Re-read the SDK's
// application_summary.go on an upgrade.
func ociFirewallApplicationFields(summary networkfirewall.ApplicationSummary) map[string]*llx.RawData {
	switch a := summary.(type) {
	case networkfirewall.IcmpApplicationSummary:
		return map[string]*llx.RawData{
			"name":        llx.StringDataPtr(a.Name),
			"type":        llx.StringData("ICMP"),
			"description": llx.StringDataPtr(a.Description),
			"icmpType":    llx.IntData(intValue(a.IcmpType)),
			"icmpCode":    ociOptionalInt(a.IcmpCode),
		}
	case networkfirewall.Icmp6ApplicationSummary:
		return map[string]*llx.RawData{
			"name":        llx.StringDataPtr(a.Name),
			"type":        llx.StringData("ICMP6"),
			"description": llx.StringDataPtr(a.Description),
			"icmpType":    llx.IntData(intValue(a.IcmpType)),
			"icmpCode":    ociOptionalInt(a.IcmpCode),
		}
	default:
		return nil
	}
}

// ociOptionalInt keeps an absent integer null rather than reporting it as zero.
//
// An ICMP application with no code matches every code of its type, which is not
// the same statement as matching code 0 - and code 0 is a real, common value
// (echo reply), so the zero-value reading would be both wrong and plausible.
func ociOptionalInt(v *int) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.IntData(int64(*v))
}

type mqlOciNetworkFirewallPolicyApplicationGroupInternal struct {
	cachePolicyID string
	cacheRegion   string
	detail        ociRetryLazy[*networkfirewall.ApplicationGroup]
}

func (o *mqlOciNetworkFirewallPolicyApplicationGroup) applications() ([]any, error) {
	detail, err := o.detail.get(func() (*networkfirewall.ApplicationGroup, error) {
		svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetApplicationGroup(context.Background(), networkfirewall.GetApplicationGroupRequest{
			NetworkFirewallPolicyId: new(o.cachePolicyID),
			ApplicationGroupName:    new(o.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.ApplicationGroup, nil
	})
	if err != nil {
		return nil, err
	}
	return stringsToAny(detail.Apps), nil
}

func (o *mqlOciNetworkFirewallPolicy) applicationGroups() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.ApplicationGroupSummary, *string, error) {
		resp, err := svc.ListApplicationGroups(ctx, networkfirewall.ListApplicationGroupsRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.ApplicationGroupSummaryCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		g := items[i]
		name := stringValue(g.Name)

		mqlGroup, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.applicationGroup", map[string]*llx.RawData{
			"__id":        llx.StringData(o.Id.Data + "/applicationGroup/" + name),
			"name":        llx.StringData(name),
			"description": llx.StringDataPtr(g.Description),
			"totalApps":   llx.IntData(intValue(g.TotalApps)),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlGroup.(*mqlOciNetworkFirewallPolicyApplicationGroup)
		typed.cachePolicyID = o.Id.Data
		typed.cacheRegion = o.cacheRegion
		res = append(res, typed)
	}
	return res, nil
}

// ----- mapped secrets -----

type mqlOciNetworkFirewallPolicyMappedSecretInternal struct {
	cachePolicyID string
	cacheRegion   string
	detail        ociRetryLazy[networkfirewall.MappedSecret]
}

// fetchDetail resolves the vault secret behind a mapped secret. The listing
// names the secret but not where it lives, and the Vault reference is the whole
// point of the resource, so it comes from a Get.
func (o *mqlOciNetworkFirewallPolicyMappedSecret) fetchDetail() (networkfirewall.MappedSecret, error) {
	return o.detail.get(func() (networkfirewall.MappedSecret, error) {
		svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetMappedSecret(context.Background(), networkfirewall.GetMappedSecretRequest{
			NetworkFirewallPolicyId: new(o.cachePolicyID),
			MappedSecretName:        new(o.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		return resp.MappedSecret, nil
	})
}

func (o *mqlOciNetworkFirewallPolicyMappedSecret) vaultSecret() (*mqlOciVaultSecret, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}

	vaultSecret, ok := detail.(networkfirewall.VaultMappedSecret)
	if !ok || vaultSecret.VaultSecretId == nil || *vaultSecret.VaultSecretId == "" {
		o.VaultSecret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(o.MqlRuntime, "oci.vault.secret", map[string]*llx.RawData{
		"id": llx.StringDataPtr(vaultSecret.VaultSecretId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciVaultSecret), nil
}

func (o *mqlOciNetworkFirewallPolicyMappedSecret) vaultSecretVersionNumber() (int64, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return 0, err
	}

	vaultSecret, ok := detail.(networkfirewall.VaultMappedSecret)
	if !ok || vaultSecret.VersionNumber == nil {
		o.VaultSecretVersionNumber.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*vaultSecret.VersionNumber), nil
}

func (o *mqlOciNetworkFirewallPolicy) mappedSecrets() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.MappedSecretSummary, *string, error) {
		resp, err := svc.ListMappedSecrets(ctx, networkfirewall.ListMappedSecretsRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.MappedSecretSummaryCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		s := items[i]
		name := stringValue(s.Name)

		mqlSecret, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.mappedSecret", map[string]*llx.RawData{
			"__id":   llx.StringData(o.Id.Data + "/mappedSecret/" + name),
			"name":   llx.StringData(name),
			"type":   llx.StringData(string(s.Type)),
			"source": llx.StringDataPtr(s.Source),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlSecret.(*mqlOciNetworkFirewallPolicyMappedSecret)
		typed.cachePolicyID = o.Id.Data
		typed.cacheRegion = o.cacheRegion
		res = append(res, typed)
	}
	return res, nil
}

// ----- NAT and tunnel inspection rules -----

func (o *mqlOciNetworkFirewallPolicy) natRules() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.NatRuleSummary, *string, error) {
		resp, err := svc.ListNatRules(ctx, networkfirewall.ListNatRulesRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.NatRuleCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		nat, ok := items[i].(networkfirewall.NatV4NatSummary)
		if !ok {
			// Skipping would leave the rule out of the policy's list, so an
			// audit counting NAT rules would under-report - and a NAT rule
			// changes which address downstream controls observe.
			return nil, fmt.Errorf(
				"oci.networkFirewall.policy %q: unhandled NAT rule type %T", o.Id.Data, items[i])
		}
		name := stringValue(nat.Name)

		condition, err := convert.JsonToDict(nat.Condition)
		if err != nil {
			return nil, err
		}

		mqlRule, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.natRule", map[string]*llx.RawData{
			"__id":          llx.StringData(o.Id.Data + "/natRule/" + name),
			"name":          llx.StringData(name),
			"action":        llx.StringData(string(nat.Action)),
			"priorityOrder": llx.IntDataPtr(nat.PriorityOrder),
			"description":   llx.StringDataPtr(nat.Description),
			"condition":     llx.DictData(condition),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (o *mqlOciNetworkFirewallPolicy) tunnelInspectionRules() ([]any, error) {
	svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]networkfirewall.TunnelInspectionRuleSummary, *string, error) {
		resp, err := svc.ListTunnelInspectionRules(ctx, networkfirewall.ListTunnelInspectionRulesRequest{
			NetworkFirewallPolicyId: new(o.Id.Data),
			Page:                    page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.TunnelInspectionRuleSummaryCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		rule, ok := items[i].(networkfirewall.VxlanInspectionRuleSummary)
		if !ok {
			// The absence of a tunnel inspection rule is itself a finding, so
			// dropping one silently would manufacture that finding.
			return nil, fmt.Errorf(
				"oci.networkFirewall.policy %q: unhandled tunnel inspection rule type %T", o.Id.Data, items[i])
		}
		name := stringValue(rule.Name)

		condition, err := convert.JsonToDict(rule.Condition)
		if err != nil {
			return nil, err
		}
		profile, err := convert.JsonToDict(rule.Profile)
		if err != nil {
			return nil, err
		}

		mqlRule, err := CreateResource(o.MqlRuntime, "oci.networkFirewall.policy.tunnelInspectionRule", map[string]*llx.RawData{
			"__id":          llx.StringData(o.Id.Data + "/tunnelInspectionRule/" + name),
			"name":          llx.StringData(name),
			"protocol":      llx.StringData("VXLAN"),
			"action":        llx.StringData(string(rule.Action)),
			"priorityOrder": llx.IntDataPtr(rule.PriorityOrder),
			"description":   llx.StringDataPtr(rule.Description),
			"condition":     llx.DictData(condition),
			"profile":       llx.DictData(profile),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

// ----- security rule conditions -----

// A security rule keeps a pointer to the policy that owns it rather than the
// policy's OCID.
//
// Its typed accessors resolve list names against the policy's collections, and
// those collections are already fetched and cached on the policy resource.
// Going back through NewResource per rule would run the policy's init before
// the runtime cache is consulted, turning one listing into a call per rule.
type mqlOciNetworkFirewallPolicySecurityRuleInternal struct {
	cachePolicy *mqlOciNetworkFirewallPolicy
	detail      ociRetryLazy[*networkfirewall.SecurityRule]
}

// condition returns what the rule matches on, by list name.
//
// The listing omits the match criteria entirely - it reports the verdict and
// the priority but not what the verdict applies to - so this is a per-rule Get.
// It stays computed rather than eager for that reason: a query that only reads
// actions across a policy should not pay a call per rule.
func (o *mqlOciNetworkFirewallPolicySecurityRule) condition() (any, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.Condition == nil {
		return nil, nil
	}
	return convert.JsonToDict(detail.Condition)
}

func (o *mqlOciNetworkFirewallPolicySecurityRule) fetchDetail() (*networkfirewall.SecurityRule, error) {
	return o.detail.get(func() (*networkfirewall.SecurityRule, error) {
		if o.cachePolicy == nil {
			return nil, errors.New("oci.networkFirewall.policy.securityRule: the owning policy is not known")
		}
		svc, err := ociNetworkFirewallClient(o.MqlRuntime, o.cachePolicy.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetSecurityRule(context.Background(), networkfirewall.GetSecurityRuleRequest{
			NetworkFirewallPolicyId: new(o.cachePolicy.Id.Data),
			SecurityRuleName:        new(o.Name.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.SecurityRule, nil
	})
}

// conditionNames returns the list names the rule matches on for one criteria
// key, having fetched the condition once.
func (o *mqlOciNetworkFirewallPolicySecurityRule) conditionNames(key string) ([]string, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.Condition == nil {
		return nil, nil
	}

	switch key {
	case "sourceAddress":
		return detail.Condition.SourceAddress, nil
	case "destinationAddress":
		return detail.Condition.DestinationAddress, nil
	case "application":
		return detail.Condition.Application, nil
	case "service":
		return detail.Condition.Service, nil
	case "url":
		return detail.Condition.Url, nil
	default:
		return nil, nil
	}
}

// resolveRuleLists maps the names under one criteria key onto the policy
// collection that holds them.
//
// An empty result and a nil result mean different things here and the caller
// keeps them apart: no names under the key means the rule constrains nothing on
// that dimension, which is the permissive reading, not an empty match.
func (o *mqlOciNetworkFirewallPolicySecurityRule) resolveRuleLists(
	key string,
	collection func(*mqlOciNetworkFirewallPolicy) *plugin.TValue[[]any],
	nameOf func(any) (string, bool),
) ([]any, error) {
	names, err := o.conditionNames(key)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return []any{}, nil
	}
	if o.cachePolicy == nil {
		return []any{}, nil
	}

	items := collection(o.cachePolicy)
	if items.Error != nil {
		return nil, items.Error
	}
	return ociFirewallSelectByName(items.Data, names, nameOf), nil
}

func ociFirewallNameOfAddressList(item any) (string, bool) {
	l, ok := item.(*mqlOciNetworkFirewallPolicyAddressList)
	if !ok {
		return "", false
	}
	return l.Name.Data, true
}

func ociFirewallNameOfUrlList(item any) (string, bool) {
	l, ok := item.(*mqlOciNetworkFirewallPolicyUrlList)
	if !ok {
		return "", false
	}
	return l.Name.Data, true
}

func ociFirewallNameOfApplication(item any) (string, bool) {
	a, ok := item.(*mqlOciNetworkFirewallPolicyApplication)
	if !ok {
		return "", false
	}
	return a.Name.Data, true
}

func ociFirewallNameOfService(item any) (string, bool) {
	s, ok := item.(*mqlOciNetworkFirewallPolicyService)
	if !ok {
		return "", false
	}
	return s.Name.Data, true
}

func (o *mqlOciNetworkFirewallPolicySecurityRule) sourceAddressLists() ([]any, error) {
	return o.resolveRuleLists("sourceAddress",
		(*mqlOciNetworkFirewallPolicy).GetAddressLists, ociFirewallNameOfAddressList)
}

func (o *mqlOciNetworkFirewallPolicySecurityRule) destinationAddressLists() ([]any, error) {
	return o.resolveRuleLists("destinationAddress",
		(*mqlOciNetworkFirewallPolicy).GetAddressLists, ociFirewallNameOfAddressList)
}

func (o *mqlOciNetworkFirewallPolicySecurityRule) applications() ([]any, error) {
	return o.resolveRuleLists("application",
		(*mqlOciNetworkFirewallPolicy).GetApplications, ociFirewallNameOfApplication)
}

func (o *mqlOciNetworkFirewallPolicySecurityRule) services() ([]any, error) {
	return o.resolveRuleLists("service",
		(*mqlOciNetworkFirewallPolicy).GetServices, ociFirewallNameOfService)
}

func (o *mqlOciNetworkFirewallPolicySecurityRule) urlLists() ([]any, error) {
	return o.resolveRuleLists("url",
		(*mqlOciNetworkFirewallPolicy).GetUrlLists, ociFirewallNameOfUrlList)
}

// ociNetworkFirewallClient builds a network firewall client for one region.
func ociNetworkFirewallClient(runtime *plugin.Runtime, region string) (*networkfirewall.NetworkFirewallClient, error) {
	conn := runtime.Connection.(*connection.OciConnection)
	return conn.NetworkFirewallClient(region)
}

// ociFirewallSelectByName picks the members of a policy collection whose name
// appears in the given list, preserving the collection's order.
func ociFirewallSelectByName(items []any, names []string, nameOf func(any) (string, bool)) []any {
	if len(names) == 0 {
		return []any{}
	}
	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		wanted[strings.ToLower(n)] = true
	}

	res := []any{}
	for _, item := range items {
		name, ok := nameOf(item)
		if !ok {
			continue
		}
		if wanted[strings.ToLower(name)] {
			res = append(res, item)
		}
	}
	return res
}
