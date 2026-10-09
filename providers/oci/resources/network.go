// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciNetwork) id() (string, error) {
	return "oci.network", nil
}

func (o *mqlOciNetwork) vcns() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// ListVcns takes one compartment and has no subtree flag, so asking only for
	// the tenancy root returned an empty VCN list for anyone who keeps their
	// networking in a child compartment. Walking the compartment tree is what
	// makes the whole network graph, subnets and route tables and gateways
	// included, hang off something that actually exists.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			vcns, err := o.getVcnsForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range vcns {
				vcn := vcns[i]

				var created *time.Time
				if vcn.TimeCreated != nil {
					created = &vcn.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.vcn", stringValue(vcn.CompartmentId), map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(vcn.Id),
					"name":                  llx.StringDataPtr(vcn.DisplayName),
					"created":               llx.TimeDataPtr(created),
					"state":                 llx.StringData(string(vcn.LifecycleState)),
					"cidrBlocks":            llx.ArrayData(convert.SliceAnyToInterface(vcn.CidrBlocks), types.String),
					"ipv6CidrBlocks":        llx.ArrayData(convert.SliceAnyToInterface(vcn.Ipv6CidrBlocks), types.String),
					"byoipv6CidrBlocks":     llx.ArrayData(convert.SliceAnyToInterface(vcn.Byoipv6CidrBlocks), types.String),
					"ipv6PrivateCidrBlocks": llx.ArrayData(convert.SliceAnyToInterface(vcn.Ipv6PrivateCidrBlocks), types.String),
					"isZprOnly":             llx.BoolDataPtr(vcn.IsZprOnly),
					"vcnDomainName":         llx.StringDataPtr(vcn.VcnDomainName),
					"securityAttributes":    llx.MapData(definedTagsToAny(vcn.SecurityAttributes), types.Dict),
					"defaultDhcpOptionsId":  llx.StringDataPtr(vcn.DefaultDhcpOptionsId),
					"defaultRouteTableId":   llx.StringDataPtr(vcn.DefaultRouteTableId),
					"defaultSecurityListId": llx.StringDataPtr(vcn.DefaultSecurityListId),
					"dnsLabel":              llx.StringDataPtr(vcn.DnsLabel),
					"freeformTags":          llx.MapData(strMapToAny(vcn.FreeformTags), types.String),
					"definedTags":           llx.MapData(definedTagsToAny(vcn.DefinedTags), types.Any),
					"systemTags":            llx.MapData(definedTagsToAny(vcn.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (s *mqlOciNetwork) getVcnsForRegion(ctx context.Context, networkClient *core.VirtualNetworkClient, compartmentID string) ([]core.Vcn, error) {
	vcns, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.Vcn, *string, error) {
		request := core.ListVcnsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := networkClient.ListVcns(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return vcns, nil
}

func initOciNetworkVcn(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.network.vcn")
	}

	obj, err := CreateResource(runtime, "oci.network", nil)
	if err != nil {
		return nil, nil, err
	}
	network := obj.(*mqlOciNetwork)

	rawVcns := network.GetVcns()
	if rawVcns.Error != nil {
		return nil, nil, rawVcns.Error
	}

	for _, raw := range rawVcns.Data {
		vcn := raw.(*mqlOciNetworkVcn)
		if vcn.Id.Data == idVal {
			return args, vcn, nil
		}
	}

	return nil, nil, errors.New("oci.network.vcn not found: " + idVal)
}

func (o *mqlOciNetworkVcn) id() (string, error) {
	return "oci.network.vcn/" + o.Id.Data, nil
}

func (o *mqlOciNetwork) securityLists() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Security lists live in the same compartment as the VCN they protect, and
	// ListSecurityLists cannot search below the compartment it is given. Scanning
	// only the tenancy root therefore reported a tenancy with no ingress rules
	// anywhere, which reads as "nothing is exposed" when the truth is that
	// nothing was looked at.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			securityLists, err := o.getSecurityListsForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range securityLists {
				securityList := securityLists[i]

				if conn.Filters.IsFilteredOutByTags(securityList.FreeformTags, securityList.DefinedTags) {
					continue
				}

				var created *time.Time
				if securityList.TimeCreated != nil {
					created = &securityList.TimeCreated.Time
				}

				egressSecurityRules := []egressSecurityRule{}
				for j := range securityList.EgressSecurityRules {
					rule := securityList.EgressSecurityRules[j]
					egressSecurityRules = append(egressSecurityRules, egressSecurityRule{
						Description:     stringValue(rule.Description),
						Stateless:       boolValue(rule.IsStateless),
						Protocol:        stringValue(rule.Protocol),
						Destination:     stringValue(rule.Destination),
						DestinationType: string(rule.DestinationType),
						TcpOptions:      rule.TcpOptions,
						UdpOptions:      rule.UdpOptions,
						IcmpOptions:     rule.IcmpOptions,
					})
				}
				egress, err := convert.JsonToDictSlice(egressSecurityRules)
				if err != nil {
					return nil, err
				}

				typedEgress := make([]securityRule, 0, len(securityList.EgressSecurityRules))
				for j := range securityList.EgressSecurityRules {
					typedEgress = append(typedEgress, securityRuleFromEgress(securityList.EgressSecurityRules[j]))
				}
				egressRules, err := newSecurityRules(o.MqlRuntime, stringValue(securityList.Id), typedEgress)
				if err != nil {
					return nil, err
				}

				ingressSecurityRules := []ingressSecurityRule{}
				for j := range securityList.IngressSecurityRules {
					rule := securityList.IngressSecurityRules[j]
					ingressSecurityRules = append(ingressSecurityRules, ingressSecurityRule{
						Description: stringValue(rule.Description),
						Stateless:   boolValue(rule.IsStateless),
						Protocol:    stringValue(rule.Protocol),
						Source:      stringValue(rule.Source),
						SourceType:  string(rule.SourceType),
						TcpOptions:  rule.TcpOptions,
						UdpOptions:  rule.UdpOptions,
						IcmpOptions: rule.IcmpOptions,
					})
				}
				ingress, err := convert.JsonToDictSlice(ingressSecurityRules)
				if err != nil {
					return nil, err
				}

				typedIngress := make([]securityRule, 0, len(securityList.IngressSecurityRules))
				for j := range securityList.IngressSecurityRules {
					typedIngress = append(typedIngress, securityRuleFromIngress(securityList.IngressSecurityRules[j]))
				}
				ingressRules, err := newSecurityRules(o.MqlRuntime, stringValue(securityList.Id), typedIngress)
				if err != nil {
					return nil, err
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.securityList", stringValue(securityList.CompartmentId), map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(securityList.Id),
					"name":                 llx.StringDataPtr(securityList.DisplayName),
					"created":              llx.TimeDataPtr(created),
					"state":                llx.StringData(string(securityList.LifecycleState)),
					"egressSecurityRules":  llx.ArrayData(egress, types.Dict),
					"ingressSecurityRules": llx.ArrayData(ingress, types.Dict),
					"egressRules":          llx.ArrayData(egressRules, types.Resource("oci.network.securityRule")),
					"ingressRules":         llx.ArrayData(ingressRules, types.Resource("oci.network.securityRule")),
					"freeformTags":         llx.MapData(strMapToAny(securityList.FreeformTags), types.String),
					"definedTags":          llx.MapData(definedTagsToAny(securityList.DefinedTags), types.Any),
					"systemTags":           llx.MapData(definedTagsToAny(securityList.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				sl := mqlInstance.(*mqlOciNetworkSecurityList)
				sl.cacheVcnID = stringValue(securityList.VcnId)
				sl.cacheRegion = region
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (s *mqlOciNetwork) getSecurityListsForRegion(ctx context.Context, networkClient *core.VirtualNetworkClient, compartmentID string) ([]core.SecurityList, error) {
	securityLists, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.SecurityList, *string, error) {
		request := core.ListSecurityListsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := networkClient.ListSecurityLists(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return securityLists, nil
}

// OCI VCN SecurityList egress rule for allowing outbound IP packets
type egressSecurityRule struct {
	// Description of egress rule
	Description string `json:"description,omitempty"`
	// Indicates if this is a stateless rule. No omitempty: a stateful rule
	// must emit `stateless: false`, not drop the key entirely.
	Stateless bool `json:"stateless"`
	// Transport protocol, follows http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	Protocol string `json:"protocol,omitempty"`
	// Range of allowed IP addresses
	Destination string `json:"destination,omitempty"`
	// Type of destination
	DestinationType string `json:"destinationType,omitempty"`
	// TCP options
	TcpOptions *core.TcpOptions `json:"tcpOptions,omitempty"`
	// Udp options
	UdpOptions *core.UdpOptions `json:"udpOptions,omitempty"`
	// Icmp options
	IcmpOptions *core.IcmpOptions `json:"icmpOptions,omitempty"`
}

// OCI VCN SecurityList Ingress rule for allowing inbound IP packets
type ingressSecurityRule struct {
	// Description of ingress rule
	Description string `json:"description,omitempty"`
	// Indicates if this is a stateless rule. No omitempty: a stateful rule
	// must emit `stateless: false`, not drop the key entirely.
	Stateless bool `json:"stateless"`
	// Transport protocol, follows http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	Protocol string `json:"protocol,omitempty"`
	// Range of allowed IP addresses
	Source string `json:"source,omitempty"`
	// Type of source
	SourceType string `json:"sourceType,omitempty"`
	// TCP options
	TcpOptions *core.TcpOptions `json:"tcpOptions,omitempty"`
	// Udp options
	UdpOptions *core.UdpOptions `json:"udpOptions,omitempty"`
	// Icmp options
	IcmpOptions *core.IcmpOptions `json:"icmpOptions,omitempty"`
}

type mqlOciNetworkSecurityListInternal struct {
	ociCompartmentRef
	cacheVcnID string
	// cacheRegion is the region key (e.g. "IAD") discovered when the security
	// list was enumerated. Used by discovery to emit per-region platform IDs
	// without re-parsing the OCID.
	cacheRegion string
}

// initOciNetworkSecurityList resolves a single security list from the scan
// asset's PlatformId when policies reference `oci.network.securityList` on a
// discovered oci-network-securitylist asset. Explicit id takes precedence.
func initOciNetworkSecurityList(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	id := ociArgString(args, "id")
	if id == "" {
		conn := runtime.Connection.(*connection.OciConnection)
		if conn.Conf == nil || conn.Conf.PlatformId == "" {
			return args, nil, nil
		}
		parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId)
		if !ok || parsed.service != "network" || parsed.objectType != "securitylist" {
			return args, nil, nil
		}
		id = parsed.id
	}

	obj, err := CreateResource(runtime, "oci.network", nil)
	if err != nil {
		return nil, nil, err
	}
	network := obj.(*mqlOciNetwork)
	list := network.GetSecurityLists()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		sl := raw.(*mqlOciNetworkSecurityList)
		if sl.Id.Data == id {
			return args, sl, nil
		}
	}
	return nil, nil, errors.New("oci.network.securityList not found: " + id)
}

func (o *mqlOciNetworkSecurityList) id() (string, error) {
	return "oci.network.securityList/" + o.Id.Data, nil
}

func (o *mqlOciNetworkSecurityList) vcn() (*mqlOciNetworkVcn, error) {
	if o.cacheVcnID == "" || !isOcid(o.cacheVcnID) {
		o.Vcn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVcn, err := NewResource(o.MqlRuntime, "oci.network.vcn", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVcnID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVcn.(*mqlOciNetworkVcn), nil
}

func (o *mqlOciNetworkSecurityList) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkSecurityList) hasStatelessRules() (bool, error) {
	if o.IngressSecurityRules.Error != nil {
		return false, o.IngressSecurityRules.Error
	}
	if anyRuleStateless(o.IngressSecurityRules.Data, "stateless") {
		return true, nil
	}
	if o.EgressSecurityRules.Error != nil {
		return false, o.EgressSecurityRules.Error
	}
	return anyRuleStateless(o.EgressSecurityRules.Data, "stateless"), nil
}

func anyRuleStateless(rules []any, key string) bool {
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if v, ok := m[key].(bool); ok && v {
			return true
		}
	}
	return false
}

func (o *mqlOciNetwork) subnets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Fanned out over the compartment tree, not just the tenancy root. The core
	// list APIs have no subtree flag, so listing the root alone reported no
	// subnets at all for any tenancy that groups its networking into child
	// compartments - and left every typed reference to a subnet (load balancer
	// exposure, database placement, stream pool networking) unable to resolve.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci subnets with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			subnets, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.Subnet, *string, error) {
				response, err := svc.ListSubnets(ctx, core.ListSubnetsRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range subnets {
				subnet := subnets[i]

				var created *time.Time
				if subnet.TimeCreated != nil {
					created = &subnet.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.subnet", stringValue(subnet.CompartmentId), map[string]*llx.RawData{
					"id":                      llx.StringDataPtr(subnet.Id),
					"name":                    llx.StringDataPtr(subnet.DisplayName),
					"availabilityDomain":      llx.StringDataPtr(subnet.AvailabilityDomain),
					"cidrBlock":               llx.StringDataPtr(subnet.CidrBlock),
					"ipv4CidrBlocks":          llx.ArrayData(convert.SliceAnyToInterface(subnet.Ipv4CidrBlocks), types.String),
					"ipv6CidrBlock":           llx.StringDataPtr(subnet.Ipv6CidrBlock),
					"ipv6CidrBlocks":          llx.ArrayData(convert.SliceAnyToInterface(subnet.Ipv6CidrBlocks), types.String),
					"ipv6VirtualRouterIp":     llx.StringDataPtr(subnet.Ipv6VirtualRouterIp),
					"virtualRouterIp":         llx.StringDataPtr(subnet.VirtualRouterIp),
					"virtualRouterMac":        llx.StringDataPtr(subnet.VirtualRouterMac),
					"state":                   llx.StringData(string(subnet.LifecycleState)),
					"dnsLabel":                llx.StringDataPtr(subnet.DnsLabel),
					"subnetDomainName":        llx.StringDataPtr(subnet.SubnetDomainName),
					"prohibitPublicIpOnVnic":  llx.BoolDataPtr(subnet.ProhibitPublicIpOnVnic),
					"prohibitInternetIngress": llx.BoolDataPtr(subnet.ProhibitInternetIngress),
					"created":                 llx.TimeDataPtr(created),
					"freeformTags":            llx.MapData(strMapToAny(subnet.FreeformTags), types.String),
					"definedTags":             llx.MapData(definedTagsToAny(subnet.DefinedTags), types.Any),
					"systemTags":              llx.MapData(definedTagsToAny(subnet.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlSub := mqlInstance.(*mqlOciNetworkSubnet)
				mqlSub.cacheVcnID = stringValue(subnet.VcnId)
				mqlSub.cacheRouteTableID = stringValue(subnet.RouteTableId)
				mqlSub.cacheDhcpOptionsID = stringValue(subnet.DhcpOptionsId)
				mqlSub.cacheSecurityListIDs = subnet.SecurityListIds
				res = append(res, mqlSub)
			}

			return res, nil
		})
}

type mqlOciNetworkSubnetInternal struct {
	ociCompartmentRef
	cacheVcnID           string
	cacheRouteTableID    string
	cacheSecurityListIDs []string
	cacheDhcpOptionsID   string
}

func initOciNetworkSubnet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.network.subnet")
	}

	obj, err := CreateResource(runtime, "oci.network", nil)
	if err != nil {
		return nil, nil, err
	}
	network := obj.(*mqlOciNetwork)

	rawSubnets := network.GetSubnets()
	if rawSubnets.Error != nil {
		return nil, nil, rawSubnets.Error
	}

	for _, raw := range rawSubnets.Data {
		subnet := raw.(*mqlOciNetworkSubnet)
		if subnet.Id.Data == idVal {
			return args, subnet, nil
		}
	}

	return nil, nil, errors.New("oci.network.subnet not found: " + idVal)
}

func (o *mqlOciNetworkSubnet) id() (string, error) {
	return "oci.network.subnet/" + o.Id.Data, nil
}

func (o *mqlOciNetworkSubnet) vcn() (*mqlOciNetworkVcn, error) {
	if o.cacheVcnID == "" || !isOcid(o.cacheVcnID) {
		o.Vcn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVcn, err := NewResource(o.MqlRuntime, "oci.network.vcn", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVcnID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVcn.(*mqlOciNetworkVcn), nil
}

func (o *mqlOciNetwork) networkSecurityGroups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Network security groups are attached to VNICs that almost never live in the
	// tenancy root, and ListNetworkSecurityGroups takes a single compartment with
	// no way to descend. Enumerating per compartment is what lets an instance's
	// nsgs resolve at all, instead of coming back empty and making every host
	// look unprotected.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci NSGs with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			nsgs, err := o.getNSGsForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range nsgs {
				nsg := nsgs[i]

				var created *time.Time
				if nsg.TimeCreated != nil {
					created = &nsg.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.networkSecurityGroup", stringValue(nsg.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(nsg.Id),
					"name":         llx.StringDataPtr(nsg.DisplayName),
					"state":        llx.StringData(string(nsg.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(nsg.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(nsg.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(nsg.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlNsg := mqlInstance.(*mqlOciNetworkNetworkSecurityGroup)
				mqlNsg.cacheRegion = region
				mqlNsg.cacheVcnID = stringValue(nsg.VcnId)
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (o *mqlOciNetwork) getNSGsForRegion(ctx context.Context, networkClient *core.VirtualNetworkClient, compartmentID string) ([]core.NetworkSecurityGroup, error) {
	nsgs, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.NetworkSecurityGroup, *string, error) {
		request := core.ListNetworkSecurityGroupsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := networkClient.ListNetworkSecurityGroups(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return nsgs, nil
}

type mqlOciNetworkNetworkSecurityGroupInternal struct {
	ociCompartmentRef
	cacheRegion string
	cacheVcnID  string
	rules       ociOnce
}

func (o *mqlOciNetworkNetworkSecurityGroup) id() (string, error) {
	return "oci.network.networkSecurityGroup/" + o.Id.Data, nil
}

// initOciNetworkNetworkSecurityGroup populates a network security group that was
// referenced only by OCID — the shape produced by the typed securityGroups()
// accessors (load balancer, compute VNIC, database) and by the exposure()
// analysis. Without this, such a resource carried only its id: every other
// field reported "no type information", and fetchSecurityRules built its client
// with an empty region (region is only set on the enumerated path), producing a
// malformed "iaas..oraclecloud.com" endpoint. The region is recovered from the
// OCID so the group can be fetched regardless of the compartment it lives in.
func initOciNetworkNetworkSecurityGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Already populated (a caller passed the full field set) — nothing to
	// fetch. `name` is always set alongside `id` on the populated path, so its
	// presence distinguishes a fully-built group from a bare id reference.
	if args["name"] != nil {
		return args, nil, nil
	}
	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch oci.network.networkSecurityGroup")
	}
	id, ok := args["id"].Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("id required to fetch oci.network.networkSecurityGroup")
	}

	region := ociRegionFromOCID(id)
	if region == "" {
		return nil, nil, errors.New("could not determine region from network security group ocid: " + id)
	}

	conn, ok := runtime.Connection.(*connection.OciConnection)
	if !ok {
		return nil, nil, errors.New("invalid oci connection")
	}
	svc, err := conn.NetworkClient(region)
	if err != nil {
		return nil, nil, err
	}

	resp, err := svc.GetNetworkSecurityGroup(context.Background(), core.GetNetworkSecurityGroupRequest{
		NetworkSecurityGroupId: common.String(id),
	})
	if err != nil {
		return nil, nil, err
	}
	nsg := resp.NetworkSecurityGroup

	var created *time.Time
	if nsg.TimeCreated != nil {
		created = &nsg.TimeCreated.Time
	}

	mqlInstance, err := createOciResourceInCompartment(runtime, "oci.network.networkSecurityGroup", stringValue(nsg.CompartmentId), map[string]*llx.RawData{
		"id":           llx.StringDataPtr(nsg.Id),
		"name":         llx.StringDataPtr(nsg.DisplayName),
		"state":        llx.StringData(string(nsg.LifecycleState)),
		"created":      llx.TimeDataPtr(created),
		"freeformTags": llx.MapData(strMapToAny(nsg.FreeformTags), types.String),
		"definedTags":  llx.MapData(definedTagsToAny(nsg.DefinedTags), types.Any),
		"systemTags":   llx.MapData(definedTagsToAny(nsg.SystemTags), types.Dict),
	})
	if err != nil {
		return nil, nil, err
	}
	mqlNsg := mqlInstance.(*mqlOciNetworkNetworkSecurityGroup)
	mqlNsg.cacheRegion = region
	mqlNsg.cacheVcnID = stringValue(nsg.VcnId)
	return args, mqlNsg, nil
}

func (o *mqlOciNetworkNetworkSecurityGroup) vcn() (*mqlOciNetworkVcn, error) {
	if o.cacheVcnID == "" || !isOcid(o.cacheVcnID) {
		o.Vcn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVcn, err := NewResource(o.MqlRuntime, "oci.network.vcn", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVcnID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVcn.(*mqlOciNetworkVcn), nil
}

// NSG security rule for serialization to dict
type nsgSecurityRule struct {
	Direction       string            `json:"direction"`
	Protocol        string            `json:"protocol"`
	Description     string            `json:"description,omitempty"`
	Source          string            `json:"source,omitempty"`
	SourceType      string            `json:"sourceType,omitempty"`
	Destination     string            `json:"destination,omitempty"`
	DestinationType string            `json:"destinationType,omitempty"`
	IsStateless     bool              `json:"isStateless"`
	TcpOptions      *core.TcpOptions  `json:"tcpOptions,omitempty"`
	UdpOptions      *core.UdpOptions  `json:"udpOptions,omitempty"`
	IcmpOptions     *core.IcmpOptions `json:"icmpOptions,omitempty"`
}

func (o *mqlOciNetworkNetworkSecurityGroup) getRulesForNSG(ctx context.Context, networkClient *core.VirtualNetworkClient, nsgId string) ([]core.SecurityRule, error) {
	rules, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.SecurityRule, *string, error) {
		request := core.ListNetworkSecurityGroupSecurityRulesRequest{
			NetworkSecurityGroupId: common.String(nsgId),
			Page:                   page,
		}

		response, err := networkClient.ListNetworkSecurityGroupSecurityRules(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return rules, nil
}

// fetchSecurityRules populates the four rule fields from one ListNetworkSecurityGroupSecurityRules
// call. It reports only an error: once it returns nil the fields are set, so
// callers read them directly rather than taking a copy back out of the fetch.
func (o *mqlOciNetworkNetworkSecurityGroup) fetchSecurityRules() error {
	return o.rules.do(func() error {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		ctx := context.Background()

		svc, err := conn.NetworkClient(o.cacheRegion)
		if err != nil {
			return err
		}

		rules, err := o.getRulesForNSG(ctx, svc, o.Id.Data)
		if err != nil {
			return err
		}

		ingressRules := []nsgSecurityRule{}
		egressRules := []nsgSecurityRule{}
		typedIngress := []securityRule{}
		typedEgress := []securityRule{}

		for i := range rules {
			rule := rules[i]
			r := nsgSecurityRule{
				Direction:       string(rule.Direction),
				Protocol:        stringValue(rule.Protocol),
				Description:     stringValue(rule.Description),
				Source:          stringValue(rule.Source),
				SourceType:      string(rule.SourceType),
				Destination:     stringValue(rule.Destination),
				DestinationType: string(rule.DestinationType),
				IsStateless:     boolValue(rule.IsStateless),
				TcpOptions:      rule.TcpOptions,
				UdpOptions:      rule.UdpOptions,
				IcmpOptions:     rule.IcmpOptions,
			}

			if rule.Direction == core.SecurityRuleDirectionIngress {
				ingressRules = append(ingressRules, r)
				typedIngress = append(typedIngress, securityRuleFromNsg(rule))
			} else {
				egressRules = append(egressRules, r)
				typedEgress = append(typedEgress, securityRuleFromNsg(rule))
			}
		}

		ingress, err := convert.JsonToDictSlice(ingressRules)
		if err != nil {
			return err
		}

		egress, err := convert.JsonToDictSlice(egressRules)
		if err != nil {
			return err
		}

		typedIngressRes, err := newSecurityRules(o.MqlRuntime, o.Id.Data, typedIngress)
		if err != nil {
			return err
		}

		typedEgressRes, err := newSecurityRules(o.MqlRuntime, o.Id.Data, typedEgress)
		if err != nil {
			return err
		}

		o.IngressSecurityRules = plugin.TValue[[]any]{Data: ingress, State: plugin.StateIsSet}
		o.EgressSecurityRules = plugin.TValue[[]any]{Data: egress, State: plugin.StateIsSet}
		o.IngressRules = plugin.TValue[[]any]{Data: typedIngressRes, State: plugin.StateIsSet}
		o.EgressRules = plugin.TValue[[]any]{Data: typedEgressRes, State: plugin.StateIsSet}
		return nil
	})
}

func (o *mqlOciNetworkNetworkSecurityGroup) ingressRules() ([]any, error) {
	if err := o.fetchSecurityRules(); err != nil {
		return nil, err
	}
	return o.IngressRules.Data, nil
}

func (o *mqlOciNetworkNetworkSecurityGroup) egressRules() ([]any, error) {
	if err := o.fetchSecurityRules(); err != nil {
		return nil, err
	}
	return o.EgressRules.Data, nil
}

func (o *mqlOciNetworkNetworkSecurityGroup) ingressSecurityRules() ([]any, error) {
	if err := o.fetchSecurityRules(); err != nil {
		return nil, err
	}
	return o.IngressSecurityRules.Data, nil
}

func (o *mqlOciNetworkNetworkSecurityGroup) egressSecurityRules() ([]any, error) {
	if err := o.fetchSecurityRules(); err != nil {
		return nil, err
	}
	return o.EgressSecurityRules.Data, nil
}

func (o *mqlOciNetworkNetworkSecurityGroup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkNetworkSecurityGroup) hasStatelessRules() (bool, error) {
	if err := o.fetchSecurityRules(); err != nil {
		return false, err
	}
	if anyRuleStateless(o.IngressSecurityRules.Data, "isStateless") {
		return true, nil
	}
	return anyRuleStateless(o.EgressSecurityRules.Data, "isStateless"), nil
}

func (o *mqlOciNetworkNetworkSecurityGroup) attachedVnics() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	networkClient, err := conn.NetworkClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	attachments, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.NetworkSecurityGroupVnic, *string, error) {
		response, err := networkClient.ListNetworkSecurityGroupVnics(ctx, core.ListNetworkSecurityGroupVnicsRequest{
			NetworkSecurityGroupId: common.String(o.Id.Data),
			Page:                   page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(attachments))
	for i := range attachments {
		att := attachments[i]
		if att.VnicId == nil {
			continue
		}
		// OCI has no batch GetVnic API, so each attachment requires a separate call.
		vnicResp, err := networkClient.GetVnic(ctx, core.GetVnicRequest{VnicId: att.VnicId})
		if err != nil {
			log.Debug().Err(err).Msgf("failed to get VNIC %s", *att.VnicId)
			continue
		}
		mqlVnic, err := ociVnicToMql(o.MqlRuntime, vnicResp.Vnic)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVnic)
	}
	return res, nil
}

func ociVnicToMql(runtime *plugin.Runtime, vnic core.Vnic) (*mqlOciComputeVnic, error) {
	var created *time.Time
	if vnic.TimeCreated != nil {
		created = &vnic.TimeCreated.Time
	}

	res, err := createOciResourceInCompartment(runtime, "oci.compute.vnic", stringValue(vnic.CompartmentId), map[string]*llx.RawData{
		"id":                  llx.StringDataPtr(vnic.Id),
		"name":                llx.StringDataPtr(vnic.DisplayName),
		"isPrimary":           llx.BoolDataPtr(vnic.IsPrimary),
		"privateIp":           llx.StringDataPtr(vnic.PrivateIp),
		"publicIp":            llx.StringDataPtr(vnic.PublicIp),
		"ipv6Addresses":       llx.ArrayData(stringsToAny(vnic.Ipv6Addresses), types.String),
		"macAddress":          llx.StringDataPtr(vnic.MacAddress),
		"hostnameLabel":       llx.StringDataPtr(vnic.HostnameLabel),
		"skipSourceDestCheck": llx.BoolDataPtr(vnic.SkipSourceDestCheck),
		"securityAttributes":  llx.MapData(definedTagsToAny(vnic.SecurityAttributes), types.Dict),
		"state":               llx.StringData(string(vnic.LifecycleState)),
		"created":             llx.TimeDataPtr(created),
		"freeformTags":        llx.MapData(strMapToAny(vnic.FreeformTags), types.String),
		"definedTags":         llx.MapData(definedTagsToAny(vnic.DefinedTags), types.Any),
		"systemTags":          llx.MapData(definedTagsToAny(vnic.SystemTags), types.Dict),
	})
	if err != nil {
		return nil, err
	}
	mqlVnic := res.(*mqlOciComputeVnic)
	mqlVnic.cacheSubnetID = stringValue(vnic.SubnetId)
	// Per-resource routing: set only when the VNIC overrides its subnet's route
	// table, and what the exposure verdict routes on when it is.
	mqlVnic.cacheRouteTableID = stringValue(vnic.RouteTableId)
	mqlVnic.cacheNsgIDs = convert.SliceAnyToInterface(vnic.NsgIds)
	return mqlVnic, nil
}

// Internet Gateways

func (o *mqlOciNetwork) internetGateways() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci internet gateways with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			igws, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.InternetGateway, *string, error) {
				response, err := svc.ListInternetGateways(ctx, core.ListInternetGatewaysRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range igws {
				igw := igws[i]

				var created *time.Time
				if igw.TimeCreated != nil {
					created = &igw.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.internetGateway", stringValue(igw.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(igw.Id),
					"name":         llx.StringDataPtr(igw.DisplayName),
					"isEnabled":    llx.BoolDataPtr(igw.IsEnabled),
					"state":        llx.StringData(string(igw.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(igw.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(igw.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(igw.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlIgw := mqlInstance.(*mqlOciNetworkInternetGateway)
				mqlIgw.cacheVcnID = stringValue(igw.VcnId)
				res = append(res, mqlIgw)
			}

			return res, nil
		})
}

type mqlOciNetworkInternetGatewayInternal struct {
	ociCompartmentRef
	cacheVcnID string
}

func (o *mqlOciNetworkInternetGateway) id() (string, error) {
	return "oci.network.internetGateway/" + o.Id.Data, nil
}

func (o *mqlOciNetworkInternetGateway) vcn() (*mqlOciNetworkVcn, error) {
	if o.cacheVcnID == "" || !isOcid(o.cacheVcnID) {
		o.Vcn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVcn, err := NewResource(o.MqlRuntime, "oci.network.vcn", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVcnID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVcn.(*mqlOciNetworkVcn), nil
}

// NAT Gateways

func (o *mqlOciNetwork) natGateways() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci NAT gateways with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			natGws, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.NatGateway, *string, error) {
				response, err := svc.ListNatGateways(ctx, core.ListNatGatewaysRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range natGws {
				ngw := natGws[i]

				var created *time.Time
				if ngw.TimeCreated != nil {
					created = &ngw.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.natGateway", stringValue(ngw.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(ngw.Id),
					"name":         llx.StringDataPtr(ngw.DisplayName),
					"blockTraffic": llx.BoolDataPtr(ngw.BlockTraffic),
					"natIp":        llx.StringDataPtr(ngw.NatIp),
					"state":        llx.StringData(string(ngw.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(ngw.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(ngw.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlNgw := mqlInstance.(*mqlOciNetworkNatGateway)
				mqlNgw.cacheVcnID = stringValue(ngw.VcnId)
				res = append(res, mqlNgw)
			}

			return res, nil
		})
}

type mqlOciNetworkNatGatewayInternal struct {
	ociCompartmentRef
	cacheVcnID string
}

func (o *mqlOciNetworkNatGateway) id() (string, error) {
	return "oci.network.natGateway/" + o.Id.Data, nil
}

func (o *mqlOciNetworkNatGateway) vcn() (*mqlOciNetworkVcn, error) {
	if o.cacheVcnID == "" || !isOcid(o.cacheVcnID) {
		o.Vcn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVcn, err := NewResource(o.MqlRuntime, "oci.network.vcn", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVcnID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVcn.(*mqlOciNetworkVcn), nil
}

// Route Tables

// routeRule is an OCI route rule for serialization to dict
type routeRule struct {
	// Target network entity OCID
	NetworkEntityId string `json:"networkEntityId"`
	// Destination CIDR block or service CIDR
	Destination string `json:"destination,omitempty"`
	// Type of destination (CIDR_BLOCK, SERVICE_CIDR_BLOCK)
	DestinationType string `json:"destinationType,omitempty"`
	// Description of the route rule
	Description string `json:"description,omitempty"`
	// Route type (STATIC, LOCAL)
	RouteType string `json:"routeType,omitempty"`
}

func (o *mqlOciNetwork) routeTables() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// A route table is created alongside the VCN it belongs to, so a tenancy that
	// puts its VCNs in child compartments has no route tables in the root at all.
	// ListRouteTables offers no subtree search, so the fan-out below is the only
	// way a subnet's routeTable reference finds its target and egress paths stay
	// auditable.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci route tables with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			rts, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.RouteTable, *string, error) {
				response, err := svc.ListRouteTables(ctx, core.ListRouteTablesRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range rts {
				rt := rts[i]

				var created *time.Time
				if rt.TimeCreated != nil {
					created = &rt.TimeCreated.Time
				}

				rules := make([]routeRule, 0, len(rt.RouteRules))
				for j := range rt.RouteRules {
					r := rt.RouteRules[j]
					rules = append(rules, routeRule{
						NetworkEntityId: stringValue(r.NetworkEntityId),
						Destination:     stringValue(r.Destination),
						DestinationType: string(r.DestinationType),
						Description:     stringValue(r.Description),
						RouteType:       string(r.RouteType),
					})
				}
				routeRules, err := convert.JsonToDictSlice(rules)
				if err != nil {
					return nil, err
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.routeTable", stringValue(rt.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(rt.Id),
					"name":         llx.StringDataPtr(rt.DisplayName),
					"routeRules":   llx.ArrayData(routeRules, types.Dict),
					"state":        llx.StringData(string(rt.LifecycleState)),
					"created":      llx.TimeDataPtr(created),
					"freeformTags": llx.MapData(strMapToAny(rt.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(rt.DefinedTags), types.Any),
					"systemTags":   llx.MapData(definedTagsToAny(rt.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlRt := mqlInstance.(*mqlOciNetworkRouteTable)
				mqlRt.cacheVcnID = stringValue(rt.VcnId)
				res = append(res, mqlRt)
			}

			return res, nil
		})
}

type mqlOciNetworkRouteTableInternal struct {
	ociCompartmentRef
	cacheVcnID string
}

func initOciNetworkRouteTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.network.routeTable")
	}

	obj, err := CreateResource(runtime, "oci.network", nil)
	if err != nil {
		return nil, nil, err
	}
	network := obj.(*mqlOciNetwork)

	rawRTs := network.GetRouteTables()
	if rawRTs.Error != nil {
		return nil, nil, rawRTs.Error
	}

	for _, raw := range rawRTs.Data {
		rt := raw.(*mqlOciNetworkRouteTable)
		if rt.Id.Data == idVal {
			return args, rt, nil
		}
	}

	return nil, nil, errors.New("oci.network.routeTable not found: " + idVal)
}

func (o *mqlOciNetworkRouteTable) id() (string, error) {
	return "oci.network.routeTable/" + o.Id.Data, nil
}

func (o *mqlOciNetworkRouteTable) vcn() (*mqlOciNetworkVcn, error) {
	if o.cacheVcnID == "" || !isOcid(o.cacheVcnID) {
		o.Vcn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVcn, err := NewResource(o.MqlRuntime, "oci.network.vcn", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVcnID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVcn.(*mqlOciNetworkVcn), nil
}

// Subnet route table reference

func (o *mqlOciNetworkSubnet) routeTable() (*mqlOciNetworkRouteTable, error) {
	if o.cacheRouteTableID == "" || !isOcid(o.cacheRouteTableID) {
		o.RouteTable.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRt, err := NewResource(o.MqlRuntime, "oci.network.routeTable", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheRouteTableID),
	})
	if err != nil {
		return nil, err
	}
	return mqlRt.(*mqlOciNetworkRouteTable), nil
}

func (o *mqlOciNetwork) publicIps() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci public ips with region %s", region)

			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}

			// The two lifetimes live at different scopes, and asking at the
			// wrong one returns nothing rather than an error.
			//
			// Reserved public IPs are regional: they persist unattached, so
			// they answer at REGION scope. Ephemeral public IPs belong to the
			// availability domain of the resource holding them - which is
			// every public IP OCI assigns to an instance by default - and
			// ListPublicIps only returns those when it is given
			// AVAILABILITY_DOMAIN scope together with the domain to look in.
			// Asking for EPHEMERAL at REGION scope, as this did, is accepted
			// and returns an empty list, so instance public IPs were silently
			// absent from the collection while reserved ones looked fine.
			publicIps, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.PublicIp, *string, error) {
				response, err := svc.ListPublicIps(ctx, core.ListPublicIpsRequest{
					Scope:         core.ListPublicIpsScopeRegion,
					CompartmentId: common.String(compartmentID),
					Lifetime:      core.ListPublicIpsLifetimeReserved,
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			// A failure here fails the collection rather than returning the
			// reserved IPs alone.
			//
			// Continuing would produce a list that is short by exactly the
			// ephemeral addresses - which is the bug this call was added to
			// fix, reintroduced with a warning in place of an error. Nothing
			// downstream can tell a tenancy whose instances have no public IPs
			// from one whose availability domains could not be listed, and an
			// authoritative-looking short list is worse than a failure in an
			// inventory tool; see ociRegionServiceUnavailable, which draws the
			// same line for throttles and IAM gaps.
			//
			// The blast radius is one (region, compartment) job: the join
			// tolerates a per-compartment denial, and ociRetryLazy does not
			// cache the failure, so a throttle is retried rather than being
			// sticky for the rest of the scan.
			availabilityDomains, err := ociAvailabilityDomains(ctx, conn, region, compartmentID)
			if err != nil {
				return nil, fmt.Errorf(
					"oci.network.publicIps: cannot list availability domains in %s, so ephemeral public IPs "+
						"cannot be read and the result would omit them: %w", region, err)
			}
			for _, availabilityDomain := range availabilityDomains {
				perDomain, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.PublicIp, *string, error) {
					response, err := svc.ListPublicIps(ctx, core.ListPublicIpsRequest{
						Scope:              core.ListPublicIpsScopeAvailabilityDomain,
						AvailabilityDomain: common.String(availabilityDomain),
						CompartmentId:      common.String(compartmentID),
						Lifetime:           core.ListPublicIpsLifetimeEphemeral,
						Page:               page,
					})
					if err != nil {
						return nil, nil, err
					}
					return response.Items, response.OpcNextPage, nil
				})
				if err != nil {
					return nil, err
				}
				publicIps = append(publicIps, perDomain...)
			}

			var res []any
			for i := range publicIps {
				publicIp := publicIps[i]

				var created *time.Time
				if publicIp.TimeCreated != nil {
					created = &publicIp.TimeCreated.Time
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.publicIp", stringValue(publicIp.CompartmentId), map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(publicIp.Id),
					"ipAddress":          llx.StringDataPtr(publicIp.IpAddress),
					"name":               llx.StringDataPtr(publicIp.DisplayName),
					"lifetime":           llx.StringData(string(publicIp.Lifetime)),
					"scope":              llx.StringData(string(publicIp.Scope)),
					"assignedEntityType": llx.StringData(string(publicIp.AssignedEntityType)),
					"assignedEntityId":   llx.StringDataPtr(publicIp.AssignedEntityId),
					"availabilityDomain": llx.StringDataPtr(publicIp.AvailabilityDomain),
					"state":              llx.StringData(string(publicIp.LifecycleState)),
					"created":            llx.TimeDataPtr(created),
					"freeformTags":       llx.MapData(strMapToAny(publicIp.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(publicIp.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlInstance)
			}

			return res, nil
		})
}

func (o *mqlOciNetworkPublicIp) id() (string, error) {
	return "oci.network.publicIp/" + o.Id.Data, nil
}

// initOciNetworkPublicIp resolves a public IP by OCID.
//
// Without an init, NewResource falls straight through to Create with only the
// id it was handed, caching a husk under the real OCID that a later
// oci.network.publicIps query would then be served. The tenancy's public IP
// listing is fetched once and shared through the runtime cache, so resolving
// against it costs one call however many load balancer addresses reference a
// reserved IP.
func initOciNetworkPublicIp(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.network.publicIp")
	}

	obj, err := CreateResource(runtime, "oci.network", nil)
	if err != nil {
		return nil, nil, err
	}

	publicIps := obj.(*mqlOciNetwork).GetPublicIps()
	if publicIps.Error != nil {
		return nil, nil, publicIps.Error
	}

	for _, raw := range publicIps.Data {
		ip, ok := raw.(*mqlOciNetworkPublicIp)
		if !ok {
			continue
		}
		if ip.Id.Data == idVal {
			return args, ip, nil
		}
	}

	return nil, nil, fmt.Errorf("oci.network.publicIp with id %q not found", idVal)
}

type mqlOciNetworkPublicIpInternal struct {
	ociCompartmentRef
}
