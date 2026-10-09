// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func ociNetworkService(runtime *plugin.Runtime) (*mqlOciNetwork, error) {
	res, err := CreateResource(runtime, "oci.network", nil)
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciNetwork), nil
}

// childrenOf filters a listed collection by the parent id each child caches.
func childrenOf[T any](list *plugin.TValue[[]any], parentID string, parentOf func(T) string) ([]any, error) {
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, raw := range list.Data {
		if c, ok := raw.(T); ok && parentOf(c) == parentID {
			out = append(out, raw)
		}
	}
	return out, nil
}

// rowKey is the cache key suffix of a row in a listed collection: its id, or
// its position when the API returns none, so rows without an id cannot
// collapse into one cached resource.
func rowKey(id string, index int) string {
	if id != "" {
		return id
	}
	return "#" + strconv.Itoa(index)
}

// ---- DHCP option sets ----

type mqlOciNetworkDhcpOptionSetInternal struct {
	ociCompartmentRef
	cacheVcnID string
}

func (o *mqlOciNetworkDhcpOptionSet) id() (string, error) {
	return "oci.network.dhcpOptionSet/" + o.Id.Data, nil
}

func (o *mqlOciNetwork) dhcpOptionSets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}
			sets, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.DhcpOptions, *string, error) {
				response, err := svc.ListDhcpOptions(ctx, core.ListDhcpOptionsRequest{
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
			res := make([]any, 0, len(sets))
			for i := range sets {
				d := sets[i]
				m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.dhcpOptionSet", stringValue(d.CompartmentId), dhcpOptionSetArgs(d))
				if err != nil {
					return nil, err
				}
				m.(*mqlOciNetworkDhcpOptionSet).cacheVcnID = stringValue(d.VcnId)
				res = append(res, m)
			}
			return res, nil
		})
}

// dhcpOptionSetArgs flattens the option set's polymorphic options: the DNS
// option names the resolver, the search domain option the search domains.
func dhcpOptionSetArgs(d core.DhcpOptions) map[string]*llx.RawData {
	serverType := ""
	var customServers, searchDomains []string
	for _, opt := range d.Options {
		switch v := opt.(type) {
		case core.DhcpDnsOption:
			serverType = string(v.ServerType)
			customServers = v.CustomDnsServers
		case core.DhcpSearchDomainOption:
			searchDomains = v.SearchDomainNames
		}
	}
	return map[string]*llx.RawData{
		"id":               llx.StringDataPtr(d.Id),
		"name":             llx.StringDataPtr(d.DisplayName),
		"state":            llx.StringData(string(d.LifecycleState)),
		"serverType":       llx.StringData(serverType),
		"customDnsServers": llx.ArrayData(stringsToAny(customServers), types.String),
		"searchDomains":    llx.ArrayData(stringsToAny(searchDomains), types.String),
		"domainNameType":   llx.StringData(string(d.DomainNameType)),
		"created":          sdkTimeData(d.TimeCreated),
		"freeformTags":     llx.MapData(strMapToAny(d.FreeformTags), types.String),
		"definedTags":      llx.MapData(definedTagsToAny(d.DefinedTags), types.Any),
	}
}

func (o *mqlOciNetworkDhcpOptionSet) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkDhcpOptionSet) vcn() (*mqlOciNetworkVcn, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetVcns(), o.cacheVcnID, &o.Vcn)
}

func (o *mqlOciNetworkVcn) dhcpOptionSets() ([]any, error) {
	return vcnChildren(o,
		func(n *mqlOciNetwork) *plugin.TValue[[]any] { return n.GetDhcpOptionSets() },
		func(d *mqlOciNetworkDhcpOptionSet) string { return d.cacheVcnID })
}

func (o *mqlOciNetworkVcn) defaultDhcpOptionSet() (*mqlOciNetworkDhcpOptionSet, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetDhcpOptionSets(), o.DefaultDhcpOptionsId.Data, &o.DefaultDhcpOptionSet)
}

func (o *mqlOciNetworkSubnet) dhcpOptionSet() (*mqlOciNetworkDhcpOptionSet, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetDhcpOptionSets(), o.cacheDhcpOptionsID, &o.DhcpOptionSet)
}

// ---- DRG route tables ----

type mqlOciNetworkDrgRouteTableInternal struct {
	ociCompartmentRef
	cacheDrgID                string
	cacheRegion               string
	cacheImportDistributionID string
}

func (o *mqlOciNetworkDrgRouteTable) id() (string, error) {
	return "oci.network.drgRouteTable/" + o.Id.Data, nil
}

// drgRouteTables lists the route tables of every DRG the network service
// listed, each in its DRG's region: route tables are listed per DRG.
func (o *mqlOciNetwork) drgRouteTables() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return forEachDrg(o, func(ctx context.Context, d *mqlOciNetworkDrg) ([]any, error) {
		region := d.drgRegion()
		svc, err := conn.NetworkClient(region)
		if err != nil {
			return nil, err
		}
		tables, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.DrgRouteTable, *string, error) {
			response, err := svc.ListDrgRouteTables(ctx, core.ListDrgRouteTablesRequest{DrgId: common.String(d.Id.Data), Page: page})
			if err != nil {
				return nil, nil, err
			}
			return response.Items, response.OpcNextPage, nil
		})
		if err != nil {
			return nil, err
		}
		res := make([]any, 0, len(tables))
		for i := range tables {
			t := tables[i]
			m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.drgRouteTable", stringValue(t.CompartmentId), map[string]*llx.RawData{
				"id":            llx.StringDataPtr(t.Id),
				"name":          llx.StringDataPtr(t.DisplayName),
				"state":         llx.StringData(string(t.LifecycleState)),
				"isEcmpEnabled": llx.BoolDataPtr(t.IsEcmpEnabled),
				"created":       sdkTimeData(t.TimeCreated),
				"freeformTags":  llx.MapData(strMapToAny(t.FreeformTags), types.String),
				"definedTags":   llx.MapData(definedTagsToAny(t.DefinedTags), types.Any),
			})
			if err != nil {
				return nil, err
			}
			rt := m.(*mqlOciNetworkDrgRouteTable)
			rt.cacheDrgID = stringValue(t.DrgId)
			rt.cacheRegion = region
			rt.cacheImportDistributionID = stringValue(t.ImportDrgRouteDistributionId)
			res = append(res, rt)
		}
		return res, nil
	})
}

// forEachDrg runs list for every DRG the network service listed and joins
// the results.
func forEachDrg(o *mqlOciNetwork, list func(ctx context.Context, d *mqlOciNetworkDrg) ([]any, error)) ([]any, error) {
	drgs := o.GetDrgs()
	if drgs.Error != nil {
		return nil, drgs.Error
	}
	ctx := context.Background()
	out := []any{}
	for _, raw := range drgs.Data {
		d, ok := raw.(*mqlOciNetworkDrg)
		if !ok {
			continue
		}
		items, err := list(ctx, d)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	return out, nil
}

func (o *mqlOciNetworkDrgRouteTable) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkDrgRouteTable) drg() (*mqlOciNetworkDrg, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetDrgs(), o.cacheDrgID, &o.Drg)
}

func (o *mqlOciNetworkDrgRouteTable) importRouteDistribution() (*mqlOciNetworkDrgRouteDistribution, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetDrgRouteDistributions(), o.cacheImportDistributionID, &o.ImportRouteDistribution)
}

type mqlOciNetworkDrgRouteTableRuleInternal struct {
	cacheNextHopID string
}

func (o *mqlOciNetworkDrgRouteTable) rules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.NetworkClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}
	rules, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]core.DrgRouteRule, *string, error) {
		response, err := svc.ListDrgRouteRules(ctx, core.ListDrgRouteRulesRequest{DrgRouteTableId: common.String(o.Id.Data), Page: page})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rules))
	for i := range rules {
		args := drgRouteRuleArgs(rules[i])
		args["__id"] = llx.StringData(o.Id.Data + "/rule/" + rowKey(stringValue(rules[i].Id), i))
		m, err := CreateResource(o.MqlRuntime, "oci.network.drgRouteTable.rule", args)
		if err != nil {
			return nil, err
		}
		m.(*mqlOciNetworkDrgRouteTableRule).cacheNextHopID = stringValue(rules[i].NextHopDrgAttachmentId)
		out = append(out, m)
	}
	return out, nil
}

func drgRouteRuleArgs(r core.DrgRouteRule) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":              llx.StringDataPtr(r.Id),
		"destination":     llx.StringDataPtr(r.Destination),
		"destinationType": llx.StringData(string(r.DestinationType)),
		"routeType":       llx.StringData(string(r.RouteType)),
		"routeProvenance": llx.StringData(string(r.RouteProvenance)),
		"isConflict":      llx.BoolData(r.IsConflict != nil && *r.IsConflict),
		"isBlackhole":     llx.BoolData(r.IsBlackhole != nil && *r.IsBlackhole),
	}
}

// drgAttachmentsOf lists the attachments of every DRG, through the DRGs the
// network service already listed.
func drgAttachmentsOf(runtime *plugin.Runtime) ([]any, error) {
	n, err := ociNetworkService(runtime)
	if err != nil {
		return nil, err
	}
	drgs := n.GetDrgs()
	if drgs.Error != nil {
		return nil, drgs.Error
	}
	out := []any{}
	for _, raw := range drgs.Data {
		d, ok := raw.(*mqlOciNetworkDrg)
		if !ok {
			continue
		}
		atts := d.GetAttachments()
		if atts.Error != nil {
			return nil, atts.Error
		}
		out = append(out, atts.Data...)
	}
	return out, nil
}

func drgAttachmentRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciNetworkDrgAttachment]) (*mqlOciNetworkDrgAttachment, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	atts, err := drgAttachmentsOf(runtime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(&plugin.TValue[[]any]{Data: atts, State: plugin.StateIsSet}, id, field)
}

func (o *mqlOciNetworkDrgRouteTableRule) nextHopDrgAttachment() (*mqlOciNetworkDrgAttachment, error) {
	return drgAttachmentRef(o.MqlRuntime, o.cacheNextHopID, &o.NextHopDrgAttachment)
}

func (o *mqlOciNetworkDrg) routeTables() ([]any, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return childrenOf(n.GetDrgRouteTables(), o.Id.Data, func(t *mqlOciNetworkDrgRouteTable) string { return t.cacheDrgID })
}

func (o *mqlOciNetworkDrgAttachment) drgRouteTable() (*mqlOciNetworkDrgRouteTable, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetDrgRouteTables(), o.cacheDrgRouteTableID, &o.DrgRouteTable)
}

// ---- DRG route distributions ----

type mqlOciNetworkDrgRouteDistributionInternal struct {
	ociCompartmentRef
	cacheDrgID  string
	cacheRegion string
}

func (o *mqlOciNetworkDrgRouteDistribution) id() (string, error) {
	return "oci.network.drgRouteDistribution/" + o.Id.Data, nil
}

// drgRouteDistributions lists the route distributions of every DRG the
// network service listed, each in its DRG's region.
func (o *mqlOciNetwork) drgRouteDistributions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return forEachDrg(o, func(ctx context.Context, d *mqlOciNetworkDrg) ([]any, error) {
		region := d.drgRegion()
		svc, err := conn.NetworkClient(region)
		if err != nil {
			return nil, err
		}
		dists, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.DrgRouteDistribution, *string, error) {
			response, err := svc.ListDrgRouteDistributions(ctx, core.ListDrgRouteDistributionsRequest{DrgId: common.String(d.Id.Data), Page: page})
			if err != nil {
				return nil, nil, err
			}
			return response.Items, response.OpcNextPage, nil
		})
		if err != nil {
			return nil, err
		}
		res := make([]any, 0, len(dists))
		for i := range dists {
			dist := dists[i]
			m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.drgRouteDistribution", stringValue(dist.CompartmentId), map[string]*llx.RawData{
				"id":               llx.StringDataPtr(dist.Id),
				"name":             llx.StringDataPtr(dist.DisplayName),
				"distributionType": llx.StringData(string(dist.DistributionType)),
				"state":            llx.StringData(string(dist.LifecycleState)),
				"created":          sdkTimeData(dist.TimeCreated),
				"freeformTags":     llx.MapData(strMapToAny(dist.FreeformTags), types.String),
				"definedTags":      llx.MapData(definedTagsToAny(dist.DefinedTags), types.Any),
			})
			if err != nil {
				return nil, err
			}
			rd := m.(*mqlOciNetworkDrgRouteDistribution)
			rd.cacheDrgID = stringValue(dist.DrgId)
			rd.cacheRegion = region
			res = append(res, rd)
		}
		return res, nil
	})
}

func (o *mqlOciNetworkDrgRouteDistribution) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkDrgRouteDistribution) drg() (*mqlOciNetworkDrg, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetDrgs(), o.cacheDrgID, &o.Drg)
}

func (o *mqlOciNetworkDrg) routeDistributions() ([]any, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return childrenOf(n.GetDrgRouteDistributions(), o.Id.Data, func(d *mqlOciNetworkDrgRouteDistribution) string { return d.cacheDrgID })
}

type mqlOciNetworkDrgRouteDistributionStatementInternal struct {
	cacheMatchDrgAttachmentID string
}

func (o *mqlOciNetworkDrgRouteDistribution) statements() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.NetworkClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}
	stmts, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]core.DrgRouteDistributionStatement, *string, error) {
		response, err := svc.ListDrgRouteDistributionStatements(ctx, core.ListDrgRouteDistributionStatementsRequest{
			DrgRouteDistributionId: common.String(o.Id.Data), Page: page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(stmts))
	for i := range stmts {
		args, attachmentID := drgDistributionStatementArgs(stmts[i])
		args["__id"] = llx.StringData(o.Id.Data + "/statement/" + rowKey(stringValue(stmts[i].Id), i))
		m, err := CreateResource(o.MqlRuntime, "oci.network.drgRouteDistribution.statement", args)
		if err != nil {
			return nil, err
		}
		m.(*mqlOciNetworkDrgRouteDistributionStatement).cacheMatchDrgAttachmentID = attachmentID
		out = append(out, m)
	}
	return out, nil
}

// drgDistributionStatementArgs flattens a statement's match criteria. A
// statement carries one criterion; an empty list matches everything.
func drgDistributionStatementArgs(st core.DrgRouteDistributionStatement) (map[string]*llx.RawData, string) {
	matchType, attachmentType, attachmentID := "MATCH_ALL", "", ""
	for _, c := range st.MatchCriteria {
		switch v := c.(type) {
		case core.DrgAttachmentTypeDrgRouteDistributionMatchCriteria:
			matchType, attachmentType = "DRG_ATTACHMENT_TYPE", string(v.AttachmentType)
		case core.DrgAttachmentIdDrgRouteDistributionMatchCriteria:
			matchType, attachmentID = "DRG_ATTACHMENT_ID", stringValue(v.DrgAttachmentId)
		case core.DrgAttachmentMatchAllDrgRouteDistributionMatchCriteria:
			matchType = "MATCH_ALL"
		}
	}
	return map[string]*llx.RawData{
		"id":                  llx.StringDataPtr(st.Id),
		"action":              llx.StringData(string(st.Action)),
		"priority":            intPtrData(st.Priority),
		"matchType":           llx.StringData(matchType),
		"matchAttachmentType": llx.StringData(attachmentType),
	}, attachmentID
}

func (o *mqlOciNetworkDrgRouteDistributionStatement) matchDrgAttachment() (*mqlOciNetworkDrgAttachment, error) {
	return drgAttachmentRef(o.MqlRuntime, o.cacheMatchDrgAttachmentID, &o.MatchDrgAttachment)
}

// ---- VTAPs ----

type mqlOciNetworkVtapInternal struct {
	ociCompartmentRef
	cacheVcnID           string
	cacheCaptureFilterID string
}

func (o *mqlOciNetworkVtap) id() (string, error) {
	return "oci.network.vtap/" + o.Id.Data, nil
}

func (o *mqlOciNetwork) vtaps() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}
			vtaps, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.Vtap, *string, error) {
				response, err := svc.ListVtaps(ctx, core.ListVtapsRequest{CompartmentId: common.String(compartmentID), Page: page})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}
			res := make([]any, 0, len(vtaps))
			for i := range vtaps {
				v := vtaps[i]
				m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.vtap", stringValue(v.CompartmentId), vtapArgs(v))
				if err != nil {
					return nil, err
				}
				vt := m.(*mqlOciNetworkVtap)
				vt.cacheVcnID = stringValue(v.VcnId)
				vt.cacheCaptureFilterID = stringValue(v.CaptureFilterId)
				res = append(res, vt)
			}
			return res, nil
		})
}

func vtapArgs(v core.Vtap) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":                    llx.StringDataPtr(v.Id),
		"name":                  llx.StringDataPtr(v.DisplayName),
		"state":                 llx.StringData(string(v.LifecycleState)),
		"isVtapEnabled":         llx.BoolData(v.IsVtapEnabled != nil && *v.IsVtapEnabled),
		"sourceType":            llx.StringData(string(v.SourceType)),
		"sourceId":              llx.StringDataPtr(v.SourceId),
		"targetType":            llx.StringData(string(v.TargetType)),
		"targetId":              llx.StringDataPtr(v.TargetId),
		"targetIp":              llx.StringData(stringValue(v.TargetIp)),
		"trafficMode":           llx.StringData(string(v.TrafficMode)),
		"encapsulationProtocol": llx.StringData(string(v.EncapsulationProtocol)),
		"maxPacketSize":         intPtrData(v.MaxPacketSize),
		"created":               sdkTimeData(v.TimeCreated),
		"freeformTags":          llx.MapData(strMapToAny(v.FreeformTags), types.String),
		"definedTags":           llx.MapData(definedTagsToAny(v.DefinedTags), types.Any),
	}
}

func (o *mqlOciNetworkVtap) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkVtap) vcn() (*mqlOciNetworkVcn, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetVcns(), o.cacheVcnID, &o.Vcn)
}

func (o *mqlOciNetworkVtap) captureFilter() (*mqlOciNetworkCaptureFilter, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetCaptureFilters(), o.cacheCaptureFilterID, &o.CaptureFilter)
}

func (o *mqlOciNetworkVcn) vtaps() ([]any, error) {
	return vcnChildren(o,
		func(n *mqlOciNetwork) *plugin.TValue[[]any] { return n.GetVtaps() },
		func(v *mqlOciNetworkVtap) string { return v.cacheVcnID })
}

// ---- capture filters ----

type mqlOciNetworkCaptureFilterInternal struct {
	ociCompartmentRef
	cacheFilter core.CaptureFilter
}

func (o *mqlOciNetworkCaptureFilter) id() (string, error) {
	return "oci.network.captureFilter/" + o.Id.Data, nil
}

func (o *mqlOciNetwork) captureFilters() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}
			filters, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.CaptureFilter, *string, error) {
				response, err := svc.ListCaptureFilters(ctx, core.ListCaptureFiltersRequest{CompartmentId: common.String(compartmentID), Page: page})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}
			res := make([]any, 0, len(filters))
			for i := range filters {
				f := filters[i]
				m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.captureFilter", stringValue(f.CompartmentId), map[string]*llx.RawData{
					"id":           llx.StringDataPtr(f.Id),
					"name":         llx.StringDataPtr(f.DisplayName),
					"filterType":   llx.StringData(string(f.FilterType)),
					"state":        llx.StringData(string(f.LifecycleState)),
					"created":      sdkTimeData(f.TimeCreated),
					"freeformTags": llx.MapData(strMapToAny(f.FreeformTags), types.String),
					"definedTags":  llx.MapData(definedTagsToAny(f.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				m.(*mqlOciNetworkCaptureFilter).cacheFilter = f
				res = append(res, m)
			}
			return res, nil
		})
}

func (o *mqlOciNetworkCaptureFilter) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkCaptureFilter) rules() ([]any, error) {
	all := captureFilterRuleArgs(o.cacheFilter)
	out := make([]any, 0, len(all))
	for i, args := range all {
		args["__id"] = llx.StringData(o.Id.Data + "/rule/" + strconv.Itoa(i))
		m, err := CreateResource(o.MqlRuntime, "oci.network.captureFilter.rule", args)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// captureFilterRuleArgs maps both rule kinds onto one shape: VTAP rules have
// a direction, flow log rules a priority, sampling rate, and enabled switch.
func captureFilterRuleArgs(f core.CaptureFilter) []map[string]*llx.RawData {
	out := []map[string]*llx.RawData{}
	for _, r := range f.VtapCaptureFilterRules {
		out = append(out, map[string]*llx.RawData{
			"action":          llx.StringData(string(r.RuleAction)),
			"direction":       llx.StringData(string(r.TrafficDirection)),
			"sourceCidr":      llx.StringData(stringValue(r.SourceCidr)),
			"destinationCidr": llx.StringData(stringValue(r.DestinationCidr)),
			"protocol":        llx.StringData(stringValue(r.Protocol)),
			"isEnabled":       llx.BoolTrue,
			"priority":        llx.NilData,
			"samplingRate":    llx.NilData,
		})
	}
	for _, r := range f.FlowLogCaptureFilterRules {
		out = append(out, map[string]*llx.RawData{
			"action":          llx.StringData(string(r.RuleAction)),
			"direction":       llx.StringData(""),
			"sourceCidr":      llx.StringData(stringValue(r.SourceCidr)),
			"destinationCidr": llx.StringData(stringValue(r.DestinationCidr)),
			"protocol":        llx.StringData(stringValue(r.Protocol)),
			"isEnabled":       llx.BoolData(r.IsEnabled == nil || *r.IsEnabled),
			"priority":        intPtrData(r.Priority),
			"samplingRate":    intPtrData(r.SamplingRate),
		})
	}
	return out
}

// ---- cross-connect groups ----

type mqlOciNetworkCrossConnectGroupInternal struct {
	ociCompartmentRef
}

func (o *mqlOciNetworkCrossConnectGroup) id() (string, error) {
	return "oci.network.crossConnectGroup/" + o.Id.Data, nil
}

func (o *mqlOciNetwork) crossConnectGroups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.NetworkClient(region)
			if err != nil {
				return nil, err
			}
			groups, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.CrossConnectGroup, *string, error) {
				response, err := svc.ListCrossConnectGroups(ctx, core.ListCrossConnectGroupsRequest{CompartmentId: common.String(compartmentID), Page: page})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}
			res := make([]any, 0, len(groups))
			for i := range groups {
				g := groups[i]
				m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.network.crossConnectGroup", stringValue(g.CompartmentId), crossConnectGroupArgs(g))
				if err != nil {
					return nil, err
				}
				res = append(res, m)
			}
			return res, nil
		})
}

func crossConnectGroupArgs(g core.CrossConnectGroup) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"id":                                llx.StringDataPtr(g.Id),
		"name":                              llx.StringDataPtr(g.DisplayName),
		"state":                             llx.StringData(string(g.LifecycleState)),
		"customerReferenceName":             llx.StringData(stringValue(g.CustomerReferenceName)),
		"macsecState":                       llx.StringData(""),
		"macsecEncryptionCipher":            llx.StringData(""),
		"macsecIsUnprotectedTrafficAllowed": llx.BoolFalse,
		"minimumLinks":                      intPtrData(g.MinimumLinks),
		"created":                           sdkTimeData(g.TimeCreated),
		"freeformTags":                      llx.MapData(strMapToAny(g.FreeformTags), types.String),
		"definedTags":                       llx.MapData(definedTagsToAny(g.DefinedTags), types.Any),
	}
	if m := g.MacsecProperties; m != nil {
		args["macsecState"] = llx.StringData(string(m.State))
		args["macsecEncryptionCipher"] = llx.StringData(string(m.EncryptionCipher))
		args["macsecIsUnprotectedTrafficAllowed"] = llx.BoolData(m.IsUnprotectedTrafficAllowed != nil && *m.IsUnprotectedTrafficAllowed)
	}
	return args
}

func (o *mqlOciNetworkCrossConnectGroup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciNetworkCrossConnectGroup) crossConnects() ([]any, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return childrenOf(n.GetCrossConnects(), o.Id.Data, func(c *mqlOciNetworkCrossConnect) string { return c.CrossConnectGroupId.Data })
}

func (o *mqlOciNetworkCrossConnect) crossConnectGroup() (*mqlOciNetworkCrossConnectGroup, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetCrossConnectGroups(), o.CrossConnectGroupId.Data, &o.CrossConnectGroup)
}

// vtapRefID is the OCID of a VTAP's source or target when it is of the kind
// an accessor resolves, and empty otherwise, so every other accessor reads
// null.
func vtapRefID(actualType, wantType, id string) string {
	if actualType != wantType {
		return ""
	}
	return ocidOrEmpty(id)
}

func (o *mqlOciNetworkVtap) sourceVnic() (*mqlOciComputeVnic, error) {
	return resolveRef(o.MqlRuntime, "oci.compute.vnic", vtapRefID(o.SourceType.Data, "VNIC", o.SourceId.Data), &o.SourceVnic)
}

func (o *mqlOciNetworkVtap) sourceSubnet() (*mqlOciNetworkSubnet, error) {
	n, err := ociNetworkService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(n.GetSubnets(), vtapRefID(o.SourceType.Data, "SUBNET", o.SourceId.Data), &o.SourceSubnet)
}

func (o *mqlOciNetworkVtap) sourceLoadBalancer() (*mqlOciLoadBalancerLoadBalancer, error) {
	return resolveRef(o.MqlRuntime, "oci.loadBalancer.loadBalancer", vtapRefID(o.SourceType.Data, "LOAD_BALANCER", o.SourceId.Data), &o.SourceLoadBalancer)
}

func (o *mqlOciNetworkVtap) sourceDbSystem() (*mqlOciDatabaseDbSystem, error) {
	return resolveRef(o.MqlRuntime, "oci.database.dbSystem", vtapRefID(o.SourceType.Data, "DB_SYSTEM", o.SourceId.Data), &o.SourceDbSystem)
}

func (o *mqlOciNetworkVtap) sourceAutonomousDatabase() (*mqlOciDatabaseAutonomousDatabase, error) {
	return resolveRef(o.MqlRuntime, "oci.database.autonomousDatabase", vtapRefID(o.SourceType.Data, "AUTONOMOUS_DATA_WAREHOUSE", o.SourceId.Data), &o.SourceAutonomousDatabase)
}

func (o *mqlOciNetworkVtap) sourceNetworkFirewall() (*mqlOciNetworkFirewallFirewall, error) {
	id := vtapRefID(o.SourceType.Data, "NETWORK_FIREWALL", o.SourceId.Data)
	if id == "" {
		o.SourceNetworkFirewall.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	svc, err := CreateResource(o.MqlRuntime, "oci.networkFirewall", nil)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.(*mqlOciNetworkFirewall).GetFirewalls(), id, &o.SourceNetworkFirewall)
}

func (o *mqlOciNetworkVtap) targetVnic() (*mqlOciComputeVnic, error) {
	return resolveRef(o.MqlRuntime, "oci.compute.vnic", vtapRefID(o.TargetType.Data, "VNIC", o.TargetId.Data), &o.TargetVnic)
}

func (o *mqlOciNetworkVtap) targetNetworkLoadBalancer() (*mqlOciNetworkLoadBalancerLoadBalancer, error) {
	id := vtapRefID(o.TargetType.Data, "NETWORK_LOAD_BALANCER", o.TargetId.Data)
	if id == "" {
		o.TargetNetworkLoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	svc, err := CreateResource(o.MqlRuntime, "oci.networkLoadBalancer", nil)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.(*mqlOciNetworkLoadBalancer).GetLoadBalancers(), id, &o.TargetNetworkLoadBalancer)
}
