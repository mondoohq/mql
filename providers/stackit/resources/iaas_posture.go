// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	iaas "github.com/stackitcloud/stackit-sdk-go/services/iaas/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Server volume attachments, routing table routes, project quotas, and the
// STACKIT public IP ranges.

// ------------------------- server volume attachments -------------------------

// mqlStackitServerAttachedVolumeInternal keeps the attached volume's ID for
// the typed volume accessor.
type mqlStackitServerAttachedVolumeInternal struct {
	cacheVolumeID string
}

func (r *mqlStackitServer) attachedVolumes() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListAttachedVolumes(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetItems()
	out := make([]any, 0, len(items))
	for i := range items {
		a := &items[i]
		volumeID := a.GetVolumeId()
		if volumeID == "" {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.server.attachedVolume", map[string]*llx.RawData{
			"__id":                llx.StringData(qualifiedId("stackit.server.attachedVolume", r.Id.Data, volumeID)),
			"deleteOnTermination": llx.BoolDataPtr(optBool(a.GetDeleteOnTerminationOk())),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlStackitServerAttachedVolume).cacheVolumeID = volumeID
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitServerAttachedVolume) volume() (*mqlStackitVolume, error) {
	return volumeFromProjectList(r.MqlRuntime, r.cacheVolumeID, &r.Volume)
}

// volumeFromProjectList resolves a volume by ID against the project's volume
// list, read once and shared by every caller. The field is null for an empty
// ID and for a volume the list does not hold.
func volumeFromProjectList(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlStackitVolume]) (*mqlStackitVolume, error) {
	if id == "" {
		return markNull(field)
	}
	root, err := CreateResource(runtime, "stackit", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	volumes := root.(*mqlStackit).GetVolumes()
	if volumes.Error != nil {
		return nil, volumes.Error
	}
	for _, v := range volumes.Data {
		vol, ok := v.(*mqlStackitVolume)
		if ok && vol.Id.Data == id {
			return vol, nil
		}
	}
	return markNull(field)
}

// ------------------------- routing table routes -------------------------

func (r *mqlStackitRoutingTable) routes() ([]any, error) {
	c := conn(r.MqlRuntime)
	orgID, areaID, err := c.RoutingTableArea(bgctx(), r.Id.Data)
	if err != nil {
		return nil, err
	}
	if areaID == "" {
		// The table is not on a network area this credential can read, so
		// its routes cannot be listed either.
		r.Routes.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListRoutesOfRoutingTable(bgctx(), orgID, areaID, c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items := resp.GetItems()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.routingTable.route", routeArgs(r.Id.Data, &items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func routeArgs(tableID string, route *iaas.Route) map[string]*llx.RawData {
	nexthopType, nexthopValue := routeNexthop(route.GetNexthop())
	createdAt, okCreated := route.GetCreatedAtOk()
	updatedAt, okUpdated := route.GetUpdatedAtOk()
	destination := routeDestination(route.GetDestination())
	key := route.GetId()
	if key == "" {
		key = destination
	}
	return map[string]*llx.RawData{
		"__id":            llx.StringData(qualifiedId("stackit.routingTable.route", tableID, key)),
		"id":              llx.StringData(route.GetId()),
		"destination":     llx.StringData(destination),
		"nexthopType":     llx.StringData(nexthopType),
		"nexthopValue":    llx.StringData(nexthopValue),
		"nexthopInternet": llx.BoolData(nexthopType == "internet"),
		"createdAt":       llx.TimeDataPtr(timeOrNil(createdAt, okCreated)),
		"updatedAt":       llx.TimeDataPtr(timeOrNil(updatedAt, okUpdated)),
		"labels":          labelData(route.GetLabels()),
	}
}

// routeNexthop renders a route's next hop as its type and address. The
// address is empty for the internet and blackhole next hops, which carry none.
func routeNexthop(n iaas.RouteNexthop) (string, string) {
	switch {
	case n.NexthopIPv4 != nil:
		return "ipv4", n.NexthopIPv4.GetValue()
	case n.NexthopIPv6 != nil:
		return "ipv6", n.NexthopIPv6.GetValue()
	case n.NexthopInternet != nil:
		return "internet", ""
	case n.NexthopBlackhole != nil:
		return "blackhole", ""
	}
	return "", ""
}

// routeDestination renders a route's destination CIDR, IPv4 or IPv6.
func routeDestination(d iaas.RouteDestination) string {
	switch {
	case d.DestinationCIDRv4 != nil:
		return d.DestinationCIDRv4.GetValue()
	case d.DestinationCIDRv6 != nil:
		return d.DestinationCIDRv6.GetValue()
	}
	return ""
}

// ------------------------- project quotas and public ranges -------------------------

type namedQuota struct {
	name  string
	quota iaas.Quota
}

// quotaEntries flattens the quota record into named entries in a fixed
// order.
func quotaEntries(q *iaas.QuotaList) []namedQuota {
	if q == nil {
		return nil
	}
	return []namedQuota{
		{"backupGigabytes", q.GetBackupGigabytes()},
		{"backups", q.GetBackups()},
		{"gigabytes", q.GetGigabytes()},
		{"networks", q.GetNetworks()},
		{"nics", q.GetNics()},
		{"publicIps", q.GetPublicIps()},
		{"ram", q.GetRam()},
		{"securityGroupRules", q.GetSecurityGroupRules()},
		{"securityGroups", q.GetSecurityGroups()},
		{"snapshots", q.GetSnapshots()},
		{"vcpu", q.GetVcpu()},
		{"volumes", q.GetVolumes()},
	}
}

func (r *mqlStackitProject) quotas() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListQuotas(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	quotas, ok := resp.GetQuotasOk()
	if !ok {
		return []any{}, nil
	}
	entries := quotaEntries(quotas)
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		res, err := CreateResource(r.MqlRuntime, "stackit.project.quota", map[string]*llx.RawData{
			"__id":  llx.StringData(qualifiedId("stackit.project.quota", c.ProjectID()+"/"+c.Region(), e.name)),
			"name":  llx.StringData(e.name),
			"limit": llx.IntData(e.quota.GetLimit()),
			"usage": llx.IntData(e.quota.GetUsage()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitProject) publicIpRanges() ([]any, error) {
	client, err := conn(r.MqlRuntime).IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListPublicIPRanges(bgctx()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	return strSlice(publicRangeCidrs(resp.GetItems())), nil
}

// publicRangeCidrs collects the CIDRs of the public ranges, skipping empty
// ones and repeats.
func publicRangeCidrs(items []iaas.PublicNetwork) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for i := range items {
		cidr := items[i].GetCidr()
		if cidr == "" {
			continue
		}
		if _, dup := seen[cidr]; dup {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out
}
