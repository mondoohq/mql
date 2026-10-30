// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"time"

	dns "github.com/stackitcloud/stackit-sdk-go/services/dns/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlStackitDns) zones() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.DNS()
	if err != nil {
		return nil, err
	}
	out := []any{}
	const pageSize int32 = 500
	for page := int32(1); ; page++ {
		resp, err := client.DefaultAPI.ListZones(bgctx(), c.ProjectID()).Page(page).PageSize(pageSize).Execute()
		if err != nil {
			if isAccessDenied(err) {
				return deniedList(err)
			}
			return nil, err
		}
		items, _ := resp.GetZonesOk()
		for i := range items {
			z := items[i]
			res, err := buildDnsZone(r.MqlRuntime, &z)
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(items) < int(pageSize) {
			break
		}
	}
	return out, nil
}

func buildDnsZone(runtime *plugin.Runtime, z *dns.Zone) (plugin.Resource, error) {
	created := parseDnsTime(z.GetCreationFinished())
	args := map[string]*llx.RawData{
		"id":                 llx.StringData(z.GetId()),
		"dnsName":            llx.StringData(z.GetDnsName()),
		"description":        llx.StringData(z.GetDescription()),
		"type":               llx.StringData(string(z.GetType())),
		"visibility":         llx.StringData(string(z.GetVisibility())),
		"state":              llx.StringData(string(z.GetState())),
		"defaultTtl":         llx.IntData(int64(z.GetDefaultTTL())),
		"contactEmail":       llx.StringData(z.GetContactEmail()),
		"serialNumber":       llx.IntData(int64(z.GetSerialNumber())),
		"primaryNameServer":  llx.StringData(z.GetPrimaryNameServer()),
		"expireTime":         llx.IntData(int64(z.GetExpireTime())),
		"refreshTime":        llx.IntData(int64(z.GetRefreshTime())),
		"retryTime":          llx.IntData(int64(z.GetRetryTime())),
		"negativeCache":      llx.IntData(int64(z.GetNegativeCache())),
		"recordCount":        llx.IntData(int64(z.GetRecordCount())),
		"acl":                llx.StringData(z.GetAcl()),
		"primaries":          strSliceData(z.GetPrimaries()),
		"isReverseZone":      llx.BoolData(z.GetIsReverseZone()),
		"creationStartedAt":  llx.TimeDataPtr(parseDnsTime(z.GetCreationStarted())),
		"creationFinishedAt": llx.TimeDataPtr(created),
		"labels":             stringMapData(dnsLabels(z.GetLabels())),
	}
	return CreateResource(runtime, "stackit.dns.zone", args)
}

// dnsLabels flattens the DNS Zone label slice (`[]dns.Label{Key, Value}`) into
// the `map[string]string` shape MQL expects for the `labels` field.
func dnsLabels(in []dns.Label) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for _, l := range in {
		out[l.GetKey()] = l.GetValue()
	}
	return out
}

// parseDnsTime turns a STACKIT DNS RFC3339-ish timestamp into a *time.Time
// (or nil if empty / malformed). DNS uses strings, not time.Time, in its API.
func parseDnsTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

func (r *mqlStackitDnsZone) id() (string, error) {
	return "stackit.dns.zone/" + r.Id.Data, nil
}

func initStackitDnsZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.DNS()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetZone(bgctx(), c.ProjectID(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	z, ok := resp.GetZoneOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit.dns.zone with id %q not found", id)
	}
	res, err := buildDnsZone(runtime, z)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlStackitDnsZone) recordSets() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.DNS()
	if err != nil {
		return nil, err
	}
	out := []any{}
	const pageSize int32 = 500
	for page := int32(1); ; page++ {
		resp, err := client.DefaultAPI.ListRecordSets(bgctx(), c.ProjectID(), r.Id.Data).Page(page).PageSize(pageSize).Execute()
		if err != nil {
			if isAccessDenied(err) {
				return deniedList(err)
			}
			return nil, err
		}
		items, _ := resp.GetRrSetsOk()
		for i := range items {
			rs := items[i]
			records := []string{}
			for _, rec := range rs.GetRecords() {
				records = append(records, rec.GetContent())
			}
			args := map[string]*llx.RawData{
				"id":                 llx.StringData(rs.GetId()),
				"zoneId":             llx.StringData(r.Id.Data),
				"name":               llx.StringData(rs.GetName()),
				"type":               llx.StringData(string(rs.GetType())),
				"ttl":                llx.IntData(int64(rs.GetTtl())),
				"state":              llx.StringData(string(rs.GetState())),
				"comment":            llx.StringData(rs.GetComment()),
				"records":            strSliceData(records),
				"active":             llx.BoolData(rs.GetActive()),
				"creationStartedAt":  llx.TimeDataPtr(parseDnsTime(rs.GetCreationStarted())),
				"creationFinishedAt": llx.TimeDataPtr(parseDnsTime(rs.GetCreationFinished())),
				"updateFinishedAt":   llx.TimeDataPtr(parseDnsTime(rs.GetUpdateFinished())),
			}
			res, err := CreateResource(r.MqlRuntime, "stackit.dns.recordSet", args)
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(items) < int(pageSize) {
			break
		}
	}
	return out, nil
}

func (r *mqlStackitDnsRecordSet) id() (string, error) {
	return "stackit.dns.recordSet/" + r.ZoneId.Data + "/" + r.Id.Data, nil
}

func (r *mqlStackitDnsRecordSet) zone() (*mqlStackitDnsZone, error) {
	if r.ZoneId.Data == "" {
		return markNull[mqlStackitDnsZone](&r.Zone)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.dns.zone", map[string]*llx.RawData{
		"id": llx.StringData(r.ZoneId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitDnsZone), nil
}
