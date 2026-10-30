// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// dnsRecordSetTypedArgs maps the per-record-type arrays of an ARM record set
// onto the record set resource's typed fields.
//
// Every field is written on every record set, because ARM returns exactly one
// populated array per set and leaves the rest empty. Publishing the empty ones
// keeps the absent record types reading as an empty list rather than as
// unresolved fields.
func dnsRecordSetTypedArgs(runtime *plugin.Runtime, recordSetID string, props *armdns.RecordSetProperties) (map[string]*llx.RawData, error) {
	p := orZero(props)

	aRecords := []any{}
	for _, r := range p.ARecords {
		if r != nil && r.IPv4Address != nil {
			aRecords = append(aRecords, *r.IPv4Address)
		}
	}
	aaaaRecords := []any{}
	for _, r := range p.AaaaRecords {
		if r != nil && r.IPv6Address != nil {
			aaaaRecords = append(aaaaRecords, *r.IPv6Address)
		}
	}
	nsRecords := []any{}
	for _, r := range p.NsRecords {
		if r != nil && r.Nsdname != nil {
			nsRecords = append(nsRecords, *r.Nsdname)
		}
	}
	ptrRecords := []any{}
	for _, r := range p.PtrRecords {
		if r != nil && r.Ptrdname != nil {
			ptrRecords = append(ptrRecords, *r.Ptrdname)
		}
	}

	// DNS splits a text value into 255-byte chunks on the wire and ARM hands
	// them back as the chunk list. Joining them restores the single value the
	// record carries, which is what an SPF or DMARC policy is actually read
	// as; leaving the chunks split would make a long policy unmatchable.
	txtRecords := []any{}
	for _, r := range p.TxtRecords {
		if r == nil {
			continue
		}
		var sb strings.Builder
		for _, chunk := range r.Value {
			if chunk != nil {
				sb.WriteString(*chunk)
			}
		}
		txtRecords = append(txtRecords, sb.String())
	}

	mxRecords := []any{}
	for i, r := range p.MxRecords {
		if r == nil {
			continue
		}
		mql, err := CreateResource(runtime, "azure.subscription.dnsService.zone.recordSet.mxRecord",
			map[string]*llx.RawData{
				"__id":       llx.StringData(dnsRecordChildID(recordSetID, "mxRecords", i)),
				"preference": llx.IntDataPtr(r.Preference),
				"exchange":   llx.StringDataPtr(r.Exchange),
			})
		if err != nil {
			return nil, err
		}
		mxRecords = append(mxRecords, mql)
	}

	caaRecords := []any{}
	for i, r := range p.CaaRecords {
		if r == nil {
			continue
		}
		mql, err := CreateResource(runtime, "azure.subscription.dnsService.zone.recordSet.caaRecord",
			map[string]*llx.RawData{
				"__id":  llx.StringData(dnsRecordChildID(recordSetID, "caaRecords", i)),
				"flags": llx.IntDataPtr(r.Flags),
				"tag":   llx.StringDataPtr(r.Tag),
				"value": llx.StringDataPtr(r.Value),
			})
		if err != nil {
			return nil, err
		}
		caaRecords = append(caaRecords, mql)
	}

	srvRecords := []any{}
	for i, r := range p.SrvRecords {
		if r == nil {
			continue
		}
		mql, err := CreateResource(runtime, "azure.subscription.dnsService.zone.recordSet.srvRecord",
			map[string]*llx.RawData{
				"__id":     llx.StringData(dnsRecordChildID(recordSetID, "srvRecords", i)),
				"priority": llx.IntDataPtr(r.Priority),
				"weight":   llx.IntDataPtr(r.Weight),
				"port":     llx.IntDataPtr(r.Port),
				"target":   llx.StringDataPtr(r.Target),
			})
		if err != nil {
			return nil, err
		}
		srvRecords = append(srvRecords, mql)
	}

	soaRecord := llx.NilData
	if p.SoaRecord != nil {
		mql, err := CreateResource(runtime, "azure.subscription.dnsService.zone.recordSet.soaRecord",
			map[string]*llx.RawData{
				"__id":         llx.StringData(recordSetID + "/soaRecord"),
				"host":         llx.StringDataPtr(p.SoaRecord.Host),
				"email":        llx.StringDataPtr(p.SoaRecord.Email),
				"serialNumber": llx.IntDataPtr(p.SoaRecord.SerialNumber),
				"refreshTime":  llx.IntDataPtr(p.SoaRecord.RefreshTime),
				"retryTime":    llx.IntDataPtr(p.SoaRecord.RetryTime),
				"expireTime":   llx.IntDataPtr(p.SoaRecord.ExpireTime),
				"minimumTtl":   llx.IntDataPtr(p.SoaRecord.MinimumTTL),
			})
		if err != nil {
			return nil, err
		}
		soaRecord = llx.ResourceData(mql, "azure.subscription.dnsService.zone.recordSet.soaRecord")
	}

	return map[string]*llx.RawData{
		"aRecords":          llx.ArrayData(aRecords, types.String),
		"aaaaRecords":       llx.ArrayData(aaaaRecords, types.String),
		"nsRecords":         llx.ArrayData(nsRecords, types.String),
		"ptrRecords":        llx.ArrayData(ptrRecords, types.String),
		"txtRecords":        llx.ArrayData(txtRecords, types.String),
		"mxRecords":         llx.ArrayData(mxRecords, types.Resource("azure.subscription.dnsService.zone.recordSet.mxRecord")),
		"caaRecords":        llx.ArrayData(caaRecords, types.Resource("azure.subscription.dnsService.zone.recordSet.caaRecord")),
		"srvRecords":        llx.ArrayData(srvRecords, types.Resource("azure.subscription.dnsService.zone.recordSet.srvRecord")),
		"soaRecord":         soaRecord,
		"metadata":          llx.MapData(convert.PtrMapStrToInterface(p.Metadata), types.String),
		"provisioningState": llx.StringDataPtr(p.ProvisioningState),
	}, nil
}

// dnsRecordChildID builds the cache key for one row of a record set's typed
// record list. The rows carry no ARM identifier of their own, so the position
// within the set is what distinguishes them; without an explicit key every row
// in the scan would alias onto the same cache entry and the list would report
// one row's data N times.
func dnsRecordChildID(recordSetID, collection string, index int) string {
	return recordSetID + "/" + collection + "/" + strconv.Itoa(index)
}
