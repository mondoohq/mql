// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/transfer/accept"
	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/transfer/request"
	"github.com/gophercloud/gophercloud/v2/openstack/dns/v2/tsigkeys"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The transfer key on a request and an acceptance, and the secret on a TSIG
// key, are the credentials those objects exist to protect. They are read out of
// the API but deliberately not modeled, so a scan result never carries them.

// ---- openstack.dns.transferRequest ----

type mqlOpenstackDnsTransferRequestInternal struct {
	cacheZoneID          string
	cacheProjectID       string
	cacheTargetProjectID string
}

func (r *mqlOpenstackDnsTransferRequest) id() (string, error) {
	return "openstack.dns.transferRequest/" + r.Id.Data, nil
}

func (o *mqlOpenstack) dnsTransferRequests() ([]any, error) {
	client, err := conn(o.MqlRuntime).DNSClient()
	if err != nil {
		return nil, err
	}
	pages, err := request.List(client, request.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := request.ExtractTransferRequests(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, tr := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.dns.transferRequest", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.dns.transferRequest/" + tr.ID),
			"id":          llx.StringData(tr.ID),
			"zoneName":    llx.StringData(tr.ZoneName),
			"description": llx.StringData(tr.Description),
			"status":      llx.StringData(tr.Status),
			"createdAt":   llx.TimeDataPtr(timePtr(tr.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(timePtr(tr.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlTR := res.(*mqlOpenstackDnsTransferRequest)
		mqlTR.cacheZoneID = tr.ZoneID
		mqlTR.cacheProjectID = tr.ProjectID
		mqlTR.cacheTargetProjectID = tr.TargetProjectID
		out = append(out, mqlTR)
	}
	return out, nil
}

func (r *mqlOpenstackDnsTransferRequest) zone() (*mqlOpenstackDnsZone, error) {
	return resolveDNSZone(r.MqlRuntime, r.cacheZoneID, &r.Zone)
}

func (r *mqlOpenstackDnsTransferRequest) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackDnsTransferRequest) targetProject() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheTargetProjectID, &r.TargetProject)
}

// ---- openstack.dns.transferAccept ----

type mqlOpenstackDnsTransferAcceptInternal struct {
	cacheZoneID            string
	cacheProjectID         string
	cacheTransferRequestID string
}

func (r *mqlOpenstackDnsTransferAccept) id() (string, error) {
	return "openstack.dns.transferAccept/" + r.Id.Data, nil
}

func (o *mqlOpenstack) dnsTransferAccepts() ([]any, error) {
	client, err := conn(o.MqlRuntime).DNSClient()
	if err != nil {
		return nil, err
	}
	pages, err := accept.List(client, accept.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := accept.ExtractTransferAccepts(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, ta := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.dns.transferAccept", map[string]*llx.RawData{
			"__id":      llx.StringData("openstack.dns.transferAccept/" + ta.ID),
			"id":        llx.StringData(ta.ID),
			"status":    llx.StringData(ta.Status),
			"createdAt": llx.TimeDataPtr(timePtr(ta.CreatedAt)),
			"updatedAt": llx.TimeDataPtr(timePtr(ta.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlTA := res.(*mqlOpenstackDnsTransferAccept)
		mqlTA.cacheZoneID = ta.ZoneID
		mqlTA.cacheProjectID = ta.ProjectID
		mqlTA.cacheTransferRequestID = ta.ZoneTransferRequestID
		out = append(out, mqlTA)
	}
	return out, nil
}

func (r *mqlOpenstackDnsTransferAccept) zone() (*mqlOpenstackDnsZone, error) {
	return resolveDNSZone(r.MqlRuntime, r.cacheZoneID, &r.Zone)
}

func (r *mqlOpenstackDnsTransferAccept) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackDnsTransferAccept) transferRequest() (*mqlOpenstackDnsTransferRequest, error) {
	if r.cacheTransferRequestID == "" {
		r.TransferRequest.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := CreateResource(r.MqlRuntime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := root.(*mqlOpenstack).GetDnsTransferRequests()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, raw := range list.Data {
		tr, ok := raw.(*mqlOpenstackDnsTransferRequest)
		if ok && tr.Id.Data == r.cacheTransferRequestID {
			return tr, nil
		}
	}
	// A completed transfer outlives the request it was accepted against, so a
	// missing request is expected rather than an error.
	r.TransferRequest.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ---- openstack.dns.tsigKey ----

type mqlOpenstackDnsTsigKeyInternal struct {
	cacheZoneID string
}

func (r *mqlOpenstackDnsTsigKey) id() (string, error) {
	return "openstack.dns.tsigKey/" + r.Id.Data, nil
}

func (o *mqlOpenstack) dnsTsigKeys() ([]any, error) {
	client, err := conn(o.MqlRuntime).DNSClient()
	if err != nil {
		return nil, err
	}
	pages, err := tsigkeys.List(client, tsigkeys.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := tsigkeys.ExtractTSIGKeys(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, k := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.dns.tsigKey", map[string]*llx.RawData{
			"__id":       llx.StringData("openstack.dns.tsigKey/" + k.ID),
			"id":         llx.StringData(k.ID),
			"name":       llx.StringData(k.Name),
			"algorithm":  llx.StringData(k.Algorithm),
			"scope":      llx.StringData(k.Scope),
			"resourceId": llx.StringData(k.ResourceID),
			"createdAt":  llx.TimeDataPtr(timePtr(k.CreatedAt)),
			"updatedAt":  llx.TimeDataPtr(timePtr(k.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlKey := res.(*mqlOpenstackDnsTsigKey)
		// Only a ZONE-scoped key names a zone; a POOL-scoped one names a pool,
		// which is not a resource this provider models.
		if strings.EqualFold(k.Scope, "ZONE") {
			mqlKey.cacheZoneID = k.ResourceID
		}
		out = append(out, mqlKey)
	}
	return out, nil
}

func (r *mqlOpenstackDnsTsigKey) zone() (*mqlOpenstackDnsZone, error) {
	return resolveDNSZone(r.MqlRuntime, r.cacheZoneID, &r.Zone)
}

// resolveDNSZone resolves a zone id to the zone resource, leaving the field null
// when no zone is named.
func resolveDNSZone(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOpenstackDnsZone]) (*mqlOpenstackDnsZone, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.dns.zone", map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackDnsZone), nil
}
