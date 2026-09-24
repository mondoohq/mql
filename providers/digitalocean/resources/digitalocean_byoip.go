// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// --- BYOIP prefixes ---

func (r *mqlDigitaloceanByoipPrefix) id() (string, error) {
	return "digitalocean.byoipPrefix/" + r.Uuid.Data, nil
}

// byoipPrefixArgs maps a godo BYOIP prefix to its MQL fields.
func byoipPrefixArgs(p *godo.BYOIPPrefix) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"uuid":          llx.StringData(p.UUID),
		"prefix":        llx.StringData(p.Prefix),
		"status":        llx.StringData(p.Status),
		"region":        llx.StringData(p.Region),
		"advertised":    llx.BoolData(p.Advertised),
		"locked":        llx.BoolData(p.Locked),
		"failureReason": llx.StringData(p.FailureReason),
		"projectId":     llx.StringData(p.ProjectID),
	}
}

func (r *mqlDigitalocean) byoipPrefixes() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	prefixes, err := paginate(context.Background(), client.BYOIPPrefixes.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(prefixes))
	for _, p := range prefixes {
		if p == nil {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.byoipPrefix", byoipPrefixArgs(p))
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func initDigitaloceanByoipPrefix(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	uuid := stringArg(args, "uuid")
	if uuid == "" {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	p, _, err := conn.Client().BYOIPPrefixes.Get(context.Background(), uuid)
	if err != nil {
		return nil, nil, err
	}
	// godo returns the decoded root's field directly, so a 200 whose body
	// carries no prefix yields a nil object with a nil error.
	if p == nil {
		return nil, nil, fmt.Errorf("digitalocean.byoipPrefix with uuid %q not found", uuid)
	}
	return byoipPrefixArgs(p), nil, nil
}

func (r *mqlDigitaloceanByoipPrefix) project() (*mqlDigitaloceanProject, error) {
	return projectRef(r.MqlRuntime, r.ProjectId.Data, &r.Project)
}

func (r *mqlDigitaloceanByoipPrefix) resources() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []interface{}
	opt := &godo.ListOptions{PerPage: 200}
	for {
		resources, resp, err := client.BYOIPPrefixes.GetResources(context.Background(), r.Uuid.Data, opt)
		if err != nil {
			return nil, err
		}
		for i := range resources {
			res := resources[i]
			created, err := CreateResource(r.MqlRuntime, "digitalocean.byoipPrefix.resource", map[string]*llx.RawData{
				"id":         llx.IntData(int64(res.ID)),
				"prefixUuid": llx.StringData(r.Uuid.Data),
				"byoip":      llx.StringData(res.BYOIP),
				"resource":   llx.StringData(res.Resource),
				"region":     llx.StringData(res.Region),
				"assignedAt": llx.TimeData(res.AssignedAt),
			})
			if err != nil {
				return nil, err
			}
			all = append(all, created)
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return all, nil
}

func (r *mqlDigitaloceanByoipPrefixResource) id() (string, error) {
	return "digitalocean.byoipPrefix.resource/" + r.PrefixUuid.Data + "/" + r.Byoip.Data, nil
}

// --- Partner Attachments (Partner Network Connect) ---

func (r *mqlDigitaloceanPartnerAttachment) id() (string, error) {
	return "digitalocean.partnerAttachment/" + r.Id.Data, nil
}

// partnerAttachmentArgs maps a godo Partner Attachment to its MQL fields.
// The BGP auth key is deliberately omitted — it is a shared secret.
func partnerAttachmentArgs(p *godo.PartnerAttachment) map[string]*llx.RawData {
	vpcIds := make([]interface{}, len(p.VPCIDs))
	for i, v := range p.VPCIDs {
		vpcIds[i] = v
	}
	children := make([]interface{}, len(p.Children))
	for i, c := range p.Children {
		children[i] = c
	}
	bgp := map[string]interface{}{
		"localAsn":      int64(p.BGP.LocalASN),
		"localRouterIp": p.BGP.LocalRouterIP,
		"peerAsn":       int64(p.BGP.PeerASN),
		"peerRouterIp":  p.BGP.PeerRouterIP,
	}
	return map[string]*llx.RawData{
		"id":                        llx.StringData(p.ID),
		"name":                      llx.StringData(p.Name),
		"state":                     llx.StringData(p.State),
		"connectionBandwidthInMbps": llx.IntData(int64(p.ConnectionBandwidthInMbps)),
		"region":                    llx.StringData(p.Region),
		"naasProvider":              llx.StringData(p.NaaSProvider),
		"redundancyZone":            llx.StringData(p.RedundancyZone),
		"vpcIds":                    llx.ArrayData(vpcIds, "\x02"),
		"bgp":                       llx.DictData(bgp),
		"parentUuid":                llx.StringData(p.ParentUuid),
		"children":                  llx.ArrayData(children, "\x02"),
		"createdAt":                 llx.TimeData(p.CreatedAt),
	}
}

func (r *mqlDigitalocean) partnerAttachments() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	attachments, err := paginate(context.Background(), client.PartnerAttachment.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(attachments))
	for _, p := range attachments {
		if p == nil {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.partnerAttachment", partnerAttachmentArgs(p))
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func initDigitaloceanPartnerAttachment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	id := stringArg(args, "id")
	if id == "" {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	p, _, err := conn.Client().PartnerAttachment.Get(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	// godo returns the decoded root's field directly, so a 200 whose body
	// carries no attachment yields a nil object with a nil error.
	if p == nil {
		return nil, nil, fmt.Errorf("digitalocean.partnerAttachment with id %q not found", id)
	}
	return partnerAttachmentArgs(p), nil, nil
}

func (r *mqlDigitaloceanPartnerAttachment) vpcs() ([]interface{}, error) {
	uuids := make([]string, 0, len(r.VpcIds.Data))
	for _, v := range r.VpcIds.Data {
		if s, ok := v.(string); ok {
			uuids = append(uuids, s)
		}
	}
	return vpcRefsByUUIDs(r.MqlRuntime, uuids)
}

// --- Account billing balance ---

func (r *mqlDigitaloceanBilling) id() (string, error) {
	return "digitalocean.billing", nil
}

func (r *mqlDigitalocean) billing() (*mqlDigitaloceanBilling, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	balance, _, err := conn.Client().Balance.Get(context.Background())
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "digitalocean.billing", map[string]*llx.RawData{
		"accountBalance":     llx.StringData(balance.AccountBalance),
		"monthToDateUsage":   llx.StringData(balance.MonthToDateUsage),
		"monthToDateBalance": llx.StringData(balance.MonthToDateBalance),
		"generatedAt":        llx.TimeData(balance.GeneratedAt),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanBilling), nil
}
