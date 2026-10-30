// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/sharedfilesystems/v2/securityservices"
	"github.com/gophercloud/gophercloud/v2/openstack/sharedfilesystems/v2/shareaccessrules"
	"github.com/gophercloud/gophercloud/v2/openstack/sharedfilesystems/v2/sharenetworks"
	"github.com/gophercloud/gophercloud/v2/openstack/sharedfilesystems/v2/shares"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// translateManilaError treats a 406 (microversion not supported by this cloud)
// as "no data", on top of the usual 401/403/404 handling. Older Manila
// deployments whose maximum microversion is below the one we request answer
// 406; that means the capability is absent, not that the query failed.
func translateManilaError(err error) error {
	if err == nil {
		return nil
	}
	var resp gophercloud.ErrUnexpectedResponseCode
	if errors.As(err, &resp) && resp.Actual == 406 {
		return nil
	}
	return translateOpenstackError(err)
}

// ---- openstack.sharedfilesystem.share ----

type mqlOpenstackSharedfilesystemShareInternal struct {
	cacheShareNetworkID string
	cacheProjectID      string
}

func (r *mqlOpenstackSharedfilesystemShare) id() (string, error) {
	return "openstack.sharedfilesystem.share/" + r.Id.Data, nil
}

func initOpenstackSharedfilesystemShare(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetShares()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackSharedfilesystemShare)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.sharedfilesystem.share", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) shares() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.SharedFileSystemClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := shares.ListDetail(client, nil).AllPages(ctx())
	if err != nil {
		if translateManilaError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := shares.ExtractShares(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		s := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.sharedfilesystem.share", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.sharedfilesystem.share/" + s.ID),
			"id":               llx.StringData(s.ID),
			"name":             llx.StringData(s.Name),
			"description":      llx.StringData(s.Description),
			"status":           llx.StringData(s.Status),
			"shareProto":       llx.StringData(s.ShareProto),
			"size":             llx.IntData(int64(s.Size)),
			"isPublic":         llx.BoolData(s.IsPublic),
			"shareType":        llx.StringData(s.ShareType),
			"shareTypeName":    llx.StringData(s.ShareTypeName),
			"availabilityZone": llx.StringData(s.AvailabilityZone),
			"host":             llx.StringData(s.Host),
			"hasReplicas":      llx.BoolData(s.HasReplicas),
			"replicationType":  llx.StringData(s.ReplicationType),
			"snapshotSupport":  llx.BoolData(s.SnapshotSupport),
			"snapshotId":       llx.StringData(s.SnapshotID),
			"metadata":         stringMapData(s.Metadata),
			"createdAt":        llx.TimeDataPtr(timePtr(s.CreatedAt)),
			"updatedAt":        llx.TimeDataPtr(timePtr(s.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlShare := res.(*mqlOpenstackSharedfilesystemShare)
		mqlShare.cacheShareNetworkID = s.ShareNetworkID
		mqlShare.cacheProjectID = s.ProjectID
		out = append(out, mqlShare)
	}
	return out, nil
}

func (r *mqlOpenstackSharedfilesystemShare) shareNetwork() (*mqlOpenstackSharedfilesystemShareNetwork, error) {
	if r.cacheShareNetworkID == "" {
		r.ShareNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.sharedfilesystem.shareNetwork", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheShareNetworkID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSharedfilesystemShareNetwork), nil
}

func (r *mqlOpenstackSharedfilesystemShare) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackSharedfilesystemShare) accessRules() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SharedFileSystemClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := shareaccessrules.List(ctx(), client, r.Id.Data).Extract()
	if err != nil {
		if translateManilaError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		a := &items[i]
		// The access key (a.AccessKey) is credential material and is not exposed.
		res, err := CreateResource(r.MqlRuntime, "openstack.sharedfilesystem.share.accessRule", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.sharedfilesystem.share.accessRule/" + a.ID),
			"id":          llx.StringData(a.ID),
			"accessType":  llx.StringData(a.AccessType),
			"accessTo":    llx.StringData(a.AccessTo),
			"accessLevel": llx.StringData(a.AccessLevel),
			"state":       llx.StringData(a.State),
			"shareId":     llx.StringData(r.Id.Data),
			"createdAt":   llx.TimeDataPtr(timePtr(a.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(timePtr(a.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.sharedfilesystem.share.accessRule ----

func (r *mqlOpenstackSharedfilesystemShareAccessRule) id() (string, error) {
	return "openstack.sharedfilesystem.share.accessRule/" + r.Id.Data, nil
}

func (r *mqlOpenstackSharedfilesystemShareAccessRule) share() (*mqlOpenstackSharedfilesystemShare, error) {
	if r.ShareId.Data == "" {
		r.Share.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.sharedfilesystem.share", map[string]*llx.RawData{
		"id": llx.StringData(r.ShareId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSharedfilesystemShare), nil
}

// ---- openstack.sharedfilesystem.securityService ----

func (r *mqlOpenstackSharedfilesystemSecurityService) id() (string, error) {
	return "openstack.sharedfilesystem.securityService/" + r.Id.Data, nil
}

func initOpenstackSharedfilesystemSecurityService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetSecurityServices()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackSharedfilesystemSecurityService)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.sharedfilesystem.securityService", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) securityServices() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.SharedFileSystemClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := securityservices.List(client, nil).AllPages(ctx())
	if err != nil {
		if translateManilaError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := securityservices.ExtractSecurityServices(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		s := &items[i]
		// The bind password (s.Password) is credential material and is not exposed.
		res, err := CreateResource(o.MqlRuntime, "openstack.sharedfilesystem.securityService", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.sharedfilesystem.securityService/" + s.ID),
			"id":          llx.StringData(s.ID),
			"name":        llx.StringData(s.Name),
			"description": llx.StringData(s.Description),
			"type":        llx.StringData(s.Type),
			"status":      llx.StringData(s.Status),
			"domain":      llx.StringData(s.Domain),
			"dnsIp":       llx.StringData(s.DNSIP),
			"ou":          llx.StringData(s.OU),
			"user":        llx.StringData(s.User),
			"server":      llx.StringData(s.Server),
			"createdAt":   llx.TimeDataPtr(timePtr(s.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(timePtr(s.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlOpenstackSharedfilesystemSecurityService).cacheProjectID = s.ProjectID
		out = append(out, res)
	}
	return out, nil
}

// mqlOpenstackSharedfilesystemSecurityServiceInternal holds the owning project
// id that project() resolves.
type mqlOpenstackSharedfilesystemSecurityServiceInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackSharedfilesystemSecurityService) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

// ---- openstack.sharedfilesystem.shareNetwork ----

func (r *mqlOpenstackSharedfilesystemShareNetwork) id() (string, error) {
	return "openstack.sharedfilesystem.shareNetwork/" + r.Id.Data, nil
}

func initOpenstackSharedfilesystemShareNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetShareNetworks()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		n := raw.(*mqlOpenstackSharedfilesystemShareNetwork)
		if n.Id.Data == id {
			return args, n, nil
		}
	}
	initSyntheticID("openstack.sharedfilesystem.shareNetwork", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) shareNetworks() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.SharedFileSystemClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := sharenetworks.ListDetail(client, nil).AllPages(ctx())
	if err != nil {
		if translateManilaError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := sharenetworks.ExtractShareNetworks(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		n := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.sharedfilesystem.shareNetwork", map[string]*llx.RawData{
			"__id":            llx.StringData("openstack.sharedfilesystem.shareNetwork/" + n.ID),
			"id":              llx.StringData(n.ID),
			"name":            llx.StringData(n.Name),
			"description":     llx.StringData(n.Description),
			"neutronNetId":    llx.StringData(n.NeutronNetID),
			"neutronSubnetId": llx.StringData(n.NeutronSubnetID),
			"networkType":     llx.StringData(n.NetworkType),
			"segmentationId":  llx.IntData(int64(n.SegmentationID)),
			"cidr":            llx.StringData(n.CIDR),
			"ipVersion":       llx.IntData(int64(n.IPVersion)),
			"createdAt":       llx.TimeDataPtr(timePtr(n.CreatedAt)),
			"updatedAt":       llx.TimeDataPtr(timePtr(n.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlOpenstackSharedfilesystemShareNetwork).cacheProjectID = n.ProjectID
		out = append(out, res)
	}
	return out, nil
}

// mqlOpenstackSharedfilesystemShareNetworkInternal holds the owning project id
// that project() resolves.
type mqlOpenstackSharedfilesystemShareNetworkInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackSharedfilesystemShareNetwork) network() (*mqlOpenstackNetwork, error) {
	if r.NeutronNetId.Data == "" {
		r.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.network", map[string]*llx.RawData{
		"id": llx.StringData(r.NeutronNetId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackNetwork), nil
}

func (r *mqlOpenstackSharedfilesystemShareNetwork) subnet() (*mqlOpenstackSubnet, error) {
	if r.NeutronSubnetId.Data == "" {
		r.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.subnet", map[string]*llx.RawData{
		"id": llx.StringData(r.NeutronSubnetId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSubnet), nil
}

func (r *mqlOpenstackSharedfilesystemShareNetwork) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}
