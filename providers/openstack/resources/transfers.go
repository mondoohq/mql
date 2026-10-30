// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	volumetransfers "github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/transfers"
	sharetransfers "github.com/gophercloud/gophercloud/v2/openstack/sharedfilesystems/v2/sharetransfers"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Both transfer kinds carry an auth key that redeems the offer. It is read out
// of the API but deliberately not modeled, so a scan result never carries the
// credential that would let its reader take the data.

// ---- openstack.blockstorage.transfer ----

type mqlOpenstackBlockstorageTransferInternal struct {
	cacheVolumeID string
}

func (r *mqlOpenstackBlockstorageTransfer) id() (string, error) {
	return "openstack.blockstorage.transfer/" + r.Id.Data, nil
}

func (o *mqlOpenstack) volumeTransfers() ([]any, error) {
	client, err := conn(o.MqlRuntime).BlockStorageClient()
	if err != nil {
		return nil, err
	}
	pages, err := volumetransfers.List(client, volumetransfers.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := volumetransfers.ExtractTransfers(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, t := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.blockstorage.transfer", map[string]*llx.RawData{
			"__id":      llx.StringData("openstack.blockstorage.transfer/" + t.ID),
			"id":        llx.StringData(t.ID),
			"name":      llx.StringData(t.Name),
			"createdAt": llx.TimeDataPtr(timePtr(t.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlT := res.(*mqlOpenstackBlockstorageTransfer)
		mqlT.cacheVolumeID = t.VolumeID
		out = append(out, mqlT)
	}
	return out, nil
}

func (r *mqlOpenstackBlockstorageTransfer) volume() (*mqlOpenstackBlockstorageVolume, error) {
	if r.cacheVolumeID == "" {
		r.Volume.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.blockstorage.volume", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheVolumeID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackBlockstorageVolume), nil
}

// ---- openstack.sharedfilesystem.transfer ----

type mqlOpenstackSharedfilesystemTransferInternal struct {
	cacheShareID              string
	cacheSourceProjectID      string
	cacheDestinationProjectID string
}

func (r *mqlOpenstackSharedfilesystemTransfer) id() (string, error) {
	return "openstack.sharedfilesystem.transfer/" + r.Id.Data, nil
}

func (o *mqlOpenstack) shareTransfers() ([]any, error) {
	client, err := conn(o.MqlRuntime).SharedFileSystemClient()
	if err != nil {
		return nil, err
	}
	pages, err := sharetransfers.ListDetail(client, sharetransfers.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := sharetransfers.ExtractTransfers(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, t := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.sharedfilesystem.transfer", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.sharedfilesystem.transfer/" + t.ID),
			"id":           llx.StringData(t.ID),
			"name":         llx.StringData(t.Name),
			"accepted":     llx.BoolData(t.Accepted),
			"resourceType": llx.StringData(t.ResourceType),
			"createdAt":    llx.TimeDataPtr(timePtr(t.CreatedAt)),
			"expiresAt":    llx.TimeDataPtr(timePtr(t.ExpiresAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlT := res.(*mqlOpenstackSharedfilesystemTransfer)
		// resourceType is "share" today; guard so a future type does not get
		// resolved as a share id.
		if t.ResourceType == "" || t.ResourceType == "share" {
			mqlT.cacheShareID = t.ResourceID
		}
		mqlT.cacheSourceProjectID = t.SourceProjectID
		mqlT.cacheDestinationProjectID = t.DestinationProjectID
		out = append(out, mqlT)
	}
	return out, nil
}

func (r *mqlOpenstackSharedfilesystemTransfer) share() (*mqlOpenstackSharedfilesystemShare, error) {
	if r.cacheShareID == "" {
		r.Share.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.sharedfilesystem.share", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheShareID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSharedfilesystemShare), nil
}

func (r *mqlOpenstackSharedfilesystemTransfer) sourceProject() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheSourceProjectID, &r.SourceProject)
}

func (r *mqlOpenstackSharedfilesystemTransfer) destinationProject() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheDestinationProjectID, &r.DestinationProject)
}
