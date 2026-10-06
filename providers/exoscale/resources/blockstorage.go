// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
)

type mqlExoscaleBlockStorageVolumeInternal struct {
	cacheInstanceID string
}

func (r *mqlExoscale) blockStorageVolumes() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-block-storage-volumes", func(c *v3.Client) ([]v3.BlockStorageVolume, error) {
		res, err := c.ListBlockStorageVolumes(ctx())
		if err != nil {
			return nil, err
		}
		return res.BlockStorageVolumes, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		v := it.item
		res, err := CreateResource(r.MqlRuntime, "exoscale.blockStorage.volume", map[string]*llx.RawData{
			"__id":      llx.StringData("exoscale.blockStorage.volume/" + string(v.ID)),
			"id":        llx.StringData(string(v.ID)),
			"zone":      llx.StringData(it.zone),
			"name":      llx.StringData(v.Name),
			"size":      llx.IntData(v.Size),
			"blocksize": llx.IntData(v.Blocksize),
			"state":     llx.StringData(string(v.State)),
			"created":   timeData(v.CreatedAT),
			"encrypted": boolData(v.Encrypted),
			"labels":    labelData(v.Labels),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlExoscaleBlockStorageVolume)
		if v.Instance != nil {
			m.cacheInstanceID = string(v.Instance.ID)
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleBlockStorageVolume) instance() (*mqlExoscaleComputeInstance, error) {
	return instanceByID(r.MqlRuntime, r.cacheInstanceID, &r.Instance)
}

// snapshots scans the listed snapshots for the ones taken from this volume.
// The volume record's own snapshot list comes back empty from the list call.
func (r *mqlExoscaleBlockStorageVolume) snapshots() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetBlockStorageSnapshots()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, s := range list.Data {
		if s.(*mqlExoscaleBlockStorageSnapshot).cacheVolumeID == r.Id.Data {
			out = append(out, s)
		}
	}
	return out, nil
}

type mqlExoscaleBlockStorageSnapshotInternal struct {
	cacheVolumeID string
}

func (r *mqlExoscale) blockStorageSnapshots() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-block-storage-snapshots", func(c *v3.Client) ([]v3.BlockStorageSnapshot, error) {
		res, err := c.ListBlockStorageSnapshots(ctx())
		if err != nil {
			return nil, err
		}
		return res.BlockStorageSnapshots, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		s := it.item
		res, err := CreateResource(r.MqlRuntime, "exoscale.blockStorage.snapshot", map[string]*llx.RawData{
			"__id":       llx.StringData("exoscale.blockStorage.snapshot/" + string(s.ID)),
			"id":         llx.StringData(string(s.ID)),
			"zone":       llx.StringData(it.zone),
			"name":       llx.StringData(s.Name),
			"size":       llx.IntData(s.Size),
			"volumeSize": llx.IntData(s.VolumeSize),
			"state":      llx.StringData(string(s.State)),
			"created":    timeData(s.CreatedAT),
			"labels":     labelData(s.Labels),
		})
		if err != nil {
			return nil, err
		}
		if s.BlockStorageVolume != nil {
			res.(*mqlExoscaleBlockStorageSnapshot).cacheVolumeID = string(s.BlockStorageVolume.ID)
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlExoscaleBlockStorageSnapshot) volume() (*mqlExoscaleBlockStorageVolume, error) {
	if r.cacheVolumeID == "" {
		nullResource(&r.Volume)
		return nil, nil
	}
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetBlockStorageVolumes()
	if list.Error != nil {
		return nil, list.Error
	}
	if v, ok := pickOneByID(list.Data, r.cacheVolumeID, func(v *mqlExoscaleBlockStorageVolume) string { return v.Id.Data }); ok {
		return v, nil
	}
	// The source volume may have been deleted while the snapshot remains.
	nullResource(&r.Volume)
	return nil, nil
}
