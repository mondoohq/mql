// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHetznerStorageBoxInternal struct {
	cacheType     *hcloud.StorageBoxType
	cacheLocation *hcloud.Location
}

func (r *mqlHetznerStorageBox) id() (string, error) {
	return fmt.Sprintf("hetzner.storageBox/%d", r.Id.Data), nil
}

// allStorageBoxes lists every project Storage Box exactly once and caches the
// raw result on the hetzner namespace resource, mirroring allServers. The
// storageBoxes() field and the location rollup both resolve through here.
func (h *mqlHetzner) allStorageBoxes() ([]*hcloud.StorageBox, error) {
	h.storageBoxesOnce.Do(func() {
		c := conn(h.MqlRuntime)
		h.storageBoxesList, h.storageBoxesErr = paginate(func(opts hcloud.ListOpts) ([]*hcloud.StorageBox, *hcloud.Response, error) {
			return c.Client().StorageBox.List(ctx(), hcloud.StorageBoxListOpts{ListOpts: opts})
		})
	})
	return h.storageBoxesList, h.storageBoxesErr
}

func (h *mqlHetzner) storageBoxes() ([]any, error) {
	items, err := h.allStorageBoxes()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, sb := range items {
		res, err := newMqlHetznerStorageBox(h.MqlRuntime, sb)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerStorageBox(runtime *plugin.Runtime, sb *hcloud.StorageBox) (*mqlHetznerStorageBox, error) {
	as := sb.AccessSettings

	snapshotPlan := map[string]any{}
	if sb.SnapshotPlan != nil {
		sp := sb.SnapshotPlan
		snapshotPlan = map[string]any{
			"maxSnapshots": int64(sp.MaxSnapshots),
			"minute":       int64(sp.Minute),
			"hour":         int64(sp.Hour),
		}
		if sp.DayOfWeek != nil {
			snapshotPlan["dayOfWeek"] = sp.DayOfWeek.String()
		}
		if sp.DayOfMonth != nil {
			snapshotPlan["dayOfMonth"] = int64(*sp.DayOfMonth)
		}
	}

	res, err := CreateResource(runtime, "hetzner.storageBox", map[string]*llx.RawData{
		"__id":                llx.StringData(fmt.Sprintf("hetzner.storageBox/%d", sb.ID)),
		"id":                  llx.IntData(sb.ID),
		"name":                llx.StringData(sb.Name),
		"username":            llx.StringData(sb.Username),
		"status":              llx.StringData(string(sb.Status)),
		"reachableExternally": llx.BoolData(as.ReachableExternally),
		"sambaEnabled":        llx.BoolData(as.SambaEnabled),
		"sshEnabled":          llx.BoolData(as.SSHEnabled),
		"webdavEnabled":       llx.BoolData(as.WebDAVEnabled),
		"zfsEnabled":          llx.BoolData(as.ZFSEnabled),
		"snapshotPlan":        llx.DictData(snapshotPlan),
		"size":                llx.IntData(int64(sb.Stats.Size)),
		"sizeData":            llx.IntData(int64(sb.Stats.SizeData)),
		"sizeSnapshots":       llx.IntData(int64(sb.Stats.SizeSnapshots)),
		"server":              llx.StringData(sb.Server),
		"system":              llx.StringData(sb.System),
		"protection":          llx.DictData(protectionDict(sb.Protection.Delete)),
		"labels":              labelData(sb.Labels),
		"created":             llx.TimeDataPtr(timePtr(sb.Created)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerStorageBox)
	m.cacheType = sb.StorageBoxType
	m.cacheLocation = sb.Location
	return m, nil
}

func initHetznerStorageBox(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "storageBox")
	if err != nil {
		return nil, nil, err
	}
	sb, _, err := conn(runtime).Client().StorageBox.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if sb == nil {
		return nil, nil, notFoundErr("storageBox", id)
	}
	res, err := newMqlHetznerStorageBox(runtime, sb)
	return args, res, err
}

func (m *mqlHetznerStorageBox) storageBoxType() (*mqlHetznerStorageBoxType, error) {
	return resolveTypedResource(&m.StorageBoxType, m.cacheType, func(t *hcloud.StorageBoxType) (*mqlHetznerStorageBoxType, error) {
		return newMqlHetznerStorageBoxType(m.MqlRuntime, t)
	})
}

func (m *mqlHetznerStorageBox) location() (*mqlHetznerLocation, error) {
	return resolveTypedResource(&m.Location, m.cacheLocation, func(l *hcloud.Location) (*mqlHetznerLocation, error) {
		return newMqlHetznerLocation(m.MqlRuntime, l)
	})
}

// subaccounts lists the Storage Box's subaccounts. The hcloud subaccount
// endpoint is not paginated (its list options carry no Page/PerPage), so a
// single AllSubaccounts call returns the full set.
func (m *mqlHetznerStorageBox) subaccounts() ([]any, error) {
	c := conn(m.MqlRuntime)
	subs, err := c.Client().StorageBox.AllSubaccounts(ctx(), &hcloud.StorageBox{ID: m.Id.Data})
	if err != nil {
		if translateHcloudError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	out := make([]any, 0, len(subs))
	for _, sa := range subs {
		res, err := newMqlHetznerStorageBoxSubaccount(m.MqlRuntime, m.Id.Data, sa)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// snapshots lists the Storage Box's snapshots. As with subaccounts, the
// endpoint is not paginated, so AllSnapshots returns the full set.
func (m *mqlHetznerStorageBox) snapshots() ([]any, error) {
	c := conn(m.MqlRuntime)
	snaps, err := c.Client().StorageBox.AllSnapshots(ctx(), &hcloud.StorageBox{ID: m.Id.Data})
	if err != nil {
		if translateHcloudError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	out := make([]any, 0, len(snaps))
	for _, sn := range snaps {
		res, err := newMqlHetznerStorageBoxSnapshot(m.MqlRuntime, m.Id.Data, sn)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// storageBoxRef builds a lazy hetzner.storageBox reference from its id, used by
// the sub-resources that point back at their parent box.
func storageBoxRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlHetznerStorageBox], id int64) (*mqlHetznerStorageBox, error) {
	if id == 0 {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(runtime, "hetzner.storageBox", map[string]*llx.RawData{
		"id": llx.IntData(id),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerStorageBox), nil
}

// mqlHetznerStorageBoxSubaccountInternal and its snapshot counterpart hold the
// storage box the entry belongs to, which the storageBox accessor resolves.
type mqlHetznerStorageBoxSubaccountInternal struct {
	cacheStorageBoxID int64
}

type mqlHetznerStorageBoxSnapshotInternal struct {
	cacheStorageBoxID int64
}

func (m *mqlHetznerStorageBoxSubaccount) storageBox() (*mqlHetznerStorageBox, error) {
	return storageBoxRef(m.MqlRuntime, &m.StorageBox, m.cacheStorageBoxID)
}

func (m *mqlHetznerStorageBoxSnapshot) storageBox() (*mqlHetznerStorageBox, error) {
	return storageBoxRef(m.MqlRuntime, &m.StorageBox, m.cacheStorageBoxID)
}

func (r *mqlHetznerStorageBoxSubaccount) id() (string, error) {
	return fmt.Sprintf("hetzner.storageBox.subaccount/%d/%d", r.cacheStorageBoxID, r.Id.Data), nil
}

func newMqlHetznerStorageBoxSubaccount(runtime *plugin.Runtime, storageBoxID int64, sa *hcloud.StorageBoxSubaccount) (*mqlHetznerStorageBoxSubaccount, error) {
	var reachable, readonly, samba, ssh, webdav bool
	if sa.AccessSettings != nil {
		reachable = sa.AccessSettings.ReachableExternally
		readonly = sa.AccessSettings.Readonly
		samba = sa.AccessSettings.SambaEnabled
		ssh = sa.AccessSettings.SSHEnabled
		webdav = sa.AccessSettings.WebDAVEnabled
	}
	res, err := CreateResource(runtime, "hetzner.storageBox.subaccount", map[string]*llx.RawData{
		"__id":                llx.StringData(fmt.Sprintf("hetzner.storageBox.subaccount/%d/%d", storageBoxID, sa.ID)),
		"id":                  llx.IntData(sa.ID),
		"name":                llx.StringData(sa.Name),
		"username":            llx.StringData(sa.Username),
		"homeDirectory":       llx.StringData(sa.HomeDirectory),
		"server":              llx.StringData(sa.Server),
		"description":         llx.StringData(sa.Description),
		"reachableExternally": llx.BoolData(reachable),
		"readonly":            llx.BoolData(readonly),
		"sambaEnabled":        llx.BoolData(samba),
		"sshEnabled":          llx.BoolData(ssh),
		"webdavEnabled":       llx.BoolData(webdav),
		"labels":              labelData(sa.Labels),
		"created":             llx.TimeDataPtr(timePtr(sa.Created)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerStorageBoxSubaccount)
	m.cacheStorageBoxID = storageBoxID
	return m, nil
}

func (r *mqlHetznerStorageBoxSnapshot) id() (string, error) {
	return fmt.Sprintf("hetzner.storageBox.snapshot/%d/%d", r.cacheStorageBoxID, r.Id.Data), nil
}

func newMqlHetznerStorageBoxSnapshot(runtime *plugin.Runtime, storageBoxID int64, sn *hcloud.StorageBoxSnapshot) (*mqlHetznerStorageBoxSnapshot, error) {
	res, err := CreateResource(runtime, "hetzner.storageBox.snapshot", map[string]*llx.RawData{
		"__id":           llx.StringData(fmt.Sprintf("hetzner.storageBox.snapshot/%d/%d", storageBoxID, sn.ID)),
		"id":             llx.IntData(sn.ID),
		"name":           llx.StringData(sn.Name),
		"description":    llx.StringData(sn.Description),
		"isAutomatic":    llx.BoolData(sn.IsAutomatic),
		"size":           llx.IntData(int64(sn.Stats.Size)),
		"sizeFilesystem": llx.IntData(int64(sn.Stats.SizeFilesystem)),
		"labels":         labelData(sn.Labels),
		"created":        llx.TimeDataPtr(timePtr(sn.Created)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerStorageBoxSnapshot)
	m.cacheStorageBoxID = storageBoxID
	return m, nil
}
