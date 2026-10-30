// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"sync"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/backups"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/quotasets"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/snapshots"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumes"
	"github.com/gophercloud/gophercloud/v2/openstack/blockstorage/v3/volumetypes"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.blockstorage.volume ----

type mqlOpenstackBlockstorageVolumeInternal struct {
	cacheProjectID        string
	cacheUserID           string
	cacheSourceVolumeID   string
	cacheSourceSnapshotID string
	cacheBackupID         string
	cacheVolumeTypeName   string
	cacheServerIDs        []string
}

func (r *mqlOpenstackBlockstorageVolume) id() (string, error) {
	return "openstack.blockstorage.volume/" + r.Id.Data, nil
}

func initOpenstackBlockstorageVolume(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetVolumes()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		v := raw.(*mqlOpenstackBlockstorageVolume)
		if v.Id.Data == id {
			return args, v, nil
		}
	}
	initSyntheticID("openstack.blockstorage.volume", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) volumes() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.BlockStorageClient()
	if err != nil {
		return nil, err
	}
	pages, err := volumes.List(client, volumes.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := volumes.ExtractVolumes(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		v := &items[i]
		res, err := newMqlOpenstackBlockstorageVolume(o.MqlRuntime, v)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlOpenstackBlockstorageVolume(runtime *plugin.Runtime, v *volumes.Volume) (*mqlOpenstackBlockstorageVolume, error) {
	res, err := CreateResource(runtime, "openstack.blockstorage.volume", map[string]*llx.RawData{
		"__id":              llx.StringData("openstack.blockstorage.volume/" + v.ID),
		"id":                llx.StringData(v.ID),
		"name":              llx.StringData(v.Name),
		"description":       llx.StringData(v.Description),
		"status":            llx.StringData(v.Status),
		"size":              llx.IntData(int64(v.Size)),
		"bootable":          llx.BoolData(parseBootable(v.Bootable)),
		"encrypted":         llx.BoolData(v.Encrypted),
		"multiAttach":       llx.BoolData(v.Multiattach),
		"volumeTypeName":    llx.StringData(v.VolumeType),
		"availabilityZone":  llx.StringData(v.AvailabilityZone),
		"replicationStatus": llx.StringData(v.ReplicationStatus),
		"metadata":          stringMapData(v.Metadata),
		"imageMetadata":     stringMapData(v.VolumeImageMetadata),
		"attachments":       dictSliceData(volumeAttachmentsToDict(v.Attachments)),
		"createdAt":         llx.TimeDataPtr(timePtr(v.CreatedAt)),
		"updatedAt":         llx.TimeDataPtr(timePtr(v.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	mqlVol := res.(*mqlOpenstackBlockstorageVolume)
	mqlVol.cacheProjectID = v.TenantID
	mqlVol.cacheUserID = v.UserID
	mqlVol.cacheSourceVolumeID = v.SourceVolID
	mqlVol.cacheSourceSnapshotID = v.SnapshotID
	if v.BackupID != nil {
		mqlVol.cacheBackupID = *v.BackupID
	}
	mqlVol.cacheVolumeTypeName = v.VolumeType
	mqlVol.cacheServerIDs = volumeServerIDs(v.Attachments)
	return mqlVol, nil
}

func (r *mqlOpenstackBlockstorageVolume) project() (*mqlOpenstackProject, error) {
	if r.cacheProjectID == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.project", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheProjectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackProject), nil
}

func (r *mqlOpenstackBlockstorageVolume) user() (*mqlOpenstackUser, error) {
	if r.cacheUserID == "" {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.user", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheUserID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackUser), nil
}

func (r *mqlOpenstackBlockstorageVolume) sourceVolume() (*mqlOpenstackBlockstorageVolume, error) {
	if r.cacheSourceVolumeID == "" {
		r.SourceVolume.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.blockstorage.volume", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheSourceVolumeID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackBlockstorageVolume), nil
}

func (r *mqlOpenstackBlockstorageVolume) sourceSnapshot() (*mqlOpenstackBlockstorageSnapshot, error) {
	if r.cacheSourceSnapshotID == "" {
		r.SourceSnapshot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.blockstorage.snapshot", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheSourceSnapshotID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackBlockstorageSnapshot), nil
}

func (r *mqlOpenstackBlockstorageVolume) servers() ([]any, error) {
	if len(r.cacheServerIDs) == 0 {
		return []any{}, nil
	}
	out := make([]any, 0, len(r.cacheServerIDs))
	for _, id := range r.cacheServerIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.compute.server", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlOpenstackBlockstorageVolume) volumeType() (*mqlOpenstackBlockstorageVolumeType, error) {
	if r.cacheVolumeTypeName == "" {
		r.VolumeType.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := CreateResource(r.MqlRuntime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := root.(*mqlOpenstack).GetVolumeTypes()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, raw := range list.Data {
		vt := raw.(*mqlOpenstackBlockstorageVolumeType)
		if vt.Name.Data == r.cacheVolumeTypeName {
			return vt, nil
		}
	}
	r.VolumeType.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (r *mqlOpenstackBlockstorageVolume) restoredFromBackup() (*mqlOpenstackBlockstorageBackup, error) {
	if r.cacheBackupID == "" {
		r.RestoredFromBackup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.blockstorage.backup", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheBackupID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackBlockstorageBackup), nil
}

func (r *mqlOpenstackBlockstorageVolume) backups() ([]any, error) {
	root, err := CreateResource(r.MqlRuntime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := root.(*mqlOpenstack).GetBackups()
	if list.Error != nil {
		return nil, list.Error
	}
	out := make([]any, 0, len(list.Data))
	for _, raw := range list.Data {
		b := raw.(*mqlOpenstackBlockstorageBackup)
		if b.cacheVolumeID == r.Id.Data {
			out = append(out, b)
		}
	}
	return out, nil
}

// parseBootable converts Cinder's "true"/"false" string into a bool.
// Cinder returns this field as a string for historical reasons.
func parseBootable(s string) bool {
	return strings.EqualFold(s, "true")
}

func volumeAttachmentsToDict(in []volumes.Attachment) []any {
	out := make([]any, 0, len(in))
	for _, a := range in {
		entry := map[string]any{
			"attachment_id": a.AttachmentID,
			"server_id":     a.ServerID,
			"device":        a.Device,
			"host_name":     a.HostName,
		}
		if !a.AttachedAt.IsZero() {
			entry["attached_at"] = a.AttachedAt
		}
		out = append(out, entry)
	}
	return out
}

func volumeServerIDs(in []volumes.Attachment) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, a := range in {
		if a.ServerID == "" {
			continue
		}
		if _, dup := seen[a.ServerID]; dup {
			continue
		}
		seen[a.ServerID] = struct{}{}
		out = append(out, a.ServerID)
	}
	return out
}

// ---- openstack.blockstorage.snapshot ----

type mqlOpenstackBlockstorageSnapshotInternal struct {
	cacheVolumeID  string
	cacheProjectID string
	cacheUserID    string
}

func (r *mqlOpenstackBlockstorageSnapshot) id() (string, error) {
	return "openstack.blockstorage.snapshot/" + r.Id.Data, nil
}

func initOpenstackBlockstorageSnapshot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetSnapshots()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackBlockstorageSnapshot)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.blockstorage.snapshot", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) snapshots() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.BlockStorageClient()
	if err != nil {
		return nil, err
	}
	pages, err := snapshots.List(client, snapshots.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := snapshots.ExtractSnapshots(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		s := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.blockstorage.snapshot", map[string]*llx.RawData{
			"__id":            llx.StringData("openstack.blockstorage.snapshot/" + s.ID),
			"id":              llx.StringData(s.ID),
			"name":            llx.StringData(s.Name),
			"description":     llx.StringData(s.Description),
			"status":          llx.StringData(s.Status),
			"size":            llx.IntData(int64(s.Size)),
			"progress":        llx.StringData(s.Progress),
			"groupSnapshotId": llx.StringData(s.GroupSnapshotID),
			"consumesQuota":   llx.BoolData(s.ConsumesQuota),
			"metadata":        stringMapData(s.Metadata),
			"createdAt":       llx.TimeDataPtr(timePtr(s.CreatedAt)),
			"updatedAt":       llx.TimeDataPtr(timePtr(s.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlSnap := res.(*mqlOpenstackBlockstorageSnapshot)
		mqlSnap.cacheVolumeID = s.VolumeID
		mqlSnap.cacheProjectID = s.ProjectID
		mqlSnap.cacheUserID = s.UserID
		out = append(out, mqlSnap)
	}
	return out, nil
}

func (r *mqlOpenstackBlockstorageSnapshot) volume() (*mqlOpenstackBlockstorageVolume, error) {
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

func (r *mqlOpenstackBlockstorageSnapshot) project() (*mqlOpenstackProject, error) {
	if r.cacheProjectID == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.project", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheProjectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackProject), nil
}

func (r *mqlOpenstackBlockstorageSnapshot) user() (*mqlOpenstackUser, error) {
	if r.cacheUserID == "" {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.user", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheUserID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackUser), nil
}

// ---- openstack.blockstorage.volumeType ----

type mqlOpenstackBlockstorageVolumeTypeInternal struct {
	encOnce        sync.Once
	encErr         error
	enc            *volumetypes.GetEncryptionType
	cacheQosSpecID string
}

func (r *mqlOpenstackBlockstorageVolumeType) id() (string, error) {
	return "openstack.blockstorage.volumeType/" + r.Id.Data, nil
}

func initOpenstackBlockstorageVolumeType(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetVolumeTypes()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		vt := raw.(*mqlOpenstackBlockstorageVolumeType)
		if vt.Id.Data == id {
			return args, vt, nil
		}
	}
	initSyntheticID("openstack.blockstorage.volumeType", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) volumeTypes() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.BlockStorageClient()
	if err != nil {
		return nil, err
	}
	pages, err := volumetypes.List(client, volumetypes.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := volumetypes.ExtractVolumeTypes(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, vt := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.blockstorage.volumeType", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.blockstorage.volumeType/" + vt.ID),
			"id":          llx.StringData(vt.ID),
			"name":        llx.StringData(vt.Name),
			"description": llx.StringData(vt.Description),
			"isPublic":    llx.BoolData(vt.IsPublic),
			"extraSpecs":  stringMapData(vt.ExtraSpecs),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlOpenstackBlockstorageVolumeType).cacheQosSpecID = vt.QosSpecID
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlOpenstackBlockstorageVolumeType) fetchEncryption() (*volumetypes.GetEncryptionType, error) {
	r.encOnce.Do(func() {
		c := conn(r.MqlRuntime)
		client, err := c.BlockStorageClient()
		if err != nil {
			r.encErr = err
			return
		}
		enc, err := volumetypes.GetEncryption(ctx(), client, r.Id.Data).Extract()
		if err != nil {
			if resp, ok := errors.AsType[gophercloud.ErrUnexpectedResponseCode](err); ok {
				switch resp.Actual {
				case 401, 403, 404:
					return
				}
			}
			r.encErr = err
			return
		}
		// Cinder returns an empty body (or all-zero fields) for unencrypted
		// volume types; treat that as "no encryption configured" rather than
		// surfacing zero values as if they were real settings.
		if enc.Provider == "" && enc.Cipher == "" && enc.EncryptionID == "" && enc.KeySize == 0 {
			return
		}
		r.enc = enc
	})
	return r.enc, r.encErr
}

func (r *mqlOpenstackBlockstorageVolumeType) encryptionProvider() (string, error) {
	enc, err := r.fetchEncryption()
	if err != nil || enc == nil {
		return "", err
	}
	return enc.Provider, nil
}

func (r *mqlOpenstackBlockstorageVolumeType) encryptionCipher() (string, error) {
	enc, err := r.fetchEncryption()
	if err != nil || enc == nil {
		return "", err
	}
	return enc.Cipher, nil
}

func (r *mqlOpenstackBlockstorageVolumeType) encryptionKeySize() (int64, error) {
	enc, err := r.fetchEncryption()
	if err != nil || enc == nil {
		return 0, err
	}
	return int64(enc.KeySize), nil
}

func (r *mqlOpenstackBlockstorageVolumeType) encryptionControlLocation() (string, error) {
	enc, err := r.fetchEncryption()
	if err != nil || enc == nil {
		return "", err
	}
	return enc.ControlLocation, nil
}

func (r *mqlOpenstackBlockstorageVolumeType) encryptionId() (string, error) {
	enc, err := r.fetchEncryption()
	if err != nil || enc == nil {
		return "", err
	}
	return enc.EncryptionID, nil
}

func (r *mqlOpenstackBlockstorageVolumeType) volumes() ([]any, error) {
	root, err := CreateResource(r.MqlRuntime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := root.(*mqlOpenstack).GetVolumes()
	if list.Error != nil {
		return nil, list.Error
	}
	out := make([]any, 0, len(list.Data))
	for _, raw := range list.Data {
		v := raw.(*mqlOpenstackBlockstorageVolume)
		if v.cacheVolumeTypeName == r.Name.Data {
			out = append(out, v)
		}
	}
	return out, nil
}

// ---- openstack.blockstorage.backup ----

type mqlOpenstackBlockstorageBackupInternal struct {
	cacheVolumeID   string
	cacheSnapshotID string
	cacheProjectID  string
}

func (r *mqlOpenstackBlockstorageBackup) id() (string, error) {
	return "openstack.blockstorage.backup/" + r.Id.Data, nil
}

func initOpenstackBlockstorageBackup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetBackups()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		b := raw.(*mqlOpenstackBlockstorageBackup)
		if b.Id.Data == id {
			return args, b, nil
		}
	}
	initSyntheticID("openstack.blockstorage.backup", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) backups() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.BlockStorageClient()
	if err != nil {
		return nil, err
	}
	pages, err := backups.ListDetail(client, backups.ListDetailOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := backups.ExtractBackups(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, b := range items {
		az := ""
		if b.AvailabilityZone != nil {
			az = *b.AvailabilityZone
		}
		meta := map[string]string{}
		if b.Metadata != nil {
			meta = *b.Metadata
		}
		res, err := CreateResource(o.MqlRuntime, "openstack.blockstorage.backup", map[string]*llx.RawData{
			"__id":                llx.StringData("openstack.blockstorage.backup/" + b.ID),
			"id":                  llx.StringData(b.ID),
			"name":                llx.StringData(b.Name),
			"description":         llx.StringData(b.Description),
			"status":              llx.StringData(b.Status),
			"size":                llx.IntData(int64(b.Size)),
			"objectCount":         llx.IntData(int64(b.ObjectCount)),
			"container":           llx.StringData(b.Container),
			"hasDependentBackups": llx.BoolData(b.HasDependentBackups),
			"isIncremental":       llx.BoolData(b.IsIncremental),
			"failReason":          llx.StringData(b.FailReason),
			"availabilityZone":    llx.StringData(az),
			"metadata":            stringMapData(meta),
			"dataTimestamp":       llx.TimeDataPtr(timePtr(b.DataTimestamp)),
			"createdAt":           llx.TimeDataPtr(timePtr(b.CreatedAt)),
			"updatedAt":           llx.TimeDataPtr(timePtr(b.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlBackup := res.(*mqlOpenstackBlockstorageBackup)
		mqlBackup.cacheVolumeID = b.VolumeID
		mqlBackup.cacheSnapshotID = b.SnapshotID
		mqlBackup.cacheProjectID = b.ProjectID
		out = append(out, mqlBackup)
	}
	return out, nil
}

func (r *mqlOpenstackBlockstorageBackup) volume() (*mqlOpenstackBlockstorageVolume, error) {
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

func (r *mqlOpenstackBlockstorageBackup) sourceSnapshot() (*mqlOpenstackBlockstorageSnapshot, error) {
	if r.cacheSnapshotID == "" {
		r.SourceSnapshot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.blockstorage.snapshot", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheSnapshotID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackBlockstorageSnapshot), nil
}

func (r *mqlOpenstackBlockstorageBackup) project() (*mqlOpenstackProject, error) {
	if r.cacheProjectID == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.project", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheProjectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackProject), nil
}

// ---- openstack.blockstorage.quotaSet ----

// mqlOpenstackBlockstorageQuotaSetInternal holds the project id the quota
// applies to, which project() resolves. The __id is supplied explicitly by the
// creator, so this resource needs no id() function.
type mqlOpenstackBlockstorageQuotaSetInternal struct {
	cacheProjectID string
}

func (o *mqlOpenstack) blockStorageQuotaSet() (*mqlOpenstackBlockstorageQuotaSet, error) {
	c := conn(o.MqlRuntime)
	client, err := c.BlockStorageClient()
	if err != nil {
		if serviceMissing(err) {
			o.BlockStorageQuotaSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	projectId := c.ProjectID()
	q, err := quotasets.Get(ctx(), client, projectId).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			o.BlockStorageQuotaSet.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	res, err := CreateResource(o.MqlRuntime, "openstack.blockstorage.quotaSet", map[string]*llx.RawData{
		"__id":               llx.StringData("openstack.blockstorage.quotaSet/" + projectId),
		"volumes":            llx.IntData(int64(q.Volumes)),
		"snapshots":          llx.IntData(int64(q.Snapshots)),
		"gigabytes":          llx.IntData(int64(q.Gigabytes)),
		"perVolumeGigabytes": llx.IntData(int64(q.PerVolumeGigabytes)),
		"backups":            llx.IntData(int64(q.Backups)),
		"backupGigabytes":    llx.IntData(int64(q.BackupGigabytes)),
		"groups":             llx.IntData(int64(q.Groups)),
	})
	if err != nil {
		return nil, err
	}
	mqlQuota := res.(*mqlOpenstackBlockstorageQuotaSet)
	mqlQuota.cacheProjectID = projectId
	return mqlQuota, nil
}

func (r *mqlOpenstackBlockstorageQuotaSet) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}
