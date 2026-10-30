// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	serverbackup "github.com/stackitcloud/stackit-sdk-go/services/serverbackup/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlStackitServerBackupInternal struct {
	// cacheVolumeBackups holds the backup's per-volume entries, captured when
	// the backup is built so volumeBackups() and volumes() can expose them
	// without another API call. cacheIdBase is the backup's own cache key,
	// used to key the volume-backup sub-resources.
	cacheVolumeBackups []serverbackup.BackupVolumeBackupsInner
	cacheIdBase        string
}

// ------------------------- server backup service -------------------------

// backupServiceEnabled reports whether the Server Backup service is turned on
// for this server, which is what separates "no backups because the service is
// off" from "no backups yet". Null when the service does not know the server
// (404) or the credential cannot read it.
func (r *mqlStackitServer) backupServiceEnabled() (bool, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServerBackup()
	if err != nil {
		return false, err
	}
	resp, err := client.DefaultAPI.GetServiceResource(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return nullBool(&r.BackupServiceEnabled)
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return nullBool(&r.BackupServiceEnabled)
			}
			return false, refusal(err)
		}
		return false, err
	}
	enabled, ok := resp.GetEnabledOk()
	if !ok || enabled == nil {
		return nullBool(&r.BackupServiceEnabled)
	}
	return *enabled, nil
}

// serverBackupPolicies lists the project's backup policies: the named
// schedule-and-retention templates a server backup schedule can be created
// from, including which one applies by default.
func (r *mqlStackit) serverBackupPolicies() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServerBackup()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackupPolicies(bgctx(), c.ProjectID()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.server.backupPolicy", serverBackupPolicyArgs(&items[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// serverBackupPolicyArgs maps a backup policy onto stackit.server.backupPolicy.
// The enabled and default flags stay tri-state; the retention period and the
// backup-name template live inside the nested backupProperties block.
func serverBackupPolicyArgs(p *serverbackup.BackupPolicy) map[string]*llx.RawData {
	var retention *int64
	backupName := ""
	if props, ok := p.GetBackupPropertiesOk(); ok && props != nil {
		backupName = props.GetName()
		if v, ok := props.GetRetentionPeriodOk(); ok && v != nil {
			days := int64(*v)
			retention = &days
		}
	}
	return map[string]*llx.RawData{
		"id":              llx.StringData(p.GetId()),
		"name":            llx.StringData(p.GetName()),
		"description":     llx.StringData(p.GetDescription()),
		"enabled":         llx.BoolDataPtr(optBool(p.GetEnabledOk())),
		"default":         llx.BoolDataPtr(optBool(p.GetDefaultOk())),
		"rrule":           llx.StringData(p.GetRrule()),
		"backupName":      llx.StringData(backupName),
		"retentionPeriod": llx.IntDataPtr(retention),
	}
}

func (r *mqlStackitServerBackupPolicy) id() (string, error) {
	return "stackit.server.backupPolicy/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Id.Data, nil
}

// ------------------------- server backups -------------------------

func (r *mqlStackitServer) backups() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServerBackup()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackups(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			// A 404 means the Server Backup service is not enabled for this
			// server, which is a legitimate "no backups" state rather than an
			// error.
			return []any{}, nil
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return []any{}, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildServerBackup(r.MqlRuntime, r.Id.Data, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildServerBackup(runtime *plugin.Runtime, serverID string, b *serverbackup.Backup) (plugin.Resource, error) {
	args := map[string]*llx.RawData{
		"id":             llx.StringData(b.GetId()),
		"serverId":       llx.StringData(serverID),
		"name":           llx.StringData(b.GetName()),
		"status":         llx.StringData(string(b.GetStatus())),
		"size":           llx.IntData(b.GetSize()),
		"createdAt":      llx.TimeDataPtr(parseRFC3339(b.GetCreatedAt())),
		"expireAt":       llx.TimeDataPtr(parseRFC3339(b.GetExpireAt())),
		"lastRestoredAt": llx.TimeDataPtr(parseRFC3339(b.GetLastRestoredAt())),
	}
	res, err := CreateResource(runtime, "stackit.server.backup", args)
	if err != nil {
		return nil, err
	}
	mqlBackup := res.(*mqlStackitServerBackup)
	mqlBackup.cacheVolumeBackups = b.GetVolumeBackups()
	mqlBackup.cacheIdBase = "stackit.server.backup/" + serverID + "/" + b.GetId()
	return res, nil
}

func (r *mqlStackitServerBackup) id() (string, error) {
	return "stackit.server.backup/" + r.ServerId.Data + "/" + r.Id.Data, nil
}

func (r *mqlStackitServerBackup) server() (*mqlStackitServer, error) {
	return serverRef(r.MqlRuntime, r.ServerId.Data, &r.Server)
}

// volumeBackups exposes the backup's per-volume entries as typed
// sub-resources, captured when the backup was built.
func (r *mqlStackitServerBackup) volumeBackups() ([]any, error) {
	out := make([]any, 0, len(r.cacheVolumeBackups))
	for i := range r.cacheVolumeBackups {
		vb := r.cacheVolumeBackups[i]
		res, err := CreateResource(r.MqlRuntime, "stackit.server.backup.volumeBackup", map[string]*llx.RawData{
			"__id":                 llx.StringData(r.cacheIdBase + "/volumeBackup/" + vb.GetId()),
			"id":                   llx.StringData(vb.GetId()),
			"volumeId":             llx.StringData(vb.GetVolumeId()),
			"size":                 llx.IntData(vb.GetSize()),
			"status":               llx.StringData(string(vb.GetStatus())),
			"lastRestoredAt":       llx.TimeDataPtr(parseRFC3339(vb.GetLastRestoredAt())),
			"lastRestoredVolumeId": llx.StringData(vb.GetLastRestoredVolumeId()),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// volumes resolves the volumes protected by the backup from the volume IDs
// carried in its per-volume backup entries.
func (r *mqlStackitServerBackup) volumes() ([]any, error) {
	ids := make([]string, 0, len(r.cacheVolumeBackups))
	for i := range r.cacheVolumeBackups {
		if id := r.cacheVolumeBackups[i].GetVolumeId(); id != "" {
			ids = append(ids, id)
		}
	}
	return volumeRefs(r.MqlRuntime, ids)
}

func (r *mqlStackitServerBackupVolumeBackup) volume() (*mqlStackitVolume, error) {
	return volumeRef(r.MqlRuntime, r.VolumeId.Data, &r.Volume)
}

func (r *mqlStackitServerBackupVolumeBackup) lastRestoredVolume() (*mqlStackitVolume, error) {
	return volumeRef(r.MqlRuntime, r.LastRestoredVolumeId.Data, &r.LastRestoredVolume)
}

// ------------------------- server backup schedules -------------------------

func (r *mqlStackitServer) backupSchedules() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServerBackup()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListBackupSchedules(bgctx(), c.ProjectID(), r.Id.Data, c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildBackupSchedule(r.MqlRuntime, r.Id.Data, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildBackupSchedule(runtime *plugin.Runtime, serverID string, s *serverbackup.BackupSchedule) (plugin.Resource, error) {
	var (
		retention int64
		volumeIds []string
	)
	if props, ok := s.GetBackupPropertiesOk(); ok {
		retention = int64(props.GetRetentionPeriod())
		volumeIds = props.GetVolumeIds()
	}
	args := map[string]*llx.RawData{
		"id":              llx.IntData(s.GetId()),
		"serverId":        llx.StringData(serverID),
		"name":            llx.StringData(s.GetName()),
		"enabled":         llx.BoolData(s.GetEnabled()),
		"rrule":           llx.StringData(s.GetRrule()),
		"retentionPeriod": llx.IntData(retention),
		"volumeIds":       strSliceData(volumeIds),
	}
	return CreateResource(runtime, "stackit.server.backupSchedule", args)
}

func (r *mqlStackitServerBackupSchedule) id() (string, error) {
	return "stackit.server.backupSchedule/" + r.ServerId.Data + "/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlStackitServerBackupSchedule) server() (*mqlStackitServer, error) {
	return serverRef(r.MqlRuntime, r.ServerId.Data, &r.Server)
}

func (r *mqlStackitServerBackupSchedule) volumes() ([]any, error) {
	ids := make([]string, 0, len(r.VolumeIds.Data))
	for _, raw := range r.VolumeIds.Data {
		if id, ok := raw.(string); ok {
			ids = append(ids, id)
		}
	}
	return volumeRefs(r.MqlRuntime, ids)
}
