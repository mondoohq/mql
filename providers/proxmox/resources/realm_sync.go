// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
	"go.mondoo.com/mql/types"
)

type mqlProxmoxRealmSyncJobInternal struct {
	// realm is the name the job syncs from. It arrives with the listing but is
	// not a field on the resource, so realmRef reads it from here.
	realm string

	detailOnce sync.Once
	detail     map[string]any
	detailErr  error
}

// ---------------------------------------------------------------------------
// Job listings
// ---------------------------------------------------------------------------

func (r *mqlProxmox) realmSyncJobs() ([]any, error) {
	return realmSyncJobResources(r.MqlRuntime, "", &r.RealmSyncJobs)
}

func (r *mqlProxmoxRealm) syncJobs() ([]any, error) {
	return realmSyncJobResources(r.MqlRuntime, r.Realm.Data, &r.SyncJobs)
}

// realmSyncJobResources builds the job resources, optionally narrowed to one
// realm. Both callers read the same memoized listing, so the cluster-wide view
// and the per-realm reverse edge cost one request between them.
//
// The slot is set to null when the listing could not be read: an empty list
// would say the realm auto-provisions nobody, which is the opposite of an
// unanswered question.
func realmSyncJobResources(runtime *plugin.Runtime, realm string, slot *plugin.TValue[[]any]) ([]any, error) {
	conn := runtime.Connection.(*connection.PveConnection)
	jobs, readable, err := conn.GetRealmSyncJobs()
	if err != nil {
		return nil, err
	}
	if !readable {
		slot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	list := []any{}
	for _, job := range jobs {
		if realm != "" && job.Realm != realm {
			continue
		}
		args := map[string]*llx.RawData{
			"id":             llx.StringData(job.ID),
			"schedule":       llx.StringData(job.Schedule),
			"comment":        llx.StringData(job.Comment),
			"enabled":        realmSyncEnabled(job.Enabled),
			"scope":          llx.StringData(job.Scope),
			"removeVanished": llx.ArrayData(parseRemoveVanished(job.RemoveVanished), types.String),
			"lastRun":        unixOrNull(job.LastRun),
			"nextRun":        unixOrNull(job.NextRun),
		}
		res, err := CreateResource(runtime, "proxmox.realm.syncJob", args)
		if err != nil {
			return nil, err
		}
		res.(*mqlProxmoxRealmSyncJob).realm = job.Realm
		list = append(list, res)
	}
	return list, nil
}

// realmSyncEnabled applies the documented Proxmox default. A job definition
// that omits `enabled` is a job Proxmox runs, so reporting false would report
// a schedule that is not in force.
func realmSyncEnabled(v *connection.PveBool) *llx.RawData {
	if v == nil {
		return llx.BoolData(true)
	}
	return llx.BoolData(v.Bool())
}

// parseRemoveVanished splits the semicolon-separated removal list. Proxmox
// spells "remove nothing" as the literal `none`, which becomes an empty list
// so a policy can test it the same way it tests an absent setting.
func parseRemoveVanished(raw string) []any {
	out := []any{}
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "none" {
		return out
	}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" || part == "none" {
			continue
		}
		out = append(out, part)
	}
	return out
}

// unixOrNull keeps an absent timestamp null. A zero epoch would render as the
// first second of 1970 and read as a real run that happened long ago.
func unixOrNull(sec int64) *llx.RawData {
	if sec <= 0 {
		return llx.NilData
	}
	t := time.Unix(sec, 0).UTC()
	return llx.TimeDataPtr(&t)
}

// ---------------------------------------------------------------------------
// Per-job detail
// ---------------------------------------------------------------------------

func (r *mqlProxmoxRealmSyncJob) enableNew() (bool, error) {
	r.detailOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.PveConnection)
		r.detail, r.detailErr = conn.GetRealmSyncJob(r.Id.Data)
	})
	if r.detailErr != nil {
		return false, r.detailErr
	}
	if r.detail == nil {
		r.EnableNew.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if v := connection.ConfigBool(r.detail, "enable-new"); v != nil {
		return *v, nil
	}
	// Proxmox enables newly synced users unless told otherwise, so an absent
	// key means the directory really does mint usable logins.
	return true, nil
}

func (r *mqlProxmoxRealmSyncJob) realmRef() (*mqlProxmoxRealm, error) {
	if r.realm == "" {
		r.RealmRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	if _, found, err := conn.LookupRealm(r.realm); err != nil {
		return nil, err
	} else if !found {
		// A job pointing at a realm the cluster no longer configures never
		// runs. Report the dangling edge as null rather than handing an
		// unknown name to a lookup that would build a blank realm.
		r.RealmRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.realm", map[string]*llx.RawData{
		"realm": llx.StringData(r.realm),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxRealm), nil
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

func initProxmoxRealm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 || args["realm"] == nil {
		return args, nil, nil
	}
	name, ok := args["realm"].Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.PveConnection)
	realm, found, err := conn.LookupRealm(name)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, fmt.Errorf("proxmox realm %q not found", name)
	}
	args["type"] = llx.StringData(realm.Type)
	args["comment"] = llx.StringData(realm.Comment)
	args["default"] = llx.BoolData(realm.Default == 1)
	args["tfaType"] = llx.StringData(realmTFAType(realm.TFA))
	return args, nil, nil
}

func initProxmoxRealmSyncJob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 || args["id"] == nil {
		return args, nil, nil
	}
	id, ok := args["id"].Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.PveConnection)
	jobs, readable, err := conn.GetRealmSyncJobs()
	if err != nil {
		return nil, nil, err
	}
	if !readable {
		return nil, nil, fmt.Errorf("proxmox realm-sync jobs are not readable on this cluster")
	}
	for _, job := range jobs {
		if job.ID != id {
			continue
		}
		args["schedule"] = llx.StringData(job.Schedule)
		args["comment"] = llx.StringData(job.Comment)
		args["enabled"] = realmSyncEnabled(job.Enabled)
		args["scope"] = llx.StringData(job.Scope)
		args["removeVanished"] = llx.ArrayData(parseRemoveVanished(job.RemoveVanished), types.String)
		args["lastRun"] = unixOrNull(job.LastRun)
		args["nextRun"] = unixOrNull(job.NextRun)
		// Built here rather than returned as args: realmRef reads the realm
		// name off the internal cache, which can only be set on a resource
		// this function holds.
		res, err := CreateResource(runtime, "proxmox.realm.syncJob", args)
		if err != nil {
			return nil, nil, err
		}
		res.(*mqlProxmoxRealmSyncJob).realm = job.Realm
		return nil, res, nil
	}
	return nil, nil, fmt.Errorf("proxmox realm-sync job %q not found", id)
}
