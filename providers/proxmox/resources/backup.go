// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

type mqlProxmoxBackupJobInternal struct {
	configOnce sync.Once
	cfg        map[string]any
	cfgErr     error

	// Target resolution hits /cluster/resources for both VMs and
	// containers; cache the result so a query that reads both
	// targetVms and targetContainers only pays the cost once.
	targetsOnce sync.Once
	cachedVms   []any
	cachedCts   []any
	targetsErr  error
}

func (r *mqlProxmox) backupJobs() ([]any, error) {
	conn := proxmoxConn(r)
	jobs, err := conn.GetBackupJobs()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(jobs))
	for i, j := range jobs {
		res, err := CreateResource(r.MqlRuntime, "proxmox.backup.job", map[string]*llx.RawData{
			"id":               llx.StringData(j.ID),
			"enabled":          llx.BoolData(j.Enabled != 0),
			"schedule":         llx.StringData(j.Schedule),
			"storage":          llx.StringData(j.Storage),
			"mode":             llx.StringData(j.Mode),
			"comment":          llx.StringData(j.Comment),
			"vmids":            llx.StringData(j.VMID),
			"pool":             llx.StringData(j.Pool),
			"all":              llx.BoolData(j.All != 0),
			"exclude":          llx.StringData(j.Exclude),
			"compress":         llx.StringData(j.Compress),
			"mailto":           llx.StringData(j.Mailto),
			"notificationMode": llx.StringData(j.NotificationMode),
			"node":             llx.StringData(j.Node),
			"prune":            llx.StringData(j.Prune),
			"fleecing":         llx.StringData(j.Fleecing),
			"notesTemplate":    llx.StringData(j.NotesTemplate),
			"protected":        llx.BoolData(j.Protected != 0),
			"nextRun":          llx.IntData(j.NextRun),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxBackupJob) targetStorage() (*mqlProxmoxStorage, error) {
	if r.Storage.Data == "" {
		r.TargetStorage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.storage", map[string]*llx.RawData{
		"id": llx.StringData(r.Storage.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxStorage), nil
}

// parseBackupVMIDs splits a Proxmox `vmid` string into individual VMIDs.
// The API accepts comma-separated lists (and tolerates whitespace).
// Tokens that don't parse as integers are skipped — the API can also
// accept "all" or ranges like "100-105" which we don't materialize as
// targets here; ranges aren't surfaced by the listing endpoint at the
// VM resource level.
func parseBackupVMIDs(raw string) []int64 {
	if raw == "" {
		return nil
	}
	var out []int64
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "all" {
			continue
		}
		// Skip ranges like "100-105" — not used in /cluster/backup output
		// but defend against the future.
		if strings.Contains(part, "-") {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

// backupSelection is the guest selection of one backup job, applied the way
// vzdump applies it: `all` takes every guest except those in `exclude`, an
// explicit `vmid` list takes exactly those guests, and a `node` restriction
// means the job only runs on that node, so only guests placed there are
// backed up.
type backupSelection struct {
	all     bool
	node    string
	want    map[int64]bool
	exclude map[int64]bool
}

func (s backupSelection) selects(vmid int64, node string) bool {
	if s.node != "" && node != s.node {
		return false
	}
	if s.all {
		return !s.exclude[vmid]
	}
	return s.want[vmid]
}

// resolveBackupTargets walks the cluster inventory once and returns the
// VMs and containers selected by the job. `all` selects everything; a
// non-empty `vmids` list selects only the matching guests. Results
// are cached on the resource so the two accessors share one fetch.
func (r *mqlProxmoxBackupJob) resolveBackupTargets() (vms, containers []any, err error) {
	r.targetsOnce.Do(func() {
		r.cachedVms, r.cachedCts, r.targetsErr = r.resolveBackupTargetsUncached()
	})
	return r.cachedVms, r.cachedCts, r.targetsErr
}

func (r *mqlProxmoxBackupJob) resolveBackupTargetsUncached() (vms, containers []any, err error) {
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	all := r.All.Data
	wanted := parseBackupVMIDs(r.Vmids.Data)
	if !all && len(wanted) == 0 {
		// Pool-scoped jobs land here; surface empty lists so an audit
		// can branch on `pool != ""` separately.
		return nil, nil, nil
	}
	sel := backupSelection{all: all, node: r.Node.Data, want: map[int64]bool{}, exclude: map[int64]bool{}}
	for _, id := range wanted {
		sel.want[id] = true
	}
	for _, id := range parseBackupVMIDs(r.Exclude.Data) {
		sel.exclude[id] = true
	}

	allVMs, vmErr := conn.GetAllVMs()
	if vmErr == nil {
		for _, vm := range allVMs {
			if !sel.selects(int64(vm.VMID), vm.Node) {
				continue
			}
			ref, err := NewResource(r.MqlRuntime, "proxmox.vm", map[string]*llx.RawData{
				"id": llx.IntData(int64(vm.VMID)),
			})
			if err != nil {
				return nil, nil, err
			}
			vms = append(vms, ref)
		}
	}
	allCT, ctErr := conn.GetAllContainers()
	if ctErr == nil {
		for _, ct := range allCT {
			if !sel.selects(int64(ct.VMID), ct.Node) {
				continue
			}
			ref, err := NewResource(r.MqlRuntime, "proxmox.container", map[string]*llx.RawData{
				"id": llx.IntData(int64(ct.VMID)),
			})
			if err != nil {
				return nil, nil, err
			}
			containers = append(containers, ref)
		}
	}
	// Only return the cluster-listing error when both lookups failed —
	// a partial result is more useful for audits than a hard failure.
	if vmErr != nil && ctErr != nil {
		return nil, nil, vmErr
	}
	return vms, containers, nil
}

func (r *mqlProxmoxBackupJob) targetVms() ([]any, error) {
	vms, _, err := r.resolveBackupTargets()
	if err != nil {
		return nil, err
	}
	if vms == nil {
		return []any{}, nil
	}
	return vms, nil
}

func (r *mqlProxmoxBackupJob) targetContainers() ([]any, error) {
	_, cts, err := r.resolveBackupTargets()
	if err != nil {
		return nil, err
	}
	if cts == nil {
		return []any{}, nil
	}
	return cts, nil
}

func (r *mqlProxmoxBackupJob) config() (any, error) {
	r.configOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.PveConnection)
		r.cfg, r.cfgErr = conn.GetBackupJob(r.Id.Data)
	})
	return r.cfg, r.cfgErr
}
