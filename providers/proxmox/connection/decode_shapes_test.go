// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"testing"
)

// These fixtures follow the shapes current Proxmox VE releases emit, read from
// the PVE sources rather than from the published schema alone:
//   - QemuServer::vmstatus and LXC::config_list build `vmid => int($vmid)`, so
//     the per-node guest listings carry integer VMIDs.
//   - LXC::vmstatus sets `cpus` from `cores || cpulimit`, and a `number`
//     config key keeps its string form, so a container limited by a fractional
//     cpulimit reports `"cpus": "1.5"`; /cluster/resources then reports
//     `"maxcpu": 1.5` for it.
//   - VZDump JobBase::decode_value parses `prune-backups` and `fleecing` into
//     objects before the job listing returns them.
//   - API2::Services returns the unit file state under `unit-state`.

func TestPveNumberDecodesEveryForm(t *testing.T) {
	cases := map[string]float64{
		`100`:   100,
		`"100"`: 100,
		`1.5`:   1.5,
		`"1.5"`: 1.5,
		`null`:  0,
		`""`:    0,
	}
	for in, want := range cases {
		var n PveNumber
		if err := json.Unmarshal([]byte(in), &n); err != nil {
			t.Errorf("%s: unexpected error %v", in, err)
			continue
		}
		if n.Float() != want {
			t.Errorf("%s decoded to %v, want %v", in, n.Float(), want)
		}
	}
	var bad PveNumber
	if err := json.Unmarshal([]byte(`"abc"`), &bad); err == nil {
		t.Error("expected an error for a non-numeric string")
	}
}

func TestPveNumberRounding(t *testing.T) {
	if got := PveNumber(1.5).Ceil(); got != 2 {
		t.Errorf("Ceil(1.5) = %d, want 2", got)
	}
	if got := PveNumber(0.2).Ceil(); got != 1 {
		t.Errorf("Ceil(0.2) = %d, want 1 so a positive limit never reads as unlimited", got)
	}
	if got := PveNumber(4).Ceil(); got != 4 {
		t.Errorf("Ceil(4) = %d, want 4", got)
	}
}

func TestPvePropsAcceptsObjectAndString(t *testing.T) {
	cases := map[string]string{
		`{"keep-last":3,"keep-daily":7}`:         "keep-daily=7,keep-last=3",
		`{"enabled":1,"storage":"local-lvm"}`:    "enabled=1,storage=local-lvm",
		`{"enabled":true}`:                       "enabled=1",
		`"keep-last=3,keep-daily=7"`:             "keep-last=3,keep-daily=7",
		`null`:                                   "",
		`{"max-workers":16,"pbs-entries-max":2}`: "max-workers=16,pbs-entries-max=2",
	}
	for in, want := range cases {
		var p PveProps
		if err := json.Unmarshal([]byte(in), &p); err != nil {
			t.Errorf("%s: unexpected error %v", in, err)
			continue
		}
		if string(p) != want {
			t.Errorf("%s decoded to %q, want %q", in, p, want)
		}
	}
}

func TestGetNodeGuestsAcceptIntegerAndQuotedVMIDs(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes/pve1/qemu", []map[string]any{
		{"vmid": 100, "name": "web", "status": "running", "cpus": 4, "template": 1},
		{"vmid": "101", "name": "legacy", "status": "stopped", "cpus": 2},
	})
	f.route("/nodes/pve1/lxc", []map[string]any{
		{"vmid": 200, "name": "ct", "status": "running", "cpus": "1.5"},
	})

	vms, err := f.conn().GetNodeVMs("pve1")
	if err != nil {
		t.Fatalf("GetNodeVMs: %v", err)
	}
	if len(vms) != 2 || vms[0].VMID != 100 || vms[1].VMID != 101 {
		t.Fatalf("unexpected VMs %+v", vms)
	}
	if vms[0].MaxCPU.Ceil() != 4 || !vms[0].Template.Bool() || vms[1].Template.Bool() {
		t.Errorf("vm[0] = %+v, want 4 CPUs and template", vms[0])
	}

	cts, err := f.conn().GetNodeContainers("pve1")
	if err != nil {
		t.Fatalf("GetNodeContainers: %v", err)
	}
	if len(cts) != 1 || cts[0].VMID != 200 {
		t.Fatalf("unexpected containers %+v", cts)
	}
	if cts[0].MaxCPU.Ceil() != 2 {
		t.Errorf("container CPUs = %d, want 2 for cpulimit 1.5", cts[0].MaxCPU.Ceil())
	}
}

func TestGetNodeVMsRejectsFractionalVMID(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes/pve1/qemu", []map[string]any{{"vmid": 100.5}})
	if _, err := f.conn().GetNodeVMs("pve1"); err == nil {
		t.Fatal("expected an error for a fractional VMID")
	}
}

func TestClusterResourcesSurviveFractionalMaxCPU(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/resources?type=vm", []map[string]any{
		{"id": "qemu/100", "type": "qemu", "vmid": 100, "node": "pve1", "maxcpu": 2, "template": 0},
		{"id": "lxc/200", "type": "lxc", "vmid": 200, "node": "pve1", "maxcpu": 1.5, "template": 1},
	})

	vms, err := f.conn().GetAllVMs()
	if err != nil {
		t.Fatalf("one fractional container must not take the VM listing down: %v", err)
	}
	if len(vms) != 1 || vms[0].MaxCPU.Ceil() != 2 {
		t.Errorf("unexpected VMs %+v", vms)
	}
	cts, err := f.conn().GetAllContainers()
	if err != nil {
		t.Fatalf("GetAllContainers: %v", err)
	}
	if len(cts) != 1 || cts[0].MaxCPU.Ceil() != 2 || !cts[0].Template.Bool() {
		t.Errorf("unexpected containers %+v", cts)
	}
}

func TestGetBackupJobsDecodesObjectSettings(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/backup", []map[string]any{
		{
			"id":            "backup-1",
			"type":          "vzdump",
			"enabled":       1,
			"all":           1,
			"schedule":      "21:00",
			"prune-backups": map[string]any{"keep-last": 3, "keep-weekly": 2},
			"fleecing":      map[string]any{"enabled": 1, "storage": "local-lvm"},
		},
		{
			// `enabled` defaults to 1, so a job without the key runs
			"id":       "backup-2",
			"type":     "vzdump",
			"schedule": "sat 02:00",
			"vmid":     "100,101",
		},
		{
			"id":      "backup-3",
			"type":    "vzdump",
			"enabled": 0,
		},
	})

	jobs, err := f.conn().GetBackupJobs()
	if err != nil {
		t.Fatalf("GetBackupJobs: %v", err)
	}
	if len(jobs) != 3 {
		t.Fatalf("expected 3 jobs, got %d", len(jobs))
	}
	if got := string(jobs[0].Prune); got != "keep-last=3,keep-weekly=2" {
		t.Errorf("Prune = %q", got)
	}
	if got := string(jobs[0].Fleecing); got != "enabled=1,storage=local-lvm" {
		t.Errorf("Fleecing = %q", got)
	}
	if !jobs[0].IsEnabled() || !jobs[0].All.Bool() {
		t.Errorf("job 1 should be enabled and select all guests: %+v", jobs[0])
	}
	if !jobs[1].IsEnabled() {
		t.Error("a job without an enabled key is enabled")
	}
	if jobs[2].IsEnabled() {
		t.Error("enabled=0 must read as disabled")
	}
}

func TestGetNodeServicesReadsUnitState(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes/pve1/services", []map[string]any{
		{"name": "pveproxy", "service": "pveproxy", "state": "running", "active-state": "active", "unit-state": "enabled", "desc": "PVE API Proxy Server"},
	})
	svcs, err := f.conn().GetNodeServices("pve1")
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].UnitFileState != "enabled" {
		t.Errorf("unexpected services %+v", svcs)
	}
}

func TestGetReplicationJobsAcceptsFractionalRate(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/replication", []map[string]any{
		{"id": "100-0", "guest": 100, "jobnum": 0, "target": "pve2", "type": "local", "rate": 0.5},
	})
	jobs, err := f.conn().GetReplicationJobs()
	if err != nil {
		t.Fatalf("a fractional rate must not fail the listing: %v", err)
	}
	if len(jobs) != 1 || jobs[0].Rate.Ceil() != 1 {
		t.Errorf("unexpected jobs %+v", jobs)
	}
}
