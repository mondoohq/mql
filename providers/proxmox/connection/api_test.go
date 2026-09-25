// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// APIError + IsAccessDeniedOrNotFound
// ---------------------------------------------------------------------------

func TestAPIError_StatusCodeRoundTrip(t *testing.T) {
	f := newFakePVE(t)
	f.errorRoute("/cluster/firewall/options", 403, "Permission check failed")
	c := f.conn()

	_, err := c.GetClusterFirewallOptions()
	if err == nil {
		t.Fatal("expected an error for a 403")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %T is not an *APIError", err)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("status = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Message != "Permission check failed" {
		t.Errorf("message = %q, want %q", apiErr.Message, "Permission check failed")
	}
}

func TestIsAccessDeniedOrNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil-err", nil, false},
		{"plain-error", errors.New("network down"), false},
		{"401", &APIError{StatusCode: 401}, true},
		{"403", &APIError{StatusCode: 403}, true},
		{"404", &APIError{StatusCode: 404}, true},
		{"500-bubbles-up", &APIError{StatusCode: 500}, false},
		{"502-bubbles-up", &APIError{StatusCode: 502}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAccessDeniedOrNotFound(tt.err); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetStorages — PBS encryption parsing
// ---------------------------------------------------------------------------

func TestGetStorages_EncryptedAndPlain(t *testing.T) {
	f := newFakePVE(t)
	f.route("/storage", []map[string]any{
		// PBS datastore configured with an encryption key
		{
			"storage":        "pbs-encrypted",
			"type":           "pbs",
			"content":        "backup",
			"enabled":        1,
			"shared":         1,
			"total":          1_000_000_000,
			"used":           500_000_000,
			"avail":          500_000_000,
			"used_fraction":  0.5,
			"encryption-key": "autogen",
		},
		// Plain dir storage — no encryption-key field at all
		{
			"storage": "local",
			"type":    "dir",
			"content": "iso,vztmpl",
			"path":    "/var/lib/vz",
			"enabled": 1,
			"shared":  0,
		},
	})

	storages, err := f.conn().GetStorages()
	if err != nil {
		t.Fatal(err)
	}
	if len(storages) != 2 {
		t.Fatalf("expected 2 storages, got %d", len(storages))
	}

	pbs := storages[0]
	if pbs.EncryptionKey != "autogen" {
		t.Errorf("PBS storage EncryptionKey = %q, want %q", pbs.EncryptionKey, "autogen")
	}
	local := storages[1]
	if local.EncryptionKey != "" {
		t.Errorf("local storage EncryptionKey = %q, want empty", local.EncryptionKey)
	}
}

// ---------------------------------------------------------------------------
// GetNodeContainers — VMID decoding
// ---------------------------------------------------------------------------

func TestGetNodeContainers_ValidVMIDs(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes/pve1/lxc", []map[string]any{
		{"vmid": 100, "name": "web", "status": "running", "maxmem": 512_000_000},
		{"vmid": 201, "name": "db", "status": "stopped", "maxmem": 1_024_000_000},
	})

	cts, err := f.conn().GetNodeContainers("pve1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cts) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(cts))
	}
	if cts[0].VMID != 100 || cts[0].Name != "web" {
		t.Errorf("container[0] = %+v, want VMID=100 Name=web", cts[0])
	}
	if cts[1].VMID != 201 {
		t.Errorf("container[1].VMID = %d, want 201", cts[1].VMID)
	}
	if cts[0].Node != "pve1" {
		t.Errorf("container[0].Node = %q, want pve1 (set by helper, not API)", cts[0].Node)
	}
}

func TestGetNodeContainers_MalformedVMIDErrors(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes/pve1/lxc", []map[string]any{
		{"vmid": "not-a-number", "name": "broken"},
	})

	_, err := f.conn().GetNodeContainers("pve1")
	if err == nil {
		t.Fatal("expected an error for a non-numeric VMID; got nil")
	}
	// Don't pin the exact message — fmt.Errorf wraps the strconv error
	// directly, so the test would break on every Go version bump. Check
	// that the surrounding context (the bad value and node name) is in
	// the wrapped message so operators can grep for it.
	msg := err.Error()
	if !contains(msg, `"not-a-number"`) || !contains(msg, "pve1") {
		t.Errorf("error %q should mention the bad VMID and node name", msg)
	}
}

// ---------------------------------------------------------------------------
// GetNodeVMs — symmetric per-node fetch. Regression test against the
// N+1 GetNodeVMs behavior (which used to hit /cluster/resources and
// filter in memory).
// ---------------------------------------------------------------------------

func TestGetNodeVMs_HitsPerNodeEndpoint(t *testing.T) {
	f := newFakePVE(t)
	// Crucially, /cluster/resources is NOT registered. If GetNodeVMs ever
	// regresses back to using GetAllVMs internally the test fails with a
	// 404 instead of silently passing on a stale endpoint.
	f.route("/nodes/pve1/qemu", []map[string]any{
		{"vmid": 100, "name": "web", "status": "running", "maxmem": 2_000_000_000},
		{"vmid": 201, "name": "db", "status": "stopped"},
	})

	vms, err := f.conn().GetNodeVMs("pve1")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 2 {
		t.Fatalf("expected 2 VMs, got %d", len(vms))
	}
	if vms[0].VMID != 100 || vms[0].Name != "web" || vms[0].Node != "pve1" {
		t.Errorf("vm[0] = %+v, want VMID=100 Name=web Node=pve1", vms[0])
	}
	if vms[1].VMID != 201 {
		t.Errorf("vm[1].VMID = %d, want 201", vms[1].VMID)
	}
	if vms[0].Type != "qemu" {
		t.Errorf("vm[0].Type = %q, want qemu (filled in by helper)", vms[0].Type)
	}
}

func TestGetNodeVMs_MalformedVMIDErrors(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes/pve1/qemu", []map[string]any{
		{"vmid": "garbage", "name": "broken"},
	})

	_, err := f.conn().GetNodeVMs("pve1")
	if err == nil {
		t.Fatal("expected an error for a non-numeric VMID; got nil")
	}
	msg := err.Error()
	if !contains(msg, `"garbage"`) || !contains(msg, "pve1") {
		t.Errorf("error %q should mention the bad VMID and node name", msg)
	}
}

// ---------------------------------------------------------------------------
// GetClusterFirewallOptions — dict semantics for the typed-options layer
// ---------------------------------------------------------------------------

func TestGetClusterFirewallOptions_ReturnsRawDict(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/firewall/options", map[string]any{
		"enable":     1,
		"policy_in":  "DROP",
		"policy_out": "ACCEPT",
	})

	opts, err := f.conn().GetClusterFirewallOptions()
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := opts["enable"].(float64); !ok || v != 1 {
		t.Errorf("enable = %v (%T), want 1", opts["enable"], opts["enable"])
	}
	if opts["policy_in"] != "DROP" {
		t.Errorf("policy_in = %v, want DROP", opts["policy_in"])
	}
}

// ---------------------------------------------------------------------------
// GetReplicationJobs — shape sanity, including int-typed `disable` field
// ---------------------------------------------------------------------------

func TestGetReplicationJobs_DisabledFlagAndRate(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/replication", []map[string]any{
		{
			"id":       "100-0",
			"guest":    100,
			"schedule": "*/30",
			"source":   "pve1",
			"target":   "pve2",
			"type":     "local",
			"disable":  1,
			"rate":     50,
		},
	})

	jobs, err := f.conn().GetReplicationJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}
	j := jobs[0]
	if j.Disable != 1 {
		t.Errorf("Disable = %d, want 1", j.Disable)
	}
	if j.Rate != 50 {
		t.Errorf("Rate = %v, want 50", j.Rate)
	}
	if j.VMID != 100 {
		t.Errorf("VMID = %d, want 100", j.VMID)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
