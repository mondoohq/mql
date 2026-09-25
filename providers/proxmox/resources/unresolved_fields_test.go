// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// pveRuntime serves the given raw `data` documents by API path and returns a
// full plugin runtime, so resources built through CreateResource go through
// the real cache.
func pveRuntime(t *testing.T, routes map[string]string) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		data, ok := routes[path]
		if !ok {
			http.Error(w, "unexpected path "+path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + data + `}`))
	}))
	t.Cleanup(srv.Close)
	conn := connection.NewConnection(1, srv.URL, "token", true)
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

// nodeStatusFixture follows /nodes/{node}/status: current-kernel is its own
// object and boot-info carries only mode and secureboot.
const nodeStatusFixture = `{
	"cpuinfo": {"model": "AMD EPYC 7302P", "sockets": 1, "cores": 16, "cpus": 32},
	"cpu": 0.25,
	"memory": {"total": 1000, "used": 400, "free": 600},
	"swap": {"total": 200, "used": 10, "free": 190},
	"kversion": "Linux 6.8.12-4-pve #1 SMP PREEMPT_DYNAMIC",
	"current-kernel": {"sysname": "Linux", "release": "6.8.12-4-pve", "version": "#1 SMP", "machine": "x86_64"},
	"pveversion": "pve-manager/8.2.7/3e0176e6bb2ade3b",
	"uptime": 3600,
	"boot-info": {"mode": "efi", "secureboot": 1}
}`

// TestNodeStatusFieldsResolve guards the node fields that are backed by
// /nodes/{node}/status and /nodes/{node}/time. They were declared as plain
// fields, which nothing ever set, so each one reached the client unset and
// read as null on every node.
func TestNodeStatusFieldsResolve(t *testing.T) {
	runtime := pveRuntime(t, map[string]string{
		"/api2/json/nodes/pve1/status": nodeStatusFixture,
		"/api2/json/nodes/pve1/time":   `{"timezone": "Europe/Berlin", "time": 1, "localtime": 1}`,
	})
	res, err := CreateResource(runtime, "proxmox.node", map[string]*llx.RawData{
		"name":   llx.StringData("pve1"),
		"status": llx.StringData("online"),
		"ip":     llx.StringData("10.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	n := res.(*mqlProxmoxNode)

	str := map[string]*plugin.TValue[string]{
		"cpuModel":      n.GetCpuModel(),
		"kernelVersion": n.GetKernelVersion(),
		"pveVersion":    n.GetPveVersion(),
		"timezone":      n.GetTimezone(),
	}
	want := map[string]string{
		"cpuModel":      "AMD EPYC 7302P",
		"kernelVersion": "Linux 6.8.12-4-pve #1 SMP PREEMPT_DYNAMIC",
		"pveVersion":    "pve-manager/8.2.7/3e0176e6bb2ade3b",
		"timezone":      "Europe/Berlin",
	}
	for name, v := range str {
		if v.Error != nil {
			t.Errorf("%s: %v", name, v.Error)
			continue
		}
		if !v.IsSet() || v.Data != want[name] {
			t.Errorf("%s = %q (set=%v), want %q", name, v.Data, v.IsSet(), want[name])
		}
	}
	ints := map[string]struct {
		v    *plugin.TValue[int64]
		want int64
	}{
		"cpuSockets": {n.GetCpuSockets(), 1},
		"cpuCores":   {n.GetCpuCores(), 16},
		"memTotal":   {n.GetMemTotal(), 1000},
		"memUsed":    {n.GetMemUsed(), 400},
		"memFree":    {n.GetMemFree(), 600},
		"swapTotal":  {n.GetSwapTotal(), 200},
		"swapUsed":   {n.GetSwapUsed(), 10},
		"uptime":     {n.GetUptime(), 3600},
	}
	for name, c := range ints {
		if !c.v.IsSet() || c.v.Data != c.want {
			t.Errorf("%s = %d (set=%v), want %d", name, c.v.Data, c.v.IsSet(), c.want)
		}
	}
	if u := n.GetCpuUsage(); !u.IsSet() || u.Data != 0.25 {
		t.Errorf("cpuUsage = %v (set=%v), want 0.25", u.Data, u.IsSet())
	}
	if sb := n.GetSecureBoot(); sb.Error != nil || !sb.Data {
		t.Errorf("secureBoot = %v, %v; want true", sb.Data, sb.Error)
	}
}

// TestNodeRebootFieldsAreNull: the API does not say which kernel boots next,
// so a pending reboot cannot be established. Reporting false claimed every
// node was up to date.
func TestNodeRebootFieldsAreNull(t *testing.T) {
	runtime := pveRuntime(t, map[string]string{"/api2/json/nodes/pve1/status": nodeStatusFixture})
	n := &mqlProxmoxNode{MqlRuntime: runtime}
	n.Name.Data = "pve1"
	if v := n.GetPendingReboot(); !v.IsNull() {
		t.Errorf("pendingReboot = %v, want null", v.Data)
	}
	if v := n.GetBootKernel(); !v.IsNull() {
		t.Errorf("bootKernel = %q, want null", v.Data)
	}
}

// TestNodeAndClusterStorageViewsDoNotAlias: the same storage name appears in
// the cluster listing and once per node, with different data. Sharing one
// cache key made the first listing answer for every other.
func TestNodeAndClusterStorageViewsDoNotAlias(t *testing.T) {
	runtime := pveRuntime(t, map[string]string{})
	cluster, err := storageInfoToResources(runtime, []connection.StorageInfo{
		{Storage: "local-lvm", Type: "lvmthin", Content: "images", Enabled: 1, Nodes: "pve1,pve2"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	pve1, err := storageInfoToResources(runtime, []connection.StorageInfo{
		{Storage: "local-lvm", Type: "lvmthin", Enabled: 1, Active: 1, Total: 100, Used: 10},
	}, "pve1")
	if err != nil {
		t.Fatal(err)
	}
	pve2, err := storageInfoToResources(runtime, []connection.StorageInfo{
		{Storage: "local-lvm", Type: "lvmthin", Enabled: 1, Active: 1, Total: 100, Used: 90},
	}, "pve2")
	if err != nil {
		t.Fatal(err)
	}
	c := cluster[0].(*mqlProxmoxStorage)
	s1 := pve1[0].(*mqlProxmoxStorage)
	s2 := pve2[0].(*mqlProxmoxStorage)
	if s1.Used.Data != 10 || s2.Used.Data != 90 {
		t.Errorf("per-node usage aliased: pve1=%d pve2=%d, want 10 and 90", s1.Used.Data, s2.Used.Data)
	}
	if c.Nodes.Data != "pve1,pve2" {
		t.Errorf("cluster view nodes = %q, want the configured restriction", c.Nodes.Data)
	}
	if s1.Id.Data != "local-lvm" || s2.Id.Data != "local-lvm" {
		t.Errorf("node views must keep the storage name as id, got %q and %q", s1.Id.Data, s2.Id.Data)
	}
}

// TestGuestPoolComesFromClusterResources: a guest's config has no `pool` key;
// membership is only in the cluster resource listing.
func TestGuestPoolComesFromClusterResources(t *testing.T) {
	runtime := pveRuntime(t, map[string]string{
		"/api2/json/cluster/resources?type=vm": `[
			{"id": "qemu/100", "type": "qemu", "vmid": 100, "node": "pve1", "pool": "prod"},
			{"id": "qemu/101", "type": "qemu", "vmid": 101, "node": "pve1"}
		]`,
	})
	conn := runtime.Connection.(*connection.PveConnection)
	pool, err := conn.GuestPool(100)
	if err != nil || pool != "prod" {
		t.Errorf("GuestPool(100) = %q, %v; want prod", pool, err)
	}

	vm := &mqlProxmoxVm{MqlRuntime: runtime}
	vm.Id.Data = 101
	got, err := vm.pool()
	if err != nil || got != nil {
		t.Fatalf("pool() for a guest in no pool = %v, %v", got, err)
	}
	if !vm.Pool.IsNull() {
		t.Error("a guest in no pool must read as null")
	}
}

func TestBackupSelection(t *testing.T) {
	all := backupSelection{all: true, exclude: map[int64]bool{101: true}, want: map[int64]bool{}}
	if !all.selects(100, "pve1") || all.selects(101, "pve1") {
		t.Error("all=1 must select every guest except the excluded ones")
	}
	onNode := backupSelection{all: true, node: "pve1", exclude: map[int64]bool{}, want: map[int64]bool{}}
	if !onNode.selects(100, "pve1") || onNode.selects(200, "pve2") {
		t.Error("a node-restricted job only covers guests on that node")
	}
	listed := backupSelection{want: map[int64]bool{100: true}, exclude: map[int64]bool{}}
	if !listed.selects(100, "pve2") || listed.selects(102, "pve2") {
		t.Error("an explicit vmid list selects exactly those guests")
	}
}
