// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// clusterWithOptions returns a cluster resource whose /cluster/options answer
// is the given raw JSON document. The structured settings are objects there:
// DataCenterConfig::parse_datacenter_config runs parse_property_string over
// migration, ha, u2f, webauthn and the rest before the API returns them.
func clusterWithOptions(t *testing.T, raw string) *mqlProxmoxCluster {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/cluster/options" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + raw + `}`))
	}))
	t.Cleanup(srv.Close)
	runtime := &plugin.Runtime{Connection: connection.NewConnection(1, srv.URL, "token", true)}
	return &mqlProxmoxCluster{MqlRuntime: runtime}
}

func TestClusterOptionsReadObjectSettings(t *testing.T) {
	c := clusterWithOptions(t, `{
		"migration": {"type": "insecure", "network": "10.0.0.0/24"},
		"ha": {"shutdown_policy": "migrate"},
		"webauthn": {"rp": "pve.example.com", "id": "pve.example.com", "origin": "https://pve.example.com:8006", "allow-subdomains": 0},
		"u2f": {"appid": "https://pve.example.com", "origin": "https://pve.example.com:8006"}
	}`)

	check := func(name string, got string, err error, want string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	got, err := c.migrationPolicy()
	check("migrationPolicy", got, err, "insecure")
	got, err = c.migrationNetwork()
	check("migrationNetwork", got, err, "10.0.0.0/24")
	got, err = c.haShutdownPolicy()
	check("haShutdownPolicy", got, err, "migrate")
	got, err = c.webauthnRelyingParty()
	check("webauthnRelyingParty", got, err, "pve.example.com")
	got, err = c.webauthnOrigin()
	check("webauthnOrigin", got, err, "https://pve.example.com:8006")
	got, err = c.u2fAppId()
	check("u2fAppId", got, err, "https://pve.example.com")

	allow, err := c.webauthnAllowSubdomains()
	if err != nil {
		t.Fatal(err)
	}
	if allow {
		t.Error("allow-subdomains=0 must read as false, not the permissive default")
	}
}

func TestClusterOptionsStillReadPropertyStrings(t *testing.T) {
	c := clusterWithOptions(t, `{"migration": "secure,network=192.168.0.0/16"}`)
	policy, err := c.migrationPolicy()
	if err != nil || policy != "secure" {
		t.Errorf("migrationPolicy = %q, %v", policy, err)
	}
	network, err := c.migrationNetwork()
	if err != nil || network != "192.168.0.0/16" {
		t.Errorf("migrationNetwork = %q, %v", network, err)
	}
}

func TestClusterOptionsAbsentSettingIsEmpty(t *testing.T) {
	c := clusterWithOptions(t, `{"console": "html5"}`)
	policy, err := c.migrationPolicy()
	if err != nil || policy != "" {
		t.Errorf("migrationPolicy = %q, %v; want empty", policy, err)
	}
}

func TestRawLxcLinesFromPairs(t *testing.T) {
	// /nodes/{node}/lxc/{vmid}/config returns `lxc` as [[key, value], ...]
	var cfg map[string]any
	if err := json.Unmarshal([]byte(`{"lxc": [["lxc.apparmor.profile", "unconfined"], ["lxc.cgroup2.devices.allow", "a"]]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	got := rawLxcLines(cfg["lxc"])
	want := []string{"lxc.apparmor.profile: unconfined", "lxc.cgroup2.devices.allow: a"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rawLxcLines = %#v, want %#v", got, want)
	}
	if got := rawLxcLines(nil); len(got) != 0 {
		t.Errorf("absent key should yield no lines, got %#v", got)
	}
	if got := rawLxcLines("lxc.cap.drop: sys_module"); !reflect.DeepEqual(got, []string{"lxc.cap.drop: sys_module"}) {
		t.Errorf("string form = %#v", got)
	}
}

func TestVMAgentReadsPropertyString(t *testing.T) {
	cases := map[string]bool{
		"1":                               true,
		"0":                               false,
		"1,fstrim_cloned_disks=1":         true,
		"enabled=1,type=virtio":           true,
		"enabled=0,freeze-fs-on-backup=1": false,
	}
	for raw, want := range cases {
		vm := testVM(configRuntime(t, http.StatusOK, map[string]any{"agent": raw}))
		got, err := vm.agent()
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if got != want {
			t.Errorf("agent %q = %v, want %v", raw, got, want)
		}
	}
	vm := testVM(configRuntime(t, http.StatusOK, map[string]any{}))
	if got, err := vm.agent(); err != nil || got {
		t.Errorf("absent agent = %v, %v; want false", got, err)
	}
}
