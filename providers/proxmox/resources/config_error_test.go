// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// configRuntime spins up a PVE API whose guest `config` endpoints answer with
// the given status, and returns a runtime wired to it. A 403 stands in for the
// case that matters: a token that can list guests but cannot read their
// configuration.
func configRuntime(t *testing.T, status int, body map[string]any) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/config") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if status >= 400 {
			http.Error(w, "Permission check failed", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": body})
	}))
	t.Cleanup(srv.Close)
	return &plugin.Runtime{Connection: connection.NewConnection(1, srv.URL, "token", true)}
}

func testContainer(runtime *plugin.Runtime) *mqlProxmoxContainer {
	ct := &mqlProxmoxContainer{MqlRuntime: runtime}
	ct.Id.Data = 100
	ct.Node.Data = "pve"
	return ct
}

func testVM(runtime *plugin.Runtime) *mqlProxmoxVm {
	vm := &mqlProxmoxVm{MqlRuntime: runtime}
	vm.Id.Data = 100
	vm.Node.Data = "pve"
	return vm
}

// TestContainerConfigReadFailureIsNotAValue proves that a denied config read
// reports an error instead of a fabricated value. Before this was fixed every
// field below answered with the zero value, so a container whose config could
// not be read looked exactly like a container running privileged, unprotected
// and with no features enabled.
func TestContainerConfigReadFailureIsNotAValue(t *testing.T) {
	runtime := configRuntime(t, http.StatusForbidden, nil)
	ct := testContainer(runtime)

	fields := map[string]func() (any, error){
		"osType":       func() (any, error) { return ct.osType() },
		"hostname":     func() (any, error) { return ct.hostname() },
		"unprivileged": func() (any, error) { return ct.unprivileged() },
		"protection":   func() (any, error) { return ct.protection() },
		"onboot":       func() (any, error) { return ct.onboot() },
		"description":  func() (any, error) { return ct.description() },
		"cmode":        func() (any, error) { return ct.cmode() },
		"searchDomain": func() (any, error) { return ct.searchDomain() },
		"nameserver":   func() (any, error) { return ct.nameserver() },
		"swap":         func() (any, error) { return ct.swap() },
		"cpuLimit":     func() (any, error) { return ct.cpuLimit() },
		"cpuUnits":     func() (any, error) { return ct.cpuUnits() },
		"rawLxc":       func() (any, error) { return ct.rawLxc() },
		"features":     func() (any, error) { return ct.features() },
		"tags":         func() (any, error) { return ct.tags() },
		"networks":     func() (any, error) { return ct.networks() },
		"mountPoints":  func() (any, error) { return ct.mountPoints() },
		"config":       func() (any, error) { return ct.config() },
	}
	for name, read := range fields {
		t.Run(name, func(t *testing.T) {
			got, err := read()
			if err == nil {
				t.Fatalf("%s() reported %#v with a nil error, but the config read failed", name, got)
			}
			if !strings.Contains(err.Error(), "403") {
				t.Errorf("%s() error %q does not carry the API failure", name, err)
			}
		})
	}
}

// TestVMConfigReadFailureIsNotAValue is the VM half of the same guarantee.
// bios() is the loudest of these: it used to answer "seabios" for a VM whose
// config was never read, which reads as a real, confirmed BIOS setting.
func TestVMConfigReadFailureIsNotAValue(t *testing.T) {
	runtime := configRuntime(t, http.StatusForbidden, nil)
	vm := testVM(runtime)

	fields := map[string]func() (any, error){
		"osType":        func() (any, error) { return vm.osType() },
		"machine":       func() (any, error) { return vm.machine() },
		"bios":          func() (any, error) { return vm.bios() },
		"bootOrder":     func() (any, error) { return vm.bootOrder() },
		"agent":         func() (any, error) { return vm.agent() },
		"protection":    func() (any, error) { return vm.protection() },
		"description":   func() (any, error) { return vm.description() },
		"lock":          func() (any, error) { return vm.lock() },
		"hookscript":    func() (any, error) { return vm.hookscript() },
		"args":          func() (any, error) { return vm.args() },
		"vga":           func() (any, error) { return vm.vga() },
		"ciuser":        func() (any, error) { return vm.ciuser() },
		"sshkeys":       func() (any, error) { return vm.sshkeys() },
		"searchDomain":  func() (any, error) { return vm.searchDomain() },
		"nameserver":    func() (any, error) { return vm.nameserver() },
		"cipasswordSet": func() (any, error) { return vm.cipasswordSet() },
		"ciCustom":      func() (any, error) { return vm.ciCustom() },
		"tags":          func() (any, error) { return vm.tags() },
		"serialPorts":   func() (any, error) { return vm.serialPorts() },
		"networks":      func() (any, error) { return vm.networks() },
		"disks":         func() (any, error) { return vm.disks() },
		"pciDevices":    func() (any, error) { return vm.pciDevices() },
		"usbDevices":    func() (any, error) { return vm.usbDevices() },
		"config":        func() (any, error) { return vm.config() },
	}
	for name, read := range fields {
		t.Run(name, func(t *testing.T) {
			got, err := read()
			if err == nil {
				t.Fatalf("%s() reported %#v with a nil error, but the config read failed", name, got)
			}
			if !strings.Contains(err.Error(), "403") {
				t.Errorf("%s() error %q does not carry the API failure", name, err)
			}
		})
	}
}

// TestContainerAbsentKeysKeepTheirDefaults pins the state the fix must leave
// alone: the config was read successfully and simply does not carry the key.
// An absent PVE flag means the flag is off, and that is a real answer.
func TestContainerAbsentKeysKeepTheirDefaults(t *testing.T) {
	runtime := configRuntime(t, http.StatusOK, map[string]any{"ostype": "debian"})
	ct := testContainer(runtime)

	if got, err := ct.osType(); err != nil || got != "debian" {
		t.Errorf("osType() = %q, %v; want debian, nil", got, err)
	}
	if got, err := ct.unprivileged(); err != nil || got {
		t.Errorf("unprivileged() = %v, %v; want false, nil for an absent key", got, err)
	}
	if got, err := ct.protection(); err != nil || got {
		t.Errorf("protection() = %v, %v; want false, nil for an absent key", got, err)
	}
	if got, err := ct.hostname(); err != nil || got != "" {
		t.Errorf("hostname() = %q, %v; want empty, nil for an absent key", got, err)
	}
	if got, err := ct.swap(); err != nil || got != 0 {
		t.Errorf("swap() = %d, %v; want 0, nil for an absent key", got, err)
	}
}

// TestVMAbsentKeysKeepTheirDefaults is the VM counterpart, including the
// documented seabios fallback that only applies to a config we did read.
func TestVMAbsentKeysKeepTheirDefaults(t *testing.T) {
	runtime := configRuntime(t, http.StatusOK, map[string]any{"protection": 1})
	vm := testVM(runtime)

	if got, err := vm.bios(); err != nil || got != "seabios" {
		t.Errorf("bios() = %q, %v; want seabios, nil for an absent key", got, err)
	}
	if got, err := vm.protection(); err != nil || !got {
		t.Errorf("protection() = %v, %v; want true, nil", got, err)
	}
	if got, err := vm.agent(); err != nil || got {
		t.Errorf("agent() = %v, %v; want false, nil for an absent key", got, err)
	}
	if got, err := vm.cipasswordSet(); err != nil || got {
		t.Errorf("cipasswordSet() = %v, %v; want false, nil for an absent key", got, err)
	}
	if got, err := vm.osType(); err != nil || got != "" {
		t.Errorf("osType() = %q, %v; want empty, nil for an absent key", got, err)
	}
}
