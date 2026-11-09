// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/talos/connection"
)

// newIntegrationRuntime connects to a live Talos node, such as one of
// `talosctl cluster create docker`, described by the TALOS_TEST_*
// environment, or skips when it is not configured.
//
//	TALOS_TEST_NODE         the node to query, such as 10.5.0.2
//	TALOS_TEST_TALOSCONFIG  a talosconfig with the os:admin role
//	TALOS_TEST_READER_TALOSCONFIG  one with the os:reader role
//	                        (talosctl config new --roles os:reader)
func newIntegrationRuntime(t *testing.T, env string) *plugin.Runtime {
	t.Helper()
	node := os.Getenv("TALOS_TEST_NODE")
	talosconfig := os.Getenv(env)
	if node == "" || talosconfig == "" {
		t.Skipf("set TALOS_TEST_NODE and %s to run talos integration tests", env)
	}
	conf := &inventory.Config{
		Type:    "talos",
		Host:    node,
		Options: map[string]string{connection.OptionTalosconfig: talosconfig},
	}
	conn, err := connection.NewTalosConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	if err != nil {
		t.Fatalf("failed to build connection: %v", err)
	}
	return plugin.NewRuntime(conn, nil, false, CreateResource, NewResource, GetData, SetData, nil)
}

func mustTalos(t *testing.T, runtime *plugin.Runtime) *mqlTalos {
	t.Helper()
	res, err := NewResource(runtime, "talos", map[string]*llx.RawData{})
	if err != nil {
		t.Fatalf("failed to create talos: %v", err)
	}
	return res.(*mqlTalos)
}

func TestIntegrationReader(t *testing.T) {
	runtime := newIntegrationRuntime(t, "TALOS_TEST_READER_TALOSCONFIG")
	conn := runtime.Connection.(*connection.TalosConnection)

	id, err := conn.NodeID()
	if err != nil || id == "" {
		t.Fatalf("NodeID = %q, %v", id, err)
	}

	talos := mustTalos(t, runtime)
	v := talos.GetVersion()
	if v.Error != nil || v.Data.Tag.Data == "" {
		t.Fatalf("version = %+v, %v", v.Data, v.Error)
	}

	params := talos.GetKernelParameters()
	if params.Error != nil || len(params.Data) == 0 {
		t.Fatalf("kernelParameters = %d, %v", len(params.Data), params.Error)
	}

	res, err := NewResource(runtime, "talos.resources", map[string]*llx.RawData{"type": llx.StringData("securitystate")})
	if err != nil {
		t.Fatalf("talos.resources(securitystate): %v", err)
	}
	resources := res.(*mqlTalosResources)
	if resources.ResolvedType.Data != "SecurityStates.talos.dev" {
		t.Errorf("resolvedType = %q", resources.ResolvedType.Data)
	}
	if list := resources.GetList(); list.Error != nil || len(list.Data) != 1 {
		t.Errorf("securitystate list = %d, %v", len(list.Data), list.Error)
	}

	// A reader is refused the machine configuration and file reads, as
	// Forbidden (ADR 046).
	if mc := talos.GetMachineConfig(); !errors.Is(mc.Error, llx.ErrForbidden) || !errors.Is(mc.Error, connection.ErrNeedsAdmin) {
		t.Errorf("machineConfig error = %v, want Forbidden and ErrNeedsAdmin", mc.Error)
	}
	_, err = NewResource(runtime, "talos.kernelParameter", map[string]*llx.RawData{"key": llx.StringData("net.ipv4.tcp_syncookies")})
	if !errors.Is(err, llx.ErrForbidden) {
		t.Errorf("talos.kernelParameter(tcp_syncookies) error = %v, want Forbidden", err)
	}
	if _, err := conn.ReadFile("/proc/sys/net/ipv4/tcp_syncookies"); !errors.Is(err, connection.ErrNeedsAdmin) {
		t.Errorf("ReadFile error = %v, want ErrNeedsAdmin", err)
	}
}

func TestIntegrationAdmin(t *testing.T) {
	runtime := newIntegrationRuntime(t, "TALOS_TEST_TALOSCONFIG")

	// Talos doesn't manage tcp_syncookies, so an admin reads it from /proc/sys.
	res, err := NewResource(runtime, "talos.kernelParameter", map[string]*llx.RawData{"key": llx.StringData("net.ipv4.tcp_syncookies")})
	if err != nil {
		t.Fatalf("talos.kernelParameter: %v", err)
	}
	param := res.(*mqlTalosKernelParameter)
	if param.Source.Data != "proc" || param.Current.Data == "" {
		t.Errorf("tcp_syncookies = %q from %q, want a value from proc", param.Current.Data, param.Source.Data)
	}

	mc := mustTalos(t, runtime).GetMachineConfig()
	if mc.Error != nil || len(mc.Data) == 0 {
		t.Fatalf("machineConfig = %d documents, %v", len(mc.Data), mc.Error)
	}
}
