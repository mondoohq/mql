// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// emptyClusterRuntime answers every list endpoint with an empty collection, so
// any lookup by id misses. That is the shape of a cluster where the object an
// ACL entry, HA entry, or storage reference names has since been deleted.
func emptyClusterRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	return listRuntime(t, map[string]any{})
}

// listRuntime serves the given path-to-body routes, defaulting to an empty
// list for anything not registered.
func listRuntime(t *testing.T, routes map[string]any) *plugin.Runtime {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api2/json")
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		body, ok := routes[path]
		if !ok {
			body = []any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": body})
	}))
	t.Cleanup(srv.Close)
	return &plugin.Runtime{Connection: connection.NewConnection(1, srv.URL, "token", true)}
}

type initFunc func(*plugin.Runtime, map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error)

// TestInitLookupMissReturnsError proves every init reports a miss as an error.
// Returning `args, nil, nil` instead would have the runtime build the resource
// out of the id alone, leaving every other field unset; reading one of those
// then surfaces as "primitive with no type information" with nothing naming
// the object that could not be found.
func TestInitLookupMissReturnsError(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   initFunc
		args map[string]*llx.RawData
		want string
	}{
		{"user", initProxmoxUser, map[string]*llx.RawData{"id": llx.StringData("ghost@pam")}, `proxmox.user "ghost@pam" not found`},
		{"group", initProxmoxGroup, map[string]*llx.RawData{"id": llx.StringData("ghosts")}, `proxmox.group "ghosts" not found`},
		{"role", initProxmoxRole, map[string]*llx.RawData{"id": llx.StringData("Ghost")}, `proxmox.role "Ghost" not found`},
		{"storage", initProxmoxStorage, map[string]*llx.RawData{"id": llx.StringData("ghost-nfs")}, `proxmox.storage "ghost-nfs" not found`},
		{"token", initProxmoxToken, map[string]*llx.RawData{"id": llx.StringData("root@pam!ghost")}, `proxmox.token "ghost" not found`},
		{"node", initProxmoxNode, map[string]*llx.RawData{"name": llx.StringData("ghost-node")}, `proxmox.node "ghost-node" not found`},
		{"haGroup", initProxmoxClusterHaGroup, map[string]*llx.RawData{"id": llx.StringData("ghost-ha")}, `proxmox.cluster.haGroup "ghost-ha" not found`},
		{"sdnZone", initProxmoxSdnZone, map[string]*llx.RawData{"zone": llx.StringData("ghostzone")}, `proxmox.sdn.zone "ghostzone" not found`},
		{"sdnVnet", initProxmoxSdnVnet, map[string]*llx.RawData{"vnet": llx.StringData("ghostvnet")}, `proxmox.sdn.vnet "ghostvnet" not found`},
		{"vm", initProxmoxVm, map[string]*llx.RawData{"id": llx.IntData(404)}, "proxmox.vm with vmid 404 not found"},
		{"container", initProxmoxContainer, map[string]*llx.RawData{"id": llx.IntData(405)}, "proxmox.container with vmid 405 not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := emptyClusterRuntime(t)
			args, res, err := tc.fn(runtime, tc.args)
			if err == nil {
				t.Fatalf("lookup miss returned no error (args=%v, resource=%v); a blank resource leaves every field unset", args, res)
			}
			if res != nil {
				t.Errorf("lookup miss returned a resource %v alongside the error", res)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name what was not found (want it to contain %q)", err, tc.want)
			}
		})
	}
}

// TestInitRejectsUnusableLookupKey covers the intermediate failures that also
// used to fall through to blank-resource creation: an empty id, a wrong-typed
// id, and a token id that is not in user@realm!tokenid form.
func TestInitRejectsUnusableLookupKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   initFunc
		args map[string]*llx.RawData
		want string
	}{
		{"emptyUserID", initProxmoxUser, map[string]*llx.RawData{"id": llx.StringData("")}, "non-empty id"},
		{"emptyGroupID", initProxmoxGroup, map[string]*llx.RawData{"id": llx.StringData("")}, "non-empty id"},
		{"emptyRoleID", initProxmoxRole, map[string]*llx.RawData{"id": llx.StringData("")}, "non-empty id"},
		{"emptyStorageID", initProxmoxStorage, map[string]*llx.RawData{"id": llx.StringData("")}, "non-empty id"},
		{"emptyNodeName", initProxmoxNode, map[string]*llx.RawData{"name": llx.StringData("")}, "non-empty name"},
		{"emptyHaGroupID", initProxmoxClusterHaGroup, map[string]*llx.RawData{"id": llx.StringData("")}, "non-empty id"},
		{"emptyZone", initProxmoxSdnZone, map[string]*llx.RawData{"zone": llx.StringData("")}, "non-empty zone"},
		{"emptyVnet", initProxmoxSdnVnet, map[string]*llx.RawData{"vnet": llx.StringData("")}, "non-empty vnet"},
		{"emptyCephFsName", initProxmoxCephFilesystem, map[string]*llx.RawData{"name": llx.StringData("")}, "non-empty name"},
		{"zeroVmid", initProxmoxVm, map[string]*llx.RawData{"id": llx.IntData(0)}, "non-zero vmid"},
		{"zeroCtVmid", initProxmoxContainer, map[string]*llx.RawData{"id": llx.IntData(0)}, "non-zero vmid"},
		{"emptyTokenID", initProxmoxToken, map[string]*llx.RawData{"id": llx.StringData("")}, "non-empty id"},
		{"tokenIDWithoutBang", initProxmoxToken, map[string]*llx.RawData{"id": llx.StringData("root@pam")}, "malformed"},
		{"vmidWrongType", initProxmoxVm, map[string]*llx.RawData{"id": llx.StringData("100")}, "non-zero vmid"},
		{"userIDWrongType", initProxmoxUser, map[string]*llx.RawData{"id": llx.IntData(1)}, "non-empty id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := emptyClusterRuntime(t)
			args, res, err := tc.fn(runtime, tc.args)
			if err == nil {
				t.Fatalf("unusable lookup key returned no error (args=%v, resource=%v)", args, res)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain the rejected key (want it to contain %q)", err, tc.want)
			}
		})
	}
}

// TestInitCompleteArgsFastPathIntact guards the legitimate early return: when
// the caller already supplied the fields, the init must hand the args straight
// back without an API call and without erroring.
func TestInitCompleteArgsFastPathIntact(t *testing.T) {
	runtime := emptyClusterRuntime(t)
	args := map[string]*llx.RawData{
		"id":   llx.IntData(100),
		"name": llx.StringData("web"),
		"node": llx.StringData("pve"),
	}
	got, res, err := initProxmoxVm(runtime, args)
	if err != nil {
		t.Fatalf("fast path returned an error: %v", err)
	}
	if res != nil {
		t.Errorf("fast path built a resource %v; it should hand back args", res)
	}
	if len(got) != len(args) {
		t.Errorf("fast path changed the args: got %v", got)
	}
}

// TestInitVmHitStillPopulates keeps the fix honest: a guest that does exist
// still resolves, with the listing fields filled in.
func TestInitVmHitStillPopulates(t *testing.T) {
	runtime := listRuntime(t, map[string]any{
		"/cluster/resources?type=vm": []any{
			map[string]any{"vmid": 100, "name": "web", "node": "pve", "status": "running", "type": "qemu", "template": 0},
		},
	})
	got, res, err := initProxmoxVm(runtime, map[string]*llx.RawData{"id": llx.IntData(100)})
	if err != nil {
		t.Fatalf("existing vm 100 failed to resolve: %v", err)
	}
	if res != nil {
		t.Fatalf("expected populated args, got resource %v", res)
	}
	if got["name"] == nil || got["name"].Value.(string) != "web" {
		t.Errorf("name not populated: %v", got["name"])
	}
	if got["node"] == nil || got["node"].Value.(string) != "pve" {
		t.Errorf("node not populated: %v", got["node"])
	}
	if got["status"] == nil || got["status"].Value.(string) != "running" {
		t.Errorf("status not populated: %v", got["status"])
	}
}
