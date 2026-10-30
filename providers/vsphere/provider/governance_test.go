// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/vapi/rest"
	"github.com/vmware/govmomi/vapi/tags"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vsphere/connection/vsimulator"
)

// field fetches a single field off a specific resource instance.
func field(t *testing.T, srv *Service, connID uint32, resource, id, name string) *plugin.DataRes {
	t.Helper()
	resp, err := srv.GetData(&plugin.DataReq{
		Connection: connID,
		Resource:   resource,
		ResourceId: id,
		Field:      name,
	})
	require.NoError(t, err, "resolving %s.%s should not error", resource, name)
	require.Empty(t, resp.Error, "resolver %s.%s returned an error", resource, name)
	return resp
}

// rootField fetches a single field off the singleton vsphere resource and
// returns the data response, failing the test on any resolver error.
func rootField(t *testing.T, srv *Service, connID uint32, field string) *plugin.DataRes {
	t.Helper()

	root, err := srv.GetData(&plugin.DataReq{
		Connection: connID,
		Resource:   "vsphere",
	})
	require.NoError(t, err)
	rootID := string(root.Data.Value)

	resp, err := srv.GetData(&plugin.DataReq{
		Connection: connID,
		Resource:   "vsphere",
		ResourceId: rootID,
		Field:      field,
	})
	require.NoError(t, err, "resolving vsphere.%s should not error", field)
	require.Empty(t, resp.Error, "resolver vsphere.%s returned an error", field)
	return resp
}

// TestGovernanceResources exercises every governance/inventory-metadata root
// accessor against the vcsim simulator. The simulator does not implement the
// vAPI certificate-management endpoints, so vsphere.certificates is expected to
// resolve cleanly to an empty list rather than error (the resolver treats those
// endpoints as best-effort).
func TestGovernanceResources(t *testing.T) {
	vs, srv, connRes := newTestService()
	defer vs.Close()

	for _, field := range []string{
		"categories",
		"tags",
		"contentLibraries",
		"customFields",
		"alarms",
		"triggeredAlarms",
		"scheduledTasks",
		"recentTasks",
		"events",
		"certificates",
	} {
		t.Run(field, func(t *testing.T) {
			resp := rootField(t, srv, connRes.Id, field)
			require.NotNil(t, resp.Data)
		})
	}

	// vcsim ships the default vCenter alarm definitions, so alarms should be
	// non-empty and prove the resolver maps real data through the runtime.
	// Distinct resource references additionally prove each alarm gets a unique
	// __id (a missing __id would collapse every entry onto one cache key).
	t.Run("alarms are populated and uniquely identified", func(t *testing.T) {
		resp := rootField(t, srv, connRes.Id, "alarms")
		require.Greater(t, len(resp.Data.Array), 1, "expected multiple default vCenter alarms")

		ids := map[string]struct{}{}
		for _, a := range resp.Data.Array {
			ids[string(a.Value)] = struct{}{}
		}
		require.Equal(t, len(resp.Data.Array), len(ids), "every alarm must have a unique __id")
	})

	// vcsim records events for the operations it performs at startup.
	t.Run("events are populated", func(t *testing.T) {
		resp := rootField(t, srv, connRes.Id, "events")
		require.NotEmpty(t, resp.Data.Array, "expected simulator events")
	})
}

// TestTagCrossRefs seeds a category + tag into the simulator, attaches the tag
// to a VM, and verifies the typed tagRefs accessor resolves it through the
// runtime — including navigating tagRefs -> category. This exercises the
// per-object vAPI lookup, the moid decode, and resolution against the shared
// root tag index.
func TestTagCrossRefs(t *testing.T) {
	vs, srv, connRes := newTestService()
	defer vs.Close()
	ctx := context.Background()

	// Seed a category + tag and attach it to a VM via an independent session,
	// mirroring how the connection builds its URL (https://host:port/sdk).
	u, err := url.Parse("https://" + vs.Server.URL.Host + "/sdk")
	require.NoError(t, err)
	u.User = url.UserPassword(vsimulator.Username, vsimulator.Password)
	gc, err := govmomi.NewClient(ctx, u, true)
	require.NoError(t, err)
	rc := rest.NewClient(gc.Client)
	require.NoError(t, rc.Login(ctx, u.User))

	tm := tags.NewManager(rc)
	catID, err := tm.CreateCategory(ctx, &tags.Category{Name: "environment", Cardinality: "SINGLE"})
	require.NoError(t, err)
	tagID, err := tm.CreateTag(ctx, &tags.Tag{Name: "production", CategoryID: catID})
	require.NoError(t, err)

	finder := find.NewFinder(gc.Client, true)
	dc, err := finder.DefaultDatacenter(ctx)
	require.NoError(t, err)
	finder.SetDatacenter(dc)
	vms, err := finder.VirtualMachineList(ctx, "*")
	require.NoError(t, err)
	require.NotEmpty(t, vms)
	vmRef := vms[0].Reference()
	require.NoError(t, tm.AttachTag(ctx, tagID, vmRef))

	// Locate the same VM through the provider and read its tagRefs.
	root, err := srv.GetData(&plugin.DataReq{Connection: connRes.Id, Resource: "vsphere"})
	require.NoError(t, err)
	rootID := string(root.Data.Value)
	dcs := field(t, srv, connRes.Id, "vsphere", rootID, "datacenters")

	var tagRefs *plugin.DataRes
	for _, d := range dcs.Data.Array {
		dcID := string(d.Value)
		vmList := field(t, srv, connRes.Id, "vsphere.datacenter", dcID, "vms")
		for _, v := range vmList.Data.Array {
			vmID := string(v.Value)
			moid := field(t, srv, connRes.Id, "vsphere.vm", vmID, "moid")
			if string(moid.Data.Value) != vmRef.Encode() {
				continue
			}
			tagRefs = field(t, srv, connRes.Id, "vsphere.vm", vmID, "tagRefs")
		}
	}
	require.NotNil(t, tagRefs, "did not find the tagged VM through the provider")
	require.Len(t, tagRefs.Data.Array, 1, "expected exactly one attached tag")

	// tagRefs[0].name == "production" and tagRefs[0].category.name == "environment"
	tagResID := string(tagRefs.Data.Array[0].Value)
	tagName := field(t, srv, connRes.Id, "vsphere.tag", tagResID, "name")
	require.Equal(t, "production", string(tagName.Data.Value))

	catRef := field(t, srv, connRes.Id, "vsphere.tag", tagResID, "category")
	catResID := string(catRef.Data.Value)
	catName := field(t, srv, connRes.Id, "vsphere.category", catResID, "name")
	require.Equal(t, "environment", string(catName.Data.Value))

	// category.tags() returns the tag back (reverse accessor).
	catTags := field(t, srv, connRes.Id, "vsphere.category", catResID, "tags")
	require.Len(t, catTags.Data.Array, 1, "category.tags should list the one tag")
	require.Equal(t, tagResID, string(catTags.Data.Array[0].Value))

	// The deprecated `tags []string` still resolves (back-compat), formatted as
	// "category:tag".
	for _, d := range dcs.Data.Array {
		dcID := string(d.Value)
		vmList := field(t, srv, connRes.Id, "vsphere.datacenter", dcID, "vms")
		for _, v := range vmList.Data.Array {
			vmID := string(v.Value)
			moid := field(t, srv, connRes.Id, "vsphere.vm", vmID, "moid")
			if string(moid.Data.Value) != vmRef.Encode() {
				continue
			}
			depTags := field(t, srv, connRes.Id, "vsphere.vm", vmID, "tags")
			require.Len(t, depTags.Data.Array, 1)
			require.Equal(t, "environment:production", string(depTags.Data.Array[0].Value))
		}
	}
}
