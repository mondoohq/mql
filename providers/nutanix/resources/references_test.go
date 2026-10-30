// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	clustermgmtconfig "github.com/nutanix/ntnx-api-golang-clients/clustermgmt-go-client/v4/models/clustermgmt/v4/config"
	netconfig "github.com/nutanix/ntnx-api-golang-clients/networking-go-client/v4/models/networking/v4/config"
	vmmcontent "github.com/nutanix/ntnx-api-golang-clients/vmm-go-client/v4/models/vmm/v4/content"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---------------------------------------------------------------------------
// nutanix.image
// ---------------------------------------------------------------------------

func TestNewMqlImageCachesReferences(t *testing.T) {
	runtime := newTestRuntime()

	img, err := newMqlImage(runtime, &vmmcontent.Image{
		ExtId:                 new("image-1"),
		Name:                  new("ubuntu-22.04"),
		ClusterLocationExtIds: []string{"cluster-a", "cluster-b"},
		OwnerExtId:            new("owner-1"),
	})
	if err != nil {
		t.Fatalf("newMqlImage returned error: %v", err)
	}
	if got, want := len(img.cacheClusterIds), 2; got != want {
		t.Fatalf("cacheClusterIds len = %d, want %d", got, want)
	}
	if img.cacheClusterIds[0] != "cluster-a" || img.cacheClusterIds[1] != "cluster-b" {
		t.Errorf("cacheClusterIds = %v, want [cluster-a cluster-b]", img.cacheClusterIds)
	}
	if img.cacheOwnerId != "owner-1" {
		t.Errorf("cacheOwnerId = %q, want owner-1", img.cacheOwnerId)
	}
}

// An image with no owner and no cluster placements must decode to the safe
// reading: no cached ids at all, so neither accessor invents a reference.
func TestNewMqlImageAbsentReferences(t *testing.T) {
	runtime := newTestRuntime()

	img, err := newMqlImage(runtime, &vmmcontent.Image{
		ExtId: new("image-2"),
		Name:  new("no-placement"),
	})
	if err != nil {
		t.Fatalf("newMqlImage returned error: %v", err)
	}
	if len(img.cacheClusterIds) != 0 {
		t.Errorf("cacheClusterIds = %v, want empty", img.cacheClusterIds)
	}
	if img.cacheOwnerId != "" {
		t.Errorf("cacheOwnerId = %q, want empty", img.cacheOwnerId)
	}
}

// clusters() on an image with no placements returns an empty list without
// reaching for the connection, which is nil on the test runtime: a lookup
// attempt would panic here rather than pass.
func TestImageClustersWithoutPlacements(t *testing.T) {
	img := &mqlNutanixImage{MqlRuntime: newTestRuntime()}

	got, err := img.clusters()
	if err != nil {
		t.Fatalf("clusters returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("clusters = %v, want empty", got)
	}
}

// An empty string inside the placement list is not a cluster; resolving it
// would issue a GET for the empty id.
func TestImageClustersSkipsEmptyIDs(t *testing.T) {
	img := &mqlNutanixImage{MqlRuntime: newTestRuntime()}
	img.cacheClusterIds = []string{"", ""}

	got, err := img.clusters()
	if err != nil {
		t.Fatalf("clusters returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("clusters = %v, want empty", got)
	}
}

func TestImageClustersResolvesFromCache(t *testing.T) {
	runtime := newTestRuntime()
	seedResource(t, runtime, "nutanix.cluster", "cluster-a")
	seedResource(t, runtime, "nutanix.cluster", "cluster-b")

	img := &mqlNutanixImage{MqlRuntime: runtime}
	img.cacheClusterIds = []string{"cluster-a", "cluster-b"}

	got, err := img.clusters()
	if err != nil {
		t.Fatalf("clusters returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("clusters len = %d, want 2", len(got))
	}
	for i, want := range []string{"cluster-a", "cluster-b"} {
		cluster, ok := got[i].(*mqlNutanixCluster)
		if !ok {
			t.Fatalf("clusters[%d] is %T, want *mqlNutanixCluster", i, got[i])
		}
		if cluster.MqlID() != want {
			t.Errorf("clusters[%d] id = %q, want %q", i, cluster.MqlID(), want)
		}
	}
}

func TestImageOwnerAbsentIsNull(t *testing.T) {
	img := &mqlNutanixImage{MqlRuntime: newTestRuntime()}

	got, err := img.owner()
	if err != nil {
		t.Fatalf("owner returned error: %v", err)
	}
	if got != nil {
		t.Errorf("owner = %v, want nil", got)
	}
	assertNullState(t, "image.owner", img.Owner.State)
}

func TestImageOwnerResolvesFromCache(t *testing.T) {
	runtime := newTestRuntime()
	seedResource(t, runtime, "nutanix.iam.user", "owner-1")

	img := &mqlNutanixImage{MqlRuntime: runtime}
	img.cacheOwnerId = "owner-1"

	got, err := img.owner()
	if err != nil {
		t.Fatalf("owner returned error: %v", err)
	}
	if got == nil || got.MqlID() != "owner-1" {
		t.Fatalf("owner = %v, want the cached user owner-1", got)
	}
}

// ---------------------------------------------------------------------------
// nutanix.network.vpc
// ---------------------------------------------------------------------------

func TestNewMqlVpcCachesExternalSubnets(t *testing.T) {
	runtime := newTestRuntime()

	vpc, err := newMqlVpc(runtime, &netconfig.Vpc{
		ExtId: new("vpc-1"),
		Name:  new("prod"),
		ExternalSubnets: []netconfig.ExternalSubnet{
			{SubnetReference: new("subnet-a")},
			// A reference the API left out or blanked is not a subnet.
			{SubnetReference: nil},
			{SubnetReference: new("")},
			{SubnetReference: new("subnet-b")},
		},
	})
	if err != nil {
		t.Fatalf("newMqlVpc returned error: %v", err)
	}
	if got, want := len(vpc.cacheExternalSubnetIds), 2; got != want {
		t.Fatalf("cacheExternalSubnetIds = %v, want %d entries", vpc.cacheExternalSubnetIds, want)
	}
	if vpc.cacheExternalSubnetIds[0] != "subnet-a" || vpc.cacheExternalSubnetIds[1] != "subnet-b" {
		t.Errorf("cacheExternalSubnetIds = %v, want [subnet-a subnet-b]", vpc.cacheExternalSubnetIds)
	}
}

func TestVpcExternalSubnetsWithoutAttachments(t *testing.T) {
	vpc := &mqlNutanixNetworkVpc{MqlRuntime: newTestRuntime()}

	got, err := vpc.externalSubnets()
	if err != nil {
		t.Fatalf("externalSubnets returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("externalSubnets = %v, want empty", got)
	}
}

func TestVpcExternalSubnetsResolveFromCache(t *testing.T) {
	runtime := newTestRuntime()
	seedResource(t, runtime, "nutanix.network.subnet", "subnet-a")

	vpc := &mqlNutanixNetworkVpc{MqlRuntime: runtime}
	vpc.cacheExternalSubnetIds = []string{"subnet-a"}

	got, err := vpc.externalSubnets()
	if err != nil {
		t.Fatalf("externalSubnets returned error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("externalSubnets len = %d, want 1", len(got))
	}
	subnet, ok := got[0].(*mqlNutanixNetworkSubnet)
	if !ok {
		t.Fatalf("externalSubnets[0] is %T, want *mqlNutanixNetworkSubnet", got[0])
	}
	if subnet.MqlID() != "subnet-a" {
		t.Errorf("externalSubnets[0] id = %q, want subnet-a", subnet.MqlID())
	}
}

// ---------------------------------------------------------------------------
// nutanix.storage.container
// ---------------------------------------------------------------------------

func TestNewMqlStorageContainerCachesAffinityHost(t *testing.T) {
	runtime := newTestRuntime()

	container, err := newMqlStorageContainer(runtime, &clustermgmtconfig.StorageContainer{
		ExtId:             new("container-1"),
		Name:              new("rf1"),
		ClusterExtId:      new("cluster-a"),
		AffinityHostExtId: new("host-1"),
	})
	if err != nil {
		t.Fatalf("newMqlStorageContainer returned error: %v", err)
	}
	if container.cacheAffinityHostId != "host-1" {
		t.Errorf("cacheAffinityHostId = %q, want host-1", container.cacheAffinityHostId)
	}
	if container.cacheClusterId != "cluster-a" {
		t.Errorf("cacheClusterId = %q, want cluster-a", container.cacheClusterId)
	}
}

// A container with a replication factor above 1 carries no affinity host; the
// absent pointer must not turn into a lookup for the empty id.
func TestNewMqlStorageContainerAbsentAffinityHost(t *testing.T) {
	runtime := newTestRuntime()

	container, err := newMqlStorageContainer(runtime, &clustermgmtconfig.StorageContainer{
		ExtId:        new("container-2"),
		Name:         new("rf2"),
		ClusterExtId: new("cluster-a"),
	})
	if err != nil {
		t.Fatalf("newMqlStorageContainer returned error: %v", err)
	}
	if container.cacheAffinityHostId != "" {
		t.Errorf("cacheAffinityHostId = %q, want empty", container.cacheAffinityHostId)
	}

	got, err := container.affinityHost()
	if err != nil {
		t.Fatalf("affinityHost returned error: %v", err)
	}
	if got != nil {
		t.Errorf("affinityHost = %v, want nil", got)
	}
	assertNullState(t, "storage.container.affinityHost", container.AffinityHost.State)
}

// The host lookup needs both halves of the key. A container whose cluster is
// unknown cannot be resolved, and must report null rather than call the API
// with an empty cluster id.
func TestStorageContainerAffinityHostWithoutCluster(t *testing.T) {
	container := &mqlNutanixStorageContainer{MqlRuntime: newTestRuntime()}
	container.cacheAffinityHostId = "host-1"

	got, err := container.affinityHost()
	if err != nil {
		t.Fatalf("affinityHost returned error: %v", err)
	}
	if got != nil {
		t.Errorf("affinityHost = %v, want nil", got)
	}
	assertNullState(t, "storage.container.affinityHost", container.AffinityHost.State)
}

func TestStorageContainerAffinityHostResolvesFromCache(t *testing.T) {
	runtime := newTestRuntime()
	seedResource(t, runtime, "nutanix.host", "host-1")

	container := &mqlNutanixStorageContainer{MqlRuntime: runtime}
	container.cacheClusterId = "cluster-a"
	container.cacheAffinityHostId = "host-1"

	got, err := container.affinityHost()
	if err != nil {
		t.Fatalf("affinityHost returned error: %v", err)
	}
	if got == nil || got.MqlID() != "host-1" {
		t.Fatalf("affinityHost = %v, want the cached host host-1", got)
	}
}

// ---------------------------------------------------------------------------
// hostByID
// ---------------------------------------------------------------------------

// hostByID takes (clusterID, hostID) because GetHostById needs both, but the
// runtime cache is keyed on the host id alone. Seeding an entry under the
// cluster id as well pins the argument order: swapping the two would return
// the wrong host instead of failing loudly.
func TestHostByIDCacheKeyIsTheHostID(t *testing.T) {
	runtime := newTestRuntime()
	seedResource(t, runtime, "nutanix.host", "host-1")
	seedResource(t, runtime, "nutanix.host", "cluster-a")

	got, err := hostByID(runtime, "cluster-a", "host-1")
	if err != nil {
		t.Fatalf("hostByID returned error: %v", err)
	}
	if got == nil {
		t.Fatal("hostByID = nil, want the cached host host-1")
	}
	if got.MqlID() != "host-1" {
		t.Errorf("hostByID resolved %q, want host-1 (cluster and host ids are swapped)", got.MqlID())
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// seedResource puts a resource of the given kind into the runtime cache under
// the id, standing in for one built earlier in the scan.
func seedResource(t *testing.T, runtime *plugin.Runtime, name, id string) {
	t.Helper()
	_, err := CreateResource(runtime, name, map[string]*llx.RawData{
		"__id": llx.StringData(id),
		"id":   llx.StringData(id),
	})
	if err != nil {
		t.Fatalf("seeding %s %q: %v", name, id, err)
	}
}

func assertNullState(t *testing.T, field string, state plugin.State) {
	t.Helper()
	if state&plugin.StateIsSet == 0 {
		t.Errorf("%s: StateIsSet not set; the runtime would re-fetch the field", field)
	}
	if state&plugin.StateIsNull == 0 {
		t.Errorf("%s: StateIsNull not set; a nil result would read as unset", field)
	}
}
