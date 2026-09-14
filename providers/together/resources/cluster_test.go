// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/together/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// kubeConfigMarker stands in for the credential the cluster list response
// carries inline in kube_config. No field of the schema may contain it.
const kubeConfigMarker = "KUBECONFIG-CREDENTIAL-MUST-NOT-LEAK"

// clustersFixture is shaped like the documented GET compute/clusters response.
// Every value is invented and the addresses come from the documentation range
// 203.0.113.0/24; only the field names have to match the API.
//
// worker-1 carries a public address and reports both optional node flags.
// worker-2 carries neither an address nor the flags, which is the absent case.
// control-1 is a control plane node, which reports one network rather than a
// list and reports none of the GPU worker fields at all.
const clustersFixture = `{
  "clusters": [
    {
      "cluster_id": "cluster-0000000000000000",
      "cluster_name": "example-cluster",
      "cluster_type": "KUBERNETES",
      "gpu_type": "H100_SXM",
      "num_gpus": 16,
      "region": "us-example-1",
      "status": "Ready",
      "billing_type": "RESERVED",
      "project_id": "proj-2222222222222222",
      "cuda_version": "12.4",
      "nvidia_driver_version": "550.54.15",
      "num_cpu_workers": 2,
      "install_traefik": false,
      "kube_config": "apiVersion: v1\nusers:\n- name: example\n  user:\n    token: ` + kubeConfigMarker + `\n",
      "cluster_config": {
        "load_balancer": "TRAEFIK",
        "jumphost_enabled": true,
        "kubernetes_dashboard_enabled": true,
        "ssh_ca_enabled": false,
        "ingress": {"enabled": true}
      },
      "oidc_config": {
        "issuer_url": "https://idp.example.invalid",
        "client_id": "client-4444444444444444",
        "group_claim": "groups",
        "group_prefix": "oidc:",
        "username_claim": "email",
        "username_prefix": "sso:"
      },
      "gpu_worker_nodes": [
        {
          "node_id": "node-aaaaaaaa",
          "host_name": "worker-1",
          "status": "Ready",
          "public_ipv4": "203.0.113.10",
          "networks": ["cluster-net", "storage-net"],
          "memory_gib": 2048,
          "num_cpu_cores": 112,
          "num_gpus": 8,
          "instance_id": "instance-aaaaaaaa",
          "auto_remediation_enabled": true,
          "marked_for_deletion": false
        },
        {
          "node_id": "node-bbbbbbbb",
          "host_name": "worker-2",
          "status": "Ready",
          "networks": ["cluster-net"],
          "memory_gib": 2048,
          "num_cpu_cores": 112,
          "num_gpus": 8
        }
      ],
      "control_plane_nodes": [
        {
          "node_id": "node-cccccccc",
          "host_name": "control-1",
          "status": "Ready",
          "network": "cluster-net",
          "memory_gib": 64,
          "num_cpu_cores": 16,
          "public_ipv4": "203.0.113.20"
        }
      ]
    }
  ]
}`

// bareClusterFixture is a cluster the API reports without a configuration block
// and without an OIDC block, which is what a cluster that predates those
// settings looks like.
const bareClusterFixture = `{
  "clusters": [
    {
      "cluster_id": "cluster-1111111111111111",
      "cluster_name": "bare-cluster",
      "cluster_type": "SLURM",
      "gpu_type": "H100_SXM",
      "num_gpus": 8,
      "region": "us-example-1",
      "status": "Ready",
      "billing_type": "ON_DEMAND",
      "gpu_worker_nodes": [],
      "control_plane_nodes": []
    }
  ]
}`

func newClusterTogether(t *testing.T, fixture string) *mqlTogether {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/compute/clusters") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture))
	}))
	t.Cleanup(srv.Close)

	conn, err := connection.NewTogetherConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			connection.OptionToken:   "not-a-real-key",
			connection.OptionBaseURL: srv.URL,
		},
	})
	require.NoError(t, err)

	return &mqlTogether{MqlRuntime: &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}}
}

func oneCluster(t *testing.T, fixture string) *mqlTogetherCluster {
	t.Helper()

	r := newClusterTogether(t, fixture)
	clusters, err := r.clusters()
	require.NoError(t, err)
	require.Len(t, clusters, 1)

	cluster, ok := clusters[0].(*mqlTogetherCluster)
	require.True(t, ok)
	return cluster
}

func clusterNodes(t *testing.T, cluster *mqlTogetherCluster) map[string]*mqlTogetherClusterNode {
	t.Helper()

	byHostname := map[string]*mqlTogetherClusterNode{}
	for _, raw := range cluster.Nodes.Data {
		node, ok := raw.(*mqlTogetherClusterNode)
		require.True(t, ok)
		byHostname[node.Hostname.Data] = node
	}
	return byHostname
}

func assertNull[T any](t *testing.T, tv plugin.TValue[T], field string) {
	t.Helper()
	assert.NotZero(t, tv.State&plugin.StateIsNull, "%s should be null, got %v", field, tv.Data)
}

func assertNotNull[T any](t *testing.T, tv plugin.TValue[T], field string) {
	t.Helper()
	assert.Zero(t, tv.State&plugin.StateIsNull, "%s should carry a value, got null", field)
}

// The exposure controls come out of cluster_config. Reading the wrong SDK field
// (install_traefik sits right next to it and is false in the fixture while the
// load balancer is TRAEFIK) or mistyping a mapping gives a confident wrong
// answer, which is why each one is asserted by value.
func TestClusterExposureControlsComeFromTheClusterConfig(t *testing.T) {
	cluster := oneCluster(t, clustersFixture)

	assert.True(t, cluster.KubernetesDashboardEnabled.Data, "kubernetesDashboardEnabled")
	assert.True(t, cluster.JumphostEnabled.Data, "jumphostEnabled")
	assert.False(t, cluster.SshCaEnabled.Data, "sshCaEnabled")
	assert.Equal(t, "TRAEFIK", cluster.LoadBalancer.Data)
	assert.True(t, cluster.IngressEnabled.Data, "ingressEnabled")

	// A reported false is a measured fact and must not read as null.
	assertNotNull(t, cluster.SshCaEnabled, "sshCaEnabled")
}

func TestClusterOidcClaimsComeFromTheOidcConfig(t *testing.T) {
	cluster := oneCluster(t, clustersFixture)

	assert.Equal(t, "groups", cluster.OidcGroupClaim.Data)
	assert.Equal(t, "oidc:", cluster.OidcGroupPrefix.Data)
	assert.Equal(t, "email", cluster.OidcUsernameClaim.Data)
	// The two prefixes differ in the fixture so that a crossed pair fails.
	assert.Equal(t, "sso:", cluster.OidcUsernamePrefix.Data)
}

// A cluster the API reports without a configuration block has not told us
// whether its dashboard is up. Null says that; false would claim a measurement
// nobody made, and an equality check would pass on it.
func TestClusterExposureControlsAreNullWhenTheApiReportsNothing(t *testing.T) {
	cluster := oneCluster(t, bareClusterFixture)

	assertNull(t, cluster.KubernetesDashboardEnabled, "kubernetesDashboardEnabled")
	assertNull(t, cluster.JumphostEnabled, "jumphostEnabled")
	assertNull(t, cluster.SshCaEnabled, "sshCaEnabled")
	assertNull(t, cluster.LoadBalancer, "loadBalancer")
	assertNull(t, cluster.IngressEnabled, "ingressEnabled")
	assertNull(t, cluster.OidcGroupClaim, "oidcGroupClaim")
	assertNull(t, cluster.OidcUsernameClaim, "oidcUsernameClaim")

	assert.Empty(t, cluster.Nodes.Data, "a cluster with no nodes reports an empty list")
}

func TestClusterNodesCoverBothCollections(t *testing.T) {
	cluster := oneCluster(t, clustersFixture)
	nodes := clusterNodes(t, cluster)

	require.Len(t, nodes, 3)
	require.Contains(t, nodes, "worker-1")
	require.Contains(t, nodes, "worker-2")
	require.Contains(t, nodes, "control-1")

	assert.Equal(t, clusterNodeRoleGPUWorker, nodes["worker-1"].Role.Data)
	assert.Equal(t, clusterNodeRoleControlPlane, nodes["control-1"].Role.Data)

	worker := nodes["worker-1"]
	assert.Equal(t, "node-aaaaaaaa", worker.Id.Data)
	assert.Equal(t, "203.0.113.10", worker.PublicIpv4.Data)
	assert.Equal(t, []any{"cluster-net", "storage-net"}, worker.Networks.Data)
	assert.Equal(t, float64(2048), worker.MemoryGib.Data)
	assert.Equal(t, int64(112), worker.NumCpuCores.Data)
	assert.Equal(t, int64(8), worker.NumGpus.Data)
	assert.Equal(t, "instance-aaaaaaaa", worker.InstanceId.Data)
	assert.True(t, worker.AutoRemediationEnabled.Data)
	assert.False(t, worker.MarkedForDeletion.Data)
	assertNotNull(t, worker.MarkedForDeletion, "markedForDeletion")

	control := nodes["control-1"]
	assert.Equal(t, "203.0.113.20", control.PublicIpv4.Data)
	// A control plane node reports network as a single value; it reaches the
	// same list field as a GPU worker's networks.
	assert.Equal(t, []any{"cluster-net"}, control.Networks.Data)
	assert.Equal(t, float64(64), control.MemoryGib.Data)
}

// A public IPv4 on a GPU worker means the machine answers on the internet. The
// predicate has to move with the address, in both directions.
func TestNodeIsPublicFollowsThePublicAddress(t *testing.T) {
	cluster := oneCluster(t, clustersFixture)
	nodes := clusterNodes(t, cluster)

	for hostname, want := range map[string]bool{
		"worker-1":  true,
		"worker-2":  false,
		"control-1": true,
	} {
		got, err := nodes[hostname].isPublic()
		require.NoError(t, err)
		assert.Equal(t, want, got, "isPublic on %s", hostname)
	}
}

// A GPU worker field the record does not carry must read null. A zero would say
// the node has no GPUs, or that auto remediation was measured and found off.
func TestNodeFieldsTheRecordDoesNotCarryAreNull(t *testing.T) {
	cluster := oneCluster(t, clustersFixture)
	nodes := clusterNodes(t, cluster)

	worker2 := nodes["worker-2"]
	assertNull(t, worker2.InstanceId, "worker instanceId")
	assertNull(t, worker2.AutoRemediationEnabled, "worker autoRemediationEnabled")
	assertNull(t, worker2.MarkedForDeletion, "worker markedForDeletion")

	control := nodes["control-1"]
	assertNull(t, control.NumGpus, "control plane numGpus")
	assertNull(t, control.InstanceId, "control plane instanceId")
	assertNull(t, control.AutoRemediationEnabled, "control plane autoRemediationEnabled")
	assertNull(t, control.MarkedForDeletion, "control plane markedForDeletion")
}

// Two nodes sharing a cache key are reported as one, carrying the first one's
// values, so the key has to separate every dimension a node repeats along.
func TestClusterNodeIDSeparatesClusterRoleAndNode(t *testing.T) {
	worker := clusterNodeRecord{id: "node-1", hostname: "host-1", role: clusterNodeRoleGPUWorker}
	control := clusterNodeRecord{id: "node-1", hostname: "host-1", role: clusterNodeRoleControlPlane}

	ids := map[string]bool{}
	for _, id := range []string{
		clusterNodeID("cluster-a", worker, 0),
		clusterNodeID("cluster-b", worker, 0),
		clusterNodeID("cluster-a", control, 0),
	} {
		assert.False(t, ids[id], "duplicate node key %q", id)
		ids[id] = true
	}

	// A record with no identifier at all still has to stay separate from the
	// next one, so neither disappears into the other's cache entry.
	first := clusterNodeID("cluster-a", clusterNodeRecord{role: clusterNodeRoleGPUWorker}, 0)
	second := clusterNodeID("cluster-a", clusterNodeRecord{role: clusterNodeRoleGPUWorker}, 1)
	assert.NotEqual(t, first, second)

	// The hostname keys a record that reports no node identifier.
	assert.Equal(t, "cluster-a/GPU_WORKER/host-9",
		clusterNodeID("cluster-a", clusterNodeRecord{hostname: "host-9", role: clusterNodeRoleGPUWorker}, 3))
}

// Every node of a cluster reaches the resource cache under its own key, so a
// cluster with several nodes reports several nodes.
func TestEveryNodeGetsItsOwnCacheEntry(t *testing.T) {
	cluster := oneCluster(t, clustersFixture)

	ids := map[string]bool{}
	for _, raw := range cluster.Nodes.Data {
		node := raw.(*mqlTogetherClusterNode)
		assert.False(t, ids[node.MqlID()], "duplicate __id %q", node.MqlID())
		ids[node.MqlID()] = true
	}
	assert.Len(t, ids, 3)
}

// The cluster list response carries a full kubeconfig inline. The schema must
// not carry it anywhere, so every declared field of the cluster and of its
// nodes is read back and searched. A dict or passthrough field added over the
// cluster object later fails here without anyone having to remember this.
func TestKubeConfigNeverReachesTheSchema(t *testing.T) {
	require.Contains(t, clustersFixture, kubeConfigMarker,
		"the fixture no longer carries a kubeconfig, so this test proves nothing")

	// The response really does hand the credential to the provider: this is
	// what the schema has to keep out, not a hypothetical.
	var resp together.BetaClusterListResponse
	require.NoError(t, json.Unmarshal([]byte(clustersFixture), &resp))
	require.Len(t, resp.Clusters, 1)
	require.Contains(t, resp.Clusters[0].KubeConfig, kubeConfigMarker)

	cluster := oneCluster(t, clustersFixture)

	clusterFields := 0
	for field, get := range getDataFields {
		if !strings.HasPrefix(field, "together.cluster.") || strings.HasPrefix(field, "together.cluster.node.") {
			continue
		}
		clusterFields++
		assert.NotContains(t, dataResText(get(cluster)), kubeConfigMarker, "%s leaked the kubeconfig", field)
	}
	assert.Greater(t, clusterFields, 20, "the cluster fields were not enumerated")

	nodeFields := 0
	for _, raw := range cluster.Nodes.Data {
		node := raw.(*mqlTogetherClusterNode)
		for field, get := range getDataFields {
			if !strings.HasPrefix(field, "together.cluster.node.") {
				continue
			}
			nodeFields++
			assert.NotContains(t, dataResText(get(node)), kubeConfigMarker, "%s leaked the kubeconfig", field)
		}
	}
	assert.Greater(t, nodeFields, 10, "the node fields were not enumerated")
}

// dataResText flattens everything a field hands back, including the members of
// a list and the values of a map, into searchable text.
func dataResText(res *plugin.DataRes) string {
	var sb strings.Builder
	sb.WriteString(res.Error)
	writePrimitiveText(res.Data, &sb)
	return sb.String()
}

func writePrimitiveText(p *llx.Primitive, sb *strings.Builder) {
	if p == nil {
		return
	}
	sb.Write(p.Value)
	sb.WriteByte(' ')
	for _, entry := range p.Array {
		writePrimitiveText(entry, sb)
	}
	for key, entry := range p.Map {
		sb.WriteString(key)
		sb.WriteByte(' ')
		writePrimitiveText(entry, sb)
	}
}
