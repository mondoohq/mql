// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// fakeKubeAPI serves canned Kubernetes Service API answers by path. A route
// answers with its status and body; an unknown path fails the test.
type kubeRoute struct {
	status int
	body   string
	// query, when set, must match the request's query parameters.
	query map[string]string
}

func fakeKubeAPI(t *testing.T, routes map[string]kubeRoute, hits *atomic.Int32) *core.BaseService {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		route, ok := routes[r.URL.Path]
		if !assert.True(t, ok, "unexpected request %s", r.URL.Path) {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		for k, v := range route.query {
			assert.Equal(t, v, r.URL.Query().Get(k), "query parameter %s of %s", k, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(route.status)
		_, _ = w.Write([]byte(route.body))
	}))
	t.Cleanup(srv.Close)
	svc, err := core.NewBaseService(&core.ServiceOptions{URL: srv.URL, Authenticator: &core.NoAuthAuthenticator{}})
	require.NoError(t, err)
	return svc
}

const refused = `{"code":"E3ff6","description":"You do not have the required permissions.","type":"Authentication"}`

func kubeTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

const vpcClusterList = `[{
	"id": "c1vpc", "name": "prod-iks", "region": "us-south", "provider": "vpc-gen2", "type": "kubernetes",
	"state": "normal", "status": "All Workers Normal", "masterKubeVersion": "1.33.4_1532",
	"targetVersion": "1.33.5_1535", "createdDate": "2026-10-07T09:19:08+0000", "resourceGroup": "rg1"
}]`

const classicClusterList = `[
	{"id": "c2classic", "name": "legacy-roks", "region": "eu-de", "provider": "classic", "type": "openshift",
	 "state": "warning", "masterKubeVersion": "4.17.12_1550_openshift", "createdDate": "2025-01-02T03:04:05.123+0000",
	 "resourceGroup": "rg2"},
	{"id": "c1vpc", "name": "prod-iks", "region": "us-south", "provider": "vpc-gen2", "type": "kubernetes"}
]`

func TestFetchKubeClustersVpcAndClassic(t *testing.T) {
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/vpc/getClusters":     {status: 200, body: vpcClusterList},
		"/v2/classic/getClusters": {status: 200, body: classicClusterList},
	}, nil)

	clusters, err := fetchKubeClusters(svc, nil)
	require.NoError(t, err)
	require.Len(t, clusters, 2, "a cluster both listings return is kept once")
	assert.Equal(t, "c1vpc", clusters[0].ID)
	assert.Equal(t, "c2classic", clusters[1].ID)

	vpc := kubeClusterArgs(clusters[0])
	assert.Equal(t, "ibm.kubernetes.cluster/c1vpc", vpc["__id"].Value)
	assert.Equal(t, "prod-iks", vpc["name"].Value)
	assert.Equal(t, "us-south", vpc["region"].Value)
	assert.Equal(t, "vpc-gen2", vpc["provider"].Value)
	assert.Equal(t, "kubernetes", vpc["type"].Value)
	assert.Equal(t, "normal", vpc["state"].Value)
	assert.Equal(t, "All Workers Normal", vpc["status"].Value)
	assert.Equal(t, "1.33.4_1532", vpc["masterKubeVersion"].Value)
	assert.Equal(t, "1.33.5_1535", vpc["targetKubeVersion"].Value)
	assert.Equal(t, time.Date(2026, 10, 7, 9, 19, 8, 0, time.UTC), vpc["createdAt"].Value.(*time.Time).UTC())

	classic := kubeClusterArgs(clusters[1])
	assert.Equal(t, "classic", classic["provider"].Value)
	assert.Equal(t, "openshift", classic["type"].Value)
	assert.Equal(t, "", classic["targetKubeVersion"].Value, "a current master has no target")
	assert.NotNil(t, classic["createdAt"].Value)

	m, err := newKubeCluster(kubeTestRuntime(), clusters[1])
	require.NoError(t, err)
	assert.Equal(t, "rg2", m.cacheResourceGroupID)
}

func TestFetchKubeClustersRegionFilter(t *testing.T) {
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/vpc/getClusters":     {status: 200, body: vpcClusterList},
		"/v2/classic/getClusters": {status: 200, body: classicClusterList},
	}, nil)
	clusters, err := fetchKubeClusters(svc, []string{"eu-de"})
	require.NoError(t, err)
	require.Len(t, clusters, 1)
	assert.Equal(t, "c2classic", clusters[0].ID)
}

func TestFetchKubeClustersEmpty(t *testing.T) {
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/vpc/getClusters":     {status: 200, body: `[]`},
		"/v2/classic/getClusters": {status: 200, body: `null`},
	}, nil)
	clusters, err := fetchKubeClusters(svc, nil)
	require.NoError(t, err)
	assert.NotNil(t, clusters)
	assert.Empty(t, clusters)
}

func TestFetchKubeClustersRefusals(t *testing.T) {
	// One listing refuses: the other's clusters survive.
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/vpc/getClusters":     {status: 200, body: vpcClusterList},
		"/v2/classic/getClusters": {status: 403, body: refused},
	}, nil)
	clusters, err := fetchKubeClusters(svc, nil)
	require.NoError(t, err)
	require.Len(t, clusters, 1)
	assert.Equal(t, "c1vpc", clusters[0].ID)

	// Both refuse: the refusal is the answer, not an empty list.
	svc = fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/vpc/getClusters":     {status: 403, body: refused},
		"/v2/classic/getClusters": {status: 403, body: refused},
	}, nil)
	_, err = fetchKubeClusters(svc, nil)
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	var e *llx.Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, []string{kubernetesPermission}, e.Permissions)

	// Any other failure fails the list.
	svc = fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/vpc/getClusters":     {status: 200, body: vpcClusterList},
		"/v2/classic/getClusters": {status: 503, body: `{"code":"down"}`},
	}, nil)
	_, err = fetchKubeClusters(svc, nil)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
}

// testCluster creates a cluster resource whose API calls go to svc.
func testCluster(t *testing.T, svc *core.BaseService, id string) *mqlIbmKubernetesCluster {
	t.Helper()
	m, err := newKubeCluster(kubeTestRuntime(), kubeCluster{ID: id, Name: "c", ResourceGroup: "rg1"})
	require.NoError(t, err)
	m.svc = svc
	return m
}

const hardenedClusterDetail = `{
	"id": "c1vpc", "name": "prod-iks", "provider": "vpc-gen2", "type": "kubernetes",
	"crn": "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acc:c1vpc::",
	"serviceEndpoints": {
		"privateServiceEndpointEnabled": true,
		"privateServiceEndpointURL": "https://c111.private.us-south.containers.cloud.ibm.com:30001",
		"publicServiceEndpointEnabled": false,
		"publicServiceEndpointURL": ""
	},
	"features": {"keyProtectEnabled": true, "pullSecretApplied": true},
	"keyManagementService": {
		"actualInstance": ["crn:v1:bluemix:public:kms:us-south:a/acc:kp-guid-1::"],
		"actualRootKey": ["root-key-1"],
		"desiredInstance": "crn:v1:bluemix:public:kms:us-south:a/acc:kp-guid-1::",
		"desiredRootKey": "root-key-1"
	}
}`

func TestKubeClusterDetailFields(t *testing.T) {
	var hits atomic.Int32
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/getCluster": {status: 200, body: hardenedClusterDetail, query: map[string]string{"cluster": "c1vpc"}},
	}, &hits)
	r := testCluster(t, svc, "c1vpc")

	crn, err := r.crn()
	require.NoError(t, err)
	assert.Equal(t, "crn:v1:bluemix:public:containers-kubernetes:us-south:a/acc:c1vpc::", crn)

	b, err := r.publicServiceEndpointEnabled()
	require.NoError(t, err)
	assert.False(t, b)
	b, err = r.privateServiceEndpointEnabled()
	require.NoError(t, err)
	assert.True(t, b)
	s, err := r.publicServiceEndpointUrl()
	require.NoError(t, err)
	assert.Equal(t, "", s)
	s, err = r.privateServiceEndpointUrl()
	require.NoError(t, err)
	assert.Equal(t, "https://c111.private.us-south.containers.cloud.ibm.com:30001", s)

	b, err = r.kmsEnabled()
	require.NoError(t, err)
	assert.True(t, b)
	s, err = r.kmsInstanceId()
	require.NoError(t, err)
	assert.Equal(t, "crn:v1:bluemix:public:kms:us-south:a/acc:kp-guid-1::", s)
	s, err = r.kmsRootKeyId()
	require.NoError(t, err)
	assert.Equal(t, "root-key-1", s)

	b, err = r.imagePullSecretsEnabled()
	require.NoError(t, err)
	assert.True(t, b)

	assert.Equal(t, int32(1), hits.Load(), "the detail view is read once for every field")
}

func TestKubeClusterDetailDefaults(t *testing.T) {
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/getCluster": {status: 200, body: `{
			"id": "c2", "crn": "crn:c2",
			"serviceEndpoints": {"publicServiceEndpointEnabled": true, "publicServiceEndpointURL": "https://c2.us-south.containers.cloud.ibm.com:30002",
				"privateServiceEndpointEnabled": false},
			"features": {"keyProtectEnabled": false, "pullSecretApplied": false},
			"keyManagementService": {}
		}`},
	}, nil)
	r := testCluster(t, svc, "c2")

	b, err := r.publicServiceEndpointEnabled()
	require.NoError(t, err)
	assert.True(t, b)
	s, err := r.publicServiceEndpointUrl()
	require.NoError(t, err)
	assert.Equal(t, "https://c2.us-south.containers.cloud.ibm.com:30002", s)
	b, err = r.privateServiceEndpointEnabled()
	require.NoError(t, err)
	assert.False(t, b)

	b, err = r.kmsEnabled()
	require.NoError(t, err)
	assert.False(t, b)
	s, err = r.kmsInstanceId()
	require.NoError(t, err)
	assert.Equal(t, "", s)

	// Without a KMS provider, the typed references are null and need no lookup.
	inst, err := r.kmsInstance()
	require.NoError(t, err)
	assert.Nil(t, inst)
	assert.True(t, r.KmsInstance.IsNull())
	key, err := r.kmsKey()
	require.NoError(t, err)
	assert.Nil(t, key)
	assert.True(t, r.KmsKey.IsNull())

	b, err = r.imagePullSecretsEnabled()
	require.NoError(t, err)
	assert.False(t, b)
}

func TestKubeClusterDetailWithoutBlocks(t *testing.T) {
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/getCluster": {status: 200, body: `{"id": "c3"}`},
	}, nil)
	r := testCluster(t, svc, "c3")
	b, err := r.publicServiceEndpointEnabled()
	require.NoError(t, err)
	assert.False(t, b, "a cluster without service endpoint data reports none enabled")
	b, err = r.kmsEnabled()
	require.NoError(t, err)
	assert.False(t, b)
	b, err = r.imagePullSecretsEnabled()
	require.NoError(t, err)
	assert.False(t, b)
}

func TestKubeClusterDetailRefused(t *testing.T) {
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/getCluster": {status: 403, body: refused},
		"/v2/getWorkers": {status: 403, body: refused},
	}, nil)
	r := testCluster(t, svc, "c1")

	// A refusal is an error on the field, not a false that reads as compliant.
	_, err := r.publicServiceEndpointEnabled()
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	_, err = r.kmsEnabled()
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	_, err = r.imagePullSecretsEnabled()
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	_, err = r.workers()
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
}

func TestClusterKMS(t *testing.T) {
	d := &kubeCluster{}
	inst, key := clusterKMS(d)
	assert.Equal(t, "", inst)
	assert.Equal(t, "", key)
	assert.False(t, clusterKMSEnabled(d))

	// Requested but not yet applied: the reference is known, encryption is not on.
	d.KeyManagementService = &struct {
		ActualInstance  []string `json:"actualInstance"`
		ActualRootKey   []string `json:"actualRootKey"`
		DesiredInstance string   `json:"desiredInstance"`
		DesiredRootKey  string   `json:"desiredRootKey"`
	}{DesiredInstance: "kp-guid-2", DesiredRootKey: "root-2"}
	inst, key = clusterKMS(d)
	assert.Equal(t, "kp-guid-2", inst)
	assert.Equal(t, "root-2", key)
	assert.False(t, clusterKMSEnabled(d))

	// The key in effect wins over the requested one.
	d.KeyManagementService.ActualInstance = []string{"kp-guid-1"}
	d.KeyManagementService.ActualRootKey = []string{"root-1"}
	inst, key = clusterKMS(d)
	assert.Equal(t, "kp-guid-1", inst)
	assert.Equal(t, "root-1", key)
	assert.True(t, clusterKMSEnabled(d), "a root key in effect means the secrets are encrypted")
}

func TestKmsInstanceGUID(t *testing.T) {
	assert.Equal(t, "kp-guid-1", kmsInstanceGUID("crn:v1:bluemix:public:kms:us-south:a/acc:kp-guid-1::"))
	assert.Equal(t, "kp-guid-1", kmsInstanceGUID("kp-guid-1"))
	assert.Equal(t, "", kmsInstanceGUID(""))
}

func TestKubeClusterWorkers(t *testing.T) {
	svc := fakeKubeAPI(t, map[string]kubeRoute{
		"/v2/getWorkers": {status: 200, query: map[string]string{"cluster": "c1vpc"}, body: `[
			{"id": "kube-c1vpc-default-0001", "flavor": "bx2.4x16", "location": "us-south-1",
			 "poolID": "c1vpc-pool1", "poolName": "default", "provider": "vpc-gen2",
			 "health": {"state": "normal", "message": "Ready"},
			 "lifecycle": {"actualState": "deployed", "actualOperatingSystem": "UBUNTU_24_64"},
			 "kubeVersion": {"actual": "1.33.4_1534", "desired": "1.33.4_1534", "target": "1.33.5_1540"}},
			{"id": "kube-c1vpc-default-0002", "flavor": "bx2.4x16", "location": "us-south-2",
			 "poolID": "c1vpc-pool1", "poolName": "default",
			 "health": {"state": "normal", "message": "Ready"},
			 "lifecycle": {"actualState": "deployed", "actualOperatingSystem": "UBUNTU_24_64"},
			 "kubeVersion": {"actual": "1.33.5_1540", "target": "1.33.5_1540"}}
		]`},
	}, nil)
	r := testCluster(t, svc, "c1vpc")

	list, err := r.workers()
	require.NoError(t, err)
	require.Len(t, list, 2)

	w := list[0].(*mqlIbmKubernetesWorker)
	assert.Equal(t, "kube-c1vpc-default-0001", w.Id.Data)
	assert.Equal(t, "normal", w.State.Data)
	assert.Equal(t, "Ready", w.Status.Data)
	assert.Equal(t, "deployed", w.LifecycleState.Data)
	assert.Equal(t, "bx2.4x16", w.Flavor.Data)
	assert.Equal(t, "us-south-1", w.Zone.Data)
	assert.Equal(t, "default", w.PoolName.Data)
	assert.Equal(t, "c1vpc-pool1", w.PoolId.Data)
	assert.Equal(t, "UBUNTU_24_64", w.OperatingSystem.Data)
	assert.Equal(t, "1.33.4_1534", w.KubeVersion.Data)
	assert.Equal(t, "1.33.5_1540", w.TargetKubeVersion.Data)
	assert.True(t, w.UpdateAvailable.Data, "a worker behind its target has an update available")
	c, err := w.cluster()
	require.NoError(t, err)
	assert.Same(t, r, c)

	current := list[1].(*mqlIbmKubernetesWorker)
	assert.False(t, current.UpdateAvailable.Data)
	assert.Equal(t, "us-south-2", current.Zone.Data)
}

func TestKubeWorkerArgsBare(t *testing.T) {
	args := kubeWorkerArgs("c1", kubeWorker{ID: "w1"})
	assert.Equal(t, "ibm.kubernetes.worker/c1/w1", args["__id"].Value)
	assert.Equal(t, "", args["state"].Value)
	assert.Equal(t, "", args["kubeVersion"].Value)
	assert.Equal(t, false, args["updateAvailable"].Value, "a worker without version data has no known update")
}

func TestWorkerUpdateAvailable(t *testing.T) {
	assert.True(t, workerUpdateAvailable("1.32.9_1570", "1.33.5_1540"))
	assert.False(t, workerUpdateAvailable("1.33.5_1540", "1.33.5_1540"))
	assert.False(t, workerUpdateAvailable("1.33.5_1540", ""), "no target, no known update")
	assert.False(t, workerUpdateAvailable("", "1.33.5_1540"))
}

func TestKubeTimeData(t *testing.T) {
	assert.Nil(t, kubeTimeData("").Value)
	assert.Nil(t, kubeTimeData("garbage").Value)
	for _, s := range []string{"2026-10-07T09:19:08+0000", "2026-10-07T09:19:08.000+0000", "2026-10-07T09:19:08Z", "2026-10-07T11:19:08+02:00"} {
		v, ok := kubeTimeData(s).Value.(*time.Time)
		require.True(t, ok, s)
		assert.Equal(t, time.Date(2026, 10, 7, 9, 19, 8, 0, time.UTC), v.UTC(), s)
	}
}
