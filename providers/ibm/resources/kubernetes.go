// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ibm/connection"
)

// kubernetesPermission is the IAM action every cluster and worker read needs.
const kubernetesPermission = "containers-kubernetes.cluster.read"

// kubeClusterLists are the cluster listings of the Kubernetes Service API, one
// per infrastructure. Each lists the clusters of every region, Kubernetes and
// OpenShift alike.
var kubeClusterLists = []struct{ name, path string }{
	{"vpc", "/v2/vpc/getClusters"},
	{"classic", "/v2/classic/getClusters"},
}

// kubeCluster is a cluster as the Kubernetes Service API returns it, in the
// list and in the detail view. Only the detail view carries the CRN.
type kubeCluster struct {
	ID                string `json:"id"`
	CRN               string `json:"crn"`
	Name              string `json:"name"`
	Region            string `json:"region"`
	Provider          string `json:"provider"`
	Type              string `json:"type"`
	State             string `json:"state"`
	Status            string `json:"status"`
	MasterKubeVersion string `json:"masterKubeVersion"`
	TargetVersion     string `json:"targetVersion"`
	CreatedDate       string `json:"createdDate"`
	ResourceGroup     string `json:"resourceGroup"`
	ServiceEndpoints  *struct {
		PrivateServiceEndpointEnabled *bool  `json:"privateServiceEndpointEnabled"`
		PrivateServiceEndpointURL     string `json:"privateServiceEndpointURL"`
		PublicServiceEndpointEnabled  *bool  `json:"publicServiceEndpointEnabled"`
		PublicServiceEndpointURL      string `json:"publicServiceEndpointURL"`
	} `json:"serviceEndpoints"`
	Features *struct {
		KeyProtectEnabled *bool `json:"keyProtectEnabled"`
		PullSecretApplied *bool `json:"pullSecretApplied"`
	} `json:"features"`
	KeyManagementService *struct {
		ActualInstance  []string `json:"actualInstance"`
		ActualRootKey   []string `json:"actualRootKey"`
		DesiredInstance string   `json:"desiredInstance"`
		DesiredRootKey  string   `json:"desiredRootKey"`
	} `json:"keyManagementService"`
}

// kubeWorker is a worker node as the Kubernetes Service API returns it, the
// same for VPC and classic clusters.
type kubeWorker struct {
	ID          string `json:"id"`
	Flavor      string `json:"flavor"`
	Location    string `json:"location"`
	PoolID      string `json:"poolID"`
	PoolName    string `json:"poolName"`
	KubeVersion *struct {
		Actual string `json:"actual"`
		Target string `json:"target"`
	} `json:"kubeVersion"`
	Health *struct {
		State   string `json:"state"`
		Message string `json:"message"`
	} `json:"health"`
	Lifecycle *struct {
		ActualState           string `json:"actualState"`
		ActualOperatingSystem string `json:"actualOperatingSystem"`
	} `json:"lifecycle"`
}

// kubeGet reads a Kubernetes Service API path with query parameters into out
// through the connection's client, so it shares its authentication, retries,
// and timeout.
func kubeGet(svc *core.BaseService, path string, query map[string]string, out any) error {
	b := core.NewRequestBuilder(core.GET)
	if _, err := b.ResolveRequestURL(svc.Options.URL, path, nil); err != nil {
		return err
	}
	b.AddHeader("Accept", "application/json")
	for k, v := range query {
		b.AddQuery(k, v)
	}
	req, err := b.Build()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	res, err := svc.Request(req, &raw)
	if err != nil {
		// A request made through the SDK core directly keeps the HTTP status
		// out of the error chain; carry it so classifyError sees it.
		if res != nil && res.StatusCode >= 400 {
			return &statusError{err: err, status: res.StatusCode}
		}
		return err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// fetchKubeClusters lists the VPC and classic clusters and keeps those in the
// --regions filter. A listing that refuses is skipped when the other answers,
// like a VPC region; when both refuse, the refusal is the answer.
func fetchKubeClusters(svc *core.BaseService, regions []string) ([]kubeCluster, error) {
	names := make([]string, len(kubeClusterLists))
	results := make([][]kubeCluster, len(kubeClusterLists))
	errs := make([]error, len(kubeClusterLists))
	for i, l := range kubeClusterLists {
		names[i] = l.name
		var list []kubeCluster
		errs[i] = classifyError(kubeGet(svc, l.path, nil, &list), kubernetesPermission)
		results[i] = list
	}
	merged, err := mergeRegionResults(names, results, errs, kubernetesPermission)
	if err != nil {
		return nil, err
	}
	out := []kubeCluster{}
	seen := map[string]bool{}
	for _, m := range merged {
		c := m.item
		if c.ID == "" || seen[c.ID] {
			continue
		}
		if len(regions) > 0 && !slices.Contains(regions, c.Region) {
			continue
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	return out, nil
}

// fetchKubeCluster reads a cluster's detail view, which the list lacks: its
// CRN, service endpoints, features, and KMS configuration.
func fetchKubeCluster(svc *core.BaseService, id string) (*kubeCluster, error) {
	var c kubeCluster
	if err := kubeGet(svc, "/v2/getCluster", map[string]string{"cluster": id}, &c); err != nil {
		return nil, classifyError(err, kubernetesPermission)
	}
	return &c, nil
}

// fetchKubeWorkers lists a cluster's workers; the combined endpoint answers
// for VPC and classic clusters.
func fetchKubeWorkers(svc *core.BaseService, clusterID string) ([]kubeWorker, error) {
	var list []kubeWorker
	if err := kubeGet(svc, "/v2/getWorkers", map[string]string{"cluster": clusterID}, &list); err != nil {
		return nil, classifyError(err, kubernetesPermission)
	}
	return list, nil
}

// kubeTimeData parses a Kubernetes Service timestamp. The API writes the zone
// offset without a colon (2026-10-07T09:19:08+0000), which RFC 3339 does not
// accept. An empty or unparseable one is null.
func kubeTimeData(s string) *llx.RawData {
	if s == "" {
		return llx.NilData
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return llx.TimeData(t)
		}
	}
	return llx.NilData
}

// ---- clusters ----

type mqlIbmKubernetesClusterInternal struct {
	cacheResourceGroupID string
	// svc overrides the connection's client; tests point it at a fake API.
	svc         *core.BaseService
	detailOnce  sync.Once
	cacheDetail *kubeCluster
	detailErr   error
}

func kubeClusterArgs(c kubeCluster) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":              llx.StringData("ibm.kubernetes.cluster/" + c.ID),
		"id":                llx.StringData(c.ID),
		"name":              llx.StringData(c.Name),
		"region":            llx.StringData(c.Region),
		"provider":          llx.StringData(c.Provider),
		"type":              llx.StringData(c.Type),
		"state":             llx.StringData(c.State),
		"status":            llx.StringData(c.Status),
		"masterKubeVersion": llx.StringData(c.MasterKubeVersion),
		"targetKubeVersion": llx.StringData(c.TargetVersion),
		"createdAt":         kubeTimeData(c.CreatedDate),
	}
}

func newKubeCluster(runtime *plugin.Runtime, c kubeCluster) (*mqlIbmKubernetesCluster, error) {
	res, err := CreateResource(runtime, "ibm.kubernetes.cluster", kubeClusterArgs(c))
	if err != nil {
		return nil, err
	}
	m := res.(*mqlIbmKubernetesCluster)
	m.cacheResourceGroupID = c.ResourceGroup
	return m, nil
}

func (r *mqlIbm) kubernetesClusters() ([]any, error) {
	c := conn(r.MqlRuntime)
	v, err := c.Memo("kubernetes/clusters", func() (any, error) {
		svc, err := c.KubernetesService()
		if err != nil {
			return nil, err
		}
		return fetchKubeClusters(svc, connection.GetRegions(c.Conf))
	})
	if err != nil {
		return nil, err
	}
	clusters := v.([]kubeCluster)
	out := make([]any, 0, len(clusters))
	for _, kc := range clusters {
		m, err := newKubeCluster(r.MqlRuntime, kc)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmKubernetesCluster) service() (*core.BaseService, error) {
	if r.svc != nil {
		return r.svc, nil
	}
	return conn(r.MqlRuntime).KubernetesService()
}

// detail reads the cluster's detail view once.
func (r *mqlIbmKubernetesCluster) detail() (*kubeCluster, error) {
	r.detailOnce.Do(func() {
		svc, err := r.service()
		if err != nil {
			r.detailErr = err
			return
		}
		r.cacheDetail, r.detailErr = fetchKubeCluster(svc, r.Id.Data)
	})
	return r.cacheDetail, r.detailErr
}

func (r *mqlIbmKubernetesCluster) crn() (string, error) {
	d, err := r.detail()
	if err != nil {
		return "", err
	}
	return d.CRN, nil
}

func (r *mqlIbmKubernetesCluster) publicServiceEndpointEnabled() (bool, error) {
	d, err := r.detail()
	if err != nil || d.ServiceEndpoints == nil {
		return false, err
	}
	return isTrue(d.ServiceEndpoints.PublicServiceEndpointEnabled), nil
}

func (r *mqlIbmKubernetesCluster) privateServiceEndpointEnabled() (bool, error) {
	d, err := r.detail()
	if err != nil || d.ServiceEndpoints == nil {
		return false, err
	}
	return isTrue(d.ServiceEndpoints.PrivateServiceEndpointEnabled), nil
}

func (r *mqlIbmKubernetesCluster) publicServiceEndpointUrl() (string, error) {
	d, err := r.detail()
	if err != nil || d.ServiceEndpoints == nil {
		return "", err
	}
	return d.ServiceEndpoints.PublicServiceEndpointURL, nil
}

func (r *mqlIbmKubernetesCluster) privateServiceEndpointUrl() (string, error) {
	d, err := r.detail()
	if err != nil || d.ServiceEndpoints == nil {
		return "", err
	}
	return d.ServiceEndpoints.PrivateServiceEndpointURL, nil
}

// clusterKMS returns the key management instance and root key a cluster's
// secrets are encrypted with. The configuration in effect wins over a
// requested one that has not been applied yet.
func clusterKMS(d *kubeCluster) (instance, rootKey string) {
	k := d.KeyManagementService
	if k == nil {
		return "", ""
	}
	instance, rootKey = k.DesiredInstance, k.DesiredRootKey
	if len(k.ActualInstance) > 0 && k.ActualInstance[0] != "" {
		instance = k.ActualInstance[0]
	}
	if len(k.ActualRootKey) > 0 && k.ActualRootKey[0] != "" {
		rootKey = k.ActualRootKey[0]
	}
	return instance, rootKey
}

// clusterKMSEnabled reports whether a KMS provider encrypts the cluster's
// secrets: the API's feature flag, or a root key in effect.
func clusterKMSEnabled(d *kubeCluster) bool {
	if d.Features != nil && isTrue(d.Features.KeyProtectEnabled) {
		return true
	}
	k := d.KeyManagementService
	return k != nil && len(k.ActualRootKey) > 0 && k.ActualRootKey[0] != ""
}

func (r *mqlIbmKubernetesCluster) kmsEnabled() (bool, error) {
	d, err := r.detail()
	if err != nil {
		return false, err
	}
	return clusterKMSEnabled(d), nil
}

func (r *mqlIbmKubernetesCluster) kmsInstanceId() (string, error) {
	d, err := r.detail()
	if err != nil {
		return "", err
	}
	instance, _ := clusterKMS(d)
	return instance, nil
}

func (r *mqlIbmKubernetesCluster) kmsRootKeyId() (string, error) {
	d, err := r.detail()
	if err != nil {
		return "", err
	}
	_, key := clusterKMS(d)
	return key, nil
}

// kmsInstanceGUID reduces a key management instance reference, a CRN or a
// GUID, to the GUID.
func kmsInstanceGUID(ref string) string {
	if strings.HasPrefix(ref, "crn:") {
		return crnSegment(ref, 7)
	}
	return ref
}

func (r *mqlIbmKubernetesCluster) kmsInstance() (*mqlIbmKmsInstance, error) {
	d, err := r.detail()
	if err != nil {
		return nil, err
	}
	instance, _ := clusterKMS(d)
	guid := kmsInstanceGUID(instance)
	if guid == "" {
		nullResource(&r.KmsInstance)
		return nil, nil
	}
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return resolveOne(&r.KmsInstance, ns.GetKmsInstances(), guid, func(i *mqlIbmKmsInstance) string { return i.Guid.Data })
}

func (r *mqlIbmKubernetesCluster) kmsKey() (*mqlIbmKmsKey, error) {
	d, err := r.detail()
	if err != nil {
		return nil, err
	}
	_, rootKey := clusterKMS(d)
	if rootKey == "" {
		nullResource(&r.KmsKey)
		return nil, nil
	}
	inst := r.GetKmsInstance()
	if inst.Error != nil {
		return nil, inst.Error
	}
	if inst.Data == nil {
		nullResource(&r.KmsKey)
		return nil, nil
	}
	return resolveOne(&r.KmsKey, inst.Data.GetKeys(), rootKey, func(k *mqlIbmKmsKey) string { return k.Id.Data })
}

func (r *mqlIbmKubernetesCluster) imagePullSecretsEnabled() (bool, error) {
	d, err := r.detail()
	if err != nil || d.Features == nil {
		return false, err
	}
	return isTrue(d.Features.PullSecretApplied), nil
}

func (r *mqlIbmKubernetesCluster) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmKubernetesCluster) tags() ([]any, error) {
	crn := r.GetCrn()
	if crn.Error != nil {
		return nil, crn.Error
	}
	return userTags(r.MqlRuntime, crn.Data)
}

func (r *mqlIbmKubernetesCluster) accessTags() ([]any, error) {
	crn := r.GetCrn()
	if crn.Error != nil {
		return nil, crn.Error
	}
	return accessTags(r.MqlRuntime, crn.Data)
}

// ---- workers ----

type mqlIbmKubernetesWorkerInternal struct {
	cacheCluster *mqlIbmKubernetesCluster
}

func kubeWorkerArgs(clusterID string, w kubeWorker) map[string]*llx.RawData {
	var state, status, lifecycle, os, actual, target string
	if w.Health != nil {
		state, status = w.Health.State, w.Health.Message
	}
	if w.Lifecycle != nil {
		lifecycle, os = w.Lifecycle.ActualState, w.Lifecycle.ActualOperatingSystem
	}
	if w.KubeVersion != nil {
		actual, target = w.KubeVersion.Actual, w.KubeVersion.Target
	}
	return map[string]*llx.RawData{
		"__id":              llx.StringData("ibm.kubernetes.worker/" + clusterID + "/" + w.ID),
		"id":                llx.StringData(w.ID),
		"state":             llx.StringData(state),
		"status":            llx.StringData(status),
		"lifecycleState":    llx.StringData(lifecycle),
		"flavor":            llx.StringData(w.Flavor),
		"zone":              llx.StringData(w.Location),
		"poolName":          llx.StringData(w.PoolName),
		"poolId":            llx.StringData(w.PoolID),
		"operatingSystem":   llx.StringData(os),
		"kubeVersion":       llx.StringData(actual),
		"targetKubeVersion": llx.StringData(target),
		"updateAvailable":   llx.BoolData(workerUpdateAvailable(actual, target)),
	}
}

// workerUpdateAvailable reports whether a worker runs a version other than
// the one IBM Cloud would update it to, which `ibmcloud ks workers` marks
// with an asterisk.
func workerUpdateAvailable(actual, target string) bool {
	return actual != "" && target != "" && actual != target
}

func (r *mqlIbmKubernetesCluster) workers() ([]any, error) {
	svc, err := r.service()
	if err != nil {
		return nil, err
	}
	list, err := fetchKubeWorkers(svc, r.Id.Data)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(list))
	for _, w := range list {
		res, err := CreateResource(r.MqlRuntime, "ibm.kubernetes.worker", kubeWorkerArgs(r.Id.Data, w))
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmKubernetesWorker).cacheCluster = r
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlIbmKubernetesWorker) cluster() (*mqlIbmKubernetesCluster, error) {
	if r.cacheCluster == nil {
		nullResource(&r.Cluster)
		return nil, nil
	}
	return r.cacheCluster, nil
}
