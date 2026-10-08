// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	ske "github.com/stackitcloud/stackit-sdk-go/services/ske/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlStackitSke) clusters() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.SKE()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListClusters(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildSkeCluster(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// mqlStackitSkeClusterInternal caches the raw SKE Nodepool slice so the
// computed nodePools() field can build typed sub-resources on access
// without a second API round-trip. It also caches the network and
// observability instance ids so the typed-reference fields can resolve
// them lazily, plus the per-pool end-of-support dates, which the API
// reports on the cluster status rather than on the pool itself.
type mqlStackitSkeClusterInternal struct {
	rawNodepools                 []ske.Nodepool
	cacheNetworkId               string
	cacheObservabilityInstanceId string
	nodepoolExpiration           map[string]ske.ExpirationStatusNodepool
}

// skeAutoUpdate reads the two automatic-patching flags out of the cluster's
// maintenance window, returning nil for either one the API does not report.
//
// A cluster can carry no maintenance window at all, and a window can name one
// flag without the other. Neither case means the update is switched off, so
// both yield nil: a false here would report automatic patching as disabled on
// a cluster whose setting was never read, and an assertion that the flag is
// true would then fail on clusters that may well be patching.
func skeAutoUpdate(cluster *ske.Cluster) (kubernetes *bool, machineImage *bool) {
	if cluster == nil {
		return nil, nil
	}
	maintenance, ok := cluster.GetMaintenanceOk()
	if !ok || maintenance == nil {
		return nil, nil
	}
	return maintenance.AutoUpdate.KubernetesVersion, maintenance.AutoUpdate.MachineImageVersion
}

func buildSkeCluster(runtime *plugin.Runtime, cluster *ske.Cluster) (plugin.Resource, error) {
	var aggregated string
	var creationTime *time.Time
	var credRotPhase, saIssuer string
	var credRotInitiated, credRotCompleted *time.Time
	var k8sExpiration *time.Time
	npExpiration := map[string]ske.ExpirationStatusNodepool{}
	egressRanges := []string{}
	podRanges := []string{}
	statusDict := toDict(cluster.GetStatus())
	if status, ok := cluster.GetStatusOk(); ok {
		if exp, ok := status.GetExpirationOk(); ok && exp != nil {
			if k, ok := exp.GetKubernetesOk(); ok && k != nil {
				k8sExpiration = timeOrNil(k.GetExpirationDateOk())
			}
			for _, np := range exp.GetNodepools() {
				npExpiration[np.GetName()] = np
			}
		}
		aggregated = string(status.GetAggregated())
		if ct, ok := status.GetCreationTimeOk(); ok && !ct.IsZero() {
			creationTime = ct
		}
		if cr, ok := status.GetCredentialsRotationOk(); ok {
			credRotPhase = string(cr.GetPhase())
			if t, ok := cr.GetLastInitiationTimeOk(); ok && !t.IsZero() {
				credRotInitiated = t
			}
			if t, ok := cr.GetLastCompletionTimeOk(); ok && !t.IsZero() {
				credRotCompleted = t
			}
		}
		if r, ok := status.GetEgressAddressRangesOk(); ok {
			egressRanges = r
		}
		if r, ok := status.GetPodAddressRangesOk(); ok {
			podRanges = r
		}
		saIssuer = status.GetServiceAccountIssuer()
	}

	var kVersion string
	if k, ok := cluster.GetKubernetesOk(); ok {
		kVersion = k.GetVersion()
	}

	hibernations := []any{}
	if h, ok := cluster.GetHibernationOk(); ok {
		hibernations = anySliceToDict(h.GetSchedules())
	}

	var aclEnabled, obsEnabled, dnsEnabled, dnsGatewayApi, albEnabled bool
	var obsInstanceId string
	allowedCidrs := []string{}
	dnsZones := []string{}
	if ext, ok := cluster.GetExtensionsOk(); ok {
		if acl, ok := ext.GetAclOk(); ok {
			aclEnabled = acl.GetEnabled()
			if c, ok := acl.GetAllowedCidrsOk(); ok {
				allowedCidrs = c
			}
		}
		if obs, ok := ext.GetObservabilityOk(); ok {
			obsEnabled = obs.GetEnabled()
			obsInstanceId = obs.GetInstanceId()
		}
		if dns, ok := ext.GetDnsOk(); ok {
			dnsEnabled = dns.GetEnabled()
			dnsGatewayApi = dns.GetGatewayApi()
			if z, ok := dns.GetZonesOk(); ok {
				dnsZones = z
			}
		}
		if alb, ok := ext.GetApplicationLoadBalancerOk(); ok {
			albEnabled = alb.GetEnabled()
		}
	}

	var auditEnabled bool
	if audit, ok := cluster.GetAuditOk(); ok {
		auditEnabled = audit.GetEnabled()
	}

	var idpEnabled bool
	var idpType string
	if access, ok := cluster.GetAccessOk(); ok {
		if idp, ok := access.GetIdpOk(); ok {
			idpEnabled = idp.GetEnabled()
			idpType = idp.GetType()
		}
	}

	var networkId, controlPlaneScope string
	if n, ok := cluster.GetNetworkOk(); ok {
		networkId = n.GetId()
		if cp, ok := n.GetControlPlaneOk(); ok && cp != nil {
			controlPlaneScope = string(cp.GetAccessScope())
		}
	}

	autoUpdateKubernetes, autoUpdateMachineImage := skeAutoUpdate(cluster)

	args := map[string]*llx.RawData{
		"name":                             llx.StringData(cluster.GetName()),
		"status":                           llx.StringData(aggregated),
		"statusDetails":                    llx.DictData(statusDict),
		"kubernetesVersion":                llx.StringData(kVersion),
		"hibernations":                     llx.ArrayData(hibernations, types.Dict),
		"maintenance":                      llx.DictData(toDict(cluster.GetMaintenance())),
		"autoUpdateKubernetes":             llx.BoolDataPtr(autoUpdateKubernetes),
		"autoUpdateMachineImage":           llx.BoolDataPtr(autoUpdateMachineImage),
		"extensions":                       llx.DictData(toDict(cluster.GetExtensions())),
		"network":                          llx.DictData(toDict(cluster.GetNetwork())),
		"creationTime":                     llx.TimeDataPtr(creationTime),
		"apiServerAclEnabled":              llx.BoolData(aclEnabled),
		"apiServerAclAllowedCidrs":         strSliceData(allowedCidrs),
		"credentialsRotationPhase":         llx.StringData(credRotPhase),
		"credentialsRotationLastInitiated": llx.TimeDataPtr(credRotInitiated),
		"credentialsRotationLastCompleted": llx.TimeDataPtr(credRotCompleted),
		"egressAddressRanges":              strSliceData(egressRanges),
		"podAddressRanges":                 strSliceData(podRanges),
		"serviceAccountIssuer":             llx.StringData(saIssuer),
		"auditEnabled":                     llx.BoolData(auditEnabled),
		"idpEnabled":                       llx.BoolData(idpEnabled),
		"idpType":                          llx.StringData(idpType),
		"observabilityEnabled":             llx.BoolData(obsEnabled),
		"dnsEnabled":                       llx.BoolData(dnsEnabled),
		"dnsGatewayApi":                    llx.BoolData(dnsGatewayApi),
		"dnsZones":                         strSliceData(dnsZones),
		"applicationLoadBalancerEnabled":   llx.BoolData(albEnabled),
		"labels":                           stringMapData(cluster.GetLabels()),
		"controlPlaneAccessScope":          llx.StringData(controlPlaneScope),
		"kubernetesExpirationDate":         llx.TimeDataPtr(k8sExpiration),
	}
	res, err := CreateResource(runtime, "stackit.ske.cluster", args)
	if err != nil {
		return nil, err
	}
	if mc, ok := res.(*mqlStackitSkeCluster); ok {
		mc.rawNodepools = cluster.GetNodepools()
		mc.cacheNetworkId = networkId
		mc.cacheObservabilityInstanceId = obsInstanceId
		mc.nodepoolExpiration = npExpiration
	}
	return res, nil
}

// networkRef resolves the STACKIT network the cluster is attached to.
func (c *mqlStackitSkeCluster) networkRef() (*mqlStackitNetwork, error) {
	if c.cacheNetworkId == "" {
		c.NetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(c.MqlRuntime, "stackit.network", map[string]*llx.RawData{
		"id": llx.StringData(c.cacheNetworkId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitNetwork), nil
}

// observabilityInstance resolves the observability instance the cluster
// ships metrics and logs to, when the observability extension is enabled.
func (c *mqlStackitSkeCluster) observabilityInstance() (*mqlStackitObservabilityInstance, error) {
	if c.cacheObservabilityInstanceId == "" {
		c.ObservabilityInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(c.MqlRuntime, "stackit.observability.instance", map[string]*llx.RawData{
		"id": llx.StringData(c.cacheObservabilityInstanceId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitObservabilityInstance), nil
}

func (r *mqlStackitSkeCluster) nodePools() ([]any, error) {
	out := make([]any, 0, len(r.rawNodepools))
	for i := range r.rawNodepools {
		np := &r.rawNodepools[i]

		var imageName, imageVersion string
		var machineType string
		if m, ok := np.GetMachineOk(); ok {
			machineType = m.GetType()
			if img, ok := m.GetImageOk(); ok {
				imageName = img.GetName()
				imageVersion = img.GetVersion()
			}
		}

		var volSize int64
		var volType string
		if v, ok := np.GetVolumeOk(); ok {
			volSize = int64(v.GetSize())
			volType = v.GetType()
		}

		var cri string
		if c, ok := np.GetCriOk(); ok {
			cri = string(c.GetName())
		}

		taints := []any{}
		if t, ok := np.GetTaintsOk(); ok {
			taints = anySliceToDict(t)
		}

		var npVersion string
		if k, ok := np.GetKubernetesOk(); ok {
			npVersion = k.GetVersion()
		}

		// End-of-support dates are reported once per pool on the cluster
		// status, not on the pool object, so look them up by pool name.
		var osExpiration, npK8sExpiration *time.Time
		if exp, ok := r.nodepoolExpiration[np.GetName()]; ok {
			osExpiration = timeOrNil(exp.GetOsExpirationDateOk())
			npK8sExpiration = timeOrNil(exp.GetKubernetesExpirationDateOk())
		}

		args := map[string]*llx.RawData{
			"name":                     llx.StringData(np.GetName()),
			"clusterName":              llx.StringData(r.Name.Data),
			"machineType":              llx.StringData(machineType),
			"machineImage":             llx.StringData(imageName),
			"machineImageVersion":      llx.StringData(imageVersion),
			"volumeSize":               llx.IntData(volSize),
			"volumeType":               llx.StringData(volType),
			"minimum":                  llx.IntData(np.GetMinimum()),
			"maximum":                  llx.IntData(np.GetMaximum()),
			"maxSurge":                 llx.IntData(np.GetMaxSurge()),
			"maxUnavailable":           llx.IntData(np.GetMaxUnavailable()),
			"availabilityZones":        strSliceData(np.GetAvailabilityZones()),
			"cri":                      llx.StringData(cri),
			"taints":                   llx.ArrayData(taints, types.Dict),
			"labels":                   stringMapData(np.GetLabels()),
			"allowSystemComponents":    llx.BoolData(np.GetAllowSystemComponents()),
			"kubernetesVersion":        llx.StringData(npVersion),
			"osExpirationDate":         llx.TimeDataPtr(osExpiration),
			"kubernetesExpirationDate": llx.TimeDataPtr(npK8sExpiration),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.ske.cluster.nodePool", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitSkeClusterNodePool) id() (string, error) {
	return "stackit.ske.cluster.nodePool/" + r.ClusterName.Data + "/" + r.Name.Data, nil
}

// anySliceToDict marshals a slice into []any of dict form.
func anySliceToDict[T any](in []T) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = toDict(in[i])
	}
	return out
}

func (r *mqlStackitSkeCluster) id() (string, error) {
	return "stackit.ske.cluster/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Name.Data, nil
}

func initStackitSkeCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name := ""
	if v, ok := args["name"]; ok && v != nil {
		name, _ = v.Value.(string)
	}
	if name == "" {
		// Scope to the connected discovered SKE cluster asset when no name is given.
		name, _ = conn(runtime).AssetObjectID("ske")
	}
	if name == "" {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.SKE()
	if err != nil {
		return nil, nil, err
	}
	cluster, err := client.DefaultAPI.GetCluster(bgctx(), c.ProjectID(), c.Region(), name).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildSkeCluster(runtime, cluster)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}
