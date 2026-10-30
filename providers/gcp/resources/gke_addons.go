// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"cloud.google.com/go/container/apiv1/containerpb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const gkeAddonsConfigResource = "gcp.project.gkeService.cluster.addonsConfig"

// gkeAddonsConfigChildArgs returns the resource arguments for every addon of a
// cluster's addons config, keyed by the field the addon hangs off.
//
// Every addon in containerpb.AddonsConfig is its own optional message wrapping
// a single bool, and GKE omits the message entirely when the addon sits at its
// default. Read straight off the dict that gave null rather than false, so a
// check written as `networkPolicyConfig.disabled == false` evaluated against
// null and passed without ever having read the cluster. Each addon resource is
// created unconditionally and reports the default an absent message stands for:
// an unset Disabled is false, an unset Enabled is false.
func gkeAddonsConfigChildArgs(id string, cfg *containerpb.AddonsConfig) map[string]map[string]*llx.RawData {
	// The load balancer type stays empty when the cluster carries no Cloud Run
	// configuration at all, which is a different claim from the explicit
	// LOAD_BALANCER_TYPE_UNSPECIFIED the API sends for a configured addon.
	cloudRunLoadBalancerType := ""
	if c := cfg.GetCloudRunConfig(); c != nil {
		cloudRunLoadBalancerType = c.LoadBalancerType.String()
	}

	return map[string]map[string]*llx.RawData{
		"httpLoadBalancingAddon": {
			"__id":     llx.StringData(id + "/httpLoadBalancing"),
			"disabled": llx.BoolData(cfg.GetHttpLoadBalancing().GetDisabled()),
		},
		"horizontalPodAutoscalingAddon": {
			"__id":     llx.StringData(id + "/horizontalPodAutoscaling"),
			"disabled": llx.BoolData(cfg.GetHorizontalPodAutoscaling().GetDisabled()),
		},
		"kubernetesDashboardAddon": {
			"__id":     llx.StringData(id + "/kubernetesDashboard"),
			"disabled": llx.BoolData(cfg.GetKubernetesDashboard().GetDisabled()),
		},
		"networkPolicyAddon": {
			"__id":     llx.StringData(id + "/networkPolicyConfig"),
			"disabled": llx.BoolData(cfg.GetNetworkPolicyConfig().GetDisabled()),
		},
		"cloudRunAddon": {
			"__id":             llx.StringData(id + "/cloudRunConfig"),
			"disabled":         llx.BoolData(cfg.GetCloudRunConfig().GetDisabled()),
			"loadBalancerType": llx.StringData(cloudRunLoadBalancerType),
		},
		"dnsCacheAddon": {
			"__id":    llx.StringData(id + "/dnsCacheConfig"),
			"enabled": llx.BoolData(cfg.GetDnsCacheConfig().GetEnabled()),
		},
		"configConnectorAddon": {
			"__id":    llx.StringData(id + "/configConnectorConfig"),
			"enabled": llx.BoolData(cfg.GetConfigConnectorConfig().GetEnabled()),
		},
		"gcePersistentDiskCsiDriverAddon": {
			"__id":    llx.StringData(id + "/gcePersistentDiskCsiDriverConfig"),
			"enabled": llx.BoolData(cfg.GetGcePersistentDiskCsiDriverConfig().GetEnabled()),
		},
		"gcpFilestoreCsiDriverAddon": {
			"__id":    llx.StringData(id + "/gcpFilestoreCsiDriverConfig"),
			"enabled": llx.BoolData(cfg.GetGcpFilestoreCsiDriverConfig().GetEnabled()),
		},
		"gkeBackupAgentAddon": {
			"__id":    llx.StringData(id + "/gkeBackupAgentConfig"),
			"enabled": llx.BoolData(cfg.GetGkeBackupAgentConfig().GetEnabled()),
		},
		"gcsFuseCsiDriverAddon": {
			"__id":    llx.StringData(id + "/gcsFuseCsiDriverConfig"),
			"enabled": llx.BoolData(cfg.GetGcsFuseCsiDriverConfig().GetEnabled()),
		},
		"statefulHaAddon": {
			"__id":    llx.StringData(id + "/statefulHaConfig"),
			"enabled": llx.BoolData(cfg.GetStatefulHaConfig().GetEnabled()),
		},
	}
}

// gkeAddonsConfigDictArgs keeps the deprecated per-addon dicts populated. An
// absent addon message stays a null dict, which is the behavior they shipped
// with.
func gkeAddonsConfigDictArgs(id string, cfg *containerpb.AddonsConfig) map[string]*llx.RawData {
	var httpLoadBalancing, horizontalPodAutoscaling, kubernetesDashboard, networkPolicyConfig map[string]any
	var cloudRunConfig, dnsCacheConfig, configConnectorConfig map[string]any
	var gcePersistentDiskCsiDriverConfig, gcpFilestoreCsiDriverConfig map[string]any
	var gkeBackupAgentConfig, gcsFuseCsiDriverConfig, statefulHaConfig map[string]any

	if cfg != nil {
		if c := cfg.HttpLoadBalancing; c != nil {
			httpLoadBalancing = map[string]any{"disabled": c.Disabled}
		}
		if c := cfg.HorizontalPodAutoscaling; c != nil {
			horizontalPodAutoscaling = map[string]any{"disabled": c.Disabled}
		}
		if c := cfg.KubernetesDashboard; c != nil {
			kubernetesDashboard = map[string]any{"disabled": c.Disabled}
		}
		if c := cfg.NetworkPolicyConfig; c != nil {
			networkPolicyConfig = map[string]any{"disabled": c.Disabled}
		}
		if c := cfg.CloudRunConfig; c != nil {
			cloudRunConfig = map[string]any{
				"disabled":         c.Disabled,
				"loadBalancerType": c.LoadBalancerType.String(),
			}
		}
		if c := cfg.DnsCacheConfig; c != nil {
			dnsCacheConfig = map[string]any{"enabled": c.Enabled}
		}
		if c := cfg.ConfigConnectorConfig; c != nil {
			configConnectorConfig = map[string]any{"enabled": c.Enabled}
		}
		if c := cfg.GcePersistentDiskCsiDriverConfig; c != nil {
			gcePersistentDiskCsiDriverConfig = map[string]any{"enabled": c.Enabled}
		}
		if c := cfg.GcpFilestoreCsiDriverConfig; c != nil {
			gcpFilestoreCsiDriverConfig = map[string]any{"enabled": c.Enabled}
		}
		if c := cfg.GkeBackupAgentConfig; c != nil {
			gkeBackupAgentConfig = map[string]any{"enabled": c.Enabled}
		}
		if c := cfg.GcsFuseCsiDriverConfig; c != nil {
			gcsFuseCsiDriverConfig = map[string]any{"enabled": c.Enabled}
		}
		if c := cfg.StatefulHaConfig; c != nil {
			statefulHaConfig = map[string]any{"enabled": c.Enabled}
		}
	}

	return map[string]*llx.RawData{
		"id":                               llx.StringData(id),
		"httpLoadBalancing":                llx.DictData(httpLoadBalancing),
		"horizontalPodAutoscaling":         llx.DictData(horizontalPodAutoscaling),
		"kubernetesDashboard":              llx.DictData(kubernetesDashboard),
		"networkPolicyConfig":              llx.DictData(networkPolicyConfig),
		"cloudRunConfig":                   llx.DictData(cloudRunConfig),
		"dnsCacheConfig":                   llx.DictData(dnsCacheConfig),
		"configConnectorConfig":            llx.DictData(configConnectorConfig),
		"gcePersistentDiskCsiDriverConfig": llx.DictData(gcePersistentDiskCsiDriverConfig),
		"gcpFilestoreCsiDriverConfig":      llx.DictData(gcpFilestoreCsiDriverConfig),
		"gkeBackupAgentConfig":             llx.DictData(gkeBackupAgentConfig),
		"gcsFuseCsiDriverConfig":           llx.DictData(gcsFuseCsiDriverConfig),
		"statefulHaConfig":                 llx.DictData(statefulHaConfig),
	}
}

// newMqlGkeAddonsConfig builds a cluster's addons config together with one
// resource per addon.
func newMqlGkeAddonsConfig(runtime *plugin.Runtime, id string, cfg *containerpb.AddonsConfig) (plugin.Resource, error) {
	args := gkeAddonsConfigDictArgs(id, cfg)
	for field, childArgs := range gkeAddonsConfigChildArgs(id, cfg) {
		name := gkeAddonsConfigResource + "." + field
		addon, err := CreateResource(runtime, name, childArgs)
		if err != nil {
			return nil, err
		}
		args[field] = llx.ResourceData(addon, name)
	}
	return CreateResource(runtime, gkeAddonsConfigResource, args)
}

// newMqlGkeControlPlaneEndpoints promotes the control plane endpoint
// configuration of a cluster. Returns llx.NilData for a cluster that reports no
// configuration, which is what a cluster still on the legacy
// privateClusterConfig fields does.
//
// Every bool in the message is optional, so an unset one stays null rather than
// reporting false: "GKE did not say" and "the endpoint is off" are different
// claims about whether an API server is reachable.
func newMqlGkeControlPlaneEndpoints(runtime *plugin.Runtime, clusterID string, cfg *containerpb.ControlPlaneEndpointsConfig) (*llx.RawData, error) {
	if cfg == nil {
		return llx.NilData, nil
	}

	args := map[string]*llx.RawData{
		"__id": llx.StringData(clusterID + "/controlPlaneEndpoints"),
	}

	if ip := cfg.GetIpEndpointsConfig(); ip != nil {
		args["ipEndpointsEnabled"] = llx.BoolDataPtr(ip.Enabled)
		args["publicEndpointEnabled"] = llx.BoolDataPtr(ip.EnablePublicEndpoint)
		args["globalAccess"] = llx.BoolDataPtr(ip.GlobalAccess)
		args["publicEndpointAddress"] = llx.StringData(ip.PublicEndpoint)
		args["privateEndpointAddress"] = llx.StringData(ip.PrivateEndpoint)
		args["privateEndpointSubnetwork"] = llx.StringData(ip.PrivateEndpointSubnetwork)
	} else {
		args["ipEndpointsEnabled"] = llx.NilData
		args["publicEndpointEnabled"] = llx.NilData
		args["globalAccess"] = llx.NilData
		args["publicEndpointAddress"] = llx.StringData("")
		args["privateEndpointAddress"] = llx.StringData("")
		args["privateEndpointSubnetwork"] = llx.StringData("")
	}

	if dns := cfg.GetDnsEndpointConfig(); dns != nil {
		args["dnsEndpoint"] = llx.StringData(dns.Endpoint)
		args["dnsAllowExternalTraffic"] = llx.BoolDataPtr(dns.AllowExternalTraffic)
		args["dnsK8sTokensEnabled"] = llx.BoolDataPtr(dns.EnableK8STokensViaDns)
		args["dnsK8sCertsEnabled"] = llx.BoolDataPtr(dns.EnableK8SCertsViaDns)
	} else {
		args["dnsEndpoint"] = llx.StringData("")
		args["dnsAllowExternalTraffic"] = llx.NilData
		args["dnsK8sTokensEnabled"] = llx.NilData
		args["dnsK8sCertsEnabled"] = llx.NilData
	}

	res, err := CreateResource(runtime, "gcp.project.gkeService.cluster.controlPlaneEndpoints", args)
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "gcp.project.gkeService.cluster.controlPlaneEndpoints"), nil
}
