// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// This file holds the shared resource arg-builders and the singular
// init functions for the resources the provider splits an account into
// (databases, Kubernetes clusters, load balancers, firewalls). Each
// builder maps a godo object to the MQL field set, and is used by both
// the account-level list accessor and the singular init — so a resource
// fetched on its own (digitalocean.database(id: "...") or a connected
// digitalocean-database asset) is populated identically to one listed
// from the account.

// databaseArgs maps a managed database cluster to its MQL fields.
func databaseArgs(db *godo.Database) map[string]*llx.RawData {
	tags := make([]interface{}, len(db.Tags))
	for i, t := range db.Tags {
		tags[i] = t
	}

	mw := map[string]interface{}{}
	if db.MaintenanceWindow != nil {
		mw["day"] = db.MaintenanceWindow.Day
		mw["hour"] = db.MaintenanceWindow.Hour
		mw["pending"] = db.MaintenanceWindow.Pending
	}

	// The DigitalOcean API returns connection URIs that embed the admin
	// password, so we deliberately do not surface them on the resource.
	// Host/port are exposed separately for connectivity checks.
	connHost := ""
	connPort := int64(0)
	connSslEnabled := false
	if db.Connection != nil {
		connHost = db.Connection.Host
		connPort = int64(db.Connection.Port)
		connSslEnabled = db.Connection.SSL
	}
	privConnHost := ""
	privConnPort := int64(0)
	// A cluster with no private endpoint has no TLS setting to report, so
	// the flag stays null instead of claiming the VPC endpoint accepts
	// plaintext.
	var privConnSslEnabled *bool
	if db.PrivateConnection != nil {
		privConnHost = db.PrivateConnection.Host
		privConnPort = int64(db.PrivateConnection.Port)
		ssl := db.PrivateConnection.SSL
		privConnSslEnabled = &ssl
	}

	dbNames := make([]interface{}, len(db.DBNames))
	for i, n := range db.DBNames {
		dbNames[i] = n
	}

	standbyHost := ""
	standbyPort := int64(0)
	if db.StandbyConnection != nil {
		standbyHost = db.StandbyConnection.Host
		standbyPort = int64(db.StandbyConnection.Port)
	}
	standbyPrivHost := ""
	standbyPrivPort := int64(0)
	if db.StandbyPrivateConnection != nil {
		standbyPrivHost = db.StandbyPrivateConnection.Host
		standbyPrivPort = int64(db.StandbyPrivateConnection.Port)
	}

	storageAutoscaleEnabled := false
	var storageThreshold, storageIncrement *int64
	if db.StorageAutoscale != nil {
		storageAutoscaleEnabled = db.StorageAutoscale.Enabled
		if db.StorageAutoscale.ThresholdPercent != nil {
			v := int64(*db.StorageAutoscale.ThresholdPercent)
			storageThreshold = &v
		}
		if db.StorageAutoscale.IncrementGib != nil {
			v := int64(*db.StorageAutoscale.IncrementGib)
			storageIncrement = &v
		}
	}

	var serviceCnames []interface{}
	if db.DOSettings != nil {
		serviceCnames = toStringSlice(db.DOSettings.ServiceCnames)
	}

	metricsEndpoints := make([]interface{}, len(db.MetricsEndpoints))
	for i, ep := range db.MetricsEndpoints {
		metricsEndpoints[i] = map[string]interface{}{
			"host": ep.Host,
			"port": float64(ep.Port),
		}
	}

	return map[string]*llx.RawData{
		"id":                               llx.StringData(db.ID),
		"name":                             llx.StringData(db.Name),
		"engine":                           llx.StringData(db.EngineSlug),
		"version":                          llx.StringData(db.VersionSlug),
		"numNodes":                         llx.IntData(int64(db.NumNodes)),
		"size":                             llx.StringData(db.SizeSlug),
		"region":                           llx.StringData(db.RegionSlug),
		"status":                           llx.StringData(db.Status),
		"storageSizeMib":                   llx.IntData(int64(db.StorageSizeMib)),
		"dbNames":                          llx.ArrayData(dbNames, "\x02"),
		"createdAt":                        llx.TimeData(db.CreatedAt),
		"projectId":                        llx.StringData(db.ProjectID),
		"privateNetworkUuid":               llx.StringData(db.PrivateNetworkUUID),
		"tags":                             llx.ArrayData(tags, "\x02"),
		"maintenanceWindow":                llx.DictData(mw),
		"connectionHost":                   llx.StringData(connHost),
		"connectionPort":                   llx.IntData(connPort),
		"connectionSslEnabled":             llx.BoolData(connSslEnabled),
		"privateConnectionHost":            llx.StringData(privConnHost),
		"privateConnectionPort":            llx.IntData(privConnPort),
		"privateConnectionSslEnabled":      llx.BoolDataPtr(privConnSslEnabled),
		"storageAutoscaleEnabled":          llx.BoolData(storageAutoscaleEnabled),
		"storageAutoscaleThresholdPercent": llx.IntDataPtr(storageThreshold),
		"storageAutoscaleIncrementGib":     llx.IntDataPtr(storageIncrement),
		"serviceCnames":                    llx.ArrayData(serviceCnames, "\x02"),
		"metricsEndpoints":                 llx.ArrayData(metricsEndpoints, "\x13"),
		"standbyConnectionHost":            llx.StringData(standbyHost),
		"standbyConnectionPort":            llx.IntData(standbyPort),
		"standbyPrivateConnectionHost":     llx.StringData(standbyPrivHost),
		"standbyPrivateConnectionPort":     llx.IntData(standbyPrivPort),
	}
}

func initDigitaloceanDatabase(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	id := stringArg(args, "id")
	if id == "" {
		id = conn.Conf.Options[connection.OptionDatabase]
	}
	if id == "" {
		return nil, nil, errors.New("digitalocean.database requires an id or a connected digitalocean-database asset")
	}
	db, _, err := conn.Client().Databases.Get(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	// godo returns the decoded root's field directly, so a 200 whose body
	// carries no database yields a nil object with a nil error.
	if db == nil {
		return nil, nil, fmt.Errorf("digitalocean.database with id %q not found", id)
	}
	return databaseArgs(db), nil, nil
}

// firewallArgs maps a cloud firewall to its MQL fields.
//
// It takes the runtime because a firewall's pending changes are modeled as
// resources rather than raw values. Building them here keeps the lister and
// initDigitaloceanFirewall on a single path, so the field cannot end up
// populated when a firewall is reached one way and empty when it is reached
// the other.
func firewallArgs(runtime *plugin.Runtime, fw *godo.Firewall) (map[string]*llx.RawData, error) {
	tags := make([]interface{}, len(fw.Tags))
	for i, t := range fw.Tags {
		tags[i] = t
	}

	pending, err := firewallPendingChanges(runtime, fw)
	if err != nil {
		return nil, err
	}

	return map[string]*llx.RawData{
		"id":             llx.StringData(fw.ID),
		"name":           llx.StringData(fw.Name),
		"status":         llx.StringData(fw.Status),
		"createdAt":      llx.TimeDataPtr(parseDoTime(fw.Created)),
		"tags":           llx.ArrayData(tags, "\x02"),
		"pendingChanges": llx.ArrayData(pending, types.Resource("digitalocean.firewall.pendingChange")),
	}, nil
}

// newMqlFirewall builds a firewall resource, caching the raw rule set and
// protected droplet IDs for the typed ingressRules(), egressRules(), and
// droplets() accessors.
func newMqlFirewall(runtime *plugin.Runtime, fw *godo.Firewall) (*mqlDigitaloceanFirewall, error) {
	args, err := firewallArgs(runtime, fw)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "digitalocean.firewall", args)
	if err != nil {
		return nil, err
	}
	mqlFirewall := res.(*mqlDigitaloceanFirewall)
	mqlFirewall.cacheInboundRules = fw.InboundRules
	mqlFirewall.cacheOutboundRules = fw.OutboundRules
	mqlFirewall.cacheDropletIDs = toIntSlice(fw.DropletIDs)
	return mqlFirewall, nil
}

// firewallPendingChanges builds the per-droplet changes a firewall has not
// finished applying. The droplet id is kept on the resource rather than
// exposed as a field: it is the cache key's distinguishing part and resolves
// to a droplet through the typed accessor.
func firewallPendingChanges(runtime *plugin.Runtime, fw *godo.Firewall) ([]interface{}, error) {
	changes := make([]interface{}, 0, len(fw.PendingChanges))
	for _, pc := range fw.PendingChanges {
		id, err := resourceID("digitalocean.firewall.pendingChange", fw.ID, strconv.Itoa(pc.DropletID))
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(runtime, "digitalocean.firewall.pendingChange", map[string]*llx.RawData{
			"__id":     llx.StringData(id),
			"removing": llx.BoolData(pc.Removing),
			"status":   llx.StringData(pc.Status),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlDigitaloceanFirewallPendingChange).cacheDropletID = int64(pc.DropletID)
		changes = append(changes, res)
	}
	return changes, nil
}

func initDigitaloceanFirewall(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	id := stringArg(args, "id")
	if id == "" {
		id = conn.Conf.Options[connection.OptionFirewall]
	}
	if id == "" {
		return nil, nil, errors.New("digitalocean.firewall requires an id or a connected digitalocean-firewall asset")
	}
	fw, _, err := conn.Client().Firewalls.Get(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	// godo returns the decoded root's field directly, so a 200 whose body
	// carries no firewall yields a nil object with a nil error. Building the
	// resource from it dereferences nil and panics the provider, which takes
	// down the whole scan rather than this one resource.
	if fw == nil {
		return nil, nil, fmt.Errorf("digitalocean.firewall with id %q not found", id)
	}
	res, err := newMqlFirewall(runtime, fw)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// loadBalancerArgs maps a load balancer to its MQL fields.
func loadBalancerArgs(lb *godo.LoadBalancer) map[string]*llx.RawData {
	tags := make([]interface{}, len(lb.Tags))
	for i, t := range lb.Tags {
		tags[i] = t
	}

	hc := map[string]interface{}{}
	if lb.HealthCheck != nil {
		hc["protocol"] = lb.HealthCheck.Protocol
		hc["port"] = float64(lb.HealthCheck.Port)
		hc["path"] = lb.HealthCheck.Path
		hc["checkIntervalSeconds"] = float64(lb.HealthCheck.CheckIntervalSeconds)
		hc["responseTimeoutSeconds"] = float64(lb.HealthCheck.ResponseTimeoutSeconds)
		hc["unhealthyThreshold"] = float64(lb.HealthCheck.UnhealthyThreshold)
		hc["healthyThreshold"] = float64(lb.HealthCheck.HealthyThreshold)
	}

	ss := map[string]interface{}{}
	if lb.StickySessions != nil {
		ss["type"] = lb.StickySessions.Type
		ss["cookieName"] = lb.StickySessions.CookieName
		ss["cookieTtlSeconds"] = float64(lb.StickySessions.CookieTtlSeconds)
	}

	lbRegion := ""
	if lb.Region != nil {
		lbRegion = lb.Region.Slug
	}

	var firewallAllow, firewallDeny []interface{}
	if lb.Firewall != nil {
		firewallAllow = toStringSlice(lb.Firewall.Allow)
		firewallDeny = toStringSlice(lb.Firewall.Deny)
	}

	domains := make([]interface{}, len(lb.Domains))
	for i, d := range lb.Domains {
		domains[i] = map[string]interface{}{
			"name":          d.Name,
			"isManaged":     d.IsManaged,
			"certificateId": d.CertificateID,
			"status":        d.Status,
		}
	}

	var glb map[string]interface{}
	if lb.GLBSettings != nil {
		glb = map[string]interface{}{
			"targetProtocol": lb.GLBSettings.TargetProtocol,
			"targetPort":     float64(lb.GLBSettings.TargetPort),
		}
		if lb.GLBSettings.CDN != nil {
			glb["cdnEnabled"] = lb.GLBSettings.CDN.IsEnabled
		}
	}

	var httpIdleTimeout *int64
	if lb.HTTPIdleTimeoutSeconds != nil {
		v := int64(*lb.HTTPIdleTimeoutSeconds)
		httpIdleTimeout = &v
	}

	return map[string]*llx.RawData{
		"id":                           llx.StringData(lb.ID),
		"name":                         llx.StringData(lb.Name),
		"ip":                           llx.StringData(lb.IP),
		"status":                       llx.StringData(lb.Status),
		"region":                       llx.StringData(lbRegion),
		"createdAt":                    llx.TimeDataPtr(parseDoTime(lb.Created)),
		"algorithm":                    llx.StringData(lb.Algorithm),
		"redirectHttpToHttps":          llx.BoolData(lb.RedirectHttpToHttps),
		"enableProxyProtocol":          llx.BoolData(lb.EnableProxyProtocol),
		"enableBackendKeepalive":       llx.BoolData(lb.EnableBackendKeepalive),
		"tags":                         llx.ArrayData(tags, "\x02"),
		"healthCheck":                  llx.DictData(hc),
		"stickySessions":               llx.DictData(ss),
		"disableLetsEncryptDnsRecords": llx.BoolDataPtr(lb.DisableLetsEncryptDNSRecords),
		"ipv6":                         llx.StringData(lb.IPv6),
		"type":                         llx.StringData(lb.Type),
		"sizeSlug":                     llx.StringData(lb.SizeSlug),
		"sizeUnit":                     llx.IntData(int64(lb.SizeUnit)),
		"projectId":                    llx.StringData(lb.ProjectID),
		"network":                      llx.StringData(lb.Network),
		"networkStack":                 llx.StringData(lb.NetworkStack),
		"tlsCipherPolicy":              llx.StringData(lb.TLSCipherPolicy),
		"httpIdleTimeoutSeconds":       llx.IntDataPtr(httpIdleTimeout),
		"firewallAllow":                llx.ArrayData(firewallAllow, "\x02"),
		"firewallDeny":                 llx.ArrayData(firewallDeny, "\x02"),
		"domains":                      llx.ArrayData(domains, "\x13"),
		"glbSettings":                  llx.DictData(glb),
	}
}

func initDigitaloceanLoadBalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	id := stringArg(args, "id")
	if id == "" {
		id = conn.Conf.Options[connection.OptionLoadBalancer]
	}
	if id == "" {
		return nil, nil, errors.New("digitalocean.loadBalancer requires an id or a connected digitalocean-loadbalancer asset")
	}
	lb, _, err := conn.Client().LoadBalancers.Get(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	// A nil object alongside a nil error, as above: report it as not found
	// rather than dereferencing it in the arg builder.
	if lb == nil {
		return nil, nil, fmt.Errorf("digitalocean.loadBalancer with id %q not found", id)
	}
	res, err := newMqlLoadBalancer(runtime, lb)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// newMqlLoadBalancer builds a load balancer resource, caching the VPC UUID,
// attached droplet IDs, and regional target IDs for the typed vpc(),
// droplets(), and targetLoadBalancers() accessors.
func newMqlLoadBalancer(runtime *plugin.Runtime, lb *godo.LoadBalancer) (*mqlDigitaloceanLoadBalancer, error) {
	res, err := CreateResource(runtime, "digitalocean.loadBalancer", loadBalancerArgs(lb))
	if err != nil {
		return nil, err
	}
	mqlLB := res.(*mqlDigitaloceanLoadBalancer)
	mqlLB.cacheVPCUUID = lb.VPCUUID
	mqlLB.cacheDropletIDs = toIntSlice(lb.DropletIDs)
	mqlLB.cacheTargetLoadBalancerIDs = lb.TargetLoadBalancerIDs
	mqlLB.cacheForwardingRules = lb.ForwardingRules
	return mqlLB, nil
}

// kubernetesClusterArgs maps a DOKS cluster to its MQL fields.
func kubernetesClusterArgs(c *godo.KubernetesCluster) map[string]*llx.RawData {
	tags := make([]interface{}, len(c.Tags))
	for i, t := range c.Tags {
		tags[i] = t
	}

	mp := map[string]interface{}{}
	if c.MaintenancePolicy != nil {
		mp["startTime"] = c.MaintenancePolicy.StartTime
		mp["day"] = float64(c.MaintenancePolicy.Day)
		mp["duration"] = c.MaintenancePolicy.Duration
	}

	status := ""
	statusMessage := ""
	if c.Status != nil {
		status = string(c.Status.State)
		statusMessage = c.Status.Message
	}

	var ssoEnabled, ssoRequired bool
	var ssoIssuerURL, ssoClientID string
	if c.SSO != nil {
		ssoEnabled = c.SSO.Enabled
		ssoRequired = c.SSO.Required
		ssoIssuerURL = c.SSO.IssuerURL
		ssoClientID = c.SSO.ClientID
	}

	var cpFirewallEnabled *bool
	var cpFirewallAllowed []interface{}
	if c.ControlPlaneFirewall != nil {
		cpFirewallEnabled = c.ControlPlaneFirewall.Enabled
		cpFirewallAllowed = toStringSlice(c.ControlPlaneFirewall.AllowedAddresses)
	}

	var routingAgentEnabled, amdGpuEnabled, amdGpuMetricsEnabled *bool
	var nvidiaGpuEnabled, rdmaEnabled, corednsAutoscalerEnabled, p2pOciRegistryEnabled *bool
	if c.P2pOciRegistryPlugin != nil {
		p2pOciRegistryEnabled = c.P2pOciRegistryPlugin.Enabled
	}
	if c.RoutingAgent != nil {
		routingAgentEnabled = c.RoutingAgent.Enabled
	}
	if c.AmdGpuDevicePlugin != nil {
		amdGpuEnabled = c.AmdGpuDevicePlugin.Enabled
	}
	if c.AmdGpuDeviceMetricsExporterPlugin != nil {
		amdGpuMetricsEnabled = c.AmdGpuDeviceMetricsExporterPlugin.Enabled
	}
	if c.NvidiaGpuDevicePlugin != nil {
		nvidiaGpuEnabled = c.NvidiaGpuDevicePlugin.Enabled
	}
	if c.RdmaSharedDevicePlugin != nil {
		rdmaEnabled = c.RdmaSharedDevicePlugin.Enabled
	}
	if c.CorednsAutoscaler != nil {
		corednsAutoscalerEnabled = c.CorednsAutoscaler.Enabled
	}

	autoscaler := map[string]interface{}{}
	if c.ClusterAutoscalerConfiguration != nil {
		ca := c.ClusterAutoscalerConfiguration
		if ca.ScaleDownUtilizationThreshold != nil {
			autoscaler["scaleDownUtilizationThreshold"] = *ca.ScaleDownUtilizationThreshold
		}
		if ca.ScaleDownUnneededTime != nil {
			autoscaler["scaleDownUnneededTime"] = *ca.ScaleDownUnneededTime
		}
		if len(ca.Expanders) > 0 {
			autoscaler["expanders"] = toStringSlice(ca.Expanders)
		}
	}

	return map[string]*llx.RawData{
		"id":                                   llx.StringData(c.ID),
		"name":                                 llx.StringData(c.Name),
		"version":                              llx.StringData(c.VersionSlug),
		"region":                               llx.StringData(c.RegionSlug),
		"status":                               llx.StringData(status),
		"createdAt":                            llx.TimeData(c.CreatedAt),
		"updatedAt":                            llx.TimeData(c.UpdatedAt),
		"clusterSubnet":                        llx.StringData(c.ClusterSubnet),
		"serviceSubnet":                        llx.StringData(c.ServiceSubnet),
		"autoUpgrade":                          llx.BoolData(c.AutoUpgrade),
		"surgeUpgrade":                         llx.BoolData(c.SurgeUpgrade),
		"ha":                                   llx.BoolData(c.HA),
		"ssoEnabled":                           llx.BoolData(ssoEnabled),
		"ssoRequired":                          llx.BoolData(ssoRequired),
		"ssoIssuerUrl":                         llx.StringData(ssoIssuerURL),
		"ssoClientId":                          llx.StringData(ssoClientID),
		"tags":                                 llx.ArrayData(tags, "\x02"),
		"maintenancePolicy":                    llx.DictData(mp),
		"ipv4":                                 llx.StringData(c.IPv4),
		"endpoint":                             llx.StringData(c.Endpoint),
		"statusMessage":                        llx.StringData(statusMessage),
		"registryEnabled":                      llx.BoolData(c.RegistryEnabled),
		"controlPlaneFirewallEnabled":          llx.BoolDataPtr(cpFirewallEnabled),
		"controlPlaneFirewallAllowedAddresses": llx.ArrayData(cpFirewallAllowed, "\x02"),
		"routingAgentEnabled":                  llx.BoolDataPtr(routingAgentEnabled),
		"amdGpuDevicePluginEnabled":            llx.BoolDataPtr(amdGpuEnabled),
		"amdGpuDeviceMetricsExporterPluginEnabled": llx.BoolDataPtr(amdGpuMetricsEnabled),
		"nvidiaGpuDevicePluginEnabled":             llx.BoolDataPtr(nvidiaGpuEnabled),
		"rdmaSharedDevicePluginEnabled":            llx.BoolDataPtr(rdmaEnabled),
		"corednsAutoscalerEnabled":                 llx.BoolDataPtr(corednsAutoscalerEnabled),
		"p2pOciRegistryEnabled":                    llx.BoolDataPtr(p2pOciRegistryEnabled),
		"workerSubnetUuid":                         llx.StringData(c.WorkerSubnetUUID),
		"isolatedWorkers":                          llx.BoolData(c.IsolatedWorkers),
		"clusterAutoscaler":                        llx.DictData(autoscaler),
	}
}

// availableUpgradeVersions lists the Kubernetes versions the cluster can
// currently upgrade to. An empty list means the cluster is already on the
// newest version DigitalOcean offers for it.
func (r *mqlDigitaloceanKubernetesCluster) availableUpgradeVersions() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	upgrades, _, err := conn.Client().Kubernetes.GetUpgrades(context.Background(), r.Id.Data)
	if err != nil {
		if isDoNotFound(err) {
			return []interface{}{}, nil
		}
		return nil, err
	}
	out := make([]interface{}, 0, len(upgrades))
	for _, u := range upgrades {
		if u == nil {
			continue
		}
		out = append(out, u.Slug)
	}
	return out, nil
}

func initDigitaloceanKubernetesCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	id := stringArg(args, "id")
	if id == "" {
		id = conn.Conf.Options[connection.OptionKubernetes]
	}
	if id == "" {
		return nil, nil, errors.New("digitalocean.kubernetes.cluster requires an id or a connected digitalocean-kubernetes-cluster asset")
	}
	c, _, err := conn.Client().Kubernetes.Get(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	// A nil object alongside a nil error, as above.
	if c == nil {
		return nil, nil, fmt.Errorf("digitalocean.kubernetes.cluster with id %q not found", id)
	}
	res, err := newMqlKubernetesCluster(runtime, c)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// mqlDigitaloceanKubernetesClusterInternal caches the UUID of the VPC the
// cluster is attached to so the typed vpc() accessor can resolve it without
// a refetch.
type mqlDigitaloceanKubernetesClusterInternal struct {
	cacheVPCUUID string

	// The kubeconfig identity costs its own API call and feeds two fields,
	// so it is fetched at most once per cluster.
	clusterUserOnce  sync.Once
	clusterUserValue *godo.KubernetesClusterUser
	clusterUserErr   error
}

// newMqlKubernetesCluster builds a DOKS cluster resource, caching the VPC
// UUID for the typed vpc() accessor.
func newMqlKubernetesCluster(runtime *plugin.Runtime, c *godo.KubernetesCluster) (*mqlDigitaloceanKubernetesCluster, error) {
	res, err := CreateResource(runtime, "digitalocean.kubernetes.cluster", kubernetesClusterArgs(c))
	if err != nil {
		return nil, err
	}
	mqlCluster := res.(*mqlDigitaloceanKubernetesCluster)
	mqlCluster.cacheVPCUUID = c.VPCUUID
	return mqlCluster, nil
}

// stringArg returns the string value of args[key], or "" when absent.
func stringArg(args map[string]*llx.RawData, key string) string {
	if a, ok := args[key]; ok {
		if s, ok := a.Value.(string); ok {
			return s
		}
	}
	return ""
}
