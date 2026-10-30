// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"slices"
	"sync"
	"time"

	clustermgmtconfig "github.com/nutanix/ntnx-api-golang-clients/clustermgmt-go-client/v4/models/clustermgmt/v4/config"
	clustercommon "github.com/nutanix/ntnx-api-golang-clients/clustermgmt-go-client/v4/models/common/v1/config"
	vmcommon "github.com/nutanix/ntnx-api-golang-clients/vmm-go-client/v4/models/common/v1/config"
	vmmconfig "github.com/nutanix/ntnx-api-golang-clients/vmm-go-client/v4/models/vmm/v4/ahv/config"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nutanix/connection"
	"go.mondoo.com/mql/types"
)

// pageSize is the number of items requested per list page from the v4 APIs.
const pageSize = 100

func (a *mqlNutanix) conn() *connection.NutanixConnection {
	return a.MqlRuntime.Connection.(*connection.NutanixConnection)
}

// guard serializes a single SDK call on the given namespace mutex. The v4 SDK
// ApiClient mutates per-request state without locking (see NutanixConnection),
// so concurrent field resolution would otherwise race on a shared client.
func guard[T any](mu *sync.Mutex, fn func() (T, error)) (T, error) {
	mu.Lock()
	defer mu.Unlock()
	return fn()
}

// cachedResource returns an already-resolved resource of the given type by its
// __id, letting cross-reference accessors skip a redundant per-instance API
// fetch when the same entity was already created during this scan.
func cachedResource[T plugin.Resource](runtime *plugin.Runtime, name, id string) (T, bool) {
	var zero T
	if r, ok := runtime.Resources.Get(name + "\x00" + id); ok {
		if typed, ok := r.(T); ok {
			return typed, true
		}
	}
	return zero, false
}

// ---------------------------------------------------------------------------
// pointer dereference helpers
// ---------------------------------------------------------------------------

func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func derefInt(v *int) int64 {
	if v == nil {
		return 0
	}
	return int64(*v)
}

func derefBool(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

// subResourceID returns extID when it is set, otherwise a stable
// parent-qualified fallback of the form "<parentID>/<kind>/<index>". Child
// records (disks, NICs, nodes, ...) whose ExtId/UUID the API omits would
// otherwise all share an empty cache key and collapse onto the first sibling
// built, so the index makes each one unique within its parent.
func subResourceID(extID, parentID, kind string, index int) string {
	if extID != "" {
		return extID
	}
	return fmt.Sprintf("%s/%s/%d", parentID, kind, index)
}

// usecsToTime converts a microsecond Unix timestamp pointer to a *time.Time,
// returning nil when the source is nil or zero.
func usecsToTime(usecs *int64) *time.Time {
	if usecs == nil || *usecs == 0 {
		return nil
	}
	t := time.UnixMicro(*usecs).UTC()
	return &t
}

func clusterIPToString(ip *clustercommon.IPAddress) string {
	if ip == nil {
		return ""
	}
	if ip.Ipv4 != nil && ip.Ipv4.Value != nil {
		return *ip.Ipv4.Value
	}
	if ip.Ipv6 != nil && ip.Ipv6.Value != nil {
		return *ip.Ipv6.Value
	}
	return ""
}

func vmIPv4ToString(ip *vmcommon.IPv4Address) string {
	if ip == nil || ip.Value == nil {
		return ""
	}
	return *ip.Value
}

func clusterIPOrFqdnToString(a *clustercommon.IPAddressOrFQDN) string {
	if a == nil {
		return ""
	}
	if a.Ipv4 != nil && a.Ipv4.Value != nil {
		return *a.Ipv4.Value
	}
	if a.Ipv6 != nil && a.Ipv6.Value != nil {
		return *a.Ipv6.Value
	}
	if a.Fqdn != nil && a.Fqdn.Value != nil {
		return *a.Fqdn.Value
	}
	return ""
}

// ---------------------------------------------------------------------------
// root accessors
// ---------------------------------------------------------------------------

func (a *mqlNutanix) clusters() ([]any, error) {
	conn := a.conn()
	clusters, err := listClusters(conn)
	if err != nil {
		return nil, err
	}

	scopeCluster := conn.ClusterID()
	res := []any{}
	for i := range clusters {
		c := clusters[i]
		if scopeCluster != "" && (c.ExtId == nil || *c.ExtId != scopeCluster) {
			continue
		}
		mqlCluster, err := newMqlCluster(a.MqlRuntime, &c)
		if err != nil {
			return nil, err
		}
		if mqlCluster == nil {
			continue
		}
		res = append(res, mqlCluster)
	}
	return res, nil
}

func (a *mqlNutanix) hosts() ([]any, error) {
	conn := a.conn()
	hosts, err := listHosts(conn)
	if err != nil {
		return nil, err
	}

	scopeNode := conn.NodeID()
	scopeCluster := conn.ClusterID()
	res := []any{}
	for i := range hosts {
		h := hosts[i]
		if scopeNode != "" && (h.ExtId == nil || *h.ExtId != scopeNode) {
			continue
		}
		if scopeCluster != "" && (h.Cluster == nil || h.Cluster.Uuid == nil || *h.Cluster.Uuid != scopeCluster) {
			continue
		}
		mqlHost, err := newMqlHost(a.MqlRuntime, &h)
		if err != nil {
			return nil, err
		}
		if mqlHost == nil {
			continue
		}
		res = append(res, mqlHost)
	}
	return res, nil
}

func (a *mqlNutanix) vms() ([]any, error) {
	conn := a.conn()
	vms, err := listVms(conn)
	if err != nil {
		return nil, err
	}

	scopeNode := conn.NodeID()
	scopeCluster := conn.ClusterID()
	res := []any{}
	for i := range vms {
		vm := vms[i]
		if scopeNode != "" && (vm.Host == nil || vm.Host.ExtId == nil || *vm.Host.ExtId != scopeNode) {
			continue
		}
		if scopeCluster != "" && (vm.Cluster == nil || vm.Cluster.ExtId == nil || *vm.Cluster.ExtId != scopeCluster) {
			continue
		}
		mqlVm, err := newMqlVm(a.MqlRuntime, &vm)
		if err != nil {
			return nil, err
		}
		if mqlVm == nil {
			continue
		}
		res = append(res, mqlVm)
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// SDK list helpers (paginated)
// ---------------------------------------------------------------------------

func listClusters(conn *connection.NutanixConnection) ([]clustermgmtconfig.Cluster, error) {
	api := conn.ClustersApi()
	limit := pageSize
	all := []clustermgmtconfig.Cluster{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.CmgMu(), func() (*clustermgmtconfig.ListClustersApiResponse, error) {
			return api.ListClusters(&p, &limit, nil, nil, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]clustermgmtconfig.Cluster)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListClusters", data)
		}
		all = append(all, items...)
		if len(items) < limit {
			break
		}
	}
	return all, nil
}

func listHosts(conn *connection.NutanixConnection) ([]clustermgmtconfig.Host, error) {
	api := conn.ClustersApi()
	limit := pageSize
	all := []clustermgmtconfig.Host{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.CmgMu(), func() (*clustermgmtconfig.ListHostsApiResponse, error) {
			return api.ListHosts(&p, &limit, nil, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]clustermgmtconfig.Host)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListHosts", data)
		}
		all = append(all, items...)
		if len(items) < limit {
			break
		}
	}
	return all, nil
}

func listVms(conn *connection.NutanixConnection) ([]vmmconfig.Vm, error) {
	api := conn.VmApi()
	limit := pageSize
	all := []vmmconfig.Vm{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.VmmMu(), func() (*vmmconfig.ListVmsApiResponse, error) {
			return api.ListVms(&p, &limit, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]vmmconfig.Vm)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListVms", data)
		}
		all = append(all, items...)
		if len(items) < limit {
			break
		}
	}
	return all, nil
}

// ---------------------------------------------------------------------------
// resource builders
// ---------------------------------------------------------------------------

func newMqlCluster(runtime *plugin.Runtime, c *clustermgmtconfig.Cluster) (*mqlNutanixCluster, error) {
	if c.ExtId == nil {
		return nil, nil
	}
	hypervisorTypes := []any{}
	functions := []any{}
	encryptionOptions := []any{}
	encryptionScopes := []any{}
	softwareMap := map[string]any{}
	version := ""
	fullVersion := ""
	arch := ""
	clusterType := ""
	operationMode := ""
	encryptionInTransitStatus := ""
	redundancyFactor := int64(0)
	incarnationId := int64(0)
	isLts := false
	isAvailable := false
	isPasswordRemoteLoginEnabled := false
	isRemoteSupportEnabled := false
	pulseEnabled := false
	timezone := ""

	if c.Config != nil {
		cfg := c.Config
		for _, ht := range cfg.HypervisorTypes {
			hypervisorTypes = append(hypervisorTypes, ht.GetName())
		}
		for _, fn := range cfg.ClusterFunction {
			functions = append(functions, fn.GetName())
		}
		// The v4.0 API does not expose a distinct cluster type; the cluster
		// functions carry the equivalent classification. Surface it as
		// clusterType so audits can select clusters by role (an AOS compute
		// cluster versus the Prism Central cluster).
		switch {
		case slices.Contains(functions, "AOS"):
			clusterType = "AOS"
		case slices.Contains(functions, "PRISM_CENTRAL"):
			clusterType = "PRISM_CENTRAL"
		case slices.Contains(functions, "CLOUD_DATA_GATEWAY"):
			clusterType = "CLOUD_DATA_GATEWAY"
		default:
			clusterType = "UNKNOWN"
		}
		for _, eo := range cfg.EncryptionOption {
			encryptionOptions = append(encryptionOptions, eo.GetName())
		}
		for _, es := range cfg.EncryptionScope {
			encryptionScopes = append(encryptionScopes, es.GetName())
		}
		for _, sw := range cfg.ClusterSoftwareMap {
			if sw.SoftwareType != nil && sw.Version != nil {
				softwareMap[sw.SoftwareType.GetName()] = *sw.Version
			}
		}
		if cfg.BuildInfo != nil {
			if cfg.BuildInfo.Version != nil {
				version = *cfg.BuildInfo.Version
			}
			if cfg.BuildInfo.FullVersion != nil {
				fullVersion = *cfg.BuildInfo.FullVersion
			}
		}
		if cfg.ClusterArch != nil {
			arch = cfg.ClusterArch.GetName()
		}
		if cfg.OperationMode != nil {
			operationMode = cfg.OperationMode.GetName()
		}
		if cfg.EncryptionInTransitStatus != nil {
			encryptionInTransitStatus = cfg.EncryptionInTransitStatus.GetName()
		}
		redundancyFactor = derefInt64(cfg.RedundancyFactor)
		incarnationId = derefInt64(cfg.IncarnationId)
		if cfg.IsLts != nil {
			isLts = *cfg.IsLts
		}
		if cfg.IsAvailable != nil {
			isAvailable = *cfg.IsAvailable
		}
		if cfg.IsPasswordRemoteLoginEnabled != nil {
			isPasswordRemoteLoginEnabled = *cfg.IsPasswordRemoteLoginEnabled
		}
		if cfg.IsRemoteSupportEnabled != nil {
			isRemoteSupportEnabled = *cfg.IsRemoteSupportEnabled
		}
		if cfg.PulseStatus != nil && cfg.PulseStatus.IsEnabled != nil {
			pulseEnabled = *cfg.PulseStatus.IsEnabled
		}
		if cfg.Timezone != nil {
			timezone = *cfg.Timezone
		}
	}

	nodeCount := int64(0)
	if c.Nodes != nil {
		nodeCount = derefInt(c.Nodes.NumberOfNodes)
	}

	upgradeStatus := ""
	if c.UpgradeStatus != nil {
		upgradeStatus = c.UpgradeStatus.GetName()
	}

	categories := []any{}
	for _, cat := range c.Categories {
		categories = append(categories, cat)
	}

	res, err := CreateResource(runtime, "nutanix.cluster", map[string]*llx.RawData{
		"__id":                         llx.StringDataPtr(c.ExtId),
		"id":                           llx.StringDataPtr(c.ExtId),
		"tenantId":                     llx.StringDataPtr(c.TenantId),
		"name":                         llx.StringDataPtr(c.Name),
		"version":                      llx.StringData(version),
		"fullVersion":                  llx.StringData(fullVersion),
		"arch":                         llx.StringData(arch),
		"clusterType":                  llx.StringData(clusterType),
		"functions":                    llx.ArrayData(functions, types.String),
		"hypervisorTypes":              llx.ArrayData(hypervisorTypes, types.String),
		"nodeCount":                    llx.IntData(nodeCount),
		"vmCount":                      llx.IntData(derefInt64(c.VmCount)),
		"inefficientVmCount":           llx.IntData(derefInt64(c.InefficientVmCount)),
		"redundancyFactor":             llx.IntData(redundancyFactor),
		"operationMode":                llx.StringData(operationMode),
		"encryptionInTransitStatus":    llx.StringData(encryptionInTransitStatus),
		"encryptionOptions":            llx.ArrayData(encryptionOptions, types.String),
		"encryptionScopes":             llx.ArrayData(encryptionScopes, types.String),
		"isLts":                        llx.BoolData(isLts),
		"isAvailable":                  llx.BoolData(isAvailable),
		"isPasswordRemoteLoginEnabled": llx.BoolData(isPasswordRemoteLoginEnabled),
		"isRemoteSupportEnabled":       llx.BoolData(isRemoteSupportEnabled),
		"pulseEnabled":                 llx.BoolData(pulseEnabled),
		"incarnationId":                llx.IntData(incarnationId),
		"backupEligibilityScore":       llx.IntData(derefInt64(c.BackupEligibilityScore)),
		"timezone":                     llx.StringData(timezone),
		"categories":                   llx.ArrayData(categories, types.String),
		"softwareMap":                  llx.MapData(softwareMap, types.String),
		"upgradeStatus":                llx.StringData(upgradeStatus),
	})
	if err != nil {
		return nil, err
	}
	mqlCluster := res.(*mqlNutanixCluster)
	if c.ExtId != nil {
		mqlCluster.clusterId = *c.ExtId
	}
	mqlCluster.cacheNetwork = c.Network
	if c.Config != nil {
		mqlCluster.cacheFaultTolerance = c.Config.FaultToleranceState
	}
	if c.Nodes != nil {
		mqlCluster.cacheNodeList = c.Nodes.NodeList
	}
	return mqlCluster, nil
}

type mqlNutanixClusterInternal struct {
	clusterId           string
	cacheNetwork        *clustermgmtconfig.ClusterNetworkReference
	cacheFaultTolerance *clustermgmtconfig.FaultToleranceState
	cacheNodeList       []clustermgmtconfig.NodeListItemReference
}

func (a *mqlNutanixCluster) network() (*mqlNutanixClusterNetworkConfig, error) {
	n := a.cacheNetwork
	if n == nil {
		a.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	nameServers := []any{}
	for i := range n.NameServerIpList {
		nameServers = append(nameServers, clusterIPOrFqdnToString(&n.NameServerIpList[i]))
	}
	ntpServers := []any{}
	for i := range n.NtpServerIpList {
		ntpServers = append(ntpServers, clusterIPOrFqdnToString(&n.NtpServerIpList[i]))
	}
	nfs := []any{}
	for _, s := range n.NfsSubnetWhitelist {
		nfs = append(nfs, s)
	}

	httpProxies := []any{}
	for i := range n.HttpProxyList {
		p := n.HttpProxyList[i]
		proxy := map[string]any{
			"ipAddress": clusterIPToString(p.IpAddress),
			"port":      derefInt(p.Port),
		}
		if p.Name != nil {
			proxy["name"] = *p.Name
		}
		if p.Username != nil {
			proxy["username"] = *p.Username
		}
		proxyTypes := []any{}
		for _, t := range p.ProxyTypes {
			proxyTypes = append(proxyTypes, t.GetName())
		}
		proxy["proxyTypes"] = proxyTypes
		httpProxies = append(httpProxies, proxy)
	}

	fqdn := ""
	if n.Fqdn != nil {
		fqdn = *n.Fqdn
	}
	externalSubnet := ""
	if n.ExternalSubnet != nil {
		externalSubnet = *n.ExternalSubnet
	}
	internalSubnet := ""
	if n.InternalSubnet != nil {
		internalSubnet = *n.InternalSubnet
	}
	kmsType := ""
	if n.KeyManagementServerType != nil {
		kmsType = n.KeyManagementServerType.GetName()
	}
	smtpEmail := ""
	smtpType := ""
	if n.SmtpServer != nil {
		if n.SmtpServer.EmailAddress != nil {
			smtpEmail = *n.SmtpServer.EmailAddress
		}
		if n.SmtpServer.Type != nil {
			smtpType = n.SmtpServer.Type.GetName()
		}
	}

	res, err := CreateResource(a.MqlRuntime, "nutanix.cluster.networkConfig", map[string]*llx.RawData{
		"__id":                    llx.StringData(fmt.Sprintf("%s/network", a.clusterId)),
		"externalAddress":         llx.StringData(clusterIPToString(n.ExternalAddress)),
		"externalDataServiceIp":   llx.StringData(clusterIPToString(n.ExternalDataServiceIp)),
		"externalSubnet":          llx.StringData(externalSubnet),
		"internalSubnet":          llx.StringData(internalSubnet),
		"fqdn":                    llx.StringData(fqdn),
		"masqueradingIp":          llx.StringData(clusterIPToString(n.MasqueradingIp)),
		"masqueradingPort":        llx.IntData(derefInt(n.MasqueradingPort)),
		"nameServers":             llx.ArrayData(nameServers, types.String),
		"ntpServers":              llx.ArrayData(ntpServers, types.String),
		"nfsSubnetWhitelist":      llx.ArrayData(nfs, types.String),
		"keyManagementServerType": llx.StringData(kmsType),
		"smtpEmailAddress":        llx.StringData(smtpEmail),
		"smtpType":                llx.StringData(smtpType),
		"httpProxies":             llx.ArrayData(httpProxies, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNutanixClusterNetworkConfig), nil
}

func (a *mqlNutanixCluster) faultTolerance() (*mqlNutanixClusterFaultToleranceState, error) {
	ft := a.cacheFaultTolerance
	if ft == nil {
		a.FaultTolerance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	current := ""
	if ft.CurrentClusterFaultTolerance != nil {
		current = ft.CurrentClusterFaultTolerance.GetName()
	}
	desired := ""
	if ft.DesiredClusterFaultTolerance != nil {
		desired = ft.DesiredClusterFaultTolerance.GetName()
	}
	domain := ""
	if ft.DomainAwarenessLevel != nil {
		domain = ft.DomainAwarenessLevel.GetName()
	}
	cassandra := false
	zookeeper := false
	if ft.RedundancyStatus != nil {
		if ft.RedundancyStatus.IsCassandraPreparationDone != nil {
			cassandra = *ft.RedundancyStatus.IsCassandraPreparationDone
		}
		if ft.RedundancyStatus.IsZookeeperPreparationDone != nil {
			zookeeper = *ft.RedundancyStatus.IsZookeeperPreparationDone
		}
	}

	res, err := CreateResource(a.MqlRuntime, "nutanix.cluster.faultToleranceState", map[string]*llx.RawData{
		"__id":                         llx.StringData(fmt.Sprintf("%s/faultTolerance", a.clusterId)),
		"currentClusterFaultTolerance": llx.StringData(current),
		"desiredClusterFaultTolerance": llx.StringData(desired),
		"currentMaxFaultTolerance":     llx.IntData(derefInt(ft.CurrentMaxFaultTolerance)),
		"desiredMaxFaultTolerance":     llx.IntData(derefInt(ft.DesiredMaxFaultTolerance)),
		"domainAwarenessLevel":         llx.StringData(domain),
		"cassandraPreparationDone":     llx.BoolData(cassandra),
		"zookeeperPreparationDone":     llx.BoolData(zookeeper),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNutanixClusterFaultToleranceState), nil
}

func (a *mqlNutanixCluster) nodes() ([]any, error) {
	res := []any{}
	for i := range a.cacheNodeList {
		n := a.cacheNodeList[i]
		nodeUuid := ""
		if n.NodeUuid != nil {
			nodeUuid = *n.NodeUuid
		}
		mqlNode, err := CreateResource(a.MqlRuntime, "nutanix.cluster.node", map[string]*llx.RawData{
			"__id":           llx.StringData(subResourceID(nodeUuid, a.clusterId, "node", i)),
			"id":             llx.StringData(nodeUuid),
			"hostIp":         llx.StringData(clusterIPToString(n.HostIp)),
			"controllerVmIp": llx.StringData(clusterIPToString(n.ControllerVmIp)),
		})
		if err != nil {
			return nil, err
		}
		node := mqlNode.(*mqlNutanixClusterNode)
		node.cacheClusterId = a.clusterId
		node.cacheNodeUuid = nodeUuid
		res = append(res, node)
	}
	return res, nil
}

type mqlNutanixClusterNodeInternal struct {
	cacheClusterId string
	cacheNodeUuid  string
}

func (a *mqlNutanixClusterNode) host() (*mqlNutanixHost, error) {
	if a.cacheClusterId == "" || a.cacheNodeUuid == "" {
		a.Host.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := hostByID(a.MqlRuntime, a.cacheClusterId, a.cacheNodeUuid)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Host.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

// hostByID resolves a host by the pair of identifiers the clustermgmt API
// needs, the external UUID of the owning cluster and the external UUID of the
// host itself, returning the cached resource when it was already created
// during this scan. A nil result means the host could not be found.
func hostByID(runtime *plugin.Runtime, clusterID, hostID string) (*mqlNutanixHost, error) {
	if h, ok := cachedResource[*mqlNutanixHost](runtime, "nutanix.host", hostID); ok {
		return h, nil
	}
	conn := runtime.Connection.(*connection.NutanixConnection)
	resp, err := guard(conn.CmgMu(), func() (*clustermgmtconfig.GetHostApiResponse, error) {
		return conn.ClustersApi().GetHostById(&clusterID, &hostID)
	})
	if err != nil {
		return nil, err
	}
	data := resp.GetData()
	if data == nil {
		return nil, nil
	}
	host, ok := data.(clustermgmtconfig.Host)
	if !ok {
		return nil, nil
	}
	return newMqlHost(runtime, &host)
}

func newMqlHost(runtime *plugin.Runtime, h *clustermgmtconfig.Host) (*mqlNutanixHost, error) {
	if h.ExtId == nil {
		return nil, nil
	}
	hypervisorType := ""
	hypervisorFullName := ""
	hypervisorState := ""
	hypervisorAcropolisConnectionState := ""
	hypervisorExternalAddress := ""
	hypervisorUserName := ""
	vmCount := int64(0)
	if h.Hypervisor != nil {
		hv := h.Hypervisor
		if hv.Type != nil {
			hypervisorType = hv.Type.GetName()
		}
		if hv.FullName != nil {
			hypervisorFullName = *hv.FullName
		}
		if hv.State != nil {
			hypervisorState = hv.State.GetName()
		}
		if hv.AcropolisConnectionState != nil {
			hypervisorAcropolisConnectionState = hv.AcropolisConnectionState.GetName()
		}
		hypervisorExternalAddress = clusterIPToString(hv.ExternalAddress)
		if hv.UserName != nil {
			hypervisorUserName = *hv.UserName
		}
		vmCount = derefInt64(hv.NumberOfVms)
	}

	hostType := ""
	if h.HostType != nil {
		hostType = h.HostType.GetName()
	}
	nodeStatus := ""
	if h.NodeStatus != nil {
		nodeStatus = h.NodeStatus.GetName()
	}

	gpus := []any{}
	for _, g := range h.GpuList {
		gpus = append(gpus, g)
	}

	res, err := CreateResource(runtime, "nutanix.host", map[string]*llx.RawData{
		"__id":             llx.StringDataPtr(h.ExtId),
		"id":               llx.StringDataPtr(h.ExtId),
		"tenantId":         llx.StringDataPtr(h.TenantId),
		"name":             llx.StringDataPtr(h.HostName),
		"hostType":         llx.StringData(hostType),
		"blockModel":       llx.StringDataPtr(h.BlockModel),
		"blockSerial":      llx.StringDataPtr(h.BlockSerial),
		"rackableUnitUuid": llx.StringDataPtr(h.RackableUnitUuid),
		// The v4.0 API does not report a node-level serial number.
		"cpuModel":                           llx.StringDataPtr(h.CpuModel),
		"cpuCores":                           llx.IntData(derefInt64(h.NumberOfCpuCores)),
		"cpuSockets":                         llx.IntData(derefInt64(h.NumberOfCpuSockets)),
		"cpuThreads":                         llx.IntData(derefInt64(h.NumberOfCpuThreads)),
		"cpuCapacityHz":                      llx.IntData(derefInt64(h.CpuCapacityHz)),
		"cpuFrequencyHz":                     llx.IntData(derefInt64(h.CpuFrequencyHz)),
		"memorySizeBytes":                    llx.IntData(derefInt64(h.MemorySizeBytes)),
		"gpuDriverVersion":                   llx.StringDataPtr(h.GpuDriverVersion),
		"gpus":                               llx.ArrayData(gpus, types.String),
		"hypervisorType":                     llx.StringData(hypervisorType),
		"hypervisorFullName":                 llx.StringData(hypervisorFullName),
		"hypervisorState":                    llx.StringData(hypervisorState),
		"hypervisorAcropolisConnectionState": llx.StringData(hypervisorAcropolisConnectionState),
		"hypervisorExternalAddress":          llx.StringData(hypervisorExternalAddress),
		"hypervisorUserName":                 llx.StringData(hypervisorUserName),
		"vmCount":                            llx.IntData(vmCount),
		"bootTime":                           llx.TimeDataPtr(usecsToTime(h.BootTimeUsecs)),
		"nodeStatus":                         llx.StringData(nodeStatus),
		"maintenanceState":                   llx.StringDataPtr(h.MaintenanceState),
		"isDegraded":                         llx.BoolData(derefBool(h.IsDegraded)),
		"isRebootPending":                    llx.BoolData(derefBool(h.IsRebootPending)),
		"isSecureBooted":                     llx.BoolData(derefBool(h.IsSecureBooted)),
		"isHardwareVirtualized":              llx.BoolData(derefBool(h.IsHardwareVirtualized)),
		"hasCsr":                             llx.BoolData(derefBool(h.HasCsr)),
		"failoverClusterFqdn":                llx.StringDataPtr(h.FailoverClusterFqdn),
		"failoverClusterNodeStatus":          llx.StringDataPtr(h.FailoverClusterNodeStatus),
		"defaultVmLocation":                  llx.StringDataPtr(h.DefaultVmLocation),
		"defaultVhdLocation":                 llx.StringDataPtr(h.DefaultVhdLocation),
	})
	if err != nil {
		return nil, err
	}
	mqlHost := res.(*mqlNutanixHost)
	if h.Cluster != nil && h.Cluster.Uuid != nil {
		mqlHost.clusterUuid = *h.Cluster.Uuid
	}
	mqlHost.hostId = ""
	if h.ExtId != nil {
		mqlHost.hostId = *h.ExtId
	}
	if h.DefaultVmContainerUuid != nil {
		mqlHost.cacheDefaultVmContainerId = *h.DefaultVmContainerUuid
	}
	if h.DefaultVhdContainerUuid != nil {
		mqlHost.cacheDefaultVhdContainerId = *h.DefaultVhdContainerUuid
	}
	mqlHost.cacheControllerVm = h.ControllerVm
	mqlHost.cacheIpmi = h.Ipmi
	mqlHost.cacheDisks = h.Disk
	return mqlHost, nil
}

func (a *mqlNutanixHost) controllerVm() (*mqlNutanixHostControllerVmInfo, error) {
	cvm := a.cacheControllerVm
	if cvm == nil {
		a.ControllerVm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	rdma := []any{}
	for i := range cvm.RdmaBackplaneAddress {
		rdma = append(rdma, clusterIPToString(&cvm.RdmaBackplaneAddress[i]))
	}
	res, err := CreateResource(a.MqlRuntime, "nutanix.host.controllerVmInfo", map[string]*llx.RawData{
		"__id":                   llx.StringData(fmt.Sprintf("%s/controllerVm", a.hostId)),
		"externalAddress":        llx.StringData(clusterIPToString(cvm.ExternalAddress)),
		"backplaneAddress":       llx.StringData(clusterIPToString(cvm.BackplaneAddress)),
		"natIp":                  llx.StringData(clusterIPToString(cvm.NatIp)),
		"natPort":                llx.IntData(derefInt(cvm.NatPort)),
		"isInMaintenanceMode":    llx.BoolData(derefBool(cvm.IsInMaintenanceMode)),
		"rdmaBackplaneAddresses": llx.ArrayData(rdma, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNutanixHostControllerVmInfo), nil
}

func (a *mqlNutanixHost) ipmi() (*mqlNutanixHostIpmiInfo, error) {
	ipmi := a.cacheIpmi
	if ipmi == nil {
		a.Ipmi.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(a.MqlRuntime, "nutanix.host.ipmiInfo", map[string]*llx.RawData{
		"__id":     llx.StringData(fmt.Sprintf("%s/ipmi", a.hostId)),
		"ip":       llx.StringData(clusterIPToString(ipmi.Ip)),
		"username": llx.StringDataPtr(ipmi.Username),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNutanixHostIpmiInfo), nil
}

func (a *mqlNutanixHost) disks() ([]any, error) {
	res := []any{}
	for i := range a.cacheDisks {
		d := a.cacheDisks[i]
		uuid := ""
		if d.Uuid != nil {
			uuid = *d.Uuid
		}
		storageTier := ""
		if d.StorageTier != nil {
			storageTier = d.StorageTier.GetName()
		}
		mqlDisk, err := CreateResource(a.MqlRuntime, "nutanix.host.disk", map[string]*llx.RawData{
			"__id":        llx.StringData(subResourceID(uuid, a.hostId, "disk", i)),
			"id":          llx.StringData(uuid),
			"mountPath":   llx.StringDataPtr(d.MountPath),
			"serialId":    llx.StringDataPtr(d.SerialId),
			"sizeInBytes": llx.IntData(derefInt64(d.SizeInBytes)),
			"storageTier": llx.StringData(storageTier),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDisk)
	}
	return res, nil
}

func newMqlVm(runtime *plugin.Runtime, vm *vmmconfig.Vm) (*mqlNutanixVm, error) {
	if vm.ExtId == nil {
		return nil, nil
	}
	powerState := ""
	if vm.PowerState != nil {
		powerState = vm.PowerState.GetName()
	}
	machineType := ""
	if vm.MachineType != nil {
		machineType = vm.MachineType.GetName()
	}
	protectionType := ""
	if vm.ProtectionType != nil {
		protectionType = vm.ProtectionType.GetName()
	}

	categories := []any{}
	for _, cat := range vm.Categories {
		if cat.ExtId != nil {
			categories = append(categories, *cat.ExtId)
		}
	}

	// Source carries the entity the VM was created from. When the entity is a
	// VM, sourceVm resolves it; otherwise the raw ExtId is exposed as sourceId.
	sourceType := ""
	sourceVmId := ""
	sourceId := ""
	if vm.Source != nil {
		if vm.Source.EntityType != nil {
			sourceType = vm.Source.EntityType.GetName()
		}
		if vm.Source.ExtId != nil {
			if sourceType == "VM" {
				sourceVmId = *vm.Source.ExtId
			} else {
				sourceId = *vm.Source.ExtId
			}
		}
	}

	res, err := CreateResource(runtime, "nutanix.vm", map[string]*llx.RawData{
		"__id":     llx.StringDataPtr(vm.ExtId),
		"id":       llx.StringDataPtr(vm.ExtId),
		"tenantId": llx.StringDataPtr(vm.TenantId),
		// The v4.0 API does not report a project reference on the VM.
		"sourceType":                        llx.StringData(sourceType),
		"sourceId":                          llx.StringData(sourceId),
		"name":                              llx.StringDataPtr(vm.Name),
		"description":                       llx.StringDataPtr(vm.Description),
		"powerState":                        llx.StringData(powerState),
		"numSockets":                        llx.IntData(derefInt(vm.NumSockets)),
		"numCoresPerSocket":                 llx.IntData(derefInt(vm.NumCoresPerSocket)),
		"numThreadsPerCore":                 llx.IntData(derefInt(vm.NumThreadsPerCore)),
		"numNumaNodes":                      llx.IntData(derefInt(vm.NumNumaNodes)),
		"memorySizeBytes":                   llx.IntData(derefInt64(vm.MemorySizeBytes)),
		"biosUuid":                          llx.StringDataPtr(vm.BiosUuid),
		"generationUuid":                    llx.StringDataPtr(vm.GenerationUuid),
		"machineType":                       llx.StringData(machineType),
		"hardwareClockTimezone":             llx.StringDataPtr(vm.HardwareClockTimezone),
		"protectionType":                    llx.StringData(protectionType),
		"categories":                        llx.ArrayData(categories, types.String),
		"isAgentVm":                         llx.BoolData(derefBool(vm.IsAgentVm)),
		"isCpuHotplugEnabled":               llx.BoolData(derefBool(vm.IsCpuHotplugEnabled)),
		"isCpuPassthroughEnabled":           llx.BoolData(derefBool(vm.IsCpuPassthroughEnabled)),
		"isMemoryOvercommitEnabled":         llx.BoolData(derefBool(vm.IsMemoryOvercommitEnabled)),
		"isVcpuHardPinningEnabled":          llx.BoolData(derefBool(vm.IsVcpuHardPinningEnabled)),
		"isGpuConsoleEnabled":               llx.BoolData(derefBool(vm.IsGpuConsoleEnabled)),
		"isVgaConsoleEnabled":               llx.BoolData(derefBool(vm.IsVgaConsoleEnabled)),
		"isScsiControllerEnabled":           llx.BoolData(derefBool(vm.IsScsiControllerEnabled)),
		"isLiveMigrateCapable":              llx.BoolData(derefBool(vm.IsLiveMigrateCapable)),
		"isCrossClusterMigrationInProgress": llx.BoolData(derefBool(vm.IsCrossClusterMigrationInProgress)),
		"isBrandingEnabled":                 llx.BoolData(derefBool(vm.IsBrandingEnabled)),
		"createTime":                        llx.TimeDataPtr(vm.CreateTime),
		"updateTime":                        llx.TimeDataPtr(vm.UpdateTime),
	})
	if err != nil {
		return nil, err
	}
	mqlVm := res.(*mqlNutanixVm)
	if vm.ExtId != nil {
		mqlVm.vmId = *vm.ExtId
	}
	if vm.Cluster != nil && vm.Cluster.ExtId != nil {
		mqlVm.clusterExtId = *vm.Cluster.ExtId
	}
	if vm.Host != nil && vm.Host.ExtId != nil {
		mqlVm.hostExtId = *vm.Host.ExtId
	}
	if vm.OwnershipInfo != nil && vm.OwnershipInfo.Owner != nil && vm.OwnershipInfo.Owner.ExtId != nil {
		mqlVm.cacheOwnerId = *vm.OwnershipInfo.Owner.ExtId
	}
	mqlVm.cacheSourceVmId = sourceVmId
	mqlVm.cacheDisks = vm.Disks
	mqlVm.cacheNics = vm.Nics
	mqlVm.cacheGpus = vm.Gpus
	mqlVm.cacheCdRoms = vm.CdRoms
	mqlVm.cacheGuestTools = vm.GuestTools
	return mqlVm, nil
}

func (a *mqlNutanixVm) disks() ([]any, error) {
	res := []any{}
	for i := range a.cacheDisks {
		d := a.cacheDisks[i]
		extId := ""
		if d.ExtId != nil {
			extId = *d.ExtId
		}
		busType := ""
		busIndex := int64(0)
		if d.DiskAddress != nil {
			if d.DiskAddress.BusType != nil {
				busType = d.DiskAddress.BusType.GetName()
			}
			busIndex = derefInt(d.DiskAddress.Index)
		}
		tenantId := ""
		if d.TenantId != nil {
			tenantId = *d.TenantId
		}
		sizeBytes := int64(0)
		diskExtId := ""
		storageContainerId := ""
		isMigrating := false
		// dataSource records the image or VM disk a disk's contents were seeded
		// from. The reference is a OneOf of either an image or a VM disk.
		sourceImageId := ""
		sourceDiskId := ""
		sourceVmId := ""
		if d.BackingInfo != nil {
			if vd, ok := d.BackingInfo.GetValue().(vmmconfig.VmDisk); ok {
				sizeBytes = derefInt64(vd.DiskSizeBytes)
				if vd.DiskExtId != nil {
					diskExtId = *vd.DiskExtId
				}
				if vd.StorageContainer != nil && vd.StorageContainer.ExtId != nil {
					storageContainerId = *vd.StorageContainer.ExtId
				}
				isMigrating = derefBool(vd.IsMigrationInProgress)
				if vd.DataSource != nil && vd.DataSource.Reference != nil {
					switch ref := vd.DataSource.Reference.GetValue().(type) {
					case vmmconfig.ImageReference:
						if ref.ImageExtId != nil {
							sourceImageId = *ref.ImageExtId
						}
					case vmmconfig.VmDiskReference:
						if ref.DiskExtId != nil {
							sourceDiskId = *ref.DiskExtId
						}
						if ref.VmReference != nil && ref.VmReference.ExtId != nil {
							sourceVmId = *ref.VmReference.ExtId
						}
					}
				}
			}
		}
		mqlDisk, err := CreateResource(a.MqlRuntime, "nutanix.vm.disk", map[string]*llx.RawData{
			"__id":                  llx.StringData(subResourceID(extId, a.vmId, "disk", i)),
			"id":                    llx.StringData(extId),
			"tenantId":              llx.StringData(tenantId),
			"busType":               llx.StringData(busType),
			"busIndex":              llx.IntData(busIndex),
			"sizeBytes":             llx.IntData(sizeBytes),
			"diskExtId":             llx.StringData(diskExtId),
			"sourceDiskId":          llx.StringData(sourceDiskId),
			"isMigrationInProgress": llx.BoolData(isMigrating),
		})
		if err != nil {
			return nil, err
		}
		mqlVmDisk := mqlDisk.(*mqlNutanixVmDisk)
		mqlVmDisk.cacheStorageContainerId = storageContainerId
		mqlVmDisk.cacheSourceVmId = sourceVmId
		mqlVmDisk.cacheSourceImageId = sourceImageId
		res = append(res, mqlVmDisk)
	}
	return res, nil
}

type mqlNutanixVmDiskInternal struct {
	cacheStorageContainerId string
	cacheSourceVmId         string
	cacheSourceImageId      string
}

func (a *mqlNutanixVmDisk) sourceImage() (*mqlNutanixImage, error) {
	if a.cacheSourceImageId == "" {
		a.SourceImage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := imageByID(a.MqlRuntime, a.cacheSourceImageId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.SourceImage.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixVmDisk) sourceVm() (*mqlNutanixVm, error) {
	if a.cacheSourceVmId == "" {
		a.SourceVm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := vmByID(a.MqlRuntime, a.cacheSourceVmId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.SourceVm.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixVmDisk) storageContainer() (*mqlNutanixStorageContainer, error) {
	if a.cacheStorageContainerId == "" {
		a.StorageContainer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := storageContainerByID(a.MqlRuntime, a.cacheStorageContainerId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.StorageContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixVm) nics() ([]any, error) {
	res := []any{}
	for i := range a.cacheNics {
		n := a.cacheNics[i]
		extId := ""
		if n.ExtId != nil {
			extId = *n.ExtId
		}
		macAddress := ""
		model := ""
		isConnected := false
		if n.BackingInfo != nil {
			if n.BackingInfo.MacAddress != nil {
				macAddress = *n.BackingInfo.MacAddress
			}
			if n.BackingInfo.Model != nil {
				model = n.BackingInfo.Model.GetName()
			}
			isConnected = derefBool(n.BackingInfo.IsConnected)
		}
		nicType := ""
		vlanMode := ""
		subnetId := ""
		ipAddresses := []any{}
		learnedIps := []any{}
		if n.NetworkInfo != nil {
			ni := n.NetworkInfo
			if ni.NicType != nil {
				nicType = ni.NicType.GetName()
			}
			if ni.VlanMode != nil {
				vlanMode = ni.VlanMode.GetName()
			}
			if ni.Subnet != nil && ni.Subnet.ExtId != nil {
				subnetId = *ni.Subnet.ExtId
			}
			if ni.Ipv4Config != nil {
				if ni.Ipv4Config.IpAddress != nil {
					ipAddresses = append(ipAddresses, vmIPv4ToString(ni.Ipv4Config.IpAddress))
				}
				for j := range ni.Ipv4Config.SecondaryIpAddressList {
					ipAddresses = append(ipAddresses, vmIPv4ToString(&ni.Ipv4Config.SecondaryIpAddressList[j]))
				}
			}
			if ni.Ipv4Info != nil {
				for j := range ni.Ipv4Info.LearnedIpAddresses {
					learnedIps = append(learnedIps, vmIPv4ToString(&ni.Ipv4Info.LearnedIpAddresses[j]))
				}
			}
		}
		mqlNic, err := CreateResource(a.MqlRuntime, "nutanix.vm.nic", map[string]*llx.RawData{
			"__id":               llx.StringData(subResourceID(extId, a.vmId, "nic", i)),
			"id":                 llx.StringData(extId),
			"macAddress":         llx.StringData(macAddress),
			"model":              llx.StringData(model),
			"isConnected":        llx.BoolData(isConnected),
			"nicType":            llx.StringData(nicType),
			"vlanMode":           llx.StringData(vlanMode),
			"ipAddresses":        llx.ArrayData(ipAddresses, types.String),
			"learnedIpAddresses": llx.ArrayData(learnedIps, types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlNic.(*mqlNutanixVmNic).cacheSubnetId = subnetId
		res = append(res, mqlNic)
	}
	return res, nil
}

type mqlNutanixVmNicInternal struct {
	cacheSubnetId string
}

func (a *mqlNutanixVmNic) subnet() (*mqlNutanixNetworkSubnet, error) {
	if a.cacheSubnetId == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := subnetByID(a.MqlRuntime, a.cacheSubnetId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixVm) gpus() ([]any, error) {
	res := []any{}
	for i := range a.cacheGpus {
		g := a.cacheGpus[i]
		extId := ""
		if g.ExtId != nil {
			extId = *g.ExtId
		}
		mode := ""
		if g.Mode != nil {
			mode = g.Mode.GetName()
		}
		vendor := ""
		if g.Vendor != nil {
			vendor = g.Vendor.GetName()
		}
		mqlGpu, err := CreateResource(a.MqlRuntime, "nutanix.vm.gpu", map[string]*llx.RawData{
			"__id":                   llx.StringData(subResourceID(extId, a.vmId, "gpu", i)),
			"id":                     llx.StringData(extId),
			"name":                   llx.StringDataPtr(g.Name),
			"mode":                   llx.StringData(mode),
			"vendor":                 llx.StringData(vendor),
			"deviceId":               llx.IntData(derefInt(g.DeviceId)),
			"fraction":               llx.IntData(derefInt(g.Fraction)),
			"frameBufferSizeBytes":   llx.IntData(derefInt64(g.FrameBufferSizeBytes)),
			"numVirtualDisplayHeads": llx.IntData(derefInt(g.NumVirtualDisplayHeads)),
			"guestDriverVersion":     llx.StringDataPtr(g.GuestDriverVersion),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGpu)
	}
	return res, nil
}

func (a *mqlNutanixVm) cdRoms() ([]any, error) {
	res := []any{}
	for i := range a.cacheCdRoms {
		c := a.cacheCdRoms[i]
		extId := ""
		if c.ExtId != nil {
			extId = *c.ExtId
		}
		isoType := ""
		if c.IsoType != nil {
			isoType = c.IsoType.GetName()
		}
		busType := ""
		busIndex := int64(0)
		if c.DiskAddress != nil {
			if c.DiskAddress.BusType != nil {
				busType = c.DiskAddress.BusType.GetName()
			}
			busIndex = derefInt(c.DiskAddress.Index)
		}
		sizeBytes := int64(0)
		storageContainerId := ""
		if c.BackingInfo != nil {
			sizeBytes = derefInt64(c.BackingInfo.DiskSizeBytes)
			if c.BackingInfo.StorageContainer != nil && c.BackingInfo.StorageContainer.ExtId != nil {
				storageContainerId = *c.BackingInfo.StorageContainer.ExtId
			}
		}
		mqlCdRom, err := CreateResource(a.MqlRuntime, "nutanix.vm.cdrom", map[string]*llx.RawData{
			"__id":      llx.StringData(subResourceID(extId, a.vmId, "cdrom", i)),
			"id":        llx.StringData(extId),
			"isoType":   llx.StringData(isoType),
			"busType":   llx.StringData(busType),
			"busIndex":  llx.IntData(busIndex),
			"sizeBytes": llx.IntData(sizeBytes),
		})
		if err != nil {
			return nil, err
		}
		mqlCdRom.(*mqlNutanixVmCdrom).cacheStorageContainerId = storageContainerId
		res = append(res, mqlCdRom)
	}
	return res, nil
}

type mqlNutanixVmCdromInternal struct {
	cacheStorageContainerId string
}

func (a *mqlNutanixVmCdrom) storageContainer() (*mqlNutanixStorageContainer, error) {
	if a.cacheStorageContainerId == "" {
		a.StorageContainer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := storageContainerByID(a.MqlRuntime, a.cacheStorageContainerId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.StorageContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixVm) guestTools() (*mqlNutanixVmGuestToolsInfo, error) {
	gt := a.cacheGuestTools
	if gt == nil {
		a.GuestTools.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	capabilities := []any{}
	for _, c := range gt.Capabilities {
		capabilities = append(capabilities, c.GetName())
	}
	res, err := CreateResource(a.MqlRuntime, "nutanix.vm.guestToolsInfo", map[string]*llx.RawData{
		"__id":                 llx.StringData(fmt.Sprintf("%s/guestTools", a.vmId)),
		"isEnabled":            llx.BoolData(derefBool(gt.IsEnabled)),
		"isInstalled":          llx.BoolData(derefBool(gt.IsInstalled)),
		"isReachable":          llx.BoolData(derefBool(gt.IsReachable)),
		"isIsoInserted":        llx.BoolData(derefBool(gt.IsIsoInserted)),
		"isVssSnapshotCapable": llx.BoolData(derefBool(gt.IsVssSnapshotCapable)),
		"version":              llx.StringDataPtr(gt.Version),
		"availableVersion":     llx.StringDataPtr(gt.AvailableVersion),
		"guestOsVersion":       llx.StringDataPtr(gt.GuestOsVersion),
		"capabilities":         llx.ArrayData(capabilities, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNutanixVmGuestToolsInfo), nil
}

// ---------------------------------------------------------------------------
// cross-references
// ---------------------------------------------------------------------------

type mqlNutanixHostInternal struct {
	hostId                     string
	clusterUuid                string
	cacheDefaultVmContainerId  string
	cacheDefaultVhdContainerId string
	cacheControllerVm          *clustermgmtconfig.ControllerVmReference
	cacheIpmi                  *clustermgmtconfig.IpmiReference
	cacheDisks                 []clustermgmtconfig.DiskReference
}

func (a *mqlNutanixHost) defaultVmContainer() (*mqlNutanixStorageContainer, error) {
	if a.cacheDefaultVmContainerId == "" {
		a.DefaultVmContainer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := storageContainerByID(a.MqlRuntime, a.cacheDefaultVmContainerId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.DefaultVmContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixHost) defaultVhdContainer() (*mqlNutanixStorageContainer, error) {
	if a.cacheDefaultVhdContainerId == "" {
		a.DefaultVhdContainer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := storageContainerByID(a.MqlRuntime, a.cacheDefaultVhdContainerId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.DefaultVhdContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixHost) cluster() (*mqlNutanixCluster, error) {
	if a.clusterUuid == "" {
		a.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := clusterByID(a.MqlRuntime, a.clusterUuid)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

type mqlNutanixVmInternal struct {
	vmId            string
	clusterExtId    string
	hostExtId       string
	cacheOwnerId    string
	cacheSourceVmId string
	cacheDisks      []vmmconfig.Disk
	cacheNics       []vmmconfig.Nic
	cacheGpus       []vmmconfig.Gpu
	cacheCdRoms     []vmmconfig.CdRom
	cacheGuestTools *vmmconfig.GuestTools
}

func (a *mqlNutanixVm) owner() (*mqlNutanixIamUser, error) {
	if a.cacheOwnerId == "" {
		a.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := userByID(a.MqlRuntime, a.cacheOwnerId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Owner.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixVm) sourceVm() (*mqlNutanixVm, error) {
	if a.cacheSourceVmId == "" {
		a.SourceVm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := vmByID(a.MqlRuntime, a.cacheSourceVmId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.SourceVm.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

// vmByID resolves a Nutanix VM by its external UUID, returning the cached
// resource when it was already created during this scan and otherwise fetching
// it on demand. A nil result means the VM could not be found.
func vmByID(runtime *plugin.Runtime, vmID string) (*mqlNutanixVm, error) {
	if v, ok := cachedResource[*mqlNutanixVm](runtime, "nutanix.vm", vmID); ok {
		return v, nil
	}
	conn := runtime.Connection.(*connection.NutanixConnection)
	id := vmID
	resp, err := guard(conn.VmmMu(), func() (*vmmconfig.GetVmApiResponse, error) {
		return conn.VmApi().GetVmById(&id)
	})
	if err != nil {
		return nil, err
	}
	data := resp.GetData()
	if data == nil {
		return nil, nil
	}
	vm, ok := data.(vmmconfig.Vm)
	if !ok {
		return nil, nil
	}
	return newMqlVm(runtime, &vm)
}

func (a *mqlNutanixVm) cluster() (*mqlNutanixCluster, error) {
	if a.clusterExtId == "" {
		a.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := clusterByID(a.MqlRuntime, a.clusterExtId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (a *mqlNutanixVm) host() (*mqlNutanixHost, error) {
	if a.hostExtId == "" || a.clusterExtId == "" {
		a.Host.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := hostByID(a.MqlRuntime, a.clusterExtId, a.hostExtId)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.Host.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func clusterByID(runtime *plugin.Runtime, clusterID string) (*mqlNutanixCluster, error) {
	if c, ok := cachedResource[*mqlNutanixCluster](runtime, "nutanix.cluster", clusterID); ok {
		return c, nil
	}
	conn := runtime.Connection.(*connection.NutanixConnection)
	id := clusterID
	resp, err := guard(conn.CmgMu(), func() (*clustermgmtconfig.GetClusterApiResponse, error) {
		return conn.ClustersApi().GetClusterById(&id, nil)
	})
	if err != nil {
		return nil, err
	}
	data := resp.GetData()
	if data == nil {
		return nil, nil
	}
	cluster, ok := data.(clustermgmtconfig.Cluster)
	if !ok {
		return nil, nil
	}
	return newMqlCluster(runtime, &cluster)
}
