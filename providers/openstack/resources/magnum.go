// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/x509"
	"sync"

	"github.com/gophercloud/gophercloud/v2/openstack/containerinfra/v1/clusters"
	"github.com/gophercloud/gophercloud/v2/openstack/containerinfra/v1/clustertemplates"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.containerinfra.cluster ----

type mqlOpenstackContainerinfraClusterInternal struct {
	cacheProjectID         string
	cacheClusterTemplateID string
	cacheKeyPair           string
	cacheFlavorID          string
	cacheMasterFlavorID    string
	cacheFixedNetwork      string
	cacheFixedSubnet       string
	cacheUserID            string
	cacheStackID           string

	// The certificate-authority fields share one fetch; see
	// certificateAuthority in magnum_nodegroups.go.
	caOnce sync.Once
	caCert *x509.Certificate
	caErr  error
}

func (r *mqlOpenstackContainerinfraCluster) id() (string, error) {
	return "openstack.containerinfra.cluster/" + r.Id.Data, nil
}

func initOpenstackContainerinfraCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetClusters()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		c := raw.(*mqlOpenstackContainerinfraCluster)
		if c.Id.Data == id {
			return args, c, nil
		}
	}
	initSyntheticID("openstack.containerinfra.cluster", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) clusters() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ContainerInfraClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := clusters.ListDetail(client, nil).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := clusters.ExtractClusters(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		cl := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.containerinfra.cluster", map[string]*llx.RawData{
			"__id":              llx.StringData("openstack.containerinfra.cluster/" + cl.UUID),
			"id":                llx.StringData(cl.UUID),
			"name":              llx.StringData(cl.Name),
			"status":            llx.StringData(cl.Status),
			"statusReason":      llx.StringData(cl.StatusReason),
			"healthStatus":      llx.StringData(cl.HealthStatus),
			"coeVersion":        llx.StringData(cl.COEVersion),
			"apiAddress":        llx.StringData(cl.APIAddress),
			"masterCount":       llx.IntData(int64(cl.MasterCount)),
			"nodeCount":         llx.IntData(int64(cl.NodeCount)),
			"masterAddresses":   stringSliceData(cl.MasterAddresses),
			"nodeAddresses":     stringSliceData(cl.NodeAddresses),
			"dockerVolumeSize":  llx.IntData(int64(cl.DockerVolumeSize)),
			"floatingIpEnabled": llx.BoolData(cl.FloatingIPEnabled),
			"masterLbEnabled":   llx.BoolData(cl.MasterLBEnabled),
			"discoveryUrl":      llx.StringData(cl.DiscoveryURL),
			"labels":            stringMapData(cl.Labels),
			"createdAt":         llx.TimeDataPtr(timePtr(cl.CreatedAt)),
			"updatedAt":         llx.TimeDataPtr(timePtr(cl.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlCluster := res.(*mqlOpenstackContainerinfraCluster)
		mqlCluster.cacheProjectID = cl.ProjectID
		mqlCluster.cacheClusterTemplateID = cl.ClusterTemplateID
		mqlCluster.cacheKeyPair = cl.KeyPair
		mqlCluster.cacheFlavorID = cl.FlavorID
		mqlCluster.cacheMasterFlavorID = cl.MasterFlavorID
		mqlCluster.cacheFixedNetwork = cl.FixedNetwork
		mqlCluster.cacheFixedSubnet = cl.FixedSubnet
		mqlCluster.cacheUserID = cl.UserID
		mqlCluster.cacheStackID = cl.StackID
		out = append(out, mqlCluster)
	}
	return out, nil
}

func (r *mqlOpenstackContainerinfraCluster) clusterTemplate() (*mqlOpenstackContainerinfraClusterTemplate, error) {
	if r.cacheClusterTemplateID == "" {
		r.ClusterTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.containerinfra.clusterTemplate", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheClusterTemplateID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackContainerinfraClusterTemplate), nil
}

func (r *mqlOpenstackContainerinfraCluster) keypair() (*mqlOpenstackComputeKeypair, error) {
	return resolveKeypair(r.MqlRuntime, r.cacheKeyPair, &r.Keypair)
}

func (r *mqlOpenstackContainerinfraCluster) flavor() (*mqlOpenstackComputeFlavor, error) {
	return resolveFlavor(r.MqlRuntime, r.cacheFlavorID, &r.Flavor)
}

func (r *mqlOpenstackContainerinfraCluster) masterFlavor() (*mqlOpenstackComputeFlavor, error) {
	return resolveFlavor(r.MqlRuntime, r.cacheMasterFlavorID, &r.MasterFlavor)
}

func (r *mqlOpenstackContainerinfraCluster) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackContainerinfraCluster) user() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheUserID, &r.User)
}

func (r *mqlOpenstackContainerinfraCluster) stack() (*mqlOpenstackOrchestrationStack, error) {
	if r.cacheStackID == "" {
		r.Stack.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.orchestration.stack", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheStackID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOrchestrationStack), nil
}

// fixedNetwork / fixedSubnet resolve the cluster's fixed network/subnet to
// typed Neutron references. Magnum accepts either a UUID or a name here; the
// reference resolves cleanly when it is a UUID (or a name matching a listed
// resource) and is null otherwise.
func (r *mqlOpenstackContainerinfraCluster) fixedNetwork() (*mqlOpenstackNetwork, error) {
	if r.cacheFixedNetwork == "" {
		r.FixedNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.network", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheFixedNetwork),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackNetwork), nil
}

func (r *mqlOpenstackContainerinfraCluster) fixedSubnet() (*mqlOpenstackSubnet, error) {
	if r.cacheFixedSubnet == "" {
		r.FixedSubnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.subnet", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheFixedSubnet),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSubnet), nil
}

// ---- openstack.containerinfra.clusterTemplate ----

type mqlOpenstackContainerinfraClusterTemplateInternal struct {
	cacheImageID           string
	cacheExternalNetworkID string
	cacheFlavorID          string
	cacheMasterFlavorID    string
	cacheKeyPairID         string
	cacheProjectID         string
	cacheUserID            string
}

func (r *mqlOpenstackContainerinfraClusterTemplate) id() (string, error) {
	return "openstack.containerinfra.clusterTemplate/" + r.Id.Data, nil
}

func initOpenstackContainerinfraClusterTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetClusterTemplates()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		t := raw.(*mqlOpenstackContainerinfraClusterTemplate)
		if t.Id.Data == id {
			return args, t, nil
		}
	}
	initSyntheticID("openstack.containerinfra.clusterTemplate", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) clusterTemplates() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ContainerInfraClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := clustertemplates.List(client, nil).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := clustertemplates.ExtractClusterTemplates(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		t := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.containerinfra.clusterTemplate", map[string]*llx.RawData{
			"__id":                llx.StringData("openstack.containerinfra.clusterTemplate/" + t.UUID),
			"id":                  llx.StringData(t.UUID),
			"name":                llx.StringData(t.Name),
			"coe":                 llx.StringData(t.COE),
			"clusterDistro":       llx.StringData(t.ClusterDistro),
			"serverType":          llx.StringData(t.ServerType),
			"tlsDisabled":         llx.BoolData(t.TLSDisabled),
			"public":              llx.BoolData(t.Public),
			"hidden":              llx.BoolData(t.Hidden),
			"registryEnabled":     llx.BoolData(t.RegistryEnabled),
			"insecureRegistry":    llx.StringData(t.InsecureRegistry),
			"floatingIpEnabled":   llx.BoolData(t.FloatingIPEnabled),
			"masterLbEnabled":     llx.BoolData(t.MasterLBEnabled),
			"networkDriver":       llx.StringData(t.NetworkDriver),
			"volumeDriver":        llx.StringData(t.VolumeDriver),
			"dockerStorageDriver": llx.StringData(t.DockerStorageDriver),
			"dockerVolumeSize":    llx.IntData(int64(t.DockerVolumeSize)),
			"dnsNameserver":       llx.StringData(t.DNSNameServer),
			"apiServerPort":       llx.IntData(int64(t.APIServerPort)),
			"httpProxy":           llx.StringData(t.HTTPProxy),
			"httpsProxy":          llx.StringData(t.HTTPSProxy),
			"noProxy":             llx.StringData(t.NoProxy),
			"labels":              stringMapData(t.Labels),
			"createdAt":           llx.TimeDataPtr(timePtr(t.CreatedAt)),
			"updatedAt":           llx.TimeDataPtr(timePtr(t.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlTemplate := res.(*mqlOpenstackContainerinfraClusterTemplate)
		mqlTemplate.cacheImageID = t.ImageID
		mqlTemplate.cacheExternalNetworkID = t.ExternalNetworkID
		mqlTemplate.cacheFlavorID = t.FlavorID
		mqlTemplate.cacheMasterFlavorID = t.MasterFlavorID
		mqlTemplate.cacheKeyPairID = t.KeyPairID
		mqlTemplate.cacheProjectID = t.ProjectID
		mqlTemplate.cacheUserID = t.UserID
		out = append(out, mqlTemplate)
	}
	return out, nil
}

func (r *mqlOpenstackContainerinfraClusterTemplate) image() (*mqlOpenstackImage, error) {
	if r.cacheImageID == "" {
		r.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.image", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheImageID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackImage), nil
}

func (r *mqlOpenstackContainerinfraClusterTemplate) externalNetwork() (*mqlOpenstackNetwork, error) {
	if r.cacheExternalNetworkID == "" {
		r.ExternalNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.network", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheExternalNetworkID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackNetwork), nil
}

func (r *mqlOpenstackContainerinfraClusterTemplate) flavor() (*mqlOpenstackComputeFlavor, error) {
	return resolveFlavor(r.MqlRuntime, r.cacheFlavorID, &r.Flavor)
}

func (r *mqlOpenstackContainerinfraClusterTemplate) masterFlavor() (*mqlOpenstackComputeFlavor, error) {
	return resolveFlavor(r.MqlRuntime, r.cacheMasterFlavorID, &r.MasterFlavor)
}

func (r *mqlOpenstackContainerinfraClusterTemplate) keypair() (*mqlOpenstackComputeKeypair, error) {
	return resolveKeypair(r.MqlRuntime, r.cacheKeyPairID, &r.Keypair)
}

func (r *mqlOpenstackContainerinfraClusterTemplate) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackContainerinfraClusterTemplate) user() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheUserID, &r.User)
}

// resolveFlavor and resolveKeypair resolve compute references by ID/name into
// typed references, marking the field null when the key is empty.
func resolveFlavor(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOpenstackComputeFlavor]) (*mqlOpenstackComputeFlavor, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.compute.flavor", map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeFlavor), nil
}

func resolveKeypair(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlOpenstackComputeKeypair]) (*mqlOpenstackComputeKeypair, error) {
	if name == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.compute.keypair", map[string]*llx.RawData{"name": llx.StringData(name)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeKeypair), nil
}
