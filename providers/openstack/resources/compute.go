// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/aggregates"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/hypervisors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/limits"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servergroups"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/services"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/openstack/connection"
)

// ---- openstack.compute.server ----

type mqlOpenstackComputeServerInternal struct {
	cacheFlavorID         string
	cacheFlavorName       string
	cacheImageID          string
	cacheKeyName          string
	cacheSecurityGroupSGs []string
	cacheVolumeIDs        []string
	cacheProjectID        string
	cacheUserID           string
}

func (r *mqlOpenstackComputeServer) id() (string, error) {
	return "openstack.compute.server/" + r.Id.Data, nil
}

func initOpenstackComputeServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetServers()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackComputeServer)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.compute.server", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) servers() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, err
	}
	pages, err := servers.List(client, servers.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := servers.ExtractServers(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		res, err := newMqlOpenstackComputeServer(o.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlOpenstackComputeServer(runtime *plugin.Runtime, s *servers.Server) (*mqlOpenstackComputeServer, error) {
	imageID := serverImage(s.Image)
	flavorID, flavorName := serverFlavorRef(s.Flavor)
	sgNames := serverSecurityGroupNames(s.SecurityGroups)
	volumeIDs := serverVolumeIDs(s.AttachedVolumes)

	res, err := CreateResource(runtime, "openstack.compute.server", map[string]*llx.RawData{
		"__id":               llx.StringData("openstack.compute.server/" + s.ID),
		"id":                 llx.StringData(s.ID),
		"name":               llx.StringData(s.Name),
		"status":             llx.StringData(s.Status),
		"powerState":         llx.IntData(int64(s.PowerState)),
		"vmState":            llx.StringData(s.VmState),
		"taskState":          llx.StringData(s.TaskState),
		"locked":             llx.BoolData(s.Locked != nil && *s.Locked),
		"hostId":             llx.StringData(s.HostID),
		"accessIPv4":         llx.StringData(s.AccessIPv4),
		"accessIPv6":         llx.StringData(s.AccessIPv6),
		"keyName":            llx.StringData(s.KeyName),
		"availabilityZone":   llx.StringData(s.AvailabilityZone),
		"diskConfig":         llx.StringData(string(s.DiskConfig)),
		"configDrive":        llx.BoolData(s.ConfigDrive),
		"host":               llx.StringData(s.Host),
		"hypervisorHostname": llx.StringData(s.HypervisorHostname),
		"instanceName":       llx.StringData(s.InstanceName),
		"userData":           llx.StringDataPtr(s.Userdata),
		"addresses":          llx.DictData(toDict(s.Addresses)),
		"metadata":           stringMapData(s.Metadata),
		"tags":               stringSliceData(derefStrings(s.Tags)),
		"created":            llx.TimeDataPtr(timePtr(s.Created)),
		"updated":            llx.TimeDataPtr(timePtr(s.Updated)),
		"launchedAt":         llx.TimeDataPtr(timePtr(s.LaunchedAt)),
		"terminatedAt":       llx.TimeDataPtr(timePtr(s.TerminatedAt)),
	})
	if err != nil {
		return nil, err
	}
	mqlServer := res.(*mqlOpenstackComputeServer)
	mqlServer.cacheFlavorID = flavorID
	mqlServer.cacheFlavorName = flavorName
	mqlServer.cacheImageID = imageID
	mqlServer.cacheKeyName = s.KeyName
	mqlServer.cacheSecurityGroupSGs = sgNames
	mqlServer.cacheVolumeIDs = volumeIDs
	mqlServer.cacheProjectID = s.TenantID
	mqlServer.cacheUserID = s.UserID
	return mqlServer, nil
}

func (r *mqlOpenstackComputeServer) image() (*mqlOpenstackImage, error) {
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

func (r *mqlOpenstackComputeServer) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackComputeServer) user() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheUserID, &r.User)
}

func (r *mqlOpenstackComputeServer) volumes() ([]any, error) {
	if len(r.cacheVolumeIDs) == 0 {
		return []any{}, nil
	}
	out := make([]any, 0, len(r.cacheVolumeIDs))
	for _, id := range r.cacheVolumeIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.blockstorage.volume", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func serverVolumeIDs(in []servers.AttachedVolume) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v.ID == "" {
			continue
		}
		out = append(out, v.ID)
	}
	return out
}

// serverGroupMetadata converts the SDK's map[string]any (Nova types metadata
// loosely) into map[string]string for the schema. Strings pass through; other
// JSON-decoded values (bool, number, array, object) are rendered to their
// JSON form so the user-visible map stays faithful to what Nova returned.
func serverGroupMetadata(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, raw := range in {
		switch v := raw.(type) {
		case nil:
			continue
		case string:
			out[k] = v
		default:
			b, err := json.Marshal(v)
			if err != nil {
				out[k] = fmt.Sprint(v)
				continue
			}
			out[k] = string(b)
		}
	}
	return out
}

func (r *mqlOpenstackComputeServer) flavor() (*mqlOpenstackComputeFlavor, error) {
	id := r.cacheFlavorID
	if id == "" && r.cacheFlavorName != "" {
		resolved, err := lookupFlavorIDByName(conn(r.MqlRuntime), r.cacheFlavorName)
		if err != nil {
			return nil, err
		}
		id = resolved
	}
	if id == "" {
		r.Flavor.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.compute.flavor", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeFlavor), nil
}

func (r *mqlOpenstackComputeServer) keypair() (*mqlOpenstackComputeKeypair, error) {
	if r.cacheKeyName == "" {
		r.Keypair.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.compute.keypair", map[string]*llx.RawData{
		"name": llx.StringData(r.cacheKeyName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeKeypair), nil
}

// securityGroups resolves the security groups Nova reports on the server.
// Nova returns groups by name, but Neutron security groups are keyed by ID, so
// we resolve names against the project's groups list. Names that don't match
// (e.g. groups in a different project the user can't see) are skipped silently.
func (r *mqlOpenstackComputeServer) securityGroups() ([]any, error) {
	if len(r.cacheSecurityGroupSGs) == 0 {
		return []any{}, nil
	}

	out := make([]any, 0, len(r.cacheSecurityGroupSGs))
	for _, name := range r.cacheSecurityGroupSGs {
		id, err := lookupSecurityGroupIDByName(r.MqlRuntime, name)
		if err != nil {
			return nil, err
		}
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.securityGroup", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// serverImage extracts the image ID from the `image` field on a server. Nova
// returns "" (or a JSON string of "") when the server is booted from volume.
func serverImage(raw any) string {
	if raw == nil {
		return ""
	}
	if v, ok := raw.(map[string]any); ok {
		id, _ := v["id"].(string)
		return id
	}
	return ""
}

// serverFlavorRef returns the flavor's id and original_name from the embedded
// flavor object on a server response. Nova removed `id` from the embedded
// flavor at microversion 2.47, so callers need to resolve the name to an id
// when only the name is present.
func serverFlavorRef(raw map[string]any) (id, name string) {
	if raw == nil {
		return "", ""
	}
	if v, ok := raw["id"].(string); ok {
		id = v
	}
	if v, ok := raw["original_name"].(string); ok {
		name = v
	}
	return id, name
}

// lookupFlavorIDByName resolves a flavor name to an id via a per-connection
// cache populated lazily from a single flavors.ListDetail call. The lock
// single-flights the first fetch; on success or auth-translated failure the
// cache map is non-nil and subsequent callers fast-path. Real errors leave
// the cache nil so the next call retries instead of inheriting a stale error.
func lookupFlavorIDByName(c *connection.OpenstackConnection, name string) (string, error) {
	c.FlavorNameCacheLock.Lock()
	defer c.FlavorNameCacheLock.Unlock()
	if c.FlavorNameCache != nil {
		return c.FlavorNameCache[name], nil
	}
	client, err := c.ComputeClient()
	if err != nil {
		return "", err
	}
	pages, err := flavors.ListDetail(client, flavors.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			c.FlavorNameCache = map[string]string{}
			return "", nil
		}
		return "", err
	}
	items, err := flavors.ExtractFlavors(pages)
	if err != nil {
		return "", err
	}
	c.FlavorNameCache = make(map[string]string, len(items))
	for _, f := range items {
		c.FlavorNameCache[f.Name] = f.ID
	}
	return c.FlavorNameCache[name], nil
}

func serverSecurityGroupNames(in []map[string]any) []string {
	out := make([]string, 0, len(in))
	for _, sg := range in {
		if name, ok := sg["name"].(string); ok && name != "" {
			out = append(out, name)
		}
	}
	return out
}

// derefStrings turns *[]string into []string, returning empty when nil.
// gophercloud uses *[]string for tags so it can distinguish unset from empty.
func derefStrings(p *[]string) []string {
	if p == nil {
		return nil
	}
	return *p
}

// toDict converts a map[string]any (or nil) into a dict-friendly map[string]any.
func toDict(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	return in
}

// ---- openstack.compute.flavor ----

func (r *mqlOpenstackComputeFlavor) id() (string, error) {
	return "openstack.compute.flavor/" + r.Id.Data, nil
}

type mqlOpenstackComputeFlavorInternal struct {
	specsLock sync.Mutex
	specsDone bool
	specsData map[string]any
}

func initOpenstackComputeFlavor(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["id"]; !ok {
		return args, nil, nil
	}
	if _, hasName := args["name"]; hasName {
		return args, nil, nil
	}

	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}

	c := conn(runtime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, nil, err
	}
	f, err := flavors.Get(ctx(), client, id).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			return args, nil, nil
		}
		return nil, nil, err
	}
	populateFlavorArgs(args, f)
	return args, nil, nil
}

func (o *mqlOpenstack) flavors() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, err
	}
	pages, err := flavors.ListDetail(client, flavors.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := flavors.ExtractFlavors(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		args := map[string]*llx.RawData{}
		populateFlavorArgs(args, &items[i])
		res, err := CreateResource(o.MqlRuntime, "openstack.compute.flavor", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func populateFlavorArgs(args map[string]*llx.RawData, f *flavors.Flavor) {
	args["__id"] = llx.StringData("openstack.compute.flavor/" + f.ID)
	args["id"] = llx.StringData(f.ID)
	args["name"] = llx.StringData(f.Name)
	args["vcpus"] = llx.IntData(int64(f.VCPUs))
	args["ram"] = llx.IntData(int64(f.RAM))
	args["disk"] = llx.IntData(int64(f.Disk))
	args["swap"] = llx.IntData(int64(f.Swap))
	args["ephemeral"] = llx.IntData(int64(f.Ephemeral))
	args["rxtxFactor"] = llx.FloatData(f.RxTxFactor)
	args["isPublic"] = llx.BoolData(f.IsPublic)
	args["description"] = llx.StringData(f.Description)
}

func (r *mqlOpenstackComputeFlavor) extraSpecs() (map[string]any, error) {
	r.specsLock.Lock()
	defer r.specsLock.Unlock()
	if r.specsDone {
		return r.specsData, nil
	}

	c := conn(r.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, err
	}
	specs, err := flavors.ListExtraSpecs(ctx(), client, r.Id.Data).Extract()
	if err != nil {
		if translateOpenstackError(err) == nil {
			r.specsDone = true
			r.specsData = map[string]any{}
			return r.specsData, nil
		}
		return nil, err
	}
	r.specsDone = true
	r.specsData = stringMap(specs)
	return r.specsData, nil
}

// ---- openstack.compute.keypair ----

type mqlOpenstackComputeKeypairInternal struct {
	cacheUserID string
}

func (r *mqlOpenstackComputeKeypair) id() (string, error) {
	return "openstack.compute.keypair/" + r.Name.Data, nil
}

func initOpenstackComputeKeypair(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	name, ok := stringArg(args, "name")
	if !ok || name == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetKeypairs()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		k := raw.(*mqlOpenstackComputeKeypair)
		if k.Name.Data == name {
			return args, k, nil
		}
	}
	initSyntheticID("openstack.compute.keypair", "name", args)
	return args, nil, nil
}

func (o *mqlOpenstack) keypairs() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, err
	}
	pages, err := keypairs.List(client, keypairs.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := keypairs.ExtractKeyPairs(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, k := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.compute.keypair", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.compute.keypair/" + k.Name),
			"name":        llx.StringData(k.Name),
			"type":        llx.StringData(k.Type),
			"fingerprint": llx.StringData(k.Fingerprint),
			"publicKey":   llx.StringData(k.PublicKey),
		})
		if err != nil {
			return nil, err
		}
		mqlKeypair := res.(*mqlOpenstackComputeKeypair)
		mqlKeypair.cacheUserID = k.UserID
		out = append(out, mqlKeypair)
	}
	return out, nil
}

func (r *mqlOpenstackComputeKeypair) user() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheUserID, &r.User)
}

// ---- openstack.compute.serverGroup ----

type mqlOpenstackComputeServerGroupInternal struct {
	cacheProjectID string
	cacheUserID    string
}

func (r *mqlOpenstackComputeServerGroup) id() (string, error) {
	return "openstack.compute.serverGroup/" + r.Id.Data, nil
}

func initOpenstackComputeServerGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetServerGroups()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		g := raw.(*mqlOpenstackComputeServerGroup)
		if g.Id.Data == id {
			return args, g, nil
		}
	}
	initSyntheticID("openstack.compute.serverGroup", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) serverGroups() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, err
	}
	pages, err := servergroups.List(client, servergroups.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := servergroups.ExtractServerGroups(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, g := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.compute.serverGroup", map[string]*llx.RawData{
			"__id":     llx.StringData("openstack.compute.serverGroup/" + g.ID),
			"id":       llx.StringData(g.ID),
			"name":     llx.StringData(g.Name),
			"policies": stringSliceData(g.Policies),
			"members":  stringSliceData(g.Members),
			"metadata": stringMapData(serverGroupMetadata(g.Metadata)),
		})
		if err != nil {
			return nil, err
		}
		mqlServerGroup := res.(*mqlOpenstackComputeServerGroup)
		mqlServerGroup.cacheProjectID = g.ProjectID
		mqlServerGroup.cacheUserID = g.UserID
		out = append(out, mqlServerGroup)
	}
	return out, nil
}

func (r *mqlOpenstackComputeServerGroup) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackComputeServerGroup) user() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheUserID, &r.User)
}

func (r *mqlOpenstackComputeServerGroup) memberServers() ([]any, error) {
	if len(r.Members.Data) == 0 {
		return []any{}, nil
	}
	out := make([]any, 0, len(r.Members.Data))
	for _, m := range r.Members.Data {
		id, ok := m.(string)
		if !ok || id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.compute.server", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.compute.hypervisor ----

type mqlOpenstackComputeHypervisorInternal struct {
	cacheServiceID string
}

func (r *mqlOpenstackComputeHypervisor) id() (string, error) {
	return "openstack.compute.hypervisor/" + r.Id.Data, nil
}

func initOpenstackComputeHypervisor(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetHypervisors()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		h := raw.(*mqlOpenstackComputeHypervisor)
		if h.Id.Data == id {
			return args, h, nil
		}
	}
	initSyntheticID("openstack.compute.hypervisor", "id", args)
	return args, nil, nil
}

func cpuInfoDict(info hypervisors.CPUInfo) map[string]any {
	features := make([]any, len(info.Features))
	for i, f := range info.Features {
		features[i] = f
	}
	return map[string]any{
		"vendor":   info.Vendor,
		"arch":     info.Arch,
		"model":    info.Model,
		"features": features,
		"topology": map[string]any{
			"sockets": info.Topology.Sockets,
			"cores":   info.Topology.Cores,
			"threads": info.Topology.Threads,
		},
	}
}

func (o *mqlOpenstack) hypervisors() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, err
	}
	pages, err := hypervisors.List(client, hypervisors.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := hypervisors.ExtractHypervisors(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, h := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.compute.hypervisor", map[string]*llx.RawData{
			"__id":            llx.StringData("openstack.compute.hypervisor/" + h.ID),
			"id":              llx.StringData(h.ID),
			"hostname":        llx.StringData(h.HypervisorHostname),
			"type":            llx.StringData(h.HypervisorType),
			"version":         llx.IntData(int64(h.HypervisorVersion)),
			"hostIp":          llx.StringData(h.HostIP),
			"state":           llx.StringData(h.State),
			"status":          llx.StringData(h.Status),
			"vcpus":           llx.IntData(int64(h.VCPUs)),
			"vcpusUsed":       llx.IntData(int64(h.VCPUsUsed)),
			"memoryMb":        llx.IntData(int64(h.MemoryMB)),
			"memoryMbUsed":    llx.IntData(int64(h.MemoryMBUsed)),
			"freeRamMb":       llx.IntData(int64(h.FreeRamMB)),
			"localGb":         llx.IntData(int64(h.LocalGB)),
			"localGbUsed":     llx.IntData(int64(h.LocalGBUsed)),
			"freeDiskGb":      llx.IntData(int64(h.FreeDiskGB)),
			"runningVms":      llx.IntData(int64(h.RunningVMs)),
			"currentWorkload": llx.IntData(int64(h.CurrentWorkload)),
			"cpuInfo":         llx.DictData(cpuInfoDict(h.CPUInfo)),
		})
		if err != nil {
			return nil, err
		}
		mqlHV := res.(*mqlOpenstackComputeHypervisor)
		mqlHV.cacheServiceID = h.Service.ID
		out = append(out, mqlHV)
	}
	return out, nil
}

func (r *mqlOpenstackComputeHypervisor) service() (*mqlOpenstackComputeService, error) {
	if r.cacheServiceID == "" {
		r.Service.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.compute.service", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheServiceID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeService), nil
}

// ---- openstack.compute.service ----

func (r *mqlOpenstackComputeService) id() (string, error) {
	return "openstack.compute.service/" + r.Id.Data, nil
}

func initOpenstackComputeService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetComputeServices()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackComputeService)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.compute.service", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) computeServices() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, err
	}
	pages, err := services.List(client, services.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := services.ExtractServices(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, s := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.compute.service", map[string]*llx.RawData{
			"__id":           llx.StringData("openstack.compute.service/" + s.ID),
			"id":             llx.StringData(s.ID),
			"binary":         llx.StringData(s.Binary),
			"host":           llx.StringData(s.Host),
			"zone":           llx.StringData(s.Zone),
			"status":         llx.StringData(s.Status),
			"state":          llx.StringData(s.State),
			"disabledReason": llx.StringData(s.DisabledReason),
			"forcedDown":     llx.BoolData(s.ForcedDown),
			"updatedAt":      llx.TimeDataPtr(timePtr(s.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.compute.aggregate ----

func (r *mqlOpenstackComputeAggregate) id() (string, error) {
	return "openstack.compute.aggregate/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func initOpenstackComputeAggregate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	idRaw, ok := args["id"]
	if !ok || idRaw == nil {
		return args, nil, nil
	}
	idVal, ok := idRaw.Value.(int64)
	if !ok || idVal == 0 {
		return args, nil, nil
	}
	if _, ok := args["__id"]; !ok {
		args["__id"] = llx.StringData("openstack.compute.aggregate/" + strconv.FormatInt(idVal, 10))
	}
	return args, nil, nil
}

func (o *mqlOpenstack) aggregates() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		return nil, err
	}
	pages, err := aggregates.List(client).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := aggregates.ExtractAggregates(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, a := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.compute.aggregate", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.compute.aggregate/" + strconv.Itoa(a.ID)),
			"id":               llx.IntData(int64(a.ID)),
			"name":             llx.StringData(a.Name),
			"availabilityZone": llx.StringData(a.AvailabilityZone),
			"hosts":            stringSliceData(a.Hosts),
			"metadata":         stringMapData(a.Metadata),
			"hostCount":        llx.IntData(int64(len(a.Hosts))),
			"createdAt":        llx.TimeDataPtr(timePtr(a.CreatedAt)),
			"updatedAt":        llx.TimeDataPtr(timePtr(a.UpdatedAt)),
			"deleted":          llx.BoolData(a.Deleted),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.compute.limits ----

// mqlOpenstackComputeLimitsInternal holds the project id the limits report
// applies to, which project() resolves. The __id is supplied explicitly by the
// creator, so this resource needs no id() function.
type mqlOpenstackComputeLimitsInternal struct {
	cacheProjectID string
}

func (o *mqlOpenstack) computeLimits() (*mqlOpenstackComputeLimits, error) {
	c := conn(o.MqlRuntime)
	client, err := c.ComputeClient()
	if err != nil {
		if serviceMissing(err) {
			o.ComputeLimits.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	lim, err := limits.Get(ctx(), client, nil).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			o.ComputeLimits.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	abs := lim.Absolute
	projectId := c.ProjectID()
	res, err := CreateResource(o.MqlRuntime, "openstack.compute.limits", map[string]*llx.RawData{
		"__id":                    llx.StringData("openstack.compute.limits/" + projectId),
		"maxTotalCores":           llx.IntData(int64(abs.MaxTotalCores)),
		"totalCoresUsed":          llx.IntData(int64(abs.TotalCoresUsed)),
		"maxTotalInstances":       llx.IntData(int64(abs.MaxTotalInstances)),
		"totalInstancesUsed":      llx.IntData(int64(abs.TotalInstancesUsed)),
		"maxTotalRAMSize":         llx.IntData(int64(abs.MaxTotalRAMSize)),
		"totalRAMUsed":            llx.IntData(int64(abs.TotalRAMUsed)),
		"maxTotalKeypairs":        llx.IntData(int64(abs.MaxTotalKeypairs)),
		"maxSecurityGroups":       llx.IntData(int64(abs.MaxSecurityGroups)),
		"totalSecurityGroupsUsed": llx.IntData(int64(abs.TotalSecurityGroupsUsed)),
		"maxSecurityGroupRules":   llx.IntData(int64(abs.MaxSecurityGroupRules)),
		"maxTotalFloatingIps":     llx.IntData(int64(abs.MaxTotalFloatingIps)),
		"totalFloatingIpsUsed":    llx.IntData(int64(abs.TotalFloatingIpsUsed)),
		"maxServerGroups":         llx.IntData(int64(abs.MaxServerGroups)),
		"totalServerGroupsUsed":   llx.IntData(int64(abs.TotalServerGroupsUsed)),
		"maxServerGroupMembers":   llx.IntData(int64(abs.MaxServerGroupMembers)),
		"maxImageMeta":            llx.IntData(int64(abs.MaxImageMeta)),
		"maxServerMeta":           llx.IntData(int64(abs.MaxServerMeta)),
		"maxPersonality":          llx.IntData(int64(abs.MaxPersonality)),
		"maxPersonalitySize":      llx.IntData(int64(abs.MaxPersonalitySize)),
	})
	if err != nil {
		return nil, err
	}
	mqlLimits := res.(*mqlOpenstackComputeLimits)
	mqlLimits.cacheProjectID = projectId
	return mqlLimits, nil
}

func (r *mqlOpenstackComputeLimits) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}
