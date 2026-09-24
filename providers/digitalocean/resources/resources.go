// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// --- Database sub-resources ---

func (r *mqlDigitaloceanDatabase) users() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	users, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]godo.DatabaseUser, *godo.Response, error) {
		return client.Databases.ListUsers(c, r.Id.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(users))
	for _, u := range users {
		res, err := CreateResource(r.MqlRuntime, "digitalocean.database.user", map[string]*llx.RawData{
			"databaseId":     llx.StringData(r.Id.Data),
			"name":           llx.StringData(u.Name),
			"role":           llx.StringData(u.Role),
			"authPlugin":     llx.StringData(databaseUserAuthPlugin(&u)),
			"kafkaAcls":      llx.ArrayData(databaseUserKafkaAcls(&u), types.Dict),
			"opensearchAcls": llx.ArrayData(databaseUserOpenSearchAcls(&u), types.Dict),
			"mongoDatabases": llx.ArrayData(databaseUserMongoDatabases(&u), types.String),
			"mongoRole":      llx.StringData(databaseUserMongoRole(&u)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanDatabaseUser) id() (string, error) {
	return "digitalocean.database.user/" + r.DatabaseId.Data + "/" + r.Name.Data, nil
}

func (r *mqlDigitaloceanDatabase) replicas() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	replicas, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]godo.DatabaseReplica, *godo.Response, error) {
		return client.Databases.ListReplicas(c, r.Id.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(replicas))
	for _, rep := range replicas {
		tags := make([]interface{}, len(rep.Tags))
		for i, t := range rep.Tags {
			tags[i] = t
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.database.replica", map[string]*llx.RawData{
			"databaseId": llx.StringData(r.Id.Data),
			"name":       llx.StringData(rep.Name),
			"region":     llx.StringData(rep.Region),
			"status":     llx.StringData(rep.Status),
			"createdAt":  llx.TimeData(rep.CreatedAt),
			"size":       llx.StringData(rep.Size),
			"tags":       llx.ArrayData(tags, "\x02"),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanDatabaseReplica) id() (string, error) {
	return "digitalocean.database.replica/" + r.DatabaseId.Data + "/" + r.Name.Data, nil
}

// databaseEngineHasPools reports whether an engine supports connection pools.
// DigitalOcean offers PgBouncer pools on PostgreSQL clusters only.
func databaseEngineHasPools(engine string) bool {
	return engine == "pg"
}

func (r *mqlDigitaloceanDatabase) pools() ([]interface{}, error) {
	// No other engine can hold a pool, so it has none, and asking the pools
	// endpoint for one would only turn that empty answer into a failure for
	// this cluster.
	if !databaseEngineHasPools(r.Engine.Data) {
		return []interface{}{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	pools, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]godo.DatabasePool, *godo.Response, error) {
		return client.Databases.ListPools(c, r.Id.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(pools))
	for _, p := range pools {
		// The pooler's connection URIs embed the pool user's password, so
		// they are deliberately not surfaced; host and port are reported
		// separately for connectivity checks. An endpoint the pool does not
		// publish leaves its fields null rather than reporting a plaintext
		// pool on port zero.
		pubHost, pubPort, pubSSL := poolConnection(p.Connection)
		privHost, privPort, privSSL := poolConnection(p.PrivateConnection)

		res, err := CreateResource(r.MqlRuntime, "digitalocean.database.pool", map[string]*llx.RawData{
			"databaseId":        llx.StringData(r.Id.Data),
			"name":              llx.StringData(p.Name),
			"database":          llx.StringData(p.Database),
			"user":              llx.StringData(p.User),
			"size":              llx.IntData(int64(p.Size)),
			"mode":              llx.StringData(p.Mode),
			"host":              llx.StringDataPtr(pubHost),
			"port":              llx.IntDataPtr(pubPort),
			"sslEnabled":        llx.BoolDataPtr(pubSSL),
			"privateHost":       llx.StringDataPtr(privHost),
			"privatePort":       llx.IntDataPtr(privPort),
			"privateSslEnabled": llx.BoolDataPtr(privSSL),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanDatabasePool) id() (string, error) {
	return "digitalocean.database.pool/" + r.DatabaseId.Data + "/" + r.Name.Data, nil
}

// poolConnection reports a connection pool endpoint's host, port, and TLS
// setting, leaving all three nil when the pool publishes no such endpoint.
//
// Returning nil rather than zero values is the point: a pool with no
// private endpoint must not read as one reachable on port 0 with TLS off,
// because a false on a TLS flag is a claim about something nobody read.
func poolConnection(c *godo.DatabaseConnection) (host *string, port *int64, ssl *bool) {
	if c == nil {
		return nil, nil, nil
	}
	h := c.Host
	p := int64(c.Port)
	s := c.SSL
	return &h, &p, &s
}

// --- VPC Peering ---

func (r *mqlDigitalocean) vpcPeerings() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	peerings, err := paginate(context.Background(), client.VPCs.ListVPCPeerings)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(peerings))
	for _, p := range peerings {
		vpcIds := make([]interface{}, len(p.VPCIDs))
		for i, id := range p.VPCIDs {
			vpcIds[i] = id
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.vpcPeering", map[string]*llx.RawData{
			"id":        llx.StringData(p.ID),
			"name":      llx.StringData(p.Name),
			"vpcIds":    llx.ArrayData(vpcIds, "\x02"),
			"status":    llx.StringData(string(p.Status)),
			"createdAt": llx.TimeData(p.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanVpcPeering) id() (string, error) {
	return "digitalocean.vpcPeering/" + r.Id.Data, nil
}

// --- Kubernetes node pools (typed) ---

func (r *mqlDigitaloceanKubernetesCluster) nodePools() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	pools, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.KubernetesNodePool, *godo.Response, error) {
		return client.Kubernetes.ListNodePools(c, r.Id.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(pools))
	for _, np := range pools {
		npTags := make([]interface{}, len(np.Tags))
		for i, t := range np.Tags {
			npTags[i] = t
		}

		labels := map[string]interface{}{}
		for k, v := range np.Labels {
			labels[k] = v
		}

		taints := make([]interface{}, len(np.Taints))
		for i, t := range np.Taints {
			taints[i] = map[string]interface{}{
				"key":    t.Key,
				"value":  t.Value,
				"effect": t.Effect,
			}
		}

		res, err := CreateResource(r.MqlRuntime, "digitalocean.kubernetes.nodePool", map[string]*llx.RawData{
			"id":        llx.StringData(np.ID),
			"clusterId": llx.StringData(r.Id.Data),
			"name":      llx.StringData(np.Name),
			"size":      llx.StringData(np.Size),
			"count":     llx.IntData(int64(np.Count)),
			"autoScale": llx.BoolData(np.AutoScale),
			"minNodes":  llx.IntData(int64(np.MinNodes)),
			"maxNodes":  llx.IntData(int64(np.MaxNodes)),
			"tags":      llx.ArrayData(npTags, "\x02"),
			"labels":    llx.DictData(labels),
			"taints":    llx.ArrayData(taints, "\x13"),
		})
		if err != nil {
			return nil, err
		}
		// Cache the godo nodes so the typed nodes() accessor can build
		// digitalocean.kubernetes.node resources without a refetch.
		res.(*mqlDigitaloceanKubernetesNodePool).cacheNodes = np.Nodes
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanKubernetesNodePool) id() (string, error) {
	return "digitalocean.kubernetes.nodePool/" + r.ClusterId.Data + "/" + r.Id.Data, nil
}

type mqlDigitaloceanKubernetesNodePoolInternal struct {
	// cacheNodes holds the godo nodes embedded in the node-pool list response
	// so the typed nodes() accessor can build resources without a refetch.
	cacheNodes []*godo.KubernetesNode
}

func (r *mqlDigitaloceanKubernetesNodePool) nodes() ([]interface{}, error) {
	out := make([]interface{}, 0, len(r.cacheNodes))
	for _, n := range r.cacheNodes {
		if n == nil {
			continue
		}
		status, statusMessage := "", ""
		if n.Status != nil {
			status = n.Status.State
			statusMessage = n.Status.Message
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.kubernetes.node", map[string]*llx.RawData{
			"id":            llx.StringData(n.ID),
			"name":          llx.StringData(n.Name),
			"status":        llx.StringData(status),
			"statusMessage": llx.StringData(statusMessage),
			"createdAt":     llx.TimeData(n.CreatedAt),
			"updatedAt":     llx.TimeData(n.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlDigitaloceanKubernetesNode).cacheDropletID = n.DropletID
		out = append(out, res)
	}
	return out, nil
}

type mqlDigitaloceanKubernetesNodeInternal struct {
	// cacheDropletID holds the backing droplet's ID (as the API returns it,
	// a numeric string) so the typed droplet() accessor can resolve it.
	cacheDropletID string
}

func (r *mqlDigitaloceanKubernetesNode) id() (string, error) {
	return "digitalocean.kubernetes.node/" + r.Id.Data, nil
}

// --- Container Registry ---

func initDigitaloceanRegistry(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	reg, _, err := conn.Client().Registry.Get(context.Background())
	if err != nil {
		// 404 means the account simply has no container registry —
		// return an empty sentinel so the resource remains usable for
		// audits that branch on `registry.name == ""`. Other errors
		// (5xx, auth) propagate so the user sees the failure instead
		// of a silently empty registry.
		if !isDoNotFound(err) {
			return nil, nil, err
		}
		args["name"] = llx.StringData("")
		args["storageUsageBytes"] = llx.IntData(0)
		args["storageUsageBytesUpdatedAt"] = llx.TimeDataPtr(nil)
		args["region"] = llx.StringData("")
		// Null rather than the zero time: an account with no registry has
		// no creation date, and reporting 1 January year 1 as a real one
		// would be an invented value.
		args["createdAt"] = llx.TimeDataPtr(nil)
		args["subscriptionTier"] = llx.StringData("")
		args["subscription"] = llx.DictData(map[string]interface{}{})
		return args, nil, nil
	}
	if reg == nil {
		return nil, nil, errors.New("the DigitalOcean API returned no container registry")
	}

	tier, subDict := registrySubscription(conn.Client())
	for k, v := range registryArgs(reg, tier, subDict) {
		args[k] = v
	}
	return args, nil, nil
}

// id keys a registry by name so an account holding several of them does
// not collapse them onto one cache entry.
//
// The empty sentinel the init returns for an account with no registry
// keeps the bare kind as its key, because resourceID refuses to build one
// from an empty name.
func (r *mqlDigitaloceanRegistry) id() (string, error) {
	if r.Name.Data == "" {
		return "digitalocean.registry", nil
	}
	return resourceID("digitalocean.registry", r.Name.Data)
}

func (r *mqlDigitaloceanRegistry) repositories() ([]interface{}, error) {
	if r.Name.Data == "" {
		return []interface{}{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()
	return listRegistryRepositories(r.MqlRuntime, client, r.Name.Data)
}

func (r *mqlDigitaloceanRegistry) garbageCollections() ([]interface{}, error) {
	if r.Name.Data == "" {
		return []interface{}{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	gcs, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.GarbageCollection, *godo.Response, error) {
		return client.Registry.ListGarbageCollections(c, r.Name.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(gcs))
	for _, gc := range gcs {
		res, err := CreateResource(r.MqlRuntime, "digitalocean.registry.garbageCollection", map[string]*llx.RawData{
			"uuid":         llx.StringData(gc.UUID),
			"registryName": llx.StringData(gc.RegistryName),
			"status":       llx.StringData(gc.Status),
			"type":         llx.StringData(string(gc.Type)),
			"createdAt":    llx.TimeData(gc.CreatedAt),
			"updatedAt":    llx.TimeData(gc.UpdatedAt),
			"blobsDeleted": llx.IntData(int64(gc.BlobsDeleted)),
			"freedBytes":   llx.IntData(int64(gc.FreedBytes)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanRegistryGarbageCollection) id() (string, error) {
	return "digitalocean.registry.garbageCollection/" + r.Uuid.Data, nil
}

func listRegistryRepositories(runtime *plugin.Runtime, client *godo.Client, regName string) ([]interface{}, error) {
	var all []interface{}
	opt := &godo.TokenListOptions{PerPage: 200}
	for {
		repos, resp, err := client.Registry.ListRepositoriesV2(context.Background(), regName, opt)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			mqlRepo, err := CreateResource(runtime, "digitalocean.registry.repository", map[string]*llx.RawData{
				"registryName":  llx.StringData(repo.RegistryName),
				"name":          llx.StringData(repo.Name),
				"tagCount":      llx.IntData(int64(repo.TagCount)),
				"manifestCount": llx.IntData(int64(repo.ManifestCount)),
			})
			if err != nil {
				return nil, err
			}
			if repo.LatestManifest != nil {
				mqlRepo.(*mqlDigitaloceanRegistryRepository).cacheLatestManifest = repo.LatestManifest
			}
			all = append(all, mqlRepo)
		}
		if resp == nil || resp.Links == nil {
			break
		}
		nextPage, err := resp.Links.NextPageToken()
		if err != nil || nextPage == "" {
			break
		}
		opt.Token = nextPage
	}
	return all, nil
}

// registryRepositories lists the repositories of every registry on the
// account.
//
// It walks the registries listing rather than the legacy single-registry
// endpoint, which names only the default registry: reading that one alone
// drops every repository held in any other registry, and the account-wide
// list would then disagree with `registries { repositories }`.
func (r *mqlDigitalocean) registryRepositories() ([]interface{}, error) {
	regs := r.GetRegistries()
	if regs.Error != nil {
		return nil, regs.Error
	}
	all := []interface{}{}
	for _, reg := range regs.Data {
		mreg, ok := reg.(*mqlDigitaloceanRegistry)
		if !ok {
			continue
		}
		repos := mreg.GetRepositories()
		if repos.Error != nil {
			return nil, repos.Error
		}
		all = append(all, repos.Data...)
	}
	return all, nil
}

func (r *mqlDigitaloceanRegistryRepository) id() (string, error) {
	return "digitalocean.registry.repository/" + r.RegistryName.Data + "/" + r.Name.Data, nil
}

type mqlDigitaloceanRegistryRepositoryInternal struct {
	cacheLatestManifest *godo.RepositoryManifest
}

func (r *mqlDigitaloceanRegistryRepository) tags() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	tags, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.RepositoryTag, *godo.Response, error) {
		return client.Registry.ListRepositoryTags(c, r.RegistryName.Data, r.Name.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(tags))
	for _, t := range tags {
		res, err := CreateResource(r.MqlRuntime, "digitalocean.registry.repository.tag", map[string]*llx.RawData{
			"registryName":        llx.StringData(t.RegistryName),
			"repository":          llx.StringData(t.Repository),
			"tag":                 llx.StringData(t.Tag),
			"manifestDigest":      llx.StringData(t.ManifestDigest),
			"compressedSizeBytes": llx.IntData(int64(t.CompressedSizeBytes)),
			"sizeBytes":           llx.IntData(int64(t.SizeBytes)),
			"updatedAt":           llx.TimeData(t.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanRegistryRepository) manifests() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	manifests, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.RepositoryManifest, *godo.Response, error) {
		return client.Registry.ListRepositoryManifests(c, r.RegistryName.Data, r.Name.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(manifests))
	for _, m := range manifests {
		res, err := newManifestResource(r.MqlRuntime, m)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanRegistryRepository) latestManifest() (*mqlDigitaloceanRegistryRepositoryManifest, error) {
	if r.cacheLatestManifest == nil {
		r.LatestManifest.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := newManifestResource(r.MqlRuntime, r.cacheLatestManifest)
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanRegistryRepositoryManifest), nil
}

func newManifestResource(runtime *plugin.Runtime, m *godo.RepositoryManifest) (plugin.Resource, error) {
	blobs := make([]interface{}, 0, len(m.Blobs))
	for _, b := range m.Blobs {
		if b == nil {
			continue
		}
		blobs = append(blobs, map[string]interface{}{
			"digest":              b.Digest,
			"compressedSizeBytes": int64(b.CompressedSizeBytes),
		})
	}
	tags := make([]interface{}, 0, len(m.Tags))
	for _, t := range m.Tags {
		tags = append(tags, t)
	}
	return CreateResource(runtime, "digitalocean.registry.repository.manifest", map[string]*llx.RawData{
		"registryName":        llx.StringData(m.RegistryName),
		"repository":          llx.StringData(m.Repository),
		"digest":              llx.StringData(m.Digest),
		"compressedSizeBytes": llx.IntData(int64(m.CompressedSizeBytes)),
		"sizeBytes":           llx.IntData(int64(m.SizeBytes)),
		"updatedAt":           llx.TimeData(m.UpdatedAt),
		"tags":                llx.ArrayData(tags, "string"),
		"blobs":               llx.ArrayData(blobs, "dict"),
	})
}

func (r *mqlDigitaloceanRegistryRepositoryTag) id() (string, error) {
	return "digitalocean.registry.repository.tag/" + r.RegistryName.Data + "/" + r.Repository.Data + ":" + r.Tag.Data, nil
}

func (r *mqlDigitaloceanRegistryRepositoryManifest) id() (string, error) {
	return "digitalocean.registry.repository.manifest/" + r.RegistryName.Data + "/" + r.Repository.Data + "@" + r.Digest.Data, nil
}

// --- Reserved IPs ---

func (r *mqlDigitalocean) reservedIPs() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	ips, err := paginate(context.Background(), client.ReservedIPs.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(ips))
	for _, ip := range ips {
		regionSlug := ""
		if ip.Region != nil {
			regionSlug = ip.Region.Slug
		}
		dropletId := int64(0)
		if ip.Droplet != nil {
			dropletId = int64(ip.Droplet.ID)
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.reservedIp", map[string]*llx.RawData{
			"ip":        llx.StringData(ip.IP),
			"region":    llx.StringData(regionSlug),
			"projectId": llx.StringData(ip.ProjectID),
			"locked":    llx.BoolData(ip.Locked),
			"dropletId": llx.IntData(dropletId),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanReservedIp) id() (string, error) {
	return "digitalocean.reservedIp/" + r.Ip.Data, nil
}

// --- App Platform ---

func (r *mqlDigitalocean) apps() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	apps, err := paginate(context.Background(), client.Apps.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(apps))
	for _, app := range apps {
		status := ""
		if !app.LastDeploymentActiveAt.IsZero() {
			status = "active"
		}
		if app.InProgressDeployment != nil {
			status = "deploying"
		}

		spec := map[string]interface{}{}
		if app.Spec != nil {
			spec["name"] = app.Spec.Name
			svcNames := make([]interface{}, len(app.Spec.Services))
			for i, s := range app.Spec.Services {
				svcNames[i] = s.Name
			}
			spec["services"] = svcNames
			workerNames := make([]interface{}, len(app.Spec.Workers))
			for i, w := range app.Spec.Workers {
				workerNames[i] = w.Name
			}
			spec["workers"] = workerNames
			jobNames := make([]interface{}, len(app.Spec.Jobs))
			for i, j := range app.Spec.Jobs {
				jobNames[i] = j.Name
			}
			spec["jobs"] = jobNames
			staticNames := make([]interface{}, len(app.Spec.StaticSites))
			for i, s := range app.Spec.StaticSites {
				staticNames[i] = s.Name
			}
			spec["staticSites"] = staticNames
			fnNames := make([]interface{}, len(app.Spec.Functions))
			for i, f := range app.Spec.Functions {
				fnNames[i] = f.Name
			}
			spec["functions"] = fnNames
		}

		name := ""
		if app.Spec != nil {
			name = app.Spec.Name
		}

		region := ""
		if app.Region != nil {
			region = app.Region.Slug
		}

		activeDeploymentId := ""
		if app.ActiveDeployment != nil {
			activeDeploymentId = app.ActiveDeployment.ID
		}

		secureHeaderKey, secureHeaderValue, secureHeaderRemoved := appSecureHeader(app.Spec)

		domains := make([]interface{}, 0, len(app.Domains))
		for _, d := range app.Domains {
			// godo hands back a slice of pointers; a nil entry would panic
			// the provider and take down the whole scan.
			if d == nil {
				continue
			}
			domainName := ""
			minimumTLSVersion := ""
			if d.Spec != nil {
				domainName = d.Spec.Domain
				minimumTLSVersion = d.Spec.MinimumTLSVersion
			}
			domains = append(domains, map[string]interface{}{
				"id":                   d.ID,
				"name":                 domainName,
				"phase":                string(d.Phase),
				"certificateExpiresAt": formatDoTime(d.CertificateExpiresAt),
				// Empty when the app leaves the domain at the App Platform
				// default rather than pinning a floor.
				"minimumTlsVersion": minimumTLSVersion,
			})
		}

		vpcID := ""
		vpcEgressIps := []interface{}{}
		if app.VPC != nil {
			vpcID = app.VPC.ID
			for _, e := range app.VPC.EgressIPs {
				if e != nil && e.IP != "" {
					vpcEgressIps = append(vpcEgressIps, e.IP)
				}
			}
		}

		buildpackStackId := ""
		var buildpacks []*godo.Buildpack
		if app.BuildConfig != nil && app.BuildConfig.CNBVersioning != nil {
			buildpackStackId = app.BuildConfig.CNBVersioning.StackID
			buildpacks = app.BuildConfig.CNBVersioning.Buildpacks
		}

		res, err := CreateResource(r.MqlRuntime, "digitalocean.app", map[string]*llx.RawData{
			"id":                     llx.StringData(app.ID),
			"name":                   llx.StringData(name),
			"liveUrl":                llx.StringData(app.LiveURL),
			"createdAt":              llx.TimeData(app.CreatedAt),
			"updatedAt":              llx.TimeData(app.UpdatedAt),
			"activeDeploymentStatus": llx.StringData(status),
			"spec":                   llx.DictData(spec),
			"region":                 llx.StringData(region),
			"tierSlug":               llx.StringData(app.TierSlug),
			"defaultIngress":         llx.StringData(app.DefaultIngress),
			"liveDomain":             llx.StringData(app.LiveDomain),
			"projectId":              llx.StringData(app.ProjectID),
			"activeDeploymentId":     llx.StringData(activeDeploymentId),
			"domains":                llx.ArrayData(domains, "\x13"),

			"enhancedThreatControlEnabled": llx.BoolData(app.Spec != nil && app.Spec.EnhancedThreatControlEnabled),
			"secureHeaderKey":              llx.StringData(secureHeaderKey),
			"secureHeaderValue":            llx.StringData(secureHeaderValue),
			"secureHeaderRemoved":          llx.BoolData(secureHeaderRemoved),
			"corsPolicies":                 llx.ArrayData(appCorsPolicies(app.Spec), types.Dict),
			"envVars":                      llx.ArrayData(appEnvVars(app.Spec), types.Dict),

			"liveUrlBase":      llx.StringData(app.LiveURLBase),
			"vpcEgressIps":     llx.ArrayData(vpcEgressIps, types.String),
			"buildpackStackId": llx.StringData(buildpackStackId),
		})
		if err != nil {
			return nil, err
		}
		mqlApp := res.(*mqlDigitaloceanApp)
		mqlApp.cacheSpec = app.Spec
		mqlApp.cacheVpcID = vpcID
		mqlApp.cacheDedicatedIps = app.DedicatedIps
		mqlApp.cacheBuildpacks = buildpacks
		mqlApp.cachePinnedDeployment = app.PinnedDeployment
		mqlApp.cacheInProgressDeployment = app.InProgressDeployment
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanApp) id() (string, error) {
	return "digitalocean.app/" + r.Id.Data, nil
}

// --- Monitoring Alert Policies ---

func (r *mqlDigitalocean) alertPolicies() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	policies, err := paginate(context.Background(), client.Monitoring.ListAlertPolicies)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(policies))
	for _, p := range policies {
		entities := make([]interface{}, len(p.Entities))
		for i, e := range p.Entities {
			entities[i] = e
		}
		pTags := make([]interface{}, len(p.Tags))
		for i, t := range p.Tags {
			pTags[i] = t
		}

		emails := make([]interface{}, 0)
		slacks := make([]interface{}, 0)
		if p.Alerts.Email != nil {
			for _, e := range p.Alerts.Email {
				emails = append(emails, e)
			}
		}
		if p.Alerts.Slack != nil {
			for _, s := range p.Alerts.Slack {
				slacks = append(slacks, map[string]interface{}{
					"channel": s.Channel,
					"url":     s.URL,
				})
			}
		}

		res, err := CreateResource(r.MqlRuntime, "digitalocean.alertPolicy", map[string]*llx.RawData{
			"uuid":        llx.StringData(p.UUID),
			"type":        llx.StringData(p.Type),
			"description": llx.StringData(p.Description),
			"compare":     llx.StringData(string(p.Compare)),
			"value":       llx.FloatData(float64(p.Value)),
			"window":      llx.StringData(p.Window),
			"enabled":     llx.BoolData(p.Enabled),
			"entities":    llx.ArrayData(entities, "\x02"),
			"tags":        llx.ArrayData(pTags, "\x02"),
			"alertEmails": llx.ArrayData(emails, "\x02"),
			"alertSlack":  llx.ArrayData(slacks, "\x13"),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanAlertPolicy) id() (string, error) {
	return "digitalocean.alertPolicy/" + r.Uuid.Data, nil
}

// --- Uptime Checks ---

func (r *mqlDigitalocean) uptimeChecks() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	checks, err := paginate(context.Background(), client.UptimeChecks.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(checks))
	for _, c := range checks {
		regions := make([]interface{}, len(c.Regions))
		for i, r := range c.Regions {
			regions[i] = r
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.uptimeCheck", map[string]*llx.RawData{
			"id":      llx.StringData(c.ID),
			"name":    llx.StringData(c.Name),
			"type":    llx.StringData(c.Type),
			"target":  llx.StringData(c.Target),
			"regions": llx.ArrayData(regions, "\x02"),
			"enabled": llx.BoolData(c.Enabled),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanUptimeCheck) id() (string, error) {
	return "digitalocean.uptimeCheck/" + r.Id.Data, nil
}

// --- CDN ---

func (r *mqlDigitalocean) cdnEndpoints() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []interface{}
	opt := &godo.ListOptions{PerPage: 200}
	for {
		cdns, resp, err := client.CDNs.List(context.Background(), opt)
		if err != nil {
			return nil, err
		}
		for _, c := range cdns {
			res, err := CreateResource(r.MqlRuntime, "digitalocean.cdn", map[string]*llx.RawData{
				"id":            llx.StringData(c.ID),
				"origin":        llx.StringData(c.Origin),
				"endpoint":      llx.StringData(c.Endpoint),
				"ttl":           llx.IntData(int64(c.TTL)),
				"certificateId": llx.StringData(c.CertificateID),
				"customDomain":  llx.StringData(c.CustomDomain),
				"createdAt":     llx.TimeData(c.CreatedAt),
			})
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}
		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return all, nil
}

func (r *mqlDigitaloceanCdn) id() (string, error) {
	return "digitalocean.cdn/" + r.Id.Data, nil
}

// --- Tags ---

func (r *mqlDigitalocean) tags() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	tags, err := paginate(context.Background(), client.Tags.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(tags))
	for _, t := range tags {
		count := 0
		if t.Resources != nil {
			count = t.Resources.Count
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.tag", map[string]*llx.RawData{
			"name":          llx.StringData(t.Name),
			"resourceCount": llx.IntData(int64(count)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanTag) id() (string, error) {
	return "digitalocean.tag/" + r.Name.Data, nil
}

// --- Spaces Keys ---

func (r *mqlDigitalocean) spacesKeys() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	// Walked through paginate rather than a hand-rolled loop: the previous
	// loop read resp.Links without first checking resp, and godo returns a
	// nil response alongside a nil error on some paths, which panics the
	// provider and takes down the whole scan.
	keys, err := paginate(context.Background(), client.SpacesKeys.List)
	if err != nil {
		// The Spaces Keys API 404s when Spaces is not enabled on the
		// account; tolerate that, but surface real failures (denied reads,
		// rate limits, network) instead of masking them as "no keys".
		if isDoNotFound(err) {
			return []interface{}{}, nil
		}
		return nil, err
	}

	all := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		if k == nil {
			continue
		}
		grants := make([]interface{}, 0, len(k.Grants))
		for _, g := range k.Grants {
			if g == nil {
				continue
			}
			grants = append(grants, map[string]interface{}{
				"bucket":     g.Bucket,
				"permission": string(g.Permission),
			})
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.spacesKey", map[string]*llx.RawData{
			"name":      llx.StringData(k.Name),
			"accessKey": llx.StringData(k.AccessKey),
			"grants":    llx.ArrayData(grants, "\x13"),
			"createdAt": llx.TimeDataPtr(parseDoTime(k.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanSpacesKey) id() (string, error) {
	return "digitalocean.spacesKey/" + r.AccessKey.Data, nil
}
