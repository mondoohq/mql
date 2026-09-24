// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/sshutil"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

func (r *mqlDigitalocean) id() (string, error) {
	return "digitalocean", nil
}

// isDoNotFound reports whether err is a 404 from the DigitalOcean API.
// Use it to distinguish "this resource is not configured / does not
// exist on this account" (a soft absence) from transient or
// authorization failures (which should propagate).
func isDoNotFound(err error) bool {
	var er *godo.ErrorResponse
	if errors.As(err, &er) {
		return er.Response != nil && er.Response.StatusCode == http.StatusNotFound
	}
	return false
}

func (r *mqlDigitaloceanAccount) id() (string, error) {
	return "digitalocean.account", nil
}

func initDigitaloceanAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	acct, _, err := conn.Client().Account.Get(context.Background())
	if err != nil {
		return nil, nil, err
	}
	// godo returns (nil, nil) on a 200 whose body carries no "account" key.
	if acct == nil {
		return nil, nil, errors.New("the DigitalOcean API returned no account")
	}
	args["email"] = llx.StringData(acct.Email)
	args["uuid"] = llx.StringData(acct.UUID)
	args["dropletLimit"] = llx.IntData(int64(acct.DropletLimit))
	args["floatingIpLimit"] = llx.IntData(int64(acct.FloatingIPLimit))
	args["volumeLimit"] = llx.IntData(int64(acct.VolumeLimit))
	args["emailVerified"] = llx.BoolData(acct.EmailVerified)
	args["status"] = llx.StringData(acct.Status)
	args["statusMessage"] = llx.StringData(acct.StatusMessage)
	teamUuid, teamName := "", ""
	if acct.Team != nil {
		teamUuid = acct.Team.UUID
		teamName = acct.Team.Name
	}
	args["teamUuid"] = llx.StringData(teamUuid)
	args["teamName"] = llx.StringData(teamName)
	return args, nil, nil
}

func toStringSlice(s []string) []interface{} {
	r := make([]interface{}, len(s))
	for i, v := range s {
		r[i] = v
	}
	return r
}

func toIntSlice(s []int) []interface{} {
	r := make([]interface{}, len(s))
	for i, v := range s {
		r[i] = int64(v)
	}
	return r
}

// formatDoTime renders a time as RFC3339 for storage in a dict, returning ""
// for the zero value so timestamps don't surface a misleading
// "0001-01-01T00:00:00Z" when the API omitted them.
func formatDoTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// helper to parse DigitalOcean time strings
func parseDoTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

type mqlDigitaloceanDropletInternal struct {
	// image caches the godo image embedded in the droplet list response so the
	// typed baseImage() accessor can build a digitalocean.image without a refetch.
	image *godo.Image
	// size caches the godo size embedded in the droplet list response so the
	// typed dropletSize() accessor can build a digitalocean.size without a refetch.
	size *godo.Size
	// cacheVolumeIDs holds the block-storage volume IDs attached to the droplet so
	// the typed volumes() accessor can resolve them without a refetch.
	cacheVolumeIDs []string
	// cacheSnapshotIDs and cacheBackupIDs hold the image IDs of the droplet's
	// snapshots and automated backups so the typed snapshots()/backups()
	// accessors can resolve them without a refetch.
	cacheSnapshotIDs []int
	cacheBackupIDs   []int
	// cacheVPCUUID holds the UUID of the VPC the droplet is attached to so
	// the typed vpc() accessor can resolve it without a refetch.
	cacheVPCUUID string
}

func (r *mqlDigitalocean) droplets() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	droplets, err := paginate(context.Background(), client.Droplets.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(droplets))
	for _, d := range droplets {
		publicIPv4 := ""
		privateIPv4 := ""
		publicIPv6 := ""
		if d.Networks != nil {
			for _, v4 := range d.Networks.V4 {
				if v4.Type == "public" && publicIPv4 == "" {
					publicIPv4 = v4.IPAddress
				}
				if v4.Type == "private" && privateIPv4 == "" {
					privateIPv4 = v4.IPAddress
				}
			}
			for _, v6 := range d.Networks.V6 {
				if v6.Type == "public" && publicIPv6 == "" {
					publicIPv6 = v6.IPAddress
				}
			}
		}

		tags := make([]interface{}, len(d.Tags))
		for i, t := range d.Tags {
			tags[i] = t
		}

		features := make([]interface{}, len(d.Features))
		for i, f := range d.Features {
			features[i] = f
		}

		backupsEnabled := false
		monitoringEnabled := false
		for _, f := range d.Features {
			if f == "backups" {
				backupsEnabled = true
			}
			if f == "monitoring" {
				monitoringEnabled = true
			}
		}

		regionSlug := ""
		if d.Region != nil {
			regionSlug = d.Region.Slug
		}
		sizeSlug := ""
		if d.Size != nil {
			sizeSlug = d.Size.Slug
		}

		var kernelDict map[string]interface{}
		if d.Kernel != nil {
			kernelDict = map[string]interface{}{
				"id":      float64(d.Kernel.ID),
				"name":    d.Kernel.Name,
				"version": d.Kernel.Version,
			}
		}

		var nextBackupStart, nextBackupEnd *time.Time
		if d.NextBackupWindow != nil {
			if d.NextBackupWindow.Start != nil {
				nextBackupStart = &d.NextBackupWindow.Start.Time
			}
			if d.NextBackupWindow.End != nil {
				nextBackupEnd = &d.NextBackupWindow.End.Time
			}
		}

		res, err := CreateResource(r.MqlRuntime, "digitalocean.droplet", map[string]*llx.RawData{
			"id":                    llx.IntData(int64(d.ID)),
			"name":                  llx.StringData(d.Name),
			"memory":                llx.IntData(int64(d.Memory)),
			"vcpus":                 llx.IntData(int64(d.Vcpus)),
			"disk":                  llx.IntData(int64(d.Disk)),
			"region":                llx.StringData(regionSlug),
			"size":                  llx.StringData(sizeSlug),
			"gpuPartitionMode":      llx.StringData(d.GPUPartitionMode),
			"status":                llx.StringData(d.Status),
			"locked":                llx.BoolData(d.Locked),
			"createdAt":             llx.TimeDataPtr(parseDoTime(d.Created)),
			"publicIpv4":            llx.StringData(publicIPv4),
			"privateIpv4":           llx.StringData(privateIPv4),
			"publicIpv6":            llx.StringData(publicIPv6),
			"tags":                  llx.ArrayData(tags, "\x02"),
			"features":              llx.ArrayData(features, "\x02"),
			"backupsEnabled":        llx.BoolData(backupsEnabled),
			"monitoringEnabled":     llx.BoolData(monitoringEnabled),
			"kernel":                llx.DictData(kernelDict),
			"nextBackupWindowStart": llx.TimeDataPtr(nextBackupStart),
			"nextBackupWindowEnd":   llx.TimeDataPtr(nextBackupEnd),
		})
		if err != nil {
			return nil, err
		}
		// Cache the godo image for the typed baseImage() accessor, the VPC
		// UUID for vpc(), plus the volume / snapshot / backup image IDs for
		// the typed volumes(), snapshots(), and backups() accessors — all
		// without a refetch.
		mqlDroplet := res.(*mqlDigitaloceanDroplet)
		mqlDroplet.image = d.Image
		mqlDroplet.size = d.Size
		mqlDroplet.cacheVPCUUID = d.VPCUUID
		mqlDroplet.cacheVolumeIDs = d.VolumeIDs
		mqlDroplet.cacheSnapshotIDs = d.SnapshotIDs
		mqlDroplet.cacheBackupIDs = d.BackupIDs
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanDroplet) id() (string, error) {
	return "digitalocean.droplet/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlDigitalocean) firewalls() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	firewalls, err := paginate(context.Background(), client.Firewalls.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(firewalls))
	for _, fw := range firewalls {
		if skipFirewall(conn.Filters.General, &fw) {
			continue
		}
		res, err := newMqlFirewall(r.MqlRuntime, &fw)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanFirewall) id() (string, error) {
	return "digitalocean.firewall/" + r.Id.Data, nil
}

func (r *mqlDigitalocean) databases() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	dbs, err := paginate(context.Background(), client.Databases.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(dbs))
	for _, db := range dbs {
		if skipDatabase(conn.Filters.General, &db) {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.database", databaseArgs(&db))
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanDatabase) id() (string, error) {
	return "digitalocean.database/" + r.Id.Data, nil
}

func (r *mqlDigitaloceanDatabase) firewallRules() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	rules, _, err := client.Databases.GetFirewallRules(context.Background(), r.Id.Data)
	if err != nil {
		return nil, err
	}

	var all []interface{}
	for _, rule := range rules {
		all = append(all, map[string]interface{}{
			"uuid":      rule.UUID,
			"type":      rule.Type,
			"value":     rule.Value,
			"createdAt": rule.CreatedAt.Format(time.RFC3339),
		})
	}
	return all, nil
}

func (r *mqlDigitalocean) domains() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []interface{}
	opt := &godo.ListOptions{PerPage: 200}
	for {
		domains, resp, err := client.Domains.List(context.Background(), opt)
		if err != nil {
			return nil, err
		}
		for _, d := range domains {
			res, err := CreateResource(r.MqlRuntime, "digitalocean.domain", map[string]*llx.RawData{
				"name":     llx.StringData(d.Name),
				"ttl":      llx.IntData(int64(d.TTL)),
				"zoneFile": llx.StringData(d.ZoneFile),
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

func (r *mqlDigitaloceanDomain) id() (string, error) {
	return "digitalocean.domain/" + r.Name.Data, nil
}

func (r *mqlDigitaloceanDomain) records() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	records, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]godo.DomainRecord, *godo.Response, error) {
		return client.Domains.Records(c, r.Name.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(records))
	for _, rec := range records {
		res, err := CreateResource(r.MqlRuntime, "digitalocean.domain.record", map[string]*llx.RawData{
			"domainName": llx.StringData(r.Name.Data),
			"id":         llx.IntData(int64(rec.ID)),
			"type":       llx.StringData(rec.Type),
			"name":       llx.StringData(rec.Name),
			"data":       llx.StringData(rec.Data),
			"ttl":        llx.IntData(int64(rec.TTL)),
			"priority":   llx.IntData(int64(rec.Priority)),
			"port":       llx.IntData(int64(rec.Port)),
			"weight":     llx.IntData(int64(rec.Weight)),
			"tag":        llx.StringData(rec.Tag),
			"flags":      llx.IntData(int64(rec.Flags)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanDomainRecord) id() (string, error) {
	return "digitalocean.domain.record/" + r.DomainName.Data + "/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlDigitalocean) volumes() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []interface{}
	opt := &godo.ListVolumeParams{ListOptions: &godo.ListOptions{PerPage: 200}}
	for {
		volumes, resp, err := client.Storage.ListVolumes(context.Background(), opt)
		if err != nil {
			return nil, err
		}
		for _, v := range volumes {
			tags := make([]interface{}, len(v.Tags))
			for i, t := range v.Tags {
				tags[i] = t
			}

			volRegion := ""
			if v.Region != nil {
				volRegion = v.Region.Slug
			}
			res, err := CreateResource(r.MqlRuntime, "digitalocean.volume", map[string]*llx.RawData{
				"id":              llx.StringData(v.ID),
				"name":            llx.StringData(v.Name),
				"sizeGigabytes":   llx.IntData(v.SizeGigaBytes),
				"region":          llx.StringData(volRegion),
				"description":     llx.StringData(v.Description),
				"filesystemType":  llx.StringData(v.FilesystemType),
				"filesystemLabel": llx.StringData(v.FilesystemLabel),
				"createdAt":       llx.TimeData(v.CreatedAt),
				"tags":            llx.ArrayData(tags, "\x02"),
			})
			if err != nil {
				return nil, err
			}
			// Cache the attached droplet IDs so the typed droplets() accessor
			// can resolve them without a refetch.
			res.(*mqlDigitaloceanVolume).cacheDropletIDs = toIntSlice(v.DropletIDs)
			all = append(all, res)
		}
		if resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.ListOptions.Page = page + 1
	}
	return all, nil
}

type mqlDigitaloceanVolumeInternal struct {
	// cacheDropletIDs holds the IDs of the droplets the volume is attached
	// to so the typed droplets() accessor can resolve them without a refetch.
	cacheDropletIDs []any
}

func (r *mqlDigitaloceanVolume) id() (string, error) {
	return "digitalocean.volume/" + r.Id.Data, nil
}

func (r *mqlDigitalocean) loadBalancers() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	lbs, err := paginate(context.Background(), client.LoadBalancers.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(lbs))
	for _, lb := range lbs {
		if skipLoadBalancer(conn.Filters.General, &lb) {
			continue
		}
		res, err := newMqlLoadBalancer(r.MqlRuntime, &lb)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

type mqlDigitaloceanLoadBalancerInternal struct {
	// cacheTargetLoadBalancerIDs holds the regional load balancer IDs a global
	// load balancer fans out to, so targetLoadBalancers() can resolve them
	// without a refetch.
	cacheTargetLoadBalancerIDs []string
	// cacheVPCUUID and cacheDropletIDs hold the VPC the load balancer is
	// attached to and the droplets behind it, so the typed vpc() and
	// droplets() accessors can resolve them without a refetch.
	cacheVPCUUID    string
	cacheDropletIDs []any
	// cacheForwardingRules holds the port mappings the load balancer accepts
	// connections on, so listeners() can build one resource per rule.
	cacheForwardingRules []godo.ForwardingRule
}

func (r *mqlDigitaloceanLoadBalancer) id() (string, error) {
	return "digitalocean.loadBalancer/" + r.Id.Data, nil
}

func (r *mqlDigitalocean) vpcs() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	vpcs, err := paginate(context.Background(), client.VPCs.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(vpcs))
	for _, v := range vpcs {
		res, err := CreateResource(r.MqlRuntime, "digitalocean.vpc", map[string]*llx.RawData{
			"id":          llx.StringData(v.ID),
			"name":        llx.StringData(v.Name),
			"description": llx.StringData(v.Description),
			"ipRange":     llx.StringData(v.IPRange),
			"region":      llx.StringData(v.RegionSlug),
			"createdAt":   llx.TimeData(v.CreatedAt),
			"default":     llx.BoolData(v.Default),
			"urn":         llx.StringData(v.URN),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanVpc) id() (string, error) {
	return "digitalocean.vpc/" + r.Id.Data, nil
}

func (r *mqlDigitalocean) kubernetesClusters() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	clusters, err := paginate(context.Background(), client.Kubernetes.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(clusters))
	for _, c := range clusters {
		if skipKubernetesCluster(conn.Filters.General, c) {
			continue
		}
		res, err := newMqlKubernetesCluster(r.MqlRuntime, c)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanKubernetesCluster) id() (string, error) {
	return "digitalocean.kubernetes.cluster/" + r.Id.Data, nil
}

// projectResourceType pulls the resource kind out of a DigitalOcean URN, which
// is shaped "do:<type>:<identifier>" (for example do:droplet:123). Returns ""
// for anything that does not follow that shape.
func projectResourceType(urn string) string {
	parts := strings.Split(urn, ":")
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

// resources lists the resources assigned to the project, which is how an
// account's infrastructure is grouped for ownership and billing.
func (r *mqlDigitaloceanProject) resources() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	items, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]godo.ProjectResource, *godo.Response, error) {
		return client.Projects.ListResources(c, r.Id.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(items))
	for _, item := range items {
		id, err := resourceID("digitalocean.project.resource", r.Id.Data, item.URN)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.project.resource", map[string]*llx.RawData{
			"__id":         llx.StringData(id),
			"urn":          llx.StringData(item.URN),
			"projectId":    llx.StringData(r.Id.Data),
			"resourceType": llx.StringData(projectResourceType(item.URN)),
			"assignedAt":   llx.TimeDataPtr(parseDoTime(item.AssignedAt)),
			"status":       llx.StringData(item.Status),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitalocean) projects() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	projects, err := paginate(context.Background(), client.Projects.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(projects))
	for _, p := range projects {
		res, err := CreateResource(r.MqlRuntime, "digitalocean.project", map[string]*llx.RawData{
			"id":          llx.StringData(p.ID),
			"name":        llx.StringData(p.Name),
			"description": llx.StringData(p.Description),
			"purpose":     llx.StringData(p.Purpose),
			"environment": llx.StringData(p.Environment),
			"createdAt":   llx.TimeDataPtr(parseDoTime(p.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(parseDoTime(p.UpdatedAt)),
			"isDefault":   llx.BoolData(p.IsDefault),
			"ownerUuid":   llx.StringData(p.OwnerUUID),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanProject) id() (string, error) {
	return "digitalocean.project/" + r.Id.Data, nil
}

func (r *mqlDigitalocean) sshKeys() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	keys, err := paginate(context.Background(), client.Keys.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		algorithm, bits := sshutil.ParsePublicKey(k.PublicKey)
		res, err := CreateResource(r.MqlRuntime, "digitalocean.sshKey", map[string]*llx.RawData{
			"id":          llx.IntData(int64(k.ID)),
			"name":        llx.StringData(k.Name),
			"fingerprint": llx.StringData(k.Fingerprint),
			"publicKey":   llx.StringData(k.PublicKey),
			"algorithm":   llx.StringData(algorithm),
			"bits":        llx.IntData(bits),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanSshKey) id() (string, error) {
	return "digitalocean.sshKey/" + strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlDigitalocean) certificates() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	certs, err := paginate(context.Background(), client.Certificates.List)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(certs))
	for _, c := range certs {
		dnsNames := make([]interface{}, len(c.DNSNames))
		for i, n := range c.DNSNames {
			dnsNames[i] = n
		}

		res, err := CreateResource(r.MqlRuntime, "digitalocean.certificate", map[string]*llx.RawData{
			"id":              llx.StringData(c.ID),
			"name":            llx.StringData(c.Name),
			"sha1Fingerprint": llx.StringData(c.SHA1Fingerprint),
			"state":           llx.StringData(c.State),
			"type":            llx.StringData(c.Type),
			"dnsNames":        llx.ArrayData(dnsNames, "\x02"),
			"notAfter":        llx.TimeDataPtr(parseDoTime(c.NotAfter)),
			"createdAt":       llx.TimeDataPtr(parseDoTime(c.Created)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanCertificate) id() (string, error) {
	return "digitalocean.certificate/" + r.Id.Data, nil
}
