// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// doURNId strips a DigitalOcean URN prefix ("do:<type>:") from s and
// returns the trailing identifier, or s unchanged when it is not a URN.
// Monitoring alert entities arrive either as a bare id or as a URN
// depending on the resource type, so callers normalize before matching.
func doURNId(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "do:") {
		if _, after, ok := strings.CutLast(s, ":"); ok {
			return after
		}
	}
	return s
}

// parseDropletID extracts a droplet id from either a bare numeric id
// ("12345") or a DigitalOcean droplet URN ("do:droplet:12345"). The
// second return is false when the string names something other than a
// droplet.
func parseDropletID(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "do:") {
		parts := strings.Split(s, ":")
		if len(parts) != 3 || parts[1] != "droplet" {
			return 0, false
		}
		s = parts[2]
	}
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// volumeRef resolves a single volume by id from the parent's cached
// index, setting StateIsSet|StateIsNull when the id is unset or unknown.
func volumeRef(runtime *plugin.Runtime, id string, target *plugin.TValue[*mqlDigitaloceanVolume]) (*mqlDigitaloceanVolume, error) {
	if id == "" {
		target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(runtime)
	if err != nil {
		return nil, err
	}
	volumes, err := parent.volumesByIDs([]string{id})
	if err != nil {
		return nil, err
	}
	if len(volumes) == 0 {
		target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return volumes[0].(*mqlDigitaloceanVolume), nil
}

// ----- Database cluster project -----

func (r *mqlDigitaloceanDatabase) project() (*mqlDigitaloceanProject, error) {
	return projectRef(r.MqlRuntime, r.ProjectId.Data, &r.Project)
}

// ----- Snapshot source -----

func (r *mqlDigitaloceanSnapshot) droplet() (*mqlDigitaloceanDroplet, error) {
	if r.ResourceType.Data != "droplet" {
		r.Droplet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id, ok := parseDropletID(r.ResourceId.Data)
	if !ok {
		r.Droplet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return dropletRef(r.MqlRuntime, id, &r.Droplet)
}

func (r *mqlDigitaloceanSnapshot) volume() (*mqlDigitaloceanVolume, error) {
	if r.ResourceType.Data != "volume" {
		r.Volume.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return volumeRef(r.MqlRuntime, r.ResourceId.Data, &r.Volume)
}

// ----- Alert policy targets -----

// droplets resolves the policy's entity IDs to droplets. Droplet alert
// types carry droplet IDs (bare or as a do:droplet: URN); policies that
// target other entity kinds resolve to an empty list.
func (r *mqlDigitaloceanAlertPolicy) droplets() ([]any, error) {
	ids := make([]any, 0, len(r.Entities.Data))
	for _, e := range r.Entities.Data {
		s, ok := e.(string)
		if !ok {
			continue
		}
		if id, ok := parseDropletID(s); ok {
			ids = append(ids, id)
		}
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return parent.dropletByIDs(ids)
}

// ----- Volume snapshots -----

// snapshots lists the snapshots taken of this volume. Volume snapshots
// appear in the account-wide snapshot list tagged with the volume they came
// from, so they are read from there rather than through the per-volume
// endpoint, which would cost one call per volume.
func (r *mqlDigitaloceanVolume) snapshots() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return parent.snapshotsForSource("volume", r.Id.Data)
}

// ----- Firewall pending change -----

// The droplet a pending change applies to is kept here rather than as a
// field: it distinguishes one change from another in the cache key and is
// otherwise only useful resolved.
type mqlDigitaloceanFirewallPendingChangeInternal struct {
	cacheDropletID int64
}

func (r *mqlDigitaloceanFirewallPendingChange) droplet() (*mqlDigitaloceanDroplet, error) {
	return dropletRef(r.MqlRuntime, r.cacheDropletID, &r.Droplet)
}

// ----- BYOIP prefix resource assignment -----

func (r *mqlDigitaloceanByoipPrefixResource) droplet() (*mqlDigitaloceanDroplet, error) {
	id, ok := parseDropletID(r.Resource.Data)
	if !ok {
		r.Droplet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return dropletRef(r.MqlRuntime, id, &r.Droplet)
}

// ----- Alert policy non-droplet targets -----
//
// Alert entities carry a resource id (bare or as a do:<type>: URN) whose
// kind depends on the alert type. Each accessor resolves the entities
// against one resource index and returns the matches, so a policy that
// targets a different kind simply resolves to an empty list.

func (r *mqlDigitaloceanAlertPolicy) databases() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, e := range r.Entities.Data {
		s, ok := e.(string)
		if !ok {
			continue
		}
		db, err := parent.databaseByID(doURNId(s))
		if err != nil {
			return nil, err
		}
		if db != nil {
			out = append(out, db)
		}
	}
	return out, nil
}

func (r *mqlDigitaloceanAlertPolicy) loadBalancers() ([]any, error) {
	ids := make([]any, 0, len(r.Entities.Data))
	for _, e := range r.Entities.Data {
		if s, ok := e.(string); ok {
			ids = append(ids, doURNId(s))
		}
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return parent.loadBalancerByUIDs(ids)
}

func (r *mqlDigitaloceanAlertPolicy) kubernetesClusters() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, e := range r.Entities.Data {
		s, ok := e.(string)
		if !ok {
			continue
		}
		cluster, err := parent.kubernetesClusterByID(doURNId(s))
		if err != nil {
			return nil, err
		}
		if cluster != nil {
			out = append(out, cluster)
		}
	}
	return out, nil
}

// ----- Partner attachment parent / children -----

func (r *mqlDigitaloceanPartnerAttachment) parentAttachment() (*mqlDigitaloceanPartnerAttachment, error) {
	if r.ParentUuid.Data == "" {
		r.ParentAttachment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	pa, err := parent.partnerAttachmentByID(r.ParentUuid.Data)
	if err != nil {
		return nil, err
	}
	if pa == nil {
		r.ParentAttachment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return pa, nil
}

func (r *mqlDigitaloceanPartnerAttachment) childAttachments() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(r.Children.Data))
	for _, c := range r.Children.Data {
		s, ok := c.(string)
		if !ok {
			continue
		}
		pa, err := parent.partnerAttachmentByID(s)
		if err != nil {
			return nil, err
		}
		if pa != nil {
			out = append(out, pa)
		}
	}
	return out, nil
}

// ----- Container registry singleton -----

// registry exposes the account's container registry from the namespace so
// registry-level metadata (usage, subscription, garbage collection) is
// reachable by walking the digitalocean tree. NewResource runs the
// registry's init, which returns an empty sentinel when no registry exists.
func (r *mqlDigitalocean) registry() (*mqlDigitaloceanRegistry, error) {
	res, err := NewResource(r.MqlRuntime, "digitalocean.registry", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanRegistry), nil
}

// ----- VPC peering -----

func (r *mqlDigitaloceanVpcPeering) vpcs() ([]any, error) {
	uuids := make([]string, 0, len(r.VpcIds.Data))
	for _, v := range r.VpcIds.Data {
		if s, ok := v.(string); ok {
			uuids = append(uuids, s)
		}
	}
	return vpcRefsByUUIDs(r.MqlRuntime, uuids)
}

// ----- Kubernetes node pool -----

func (r *mqlDigitaloceanKubernetesNode) droplet() (*mqlDigitaloceanDroplet, error) {
	// The API returns the backing droplet's ID as a numeric string; it is
	// empty until the node's droplet has been provisioned.
	dropletID, err := strconv.ParseInt(r.cacheDropletID, 10, 64)
	if err != nil || dropletID == 0 {
		r.Droplet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return dropletRef(r.MqlRuntime, dropletID, &r.Droplet)
}

func (r *mqlDigitaloceanKubernetesNodePool) cluster() (*mqlDigitaloceanKubernetesCluster, error) {
	if r.ClusterId.Data == "" {
		r.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cluster, err := parent.kubernetesClusterByID(r.ClusterId.Data)
	if err != nil {
		return nil, err
	}
	if cluster == nil {
		r.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return cluster, nil
}

// ----- Droplet -----

func (r *mqlDigitaloceanDroplet) volumes() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return parent.volumesByIDs(r.cacheVolumeIDs)
}

func (r *mqlDigitaloceanDroplet) snapshots() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(r.cacheSnapshotIDs))
	for i, id := range r.cacheSnapshotIDs {
		ids[i] = strconv.Itoa(id)
	}
	return parent.snapshotsByIDs(ids)
}

func (r *mqlDigitaloceanDroplet) backups() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return parent.imagesByIDs(r.cacheBackupIDs)
}

// ----- Load balancer -----

func (r *mqlDigitaloceanLoadBalancer) project() (*mqlDigitaloceanProject, error) {
	return projectRef(r.MqlRuntime, r.ProjectId.Data, &r.Project)
}

func (r *mqlDigitaloceanLoadBalancer) targetLoadBalancers() ([]any, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ids := make([]any, len(r.cacheTargetLoadBalancerIDs))
	for i, id := range r.cacheTargetLoadBalancerIDs {
		ids[i] = id
	}
	return parent.loadBalancerByUIDs(ids)
}

// ----- App Platform -----

func (r *mqlDigitaloceanApp) project() (*mqlDigitaloceanProject, error) {
	return projectRef(r.MqlRuntime, r.ProjectId.Data, &r.Project)
}

// ----- Reserved IP (v4) -----

func (r *mqlDigitaloceanReservedIp) project() (*mqlDigitaloceanProject, error) {
	return projectRef(r.MqlRuntime, r.ProjectId.Data, &r.Project)
}

func (r *mqlDigitaloceanReservedIp) droplet() (*mqlDigitaloceanDroplet, error) {
	return dropletRef(r.MqlRuntime, r.DropletId.Data, &r.Droplet)
}

// ----- CDN -----

func (r *mqlDigitaloceanCdn) certificate() (*mqlDigitaloceanCertificate, error) {
	if r.CertificateId.Data == "" {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cert, err := parent.certificateByID(r.CertificateId.Data)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return cert, nil
}

// ----- Database sub-resource back-references -----

func databaseClusterRef(runtime *plugin.Runtime, id string, target *plugin.TValue[*mqlDigitaloceanDatabase]) (*mqlDigitaloceanDatabase, error) {
	if id == "" {
		target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(runtime)
	if err != nil {
		return nil, err
	}
	db, err := parent.databaseByID(id)
	if err != nil {
		return nil, err
	}
	if db == nil {
		target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return db, nil
}

func (r *mqlDigitaloceanDatabaseBackup) database() (*mqlDigitaloceanDatabase, error) {
	return databaseClusterRef(r.MqlRuntime, r.DatabaseId.Data, &r.Database)
}

func (r *mqlDigitaloceanDatabaseUser) database() (*mqlDigitaloceanDatabase, error) {
	return databaseClusterRef(r.MqlRuntime, r.DatabaseId.Data, &r.Database)
}

func (r *mqlDigitaloceanDatabaseReplica) database() (*mqlDigitaloceanDatabase, error) {
	return databaseClusterRef(r.MqlRuntime, r.DatabaseId.Data, &r.Database)
}

// pool exposes the parent cluster as databaseCluster() because its
// `database` field already names the logical database the pool connects to.
func (r *mqlDigitaloceanDatabasePool) databaseCluster() (*mqlDigitaloceanDatabase, error) {
	return databaseClusterRef(r.MqlRuntime, r.DatabaseId.Data, &r.DatabaseCluster)
}

// ----- Vector database backup back-reference -----

func (r *mqlDigitaloceanVectorDatabaseBackup) vectorDatabase() (*mqlDigitaloceanVectorDatabase, error) {
	if r.VectorDatabaseId.Data == "" {
		r.VectorDatabase.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	vdb, err := parent.vectorDatabaseByID(r.VectorDatabaseId.Data)
	if err != nil {
		return nil, err
	}
	if vdb == nil {
		r.VectorDatabase.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return vdb, nil
}
