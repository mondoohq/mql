// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// certExpired reports whether an expiry timestamp is in the past. A nil
// timestamp (for example a not-yet-provisioned managed certificate) reports
// false.
func certExpired(expireTime plugin.TValue[*time.Time]) (bool, error) {
	if expireTime.Error != nil {
		return false, expireTime.Error
	}
	if expireTime.Data == nil {
		return false, nil
	}
	return expireTime.Data.Before(time.Now()), nil
}

// certDaysUntilExpiry returns the whole number of days until an expiry
// timestamp, rounded down toward expiry: a value of 0 means the certificate
// expires within the next 24 hours, and the result goes negative once the
// certificate has expired. A nil timestamp returns 0.
func certDaysUntilExpiry(expireTime plugin.TValue[*time.Time]) (int64, error) {
	if expireTime.Error != nil {
		return 0, expireTime.Error
	}
	if expireTime.Data == nil {
		return 0, nil
	}
	const day = 24 * time.Hour
	remaining := time.Until(*expireTime.Data)
	days := remaining / day
	// Integer division truncates toward zero; floor negative durations so an
	// already-expired certificate consistently reports a negative day count.
	if remaining < 0 && remaining%day != 0 {
		days--
	}
	return int64(days), nil
}

// projectFromResourceName extracts the project id from a GCP resource name of
// the form "projects/{project}/...". Returns "" when no project segment is
// present.
func projectFromResourceName(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "projects" {
			return parts[i+1]
		}
	}
	return ""
}

// resolveServiceAccountRef resolves a service account reference to the typed
// gcp.project.iamService.serviceAccount resource. The raw value may be a bare
// email or a full "projects/{project}/serviceAccounts/{email}" path; for a bare
// email the fallbackProjectId is used. Returns nil when the reference is empty
// or cannot be resolved to a project + email.
func resolveServiceAccountRef(runtime *plugin.Runtime, raw, fallbackProjectId string) (*mqlGcpProjectIamServiceServiceAccount, error) {
	if raw == "" {
		return nil, nil
	}
	projectId, email := fallbackProjectId, raw
	if _, after, ok := strings.Cut(raw, "/serviceAccounts/"); ok {
		email = after
		if p := projectFromResourceName(raw); p != "" {
			projectId = p
		}
	}
	if projectId == "" || email == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

// projectRefById resolves the typed gcp.project resource for a project id.
// Returns nil when the id is empty, leaving the caller to mark the field null.
func projectRefById(runtime *plugin.Runtime, projectId string) (*mqlGcpProject, error) {
	if projectId == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProject), nil
}

// artifactRegistryRepoFromPath parses an Artifact Registry repository resource
// name of the form "projects/{project}/locations/{location}/repositories/{repo}"
// and returns its project, location, and repository components. Any component
// not present in the path is returned empty.
func artifactRegistryRepoFromPath(path string) (project, location, repo string) {
	parts := strings.Split(path, "/")
	for i := 0; i+1 < len(parts); i++ {
		switch parts[i] {
		case "projects":
			project = parts[i+1]
		case "locations":
			location = parts[i+1]
		case "repositories":
			repo = parts[i+1]
		}
	}
	return project, location, repo
}

// artifactRegistryRepoFromImage parses an Artifact Registry container image URL
// of the form "{location}-docker.pkg.dev/{project}/{repo}/{image}[:tag|@digest]"
// and returns its project, location, and repository components. It returns empty
// strings for images that are not hosted in Artifact Registry (for example
// Container Registry "gcr.io" images or external registries).
func artifactRegistryRepoFromImage(image string) (project, location, repo string) {
	s := strings.TrimPrefix(image, "https://")
	parts := strings.Split(s, "/")
	if len(parts) < 3 {
		return "", "", ""
	}
	host := parts[0]
	const suffix = "-docker.pkg.dev"
	if !strings.HasSuffix(host, suffix) {
		return "", "", ""
	}
	return parts[1], strings.TrimSuffix(host, suffix), parts[2]
}

// resolveArtifactRegistryRepoRef resolves the typed Artifact Registry repository
// resource for a given project, location, and repository name. It returns nil
// when any component is empty so callers can mark the field null.
func resolveArtifactRegistryRepoRef(runtime *plugin.Runtime, project, location, repo string) (*mqlGcpProjectArtifactRegistryServiceRepository, error) {
	if project == "" || location == "" || repo == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.artifactRegistryService.repository", map[string]*llx.RawData{
		"name":      llx.StringData(repo),
		"location":  llx.StringData(location),
		"projectId": llx.StringData(project),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectArtifactRegistryServiceRepository), nil
}

// parentFolderFromId resolves the typed folder for a Cloud Resource Manager
// parent reference. It returns nil when the parent is not a folder (for example
// an organization or an empty reference), leaving the caller to mark the field
// null.
func parentFolderFromId(parentId string, runtime *plugin.Runtime) (*mqlGcpFolder, error) {
	const prefix = "folders/"
	if !strings.HasPrefix(parentId, prefix) {
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.folder", map[string]*llx.RawData{
		"id": llx.StringData(strings.TrimPrefix(parentId, prefix)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpFolder), nil
}

// parentOrganizationFromId resolves the typed organization for a Cloud Resource
// Manager parent reference. It returns nil when the direct parent is not an
// organization (for example a folder). The organization resource resolves the
// organization of the active connection, which is the parent org of any project
// or folder under that org.
func parentOrganizationFromId(parentId string, runtime *plugin.Runtime) (*mqlGcpOrganization, error) {
	if !strings.HasPrefix(parentId, "organizations/") {
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpOrganization), nil
}

// protoToDict converts a protobuf message to a map[string]any suitable for use as a dict field.
// Returns nil for nil input, including typed nil interface values.
func protoToDict(msg proto.Message) (map[string]any, error) {
	if msg == nil {
		return nil, nil
	}
	if v := reflect.ValueOf(msg); v.Kind() == reflect.Pointer && v.IsNil() {
		return nil, nil
	}
	data, err := protojson.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// protoToDictSlice converts a slice of protobuf messages the same way
// protoToDict converts one. Use it instead of convert.JsonToDictSlice for
// protobuf-generated types: encoding/json emits their snake_case json tags and
// renders enums as numbers, neither of which matches what the schema documents.
func protoToDictSlice[T proto.Message](msgs []T) ([]any, error) {
	res := make([]any, 0, len(msgs))
	for _, msg := range msgs {
		d, err := protoToDict(msg)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

func (g *mqlGcpRetryConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func newRetryConfigResource(runtime *plugin.Runtime, parentId string, maxAttempts int64, minBackoff, maxBackoff string, maxDoublings int64, maxRetryDuration string) (*mqlGcpRetryConfig, error) {
	res, err := CreateResource(runtime, "gcp.retryConfig", map[string]*llx.RawData{
		"id":               llx.StringData(parentId + "/retryConfig"),
		"maxAttempts":      llx.IntData(maxAttempts),
		"minBackoff":       llx.StringData(minBackoff),
		"maxBackoff":       llx.StringData(maxBackoff),
		"maxDoublings":     llx.IntData(maxDoublings),
		"maxRetryDuration": llx.StringData(maxRetryDuration),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpRetryConfig), nil
}

func RegionNameFromRegionUrl(regionUrl string) string {
	regionUrlSegments := strings.Split(regionUrl, "/")
	return regionUrlSegments[len(regionUrlSegments)-1]
}

// zoneNamesFromUrls extracts the zone name (last path segment) from a list of
// full zone URLs (e.g. ".../zones/us-central1-a" -> "us-central1-a").
func zoneNamesFromUrls(urls []string) []any {
	res := make([]any, 0, len(urls))
	for _, u := range urls {
		segments := strings.Split(u, "/")
		res = append(res, segments[len(segments)-1])
	}
	return res
}

func timestampAsTimePtr(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	tm := t.AsTime()
	return &tm
}

func boolValueToPtr(b *wrapperspb.BoolValue) *bool {
	if b == nil {
		return nil
	}
	v := b.GetValue()
	return &v
}

// parseResourceName returns the name of a resource from either a full path or just the name.
func parseResourceName(fullPath string) string {
	segments := strings.Split(fullPath, "/")
	return segments[len(segments)-1]
}

// parseProjectFromPath extracts the project ID from a GCP resource path.
// The path format is: projects/{project}/...
// Returns "" if no project segment is found.
func parseProjectFromPath(fullPath string) string {
	segments := strings.Split(fullPath, "/")
	for i, s := range segments {
		if s == "projects" && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	return ""
}

// resolvePubsubTopicRef resolves a Pub/Sub topic reference to the typed
// gcp.project.pubsubService.topic resource. The reference is typically a full
// "projects/{project}/topics/{topic}" path; both the project and the short
// topic name are pulled from it (fallbackProjectId is used only when the path
// carries no project segment). Both are required: the topic init matches on the
// short name and needs the project to build its parent service, so passing the
// full path as the name (or omitting the project) leaves the ref unresolved.
// Returns nil when the reference is empty.
func resolvePubsubTopicRef(runtime *plugin.Runtime, topicRef, fallbackProjectId string) (*mqlGcpProjectPubsubServiceTopic, error) {
	if topicRef == "" {
		return nil, nil
	}
	projectId := fallbackProjectId
	if p := parseProjectFromPath(topicRef); p != "" {
		projectId = p
	}
	res, err := NewResource(runtime, "gcp.project.pubsubService.topic", map[string]*llx.RawData{
		"name":      llx.StringData(parseResourceName(topicRef)),
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectPubsubServiceTopic), nil
}

// parseLocationFromPath extracts the location/region from a GCP resource path.
// The path format is: projects/{project}/locations/{location}/...
// Returns "global" if no location segment is found.
func parseLocationFromPath(fullPath string) string {
	segments := strings.Split(fullPath, "/")
	for i, s := range segments {
		if s == "locations" && i+1 < len(segments) {
			return segments[i+1]
		}
	}
	return "global"
}

type assetIdentifier struct {
	name    string
	region  string
	project string
}

func getAssetIdentifier(runtime *plugin.Runtime) *assetIdentifier {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil
	}
	// The root asset and any inventory-file asset without a platform_ids block
	// carry no platform ids, so this must not index blindly: a panic here is
	// unrecoverable and takes down the whole scan. Every caller already handles
	// a nil return.
	asset := conn.Asset()
	if asset == nil || len(asset.PlatformIds) == 0 {
		return nil
	}
	id := asset.PlatformIds[0]

	if strings.HasPrefix(id, "//platformid.api.mondoo.app/runtime/gcp/") {
		// "//platformid.api.mondoo.app/runtime/gcp/{o.service}/v1/projects/{project}/regions/{region}/{objectType}/{name}"
		segments := strings.Split(id, "/")
		if len(segments) < 12 {
			return nil
		}
		name := segments[len(segments)-1]
		region := segments[10]
		project := segments[8]
		return &assetIdentifier{name: name, region: region, project: project}
	}

	return nil
}

type resourceId struct {
	Project string
	Region  string
	Name    string
}

func getDiskByUrl(diskUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceDisk, error) {
	if diskUrl == "" {
		return nil, nil
	}

	// URL format: https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/disks/{disk}
	//          or https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}/disks/{disk}
	diskId, err := getDiskIdByUrl(diskUrl)
	if err != nil {
		return nil, err
	}

	// The gcp.project.computeService.disk resource has no init, so NewResource
	// would leave a husk whose id() (derived from the unset Id field) collides
	// with every other url-resolved disk. Instead scan the parent project's
	// already-populated disks() list and return the real resource, mirroring
	// attachedDisk.source(). Returns (nil, nil) when the disk isn't in the
	// scanned project (e.g. a cross-project reference not otherwise scanned).
	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(diskId.Project),
	})
	if err != nil {
		return nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	disks := computeSvc.GetDisks()
	if disks.Error != nil {
		return nil, disks.Error
	}
	for _, d := range disks.Data {
		disk, ok := d.(*mqlGcpProjectComputeServiceDisk)
		if !ok || disk.Name.Data != diskId.Name {
			continue
		}
		// Disk names are unique per zone/region, so match the location segment
		// when the disk is zonal; regional disks carry no Zone, so fall back to
		// a name match within the project.
		if zone := disk.Zone.Data; zone != nil {
			if zone.GetName().Data == diskId.Region {
				return disk, nil
			}
			continue
		}
		// Regional disk (no zone): the location segment can't be matched against
		// a zone, so this falls back to a name match within the project. Two
		// regional disks with the same name in different regions would be
		// ambiguous; warn so it's visible.
		log.Warn().Str("disk", diskId.Name).Str("location", diskId.Region).
			Msg("resolving regional source disk by name only; result may be ambiguous across regions")
		return disk, nil
	}
	return nil, nil
}

// resolveComputeSnapshotByName returns the fully-populated snapshot with the
// given name from the project's snapshots() list. The snapshot resource has no
// init, so a NewResource by-name would collide on an empty __id; scanning the
// parent list returns the real resource. Returns (nil, nil) when not found.
func resolveComputeSnapshotByName(runtime *plugin.Runtime, projectId, name string) (*mqlGcpProjectComputeServiceSnapshot, error) {
	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	snapshots := computeSvc.GetSnapshots()
	if snapshots.Error != nil {
		return nil, snapshots.Error
	}
	for _, s := range snapshots.Data {
		snap, ok := s.(*mqlGcpProjectComputeServiceSnapshot)
		if ok && snap.Name.Data == name {
			return snap, nil
		}
	}
	return nil, nil
}

// resolveComputeStoragePoolByName returns the fully-populated storage pool with
// the given name from the project's storagePools() list. Same rationale as
// resolveComputeSnapshotByName. Returns (nil, nil) when not found.
func resolveComputeStoragePoolByName(runtime *plugin.Runtime, projectId, name string) (*mqlGcpProjectComputeServiceStoragePool, error) {
	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	pools := computeSvc.GetStoragePools()
	if pools.Error != nil {
		return nil, pools.Error
	}
	for _, p := range pools.Data {
		pool, ok := p.(*mqlGcpProjectComputeServiceStoragePool)
		if ok && pool.Name.Data == name {
			return pool, nil
		}
	}
	return nil, nil
}

// getNetworkByUrl resolves a typed network resource from either of the two
// reference formats GCP APIs hand back:
//
//   - Self-link URL:  https://www.googleapis.com/compute/v1/projects/{project}/global/networks/{name}
//     (also https://compute.googleapis.com/compute/v1/...)
//     Used by Compute, Memorystore PSC connections, etc.
//
//   - Bare resource name:  projects/{project}/global/networks/{name}
//     Used by Datastream's VpcPeeringConfig.Vpc, Memcache's AuthorizedNetwork, etc.
//
// After the prefix strip, both shapes collapse to the same path layout and
// can be split into 5 segments: ["projects", project, "global", "networks", name].
// Anything that doesn't fit that shape (empty, malformed) is rejected.
func getNetworkByUrl(networkUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceNetwork, error) {
	// A reference to a network is not mandatory for this resource
	if networkUrl == "" {
		return nil, nil
	}

	project, name, ok := parseNetworkURL(networkUrl)
	if !ok {
		return nil, fmt.Errorf("unrecognized network reference: %q", networkUrl)
	}

	// Use NewResource so initGcpProjectComputeServiceNetwork runs and
	// populates every field (scalars like autoCreateSubnetworks would
	// otherwise surface as "no type information" when accessed).
	res, err := NewResource(runtime, "gcp.project.computeService.network", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"projectId": llx.StringData(project),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceNetwork), nil
}

// parseSubnetworkURL extracts the project, region, and name from a compute
// subnetwork self-link. It accepts both the www.googleapis.com and
// compute.googleapis.com hosts. ok is false when the URL is empty or is not a
// recognized subnetwork reference.
func parseSubnetworkURL(subnetUrl string) (project, region, name string, ok bool) {
	if subnetUrl == "" {
		return "", "", "", false
	}
	// Format is https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/subnet-1
	// or https://compute.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/subnet-1
	params := strings.TrimPrefix(subnetUrl, "https://www.googleapis.com/compute/v1/")
	params = strings.TrimPrefix(params, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	if len(parts) < 6 || parts[0] != "projects" || parts[2] != "regions" || parts[4] != "subnetworks" {
		return "", "", "", false
	}
	return parts[1], parts[3], parts[5], true
}

func getSubnetworkByUrl(subnetUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceSubnetwork, error) {
	// A reference to a subnetwork is not mandatory for this resource
	if subnetUrl == "" {
		return nil, nil
	}

	project, region, name, ok := parseSubnetworkURL(subnetUrl)
	if !ok {
		return nil, fmt.Errorf("unrecognized subnetwork reference: %q", subnetUrl)
	}
	// regionUrl is the full URL up to and including the region segment
	regionUrl := "https://www.googleapis.com/compute/v1/projects/" + project + "/regions/" + region

	// Use NewResource so initGcpProjectComputeServiceSubnetwork runs and
	// populates every field instead of leaving the resource partially set.
	//
	// regionUrl has to go in the args, not just onto cacheRegionUrl afterwards.
	// The init matches a listed subnetwork on name, project *and* region, and
	// with no regionUrl its region is "", which matches nothing. It then falls
	// through to a direct Get carrying that empty region and GCP rejects it:
	//   GET .../projects/{p}/regions//subnetworks/{n} -> 400 Invalid value for
	//   field 'region': ''
	// which surfaces as an errored check rather than a resolved subnetwork.
	res, err := NewResource(runtime, "gcp.project.computeService.subnetwork", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"projectId": llx.StringData(project),
		"regionUrl": llx.StringData(regionUrl),
	})
	if err != nil {
		return nil, err
	}
	mqlRef := res.(*mqlGcpProjectComputeServiceSubnetwork)
	mqlRef.cacheRegionUrl = regionUrl
	return res.(*mqlGcpProjectComputeServiceSubnetwork), nil
}

func getDiskIdByUrl(diskUrl string) (*resourceId, error) {
	// A reference to a subnetwork is not mandatory for this resource
	if diskUrl == "" {
		return nil, errors.New("diskUrl is empty")
	}

	// Format is https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/disks/disk-1
	// or https://compute.googleapis.com/compute/v1/projects/project1/regions/us-central1/disks/disk-1
	params := strings.TrimPrefix(diskUrl, "https://www.googleapis.com/compute/v1/")
	params = strings.TrimPrefix(params, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	if len(parts) < 6 || parts[0] != "projects" {
		return nil, errors.New("invalid disk URL: " + diskUrl)
	}
	return &resourceId{Project: parts[1], Region: parts[3], Name: parts[5]}, nil
}

// parseProjectFromComputeUrl extracts the project id from a Compute self-link.
// Returns "" when the URL doesn't match either compute self-link prefix.
func parseProjectFromComputeUrl(url string) string {
	params := strings.TrimPrefix(url, "https://www.googleapis.com/compute/v1/")
	params = strings.TrimPrefix(params, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	if len(parts) < 2 || parts[0] != "projects" {
		return ""
	}
	return parts[1]
}

// getRegionByUrl resolves the typed region resource matching a region URL.
// Returns (nil, nil) for empty URLs (global resources). The init function on
// `gcp.project.computeService.region` does the actual fetch — either via
// `Regions.Get(projectId, name)` when the region isn't already in the
// runtime cache, or by returning the cached entry if `regions()` was
// previously listed on the same project.
func getRegionByUrl(regionUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceRegion, error) {
	if regionUrl == "" {
		return nil, nil
	}
	regionName := RegionNameFromRegionUrl(regionUrl)
	if regionName == "" {
		return nil, fmt.Errorf("could not extract region name from %q", regionUrl)
	}
	projectId := parseProjectFromComputeUrl(regionUrl)
	if projectId == "" {
		return nil, fmt.Errorf("could not extract project id from region url %q", regionUrl)
	}
	res, err := NewResource(runtime, "gcp.project.computeService.region", map[string]*llx.RawData{
		"name":      llx.StringData(regionName),
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceRegion), nil
}

// getZoneByUrl resolves the typed zone resource matching a zone URL.
// Returns (nil, nil) for empty URLs (regional resources). Resolution goes
// through the zone resource's init function (single `Zones.Get` call, or
// runtime cache hit if `zones()` was previously listed).
func getZoneByUrl(zoneUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceZone, error) {
	if zoneUrl == "" {
		return nil, nil
	}
	segments := strings.Split(zoneUrl, "/")
	zoneName := segments[len(segments)-1]
	if zoneName == "" {
		return nil, fmt.Errorf("could not extract zone name from %q", zoneUrl)
	}
	projectId := parseProjectFromComputeUrl(zoneUrl)
	if projectId == "" {
		return nil, fmt.Errorf("could not extract project id from zone url %q", zoneUrl)
	}
	res, err := NewResource(runtime, "gcp.project.computeService.zone", map[string]*llx.RawData{
		"name":      llx.StringData(zoneName),
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceZone), nil
}

// cachedResource returns a resource already built in this runtime, or nil.
//
// The runtime keys its resource cache on resourceName + "\x00" + id. Callers
// that check the cache before doing I/O need that same key, and spelling it out
// at each call site means a future change to the format has to find every copy.
// Mirrors the helper of the same name in the azure provider.
func cachedResource(runtime *plugin.Runtime, resourceName, id string) plugin.Resource {
	if id == "" || runtime == nil || runtime.Resources == nil {
		return nil
	}
	if res, ok := runtime.Resources.Get(resourceName + "\x00" + id); ok {
		return res
	}
	return nil
}
