// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/smithy-go/ptr"

	computev1 "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectComputeServiceAddressInternal struct {
	cacheNetworkUrl    string
	cacheRegionUrl     string
	cacheSubnetworkUrl string
}

type mqlGcpProjectComputeServiceBackendServiceInternal struct {
	cacheEdgeSecurityPolicyUrl string
	cacheNetworkUrl            string
	cacheRegionUrl             string
	cacheSecurityPolicyUrl     string
}

type mqlGcpProjectComputeServiceNetworkPeeringInternal struct {
	cacheNetworkUrl string
}

type mqlGcpProjectComputeServiceSslCertificateInternal struct {
	cacheRegionUrl string
}

type mqlGcpProjectComputeServiceSslPolicyInternal struct {
	cacheRegionUrl string
}

type mqlGcpProjectComputeServiceSubnetworkInternal struct {
	cacheNetworkUrl string
	cacheRegionUrl  string
	cacheSelfLink   string
}

func initGcpProjectComputeService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	// Only default the project from the connection when the caller did not
	// supply one. NewResource runs this init before the resource-cache lookup,
	// so an unconditional overwrite redirects every caller-scoped reference
	// (gcp.projects.list { compute.instances }, instance.exposure) at the
	// connection's own project, and on an organization- or folder-scoped
	// connection ResourceID() is not a project id at all.
	if pid, ok := args["projectId"]; !ok || pid == nil {
		args["projectId"] = llx.StringData(conn.ResourceID())
	}

	return args, nil, nil
}

func (g *mqlGcpProject) compute() (*mqlGcpProjectComputeService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := NewResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	computeService := res.(*mqlGcpProjectComputeService)
	return computeService, nil
}

func (g *mqlGcpProjectComputeService) enabled() (bool, error) {
	gcpProjectRes, err := NewResource(g.MqlRuntime, "gcp.project", map[string]*llx.RawData{"id": llx.StringData(g.ProjectId.Data)})
	if err != nil {
		return false, err
	}
	gcpProject := gcpProjectRes.(*mqlGcpProject)

	serviceEnabled, err := gcpProject.isServiceEnabled(service_compute)
	if err != nil {
		return false, err
	}
	return serviceEnabled, nil
}

// serviceEnabled resolves the compute service-enabled gate and propagates the
// error from that resolution.
//
// Reading `GetEnabled().Data` on its own is not safe: enabled() resolves
// gcp.project and calls isServiceEnabled, and on any failure of that chain (a
// serviceusage permission gap, the Service Usage API itself disabled, a
// transient error) GetOrCompute returns Data=false alongside a non-nil Error.
// A caller that only reads Data then reports "this project has no instances /
// firewalls / disks" for a project it was never able to check -- an empty list
// is the most dangerous wrong answer for a posture check, because it passes
// vacuously instead of failing or erroring.
func (g *mqlGcpProjectComputeService) serviceEnabled() (bool, error) {
	enabled := g.GetEnabled()
	if enabled.Error != nil {
		return false, enabled.Error
	}
	return enabled.Data, nil
}

func (g *mqlGcpProjectComputeService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.computeService", projectId), nil
}

func (g *mqlGcpProjectComputeServiceRegion) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	id := g.Name.Data
	return "gcp.project.computeService.region/" + id, nil
}

func initGcpProjectComputeServiceRegion(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	// projectId scopes the lookup but is not a field on this resource, so it has
	// to be consumed here. Leaving it in args reaches SetAllData on any path
	// that returns without a resource, which rejects it as an unknown field --
	// a bare `gcp.project.computeService.region` then fails with
	// "cannot set 'projectId' ... field not found" instead of resolving.
	projectId := conn.ResourceID()
	if pid := args["projectId"]; pid != nil {
		if v, ok := pid.Value.(string); ok && v != "" {
			projectId = v
		}
	}
	delete(args, "projectId")

	// When the caller passes a name, fetch the single region directly via
	// Regions.Get rather than relying on a downstream regions() scan. This
	// makes `NewResource("...region", {name, projectId})` cheap for typed
	// references (e.g. instance.region()) when regions() has not been listed.
	// Without a name there is nothing to look up. Returning an empty resource
	// here would hand the runtime a husk whose every field is unset, which
	// surfaces as "encountered a primitive with no type information" with
	// nothing naming the cause; say what is missing instead.
	nameArg, hasName := args["name"]
	if !hasName || nameArg == nil {
		return nil, nil, errors.New(`gcp.project.computeService.region requires a "name" argument`)
	}
	name, ok := nameArg.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.computeService.region requires a non-empty "name" argument`)
	}

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, compute.ComputeReadonlyScope)
	if err != nil {
		return nil, nil, err
	}
	computeSvc, err := compute.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}
	region, err := computeSvc.Regions.Get(projectId, name).Do()
	if err != nil {
		return nil, nil, err
	}
	mqlRegion, err := newMqlRegion(runtime, projectId, region)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlRegion.(plugin.Resource), nil
}

func initGcpProjectComputeServiceZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	// projectId scopes the lookup but is not a field on this resource. See
	// initGcpProjectComputeServiceRegion for why it must not survive into args.
	projectId := conn.ResourceID()
	if pid := args["projectId"]; pid != nil {
		if v, ok := pid.Value.(string); ok && v != "" {
			projectId = v
		}
	}
	delete(args, "projectId")

	// Without a name there is nothing to look up. Returning an empty resource
	// here would hand the runtime a husk whose every field is unset, which
	// surfaces as "encountered a primitive with no type information" with
	// nothing naming the cause; say what is missing instead.
	nameArg, hasName := args["name"]
	if !hasName || nameArg == nil {
		return nil, nil, errors.New(`gcp.project.computeService.zone requires a "name" argument`)
	}
	name, ok := nameArg.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.computeService.zone requires a non-empty "name" argument`)
	}

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, compute.ComputeReadonlyScope)
	if err != nil {
		return nil, nil, err
	}
	computeSvc, err := compute.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}
	zone, err := computeSvc.Zones.Get(projectId, name).Do()
	if err != nil {
		return nil, nil, err
	}
	mqlZone, err := newMqlZone(runtime, zone)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlZone.(plugin.Resource), nil
}

func newMqlZone(runtime *plugin.Runtime, z *compute.Zone) (any, error) {
	return CreateResource(runtime, "gcp.project.computeService.zone", map[string]*llx.RawData{
		"id":          llx.StringData(strconv.FormatInt(int64(z.Id), 10)),
		"name":        llx.StringData(z.Name),
		"description": llx.StringData(z.Description),
		"status":      llx.StringData(z.Status),
		"created":     llx.TimeDataPtr(parseTime(z.CreationTimestamp)),
	})
}

func (g *mqlGcpProjectComputeService) regions() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	if err := computeSvc.Regions.List(projectId).Pages(ctx, func(page *compute.RegionList) error {
		for _, r := range page.Items {
			mqlRegion, err := newMqlRegion(g.MqlRuntime, projectId, r)
			if err != nil {
				return err
			}
			res = append(res, mqlRegion)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	log.Debug().Str("project", projectId).Int("regions", len(res)).Msg("gcp.compute> listed regions")
	return res, nil
}

func (g *mqlGcpProjectComputeServiceZone) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcp.project.computeService.zone/" + id, nil
}

func (g *mqlGcpProjectComputeService) zones() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, compute.ComputeReadonlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := computeSvc.Zones.List(projectId)
	if err := req.Pages(ctx, func(page *compute.ZoneList) error {
		for _, zone := range page.Items {
			mqlZone, err := newMqlZone(g.MqlRuntime, zone)
			if err != nil {
				return err
			}
			res = append(res, mqlZone)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	log.Debug().Str("project", projectId).Int("zones", len(res)).Msg("gcp.compute> listed zones")
	return res, nil
}

// machineTypeID builds the cache key for a machine type. The zone is part of
// the key because a machine type is a per-zone catalogue entry and its numeric
// id is shared across zones.
func machineTypeID(projectId, zoneName, name string) string {
	return "gcp.project.computeService.machineType/" + projectId + "/" + zoneName + "/" + name
}

// id is the fallback for a machine type built without an explicit "__id".
// It cannot see the zone (the field holds a resource, not a name, and may not
// be set yet at construction time), so newMqlMachineType passes "__id"
// directly, which wins over this method.
func (g *mqlGcpProjectComputeServiceMachineType) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data

	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	return "gcp.project.computeService.machineType/" + projectId + "/" + id, nil
}

func (g *mqlGcpProjectComputeServiceMachineType) zone() (any, error) {
	// NOTE: this should never be called since we add the zone during construction of the resource
	return nil, errors.New("not implemented")
}

func newMqlMachineType(runtime *plugin.Runtime, entry *compute.MachineType, projectId string, zone *mqlGcpProjectComputeServiceZone) (*mqlGcpProjectComputeServiceMachineType, error) {
	res, err := CreateResource(runtime, "gcp.project.computeService.machineType", map[string]*llx.RawData{
		// Machine types are a per-zone catalogue and the numeric id is a
		// catalogue constant: e2-medium carries the same Id in every zone. An
		// id() keyed on (project, id) therefore collapsed every zone's copy
		// onto one cache entry, so machineTypes() returned N duplicates all
		// reporting the FIRST zone -- and machineTypeByZoneAndName, which
		// indexes on zone+name, only ever saw that one zone, silently falling
		// back to a per-instance MachineTypes.Get for every VM elsewhere.
		// An explicit __id wins over id(); see the note on id() below.
		"__id":                         llx.StringData(machineTypeID(projectId, zone.GetName().Data, entry.Name)),
		"id":                           llx.StringData(strconv.FormatInt(int64(entry.Id), 10)),
		"projectId":                    llx.StringData(projectId),
		"name":                         llx.StringData(entry.Name),
		"description":                  llx.StringData(entry.Description),
		"guestCpus":                    llx.IntData(entry.GuestCpus),
		"isSharedCpu":                  llx.BoolData(entry.IsSharedCpu),
		"maximumPersistentDisks":       llx.IntData(entry.MaximumPersistentDisks),
		"maximumPersistentDisksSizeGb": llx.IntData(entry.MaximumPersistentDisksSizeGb),
		"memoryMb":                     llx.IntData(entry.MemoryMb),
		"created":                      llx.TimeDataPtr(parseTime(entry.CreationTimestamp)),
		"zone":                         llx.ResourceData(zone, "gcp.project.computeService.zone"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceMachineType), nil
}

func (g *mqlGcpProjectComputeService) machineTypes() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	zones := g.GetZones()
	if zones.Error != nil {
		return nil, zones.Error
	}
	zonesByName := make(map[string]*mqlGcpProjectComputeServiceZone, len(zones.Data))
	for _, z := range zones.Data {
		zone := z.(*mqlGcpProjectComputeServiceZone)
		name := zone.GetName()
		if name.Error != nil {
			return nil, name.Error
		}
		zonesByName[name.Data] = zone
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.MachineTypes.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.MachineTypeAggregatedList) error {
		for scope, scopedList := range page.Items {
			zoneName, ok := strings.CutPrefix(scope, "zones/")
			if !ok {
				continue
			}
			zone, ok := zonesByName[zoneName]
			if !ok {
				continue
			}
			for _, machinetype := range scopedList.MachineTypes {
				mqlMachineType, err := newMqlMachineType(g.MqlRuntime, machinetype, projectId, zone)
				if err != nil {
					return err
				}
				res = append(res, mqlMachineType)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func initGcpProjectComputeServiceInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["region"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// The instance is matched by (region, name, projectId); without all three we
	// can't do the lookup. This has to run before the parent computeService is
	// built: a missing projectId reaches CreateResource as a nil *llx.RawData and
	// the generated setter dereferences it, panicking before any later guard runs.
	if args["region"] == nil || args["name"] == nil || args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.instance requires region, name, and projectId")
	}
	wantRegion := args["region"]
	wantName := args["name"]
	wantProjectId := args["projectId"]

	// Try to find the instance in the MQL cache first
	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	instances := computeSvc.GetInstances()
	if instances.Error != nil {
		return nil, nil, instances.Error
	}

	for _, inst := range instances.Data {
		instance := inst.(*mqlGcpProjectComputeServiceInstance)
		name := instance.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		projectId := instance.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}
		instanceZone := instance.GetZone()
		if instanceZone.Error != nil {
			return nil, nil, instanceZone.Error
		}
		if instanceZone.Data == nil {
			continue
		}

		if instanceZone.Data.Name.Data == wantRegion.Value && name.Data == wantName.Value && projectId.Data == wantProjectId.Value {
			return args, instance, nil
		}
	}

	return nil, nil, errors.New("instance not found")
}

func (g *mqlGcpProjectComputeServiceInstanceShieldedInstanceConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceInstance) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data

	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	return "gcp.project.computeService.instance/" + projectId + "/" + id, nil
}

type mqlGcpProjectComputeServiceInternal struct {
	machineTypeIndexOnce sync.Once
	machineTypeIndex     map[string]*mqlGcpProjectComputeServiceMachineType
	machineTypeIndexErr  error
	// sharedVpcState caches the project's Shared VPC topology; see
	// compute_shared_vpc.go.
	sharedVpcState sharedVpcState
}

// machineTypeByZoneAndName resolves a machine type from the project's
// machineTypes() aggregated list, building a zone+name index once on first use
// so each lookup is O(1) rather than a linear scan per instance. Returns
// (nil, nil) when the machine type is not in the list (e.g. a custom machine
// type), so callers fall back to a direct Get.
func (g *mqlGcpProjectComputeService) machineTypeByZoneAndName(zone, name string) (*mqlGcpProjectComputeServiceMachineType, error) {
	g.machineTypeIndexOnce.Do(func() {
		machineTypes := g.GetMachineTypes()
		if machineTypes.Error != nil {
			// Logged once here (sync.Once) so the degradation to per-instance
			// Gets is observable rather than a silent error swallow.
			log.Warn().Err(machineTypes.Error).Msg("could not list machine types; instance.machineType() will fall back to per-instance Get")
			g.machineTypeIndexErr = machineTypes.Error
			return
		}
		index := make(map[string]*mqlGcpProjectComputeServiceMachineType, len(machineTypes.Data))
		for _, mt := range machineTypes.Data {
			m, ok := mt.(*mqlGcpProjectComputeServiceMachineType)
			if !ok || m.Name.Error != nil || m.Zone.Error != nil || m.Zone.Data == nil || m.Zone.Data.Name.Error != nil {
				continue
			}
			index[m.Zone.Data.Name.Data+"/"+m.Name.Data] = m
		}
		g.machineTypeIndex = index
	})
	if g.machineTypeIndexErr != nil {
		return nil, g.machineTypeIndexErr
	}
	return g.machineTypeIndex[zone+"/"+name], nil
}

func (g *mqlGcpProjectComputeServiceInstance) machineType() (*mqlGcpProjectComputeServiceMachineType, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	zone := g.GetZone()
	if zone.Error != nil {
		return nil, zone.Error
	}

	zoneName := zone.Data.GetName()
	if zoneName.Error != nil {
		return nil, zoneName.Error
	}

	machineTypeUrl := g.instanceMachineType
	values := strings.Split(machineTypeUrl, "/")
	machineTypeValue := values[len(values)-1]

	// Resolve through the project's machineTypes() aggregated list, which is
	// fetched once and indexed, rather than issuing a MachineTypes.Get per
	// instance. For hundreds of VMs this turns N Gets into a single
	// AggregatedList plus O(1) lookups.
	svcObj, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	if m, _ := svcObj.(*mqlGcpProjectComputeService).machineTypeByZoneAndName(zoneName.Data, machineTypeValue); m != nil {
		return m, nil
	}

	// Fall back to a direct Get for two cases: the machine type is absent from
	// the aggregated list (custom machine types are synthesized and never
	// listed), or the list could not be fetched (logged once in
	// machineTypeByZoneAndName). The error is intentionally not propagated —
	// the direct Get is the path machineType() used before this optimization,
	// so a transient list failure degrades to the prior behavior rather than
	// introducing a new failure mode.
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	machineType, err := computeSvc.MachineTypes.Get(projectId, zoneName.Data, machineTypeValue).Do()
	if err != nil {
		return nil, err
	}

	return newMqlMachineType(g.MqlRuntime, machineType, projectId, zone.Data)
}

// newMqlServiceAccount builds the per-instance service account binding. The
// resource carries the OAuth `scopes` granted to one VM, which differ between
// VMs sharing the same service account, so the cache key has to include the
// instance. Keying on the email alone made every VM using the default compute
// service account report the first VM's scopes.
func newMqlServiceAccount(runtime *plugin.Runtime, instanceId uint64, sa *compute.ServiceAccount) (any, error) {
	return CreateResource(runtime, "gcp.project.computeService.serviceaccount", map[string]*llx.RawData{
		"__id":   llx.StringData(fmt.Sprintf("gcp.project.computeService.instance/%d/serviceaccount/%s", instanceId, sa.Email)),
		"email":  llx.StringData(sa.Email),
		"scopes": llx.ArrayData(convert.SliceAnyToInterface(sa.Scopes), types.String),
	})
}

type mqlGcpProjectComputeServiceAttachedDiskInternal struct {
	attachedDiskSource string
}

func newMqlAttachedDisk(id string, projectId string, runtime *plugin.Runtime, attachedDisk *compute.AttachedDisk) (*mqlGcpProjectComputeServiceAttachedDisk, error) {
	guestOsFeatures := []string{}
	for i := range attachedDisk.GuestOsFeatures {
		entry := attachedDisk.GuestOsFeatures[i]
		guestOsFeatures = append(guestOsFeatures, entry.Type)
	}

	diskEncryption, err := newMqlCustomerEncryptionKey(runtime, id, "diskEncryption", attachedDisk.DiskEncryptionKey)
	if err != nil {
		return nil, err
	}

	mqlAttachedDisk, err := CreateResource(runtime, "gcp.project.computeService.attachedDisk", map[string]*llx.RawData{
		"id":                llx.StringData(id),
		"projectId":         llx.StringData(projectId),
		"architecture":      llx.StringData(attachedDisk.Architecture),
		"autoDelete":        llx.BoolData(attachedDisk.AutoDelete),
		"boot":              llx.BoolData(attachedDisk.Boot),
		"deviceName":        llx.StringData(attachedDisk.DeviceName),
		"diskSizeGb":        llx.IntData(attachedDisk.DiskSizeGb),
		"forceAttach":       llx.BoolData(attachedDisk.ForceAttach),
		"guestOsFeatures":   llx.ArrayData(convert.SliceAnyToInterface(guestOsFeatures), types.String),
		"index":             llx.IntData(attachedDisk.Index),
		"interface":         llx.StringData(attachedDisk.Interface),
		"licenses":          llx.ArrayData(convert.SliceAnyToInterface(attachedDisk.Licenses), types.String),
		"mode":              llx.StringData(attachedDisk.Mode),
		"type":              llx.StringData(attachedDisk.Type),
		"diskEncryptionKey": llx.DictData(customerEncryptionKeyToDict(attachedDisk.DiskEncryptionKey)),
		"diskEncryption":    diskEncryption,
	})
	if err != nil {
		return nil, err
	}
	r := mqlAttachedDisk.(*mqlGcpProjectComputeServiceAttachedDisk)
	r.attachedDiskSource = attachedDisk.Source
	return r, nil
}

func (g *mqlGcpProjectComputeServiceAttachedDisk) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data

	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	return "gcp.project.computeService.attachedDisk/" + projectId + "/" + id, nil
}

func (g *mqlGcpProjectComputeServiceAttachedDisk) source() (*mqlGcpProjectComputeServiceDisk, error) {
	diskId, err := getDiskIdByUrl(g.attachedDiskSource)
	if err != nil {
		return nil, err
	}

	obj, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.ProjectId.Data),
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
		disk := d.(*mqlGcpProjectComputeServiceDisk)
		if disk.Name.Data != diskId.Name {
			continue
		}
		if zone := disk.Zone.Data; zone != nil {
			if zone.GetName().Data == diskId.Region {
				return disk, nil
			}
			continue
		}
		// Regional disk (no zone): fall back to a name match within the project.
		// Same-named regional disks in different regions would be ambiguous.
		log.Warn().Str("disk", diskId.Name).Str("location", diskId.Region).
			Msg("resolving regional attached disk by name only; result may be ambiguous across regions")
		return disk, nil
	}
	return nil, errors.New("disk not found")
}

type mqlGcpProjectComputeServiceInstanceInternal struct {
	instanceMachineType       string
	cacheNetworkUrls          []string
	cacheSubnetworkUrls       []string
	cacheServiceAccountEmails []string
}

func (g *mqlGcpProjectComputeServiceInstance) effectiveTags() ([]any, error) {
	if g.SelfLink.Error != nil {
		return nil, g.SelfLink.Error
	}
	return effectiveTagsForResource(g.MqlRuntime, computeSelfLinkToResourceName(g.SelfLink.Data))
}

func newMqlComputeServiceInstance(projectId string, zone *mqlGcpProjectComputeServiceZone, runtime *plugin.Runtime, instance *compute.Instance) (*mqlGcpProjectComputeServiceInstance, error) {
	metadata := map[string]string{}
	if instance.Metadata != nil {
		for m := range instance.Metadata.Items {
			item := instance.Metadata.Items[m]

			value := ""
			if item.Value != nil {
				value = *item.Value
			}
			metadata[item.Key] = value
		}
	}

	mqlServiceAccounts := []any{}
	for i := range instance.ServiceAccounts {
		sa := instance.ServiceAccounts[i]

		mqlServiceAccount, err := newMqlServiceAccount(runtime, instance.Id, sa)
		if err != nil {
			log.Error().Err(err).Send()
		} else {
			mqlServiceAccounts = append(mqlServiceAccounts, mqlServiceAccount)
		}
	}

	var physicalHost string
	if instance.ResourceStatus != nil {
		physicalHost = instance.ResourceStatus.PhysicalHost
	}

	var enableIntegrityMonitoring bool
	var enableSecureBoot bool
	var enableVtpm bool
	var mqlShieldedInstanceConfig plugin.Resource
	if instance.ShieldedInstanceConfig != nil {
		enableIntegrityMonitoring = instance.ShieldedInstanceConfig.EnableIntegrityMonitoring
		enableSecureBoot = instance.ShieldedInstanceConfig.EnableSecureBoot
		enableVtpm = instance.ShieldedInstanceConfig.EnableVtpm
		var err error
		mqlShieldedInstanceConfig, err = CreateResource(runtime, "gcp.project.computeService.instance.shieldedInstanceConfig", map[string]*llx.RawData{
			"id":                        llx.StringData(fmt.Sprintf("%d/shieldedInstanceConfig", instance.Id)),
			"enableIntegrityMonitoring": llx.BoolData(enableIntegrityMonitoring),
			"enableSecureBoot":          llx.BoolData(enableSecureBoot),
			"enableVtpm":                llx.BoolData(enableVtpm),
		})
		if err != nil {
			return nil, err
		}
	}

	var enableDisplay bool
	if instance.DisplayDevice != nil {
		enableDisplay = instance.DisplayDevice.EnableDisplay
	}

	guestAccelerators, err := convert.JsonToDictSlice(instance.GuestAccelerators)
	if err != nil {
		return nil, err
	}

	mqlNics := make([]any, 0, len(instance.NetworkInterfaces))
	for _, ni := range instance.NetworkInterfaces {
		if ni == nil {
			continue
		}
		nic, err := newMqlComputeNetworkInterface(runtime, instance.Id, ni)
		if err != nil {
			return nil, err
		}
		mqlNics = append(mqlNics, nic)
	}

	stackTypeSet := map[string]struct{}{}
	networkStackTypes := []any{}
	var networkUrls, subnetworkUrls []string
	for _, ni := range instance.NetworkInterfaces {
		if ni == nil {
			continue
		}
		if ni.Network != "" {
			networkUrls = append(networkUrls, ni.Network)
		}
		if ni.Subnetwork != "" {
			subnetworkUrls = append(subnetworkUrls, ni.Subnetwork)
		}
		if ni.StackType == "" {
			continue
		}
		if _, ok := stackTypeSet[ni.StackType]; ok {
			continue
		}
		stackTypeSet[ni.StackType] = struct{}{}
		networkStackTypes = append(networkStackTypes, ni.StackType)
	}

	var serviceAccountEmails []string
	for _, sa := range instance.ServiceAccounts {
		if sa != nil && sa.Email != "" {
			serviceAccountEmails = append(serviceAccountEmails, sa.Email)
		}
	}

	var mqlWorkloadIdentityConfig map[string]any
	if instance.WorkloadIdentityConfig != nil {
		mqlWorkloadIdentityConfig, err = convert.JsonToDict(instance.WorkloadIdentityConfig)
		if err != nil {
			return nil, err
		}
	}

	mqlInstanceEncryptionKey := customerEncryptionKeyToDict(instance.InstanceEncryptionKey)
	mqlSourceMachineImageEncryptionKey := customerEncryptionKeyToDict(instance.SourceMachineImageEncryptionKey)
	instanceEncryption, err := newMqlCustomerEncryptionKey(runtime, "gcp.project.computeService.instance/"+strconv.FormatUint(instance.Id, 10), "instanceEncryption", instance.InstanceEncryptionKey)
	if err != nil {
		return nil, err
	}
	sourceMachineImageEncryption, err := newMqlCustomerEncryptionKey(runtime, "gcp.project.computeService.instance/"+strconv.FormatUint(instance.Id, 10), "sourceMachineImageEncryption", instance.SourceMachineImageEncryptionKey)
	if err != nil {
		return nil, err
	}

	var mqlAdvancedMachineFeatures map[string]any
	if instance.AdvancedMachineFeatures != nil {
		mqlAdvancedMachineFeatures = map[string]any{
			"enableNestedVirtualization": instance.AdvancedMachineFeatures.EnableNestedVirtualization,
			"enableUefiNetworking":       instance.AdvancedMachineFeatures.EnableUefiNetworking,
			"threadsPerCore":             instance.AdvancedMachineFeatures.ThreadsPerCore,
			"visibleCoreCount":           instance.AdvancedMachineFeatures.VisibleCoreCount,
			"performanceMonitoringUnit":  instance.AdvancedMachineFeatures.PerformanceMonitoringUnit,
			"turboMode":                  instance.AdvancedMachineFeatures.TurboMode,
		}
	}

	reservationAffinity, err := convert.JsonToDict(instance.ReservationAffinity)
	if err != nil {
		return nil, err
	}

	scheduling, err := convert.JsonToDict(instance.Scheduling)
	if err != nil {
		return nil, err
	}
	shieldedIntegrityPolicy, err := convert.JsonToDict(instance.ShieldedInstanceIntegrityPolicy)
	if err != nil {
		return nil, err
	}

	var totalEgressBandwidthTier string
	if instance.NetworkPerformanceConfig != nil {
		totalEgressBandwidthTier = instance.NetworkPerformanceConfig.TotalEgressBandwidthTier
	}

	instanceId := strconv.FormatUint(instance.Id, 10)
	attachedDisks := []any{}
	for i := range instance.Disks {
		disk := instance.Disks[i]
		attachedDiskID := instanceId + "/" + strconv.FormatInt(disk.Index, 10)
		attachedDisk, err := newMqlAttachedDisk(attachedDiskID, projectId, runtime, disk)
		if err != nil {
			log.Error().Err(err).Send()
			continue
		}
		attachedDisks = append(attachedDisks, attachedDisk)
	}

	var mqlConfidentialCompute plugin.Resource
	if instance.ConfidentialInstanceConfig != nil {
		mqlConfidentialCompute, err = CreateResource(runtime, "gcp.project.computeService.instance.confidentialCompute", map[string]*llx.RawData{
			"__id":         llx.StringData(fmt.Sprintf("%d/confidentialCompute", instance.Id)),
			"enabled":      llx.BoolData(instance.ConfidentialInstanceConfig.EnableConfidentialCompute),
			"instanceType": llx.StringData(instance.ConfidentialInstanceConfig.ConfidentialInstanceType),
		})
		if err != nil {
			return nil, err
		}
	}

	var tagsItems []string
	if instance.Tags != nil {
		tagsItems = instance.Tags.Items
	}

	entry, err := CreateResource(runtime, "gcp.project.computeService.instance", map[string]*llx.RawData{
		"id":                              llx.StringData(instanceId),
		"projectId":                       llx.StringData(projectId),
		"name":                            llx.StringData(instance.Name),
		"description":                     llx.StringData(instance.Description),
		"confidentialCompute":             llx.ResourceData(mqlConfidentialCompute, "gcp.project.computeService.instance.confidentialCompute"),
		"canIpForward":                    llx.BoolData(instance.CanIpForward),
		"cpuPlatform":                     llx.StringData(instance.CpuPlatform),
		"created":                         llx.TimeDataPtr(parseTime(instance.CreationTimestamp)),
		"deletionProtection":              llx.BoolData(instance.DeletionProtection),
		"enableDisplay":                   llx.BoolData(enableDisplay),
		"guestAccelerators":               llx.ArrayData(guestAccelerators, types.Dict),
		"fingerprint":                     llx.StringData(instance.Fingerprint),
		"selfLink":                        llx.StringData(instance.SelfLink),
		"hostname":                        llx.StringData(instance.Hostname),
		"keyRevocationActionType":         llx.StringData(instance.KeyRevocationActionType),
		"labels":                          llx.MapData(convert.MapToInterfaceMap(instance.Labels), types.String),
		"lastStartTimestamp":              llx.TimeDataPtr(parseTime(instance.LastStartTimestamp)),
		"lastStopTimestamp":               llx.TimeDataPtr(parseTime(instance.LastStopTimestamp)),
		"lastSuspendedTimestamp":          llx.TimeDataPtr(parseTime(instance.LastSuspendedTimestamp)),
		"metadata":                        llx.MapData(convert.MapToInterfaceMap(metadata), types.String),
		"minCpuPlatform":                  llx.StringData(instance.MinCpuPlatform),
		"nics":                            llx.ArrayData(mqlNics, types.Resource("gcp.project.computeService.instance.networkInterface")),
		"networkStackTypes":               llx.ArrayData(networkStackTypes, types.String),
		"privateIpv6GoogleAccess":         llx.StringData(instance.PrivateIpv6GoogleAccess),
		"localSsdEncryptionMode":          llx.StringData(instance.LocalSsdEncryptionMode),
		"reservationAffinity":             llx.DictData(reservationAffinity),
		"resourcePolicies":                llx.ArrayData(convert.SliceAnyToInterface(instance.ResourcePolicies), types.String),
		"physicalHostResourceStatus":      llx.StringData(physicalHost),
		"scheduling":                      llx.DictData(scheduling),
		"shieldedInstanceConfig":          llx.ResourceData(mqlShieldedInstanceConfig, "gcp.project.computeService.instance.shieldedInstanceConfig"),
		"shieldedInstanceIntegrityPolicy": llx.DictData(shieldedIntegrityPolicy),
		"startRestricted":                 llx.BoolData(instance.StartRestricted),
		"status":                          llx.StringData(instance.Status),
		"statusMessage":                   llx.StringData(instance.StatusMessage),
		"sourceMachineImage":              llx.StringData(instance.SourceMachineImage),
		"tags":                            llx.ArrayData(convert.SliceAnyToInterface(tagsItems), types.String),
		"totalEgressBandwidthTier":        llx.StringData(totalEgressBandwidthTier),
		"serviceAccounts":                 llx.ArrayData(mqlServiceAccounts, types.Resource("gcp.project.computeService.serviceaccount")),
		"disks":                           llx.ArrayData(attachedDisks, types.Resource("gcp.project.computeService.attachedDisk")),
		"zone":                            llx.ResourceData(zone, "gcp.project.computeService.zone"),
		"satisfiesPzi":                    llx.BoolData(instance.SatisfiesPzi),
		"satisfiesPzs":                    llx.BoolData(instance.SatisfiesPzs),
		"workloadIdentityConfig":          llx.DictData(mqlWorkloadIdentityConfig),
		"instanceEncryptionKey":           llx.DictData(mqlInstanceEncryptionKey),
		"instanceEncryption":              instanceEncryption,
		"sourceMachineImageEncryptionKey": llx.DictData(mqlSourceMachineImageEncryptionKey),
		"sourceMachineImageEncryption":    sourceMachineImageEncryption,
		"advancedMachineFeatures":         llx.DictData(mqlAdvancedMachineFeatures),
	})
	if err != nil {
		return nil, err
	}
	mqlR := entry.(*mqlGcpProjectComputeServiceInstance)
	mqlR.instanceMachineType = instance.MachineType
	mqlR.cacheNetworkUrls = networkUrls
	mqlR.cacheSubnetworkUrls = subnetworkUrls
	mqlR.cacheServiceAccountEmails = serviceAccountEmails
	return mqlR, nil
}

func (g *mqlGcpProjectComputeServiceInstance) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func (g *mqlGcpProjectComputeServiceInstance) networks() ([]any, error) {
	res := make([]any, 0, len(g.cacheNetworkUrls))
	for _, url := range g.cacheNetworkUrls {
		network, err := getNetworkByUrl(url, g.MqlRuntime)
		if err != nil {
			return nil, err
		}
		if network != nil {
			res = append(res, network)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceInstance) subnetworks() ([]any, error) {
	res := make([]any, 0, len(g.cacheSubnetworkUrls))
	for _, url := range g.cacheSubnetworkUrls {
		subnet, err := getSubnetworkByUrl(url, g.MqlRuntime)
		if err != nil {
			return nil, err
		}
		if subnet != nil {
			res = append(res, subnet)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceInstance) serviceAccountRefs() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	res := make([]any, 0, len(g.cacheServiceAccountEmails))
	for _, email := range g.cacheServiceAccountEmails {
		sa, err := resolveServiceAccountRef(g.MqlRuntime, email, projectId)
		if err != nil {
			return nil, err
		}
		if sa != nil {
			res = append(res, sa)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectComputeService) instances() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	zones := g.GetZones()
	if zones.Error != nil {
		return nil, zones.Error
	}
	zonesByName := make(map[string]*mqlGcpProjectComputeServiceZone, len(zones.Data))
	for _, z := range zones.Data {
		zone := z.(*mqlGcpProjectComputeServiceZone)
		name := zone.GetName()
		if name.Error != nil {
			return nil, name.Error
		}
		zonesByName[name.Data] = zone
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.Instances.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for scope, scopedList := range page.Items {
			zoneName, ok := strings.CutPrefix(scope, "zones/")
			if !ok {
				continue
			}
			zone, ok := zonesByName[zoneName]
			if !ok {
				continue
			}
			for _, instance := range scopedList.Instances {
				mqlInstance, err := newMqlComputeServiceInstance(projectId, zone, g.MqlRuntime, instance)
				if err != nil {
					return err
				}
				res = append(res, mqlInstance)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	log.Debug().Str("project", projectId).Int("instances", len(res)).Msg("gcp.compute> listed instances")
	return res, nil
}

func (g *mqlGcpProjectComputeServiceServiceaccount) id() (string, error) {
	if g.Email.Error != nil {
		return "", g.Email.Error
	}
	email := g.Email.Data
	return "gcp.project.computeService.serviceaccount/" + email, nil
}

func (g *mqlGcpProjectComputeServiceDisk) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.disk/" + id, nil
}

func (g *mqlGcpProjectComputeServiceDisk) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

type mqlGcpProjectComputeServiceDiskInternal struct {
	cacheSourceDiskUrl     string
	cacheSourceImageUrl    string
	cacheSourceSnapshotUrl string
	cacheStoragePoolUrl    string
	cacheKmsKeyName        string
	cacheSelfLink          string
}

func (g *mqlGcpProjectComputeServiceDisk) effectiveTags() ([]any, error) {
	return effectiveTagsForResource(g.MqlRuntime, computeSelfLinkToResourceName(g.cacheSelfLink))
}

func (g *mqlGcpProjectComputeServiceDisk) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectComputeServiceDisk) sourceDisk() (*mqlGcpProjectComputeServiceDisk, error) {
	if g.cacheSourceDiskUrl == "" {
		g.SourceDisk.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	disk, err := getDiskByUrl(g.cacheSourceDiskUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if disk == nil {
		g.SourceDisk.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return disk, nil
}

func (g *mqlGcpProjectComputeServiceDisk) sourceImage() (*mqlGcpProjectComputeServiceImage, error) {
	url := g.cacheSourceImageUrl
	if url == "" {
		g.SourceImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// URL format: https://www.googleapis.com/compute/v1/projects/{project}/global/images/{image}
	const computePrefix = "https://www.googleapis.com/compute/v1/"
	if !strings.HasPrefix(url, computePrefix) {
		return nil, errors.New("invalid source image URL: " + url)
	}
	parts := strings.Split(strings.TrimPrefix(url, computePrefix), "/")
	if len(parts) < 5 {
		return nil, errors.New("invalid source image URL: " + url)
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.computeService.image", map[string]*llx.RawData{
		"name":      llx.StringData(parts[len(parts)-1]),
		"projectId": llx.StringData(parts[1]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceImage), nil
}

func (g *mqlGcpProjectComputeServiceDisk) sourceSnapshot() (*mqlGcpProjectComputeServiceSnapshot, error) {
	url := g.cacheSourceSnapshotUrl
	if url == "" {
		g.SourceSnapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// URL format: https://www.googleapis.com/compute/v1/projects/{project}/global/snapshots/{snapshot}
	const computePrefix = "https://www.googleapis.com/compute/v1/"
	if !strings.HasPrefix(url, computePrefix) {
		return nil, errors.New("invalid source snapshot URL: " + url)
	}
	parts := strings.Split(strings.TrimPrefix(url, computePrefix), "/")
	if len(parts) < 5 || parts[0] != "projects" {
		return nil, errors.New("invalid source snapshot URL: " + url)
	}
	snap, err := resolveComputeSnapshotByName(g.MqlRuntime, parts[1], parts[len(parts)-1])
	if err != nil {
		return nil, err
	}
	if snap == nil {
		g.SourceSnapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return snap, nil
}

func (g *mqlGcpProjectComputeServiceDisk) storagePool() (*mqlGcpProjectComputeServiceStoragePool, error) {
	url := g.cacheStoragePoolUrl
	if url == "" {
		g.StoragePool.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// URL format: https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/storagePools/{name}
	const computePrefix = "https://www.googleapis.com/compute/v1/"
	if !strings.HasPrefix(url, computePrefix) {
		return nil, errors.New("invalid storage pool URL: " + url)
	}
	parts := strings.Split(strings.TrimPrefix(url, computePrefix), "/")
	if len(parts) < 6 || parts[0] != "projects" {
		return nil, errors.New("invalid storage pool URL: " + url)
	}
	pool, err := resolveComputeStoragePoolByName(g.MqlRuntime, parts[1], parts[5])
	if err != nil {
		return nil, err
	}
	if pool == nil {
		g.StoragePool.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return pool, nil
}

// customerEncryptionKeyToDict converts a Compute Engine CustomerEncryptionKey to a dict
// shape: {kmsKeyName, kmsKeyServiceAccount, rawKey, rsaEncryptedKey, sha256}. Returns
// nil when the key is nil so the field surfaces as null in MQL.
func customerEncryptionKeyToDict(key *compute.CustomerEncryptionKey) map[string]any {
	if key == nil {
		return nil
	}
	return map[string]any{
		"kmsKeyName":           key.KmsKeyName,
		"kmsKeyServiceAccount": key.KmsKeyServiceAccount,
		"rawKey":               key.RawKey,
		"rsaEncryptedKey":      key.RsaEncryptedKey,
		"sha256":               key.Sha256,
	}
}

// computeAggregatedScope splits a Compute AggregatedList scope key into its
// kind and name. Compute keys aggregated results by "zones/<zone>" for zonal
// resources and "regions/<region>" for regional ones; the "global" bucket and
// any future scope kind report ok=false so callers skip them explicitly rather
// than silently mapping them into the wrong location.
func computeAggregatedScope(scope string) (kind, name string, ok bool) {
	if n, found := strings.CutPrefix(scope, "zones/"); found && n != "" {
		return "zone", n, true
	}
	if n, found := strings.CutPrefix(scope, "regions/"); found && n != "" {
		return "region", n, true
	}
	return "", "", false
}

func (g *mqlGcpProjectComputeService) disks() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	// get list of zones first since we need this for all entries
	zones := g.GetZones()
	if zones.Error != nil {
		return nil, zones.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	zonesByName := make(map[string]*mqlGcpProjectComputeServiceZone, len(zones.Data))
	for _, z := range zones.Data {
		zone := z.(*mqlGcpProjectComputeServiceZone)
		name := zone.GetName()
		if name.Error != nil {
			return nil, name.Error
		}
		zonesByName[name.Data] = zone
	}

	var res []any
	req := computeSvc.Disks.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.DiskAggregatedList) error {
		for scope, scopedList := range page.Items {
			// Disks are aggregated under both "zones/<zone>" (zonal) and
			// "regions/<region>" (regional, synchronously replicated). Skipping
			// the regional scope hid every regional PD -- the HA disk type --
			// from encryption and source-image audits with no error.
			kind, locationName, ok := computeAggregatedScope(scope)
			if !ok {
				continue
			}
			// A regional disk has no zone, so the field resolves to null. It
			// must be llx.NilData and not a typed-nil resource pointer: a typed
			// nil is a non-nil interface, which RawToTValue records as set and
			// NOT null, and the runtime then dereferences it.
			zoneData := llx.NilData
			if kind == "zone" {
				zone, found := zonesByName[locationName]
				if !found {
					continue
				}
				zoneData = llx.ResourceData(zone, "gcp.project.computeService.zone")
			}
			for _, disk := range scopedList.Disks {
				guestOsFeatures := []string{}
				for i := range disk.GuestOsFeatures {
					entry := disk.GuestOsFeatures[i]
					guestOsFeatures = append(guestOsFeatures, entry.Type)
				}

				mqlDiskEnc := customerEncryptionKeyToDict(disk.DiskEncryptionKey)
				mqlSourceImageEnc := customerEncryptionKeyToDict(disk.SourceImageEncryptionKey)
				mqlSourceSnapshotEnc := customerEncryptionKeyToDict(disk.SourceSnapshotEncryptionKey)
				diskID := "gcp.project.computeService.disk/" + strconv.FormatUint(disk.Id, 10)
				diskEncryption, err := newMqlCustomerEncryptionKey(g.MqlRuntime, diskID, "diskEncryption", disk.DiskEncryptionKey)
				if err != nil {
					return err
				}
				sourceImageEncryption, err := newMqlCustomerEncryptionKey(g.MqlRuntime, diskID, "sourceImageEncryption", disk.SourceImageEncryptionKey)
				if err != nil {
					return err
				}
				sourceSnapshotEncryption, err := newMqlCustomerEncryptionKey(g.MqlRuntime, diskID, "sourceSnapshotEncryption", disk.SourceSnapshotEncryptionKey)
				if err != nil {
					return err
				}

				var mqlAsyncPrimary map[string]any
				if disk.AsyncPrimaryDisk != nil {
					mqlAsyncPrimary = map[string]any{
						"disk":                     disk.AsyncPrimaryDisk.Disk,
						"consistencyGroupPolicy":   disk.AsyncPrimaryDisk.ConsistencyGroupPolicy,
						"consistencyGroupPolicyId": disk.AsyncPrimaryDisk.ConsistencyGroupPolicyId,
					}
				}

				var mqlAsyncSecondaries map[string]any
				if len(disk.AsyncSecondaryDisks) > 0 {
					mqlAsyncSecondaries = make(map[string]any, len(disk.AsyncSecondaryDisks))
					for scope, entry := range disk.AsyncSecondaryDisks {
						var inner map[string]any
						if entry.AsyncReplicationDisk != nil {
							inner = map[string]any{
								"disk":                     entry.AsyncReplicationDisk.Disk,
								"consistencyGroupPolicy":   entry.AsyncReplicationDisk.ConsistencyGroupPolicy,
								"consistencyGroupPolicyId": entry.AsyncReplicationDisk.ConsistencyGroupPolicyId,
							}
						}
						mqlAsyncSecondaries[scope] = map[string]any{
							"asyncReplicationDisk": inner,
						}
					}
				}

				mqlDisk, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.disk", map[string]*llx.RawData{
					"id":                          llx.StringData(strconv.FormatUint(disk.Id, 10)),
					"name":                        llx.StringData(disk.Name),
					"architecture":                llx.StringData(disk.Architecture),
					"description":                 llx.StringData(disk.Description),
					"guestOsFeatures":             llx.ArrayData(convert.SliceAnyToInterface(guestOsFeatures), types.String),
					"labels":                      llx.MapData(convert.MapToInterfaceMap(disk.Labels), types.String),
					"lastAttachTimestamp":         llx.TimeDataPtr(parseTime(disk.LastAttachTimestamp)),
					"lastDetachTimestamp":         llx.TimeDataPtr(parseTime(disk.LastDetachTimestamp)),
					"locationHint":                llx.StringData(disk.LocationHint),
					"licenses":                    llx.ArrayData(convert.SliceAnyToInterface(disk.Licenses), types.String),
					"physicalBlockSizeBytes":      llx.IntData(disk.PhysicalBlockSizeBytes),
					"provisionedIops":             llx.IntData(disk.ProvisionedIops),
					"region":                      llx.StringData(RegionNameFromRegionUrl(disk.Region)),
					"replicaZones":                llx.ArrayData(zoneNamesFromUrls(disk.ReplicaZones), types.String),
					"resourcePolicies":            llx.ArrayData(convert.SliceAnyToInterface(disk.ResourcePolicies), types.String),
					"satisfiesPzi":                llx.BoolData(disk.SatisfiesPzi),
					"satisfiesPzs":                llx.BoolData(disk.SatisfiesPzs),
					"sizeGb":                      llx.IntData(disk.SizeGb),
					"status":                      llx.StringData(disk.Status),
					"zone":                        zoneData,
					"created":                     llx.TimeDataPtr(parseTime(disk.CreationTimestamp)),
					"diskEncryptionKey":           llx.DictData(mqlDiskEnc),
					"diskEncryption":              diskEncryption,
					"sourceImageEncryptionKey":    llx.DictData(mqlSourceImageEnc),
					"sourceImageEncryption":       sourceImageEncryption,
					"sourceSnapshotEncryptionKey": llx.DictData(mqlSourceSnapshotEnc),
					"sourceSnapshotEncryption":    sourceSnapshotEncryption,
					"asyncPrimaryDisk":            llx.DictData(mqlAsyncPrimary),
					"asyncSecondaryDisks":         llx.DictData(mqlAsyncSecondaries),
					"enableConfidentialCompute":   llx.BoolData(disk.EnableConfidentialCompute),
					"type":                        llx.StringData(disk.Type),
					"users":                       llx.ArrayData(convert.SliceAnyToInterface(disk.Users), types.String),
					"accessMode":                  llx.StringData(disk.AccessMode),
					"sourceStorageObject":         llx.StringData(disk.SourceStorageObject),
					"sourceInstantSnapshot":       llx.StringData(disk.SourceInstantSnapshot),
					"licenseCodes":                llx.ArrayData(convert.SliceAnyToInterface([]int64(disk.LicenseCodes)), types.Int),
					"provisionedThroughput":       llx.IntData(disk.ProvisionedThroughput),
				})
				if err != nil {
					return err
				}
				mqlD := mqlDisk.(*mqlGcpProjectComputeServiceDisk)
				mqlD.cacheSourceDiskUrl = disk.SourceDisk
				mqlD.cacheSourceImageUrl = disk.SourceImage
				mqlD.cacheSourceSnapshotUrl = disk.SourceSnapshot
				mqlD.cacheStoragePoolUrl = disk.StoragePool
				mqlD.cacheSelfLink = disk.SelfLink
				if disk.DiskEncryptionKey != nil {
					mqlD.cacheKmsKeyName = disk.DiskEncryptionKey.KmsKeyName
				}
				res = append(res, mqlDisk)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

type mqlGcpProjectComputeServiceFirewallInternal struct {
	cacheNetworkUrl string
	cacheSelfLink   string
}

func (g *mqlGcpProjectComputeServiceFirewall) effectiveTags() ([]any, error) {
	return effectiveTagsForResource(g.MqlRuntime, computeSelfLinkToResourceName(g.cacheSelfLink))
}

func (g *mqlGcpProjectComputeServiceFirewall) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.cacheNetworkUrl == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return getNetworkByUrl(g.cacheNetworkUrl, g.MqlRuntime)
}

func (g *mqlGcpProjectComputeServiceFirewall) resolveServiceAccountRefs(emails *plugin.TValue[[]any]) ([]any, error) {
	if emails.Error != nil {
		return nil, emails.Error
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	res := make([]any, 0, len(emails.Data))
	for _, e := range emails.Data {
		email, ok := e.(string)
		if !ok || email == "" {
			continue
		}
		sa, err := resolveServiceAccountRef(g.MqlRuntime, email, projectId)
		if err != nil {
			return nil, err
		}
		if sa != nil {
			res = append(res, sa)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceFirewall) sourceServiceAccountRefs() ([]any, error) {
	return g.resolveServiceAccountRefs(g.GetSourceServiceAccounts())
}

func (g *mqlGcpProjectComputeServiceFirewall) targetServiceAccountRefs() ([]any, error) {
	return g.resolveServiceAccountRefs(g.GetTargetServiceAccounts())
}

func (g *mqlGcpProjectComputeServiceFirewall) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.firewall/" + id, nil
}

func initGcpProjectComputeServiceFirewall(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: a missing projectId would nil-deref
	// (and blow the type assertion) rather than return an error.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.firewall requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	firewalls := computeSvc.GetFirewalls()
	if firewalls.Error != nil {
		return nil, nil, firewalls.Error
	}

	// Guard every arg this lookup dereferences: args["x"] on an absent key is a
	// nil *llx.RawData, and dereferencing it panics the provider, which kills
	// the whole scan rather than failing one query.
	if args["name"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.firewall requires a \"name\" argument")
	}
	for _, f := range firewalls.Data {
		firewall := f.(*mqlGcpProjectComputeServiceFirewall)
		name := firewall.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		projectId := firewall.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if name.Data == args["name"].Value && projectId.Data == args["projectId"].Value {
			return args, firewall, nil
		}
	}
	return nil, nil, errors.New("firewall not found")
}

func (g *mqlGcpProjectComputeService) firewalls() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	type mqlFirewall struct {
		IpProtocol string   `json:"ipProtocol"`
		Ports      []string `json:"ports"`
	}

	res := []any{}
	req := computeSvc.Firewalls.List(projectId)
	if err := req.Pages(ctx, func(page *compute.FirewallList) error {
		for _, firewall := range page.Items {
			allowed := make([]mqlFirewall, 0, len(firewall.Allowed))
			for _, a := range firewall.Allowed {
				allowed = append(allowed, mqlFirewall{IpProtocol: a.IPProtocol, Ports: a.Ports})
			}
			allowedDict, err := convert.JsonToDictSlice(allowed)
			if err != nil {
				return err
			}

			denied := make([]mqlFirewall, 0, len(firewall.Denied))
			for _, d := range firewall.Denied {
				denied = append(denied, mqlFirewall{IpProtocol: d.IPProtocol, Ports: d.Ports})
			}
			deniedDict, err := convert.JsonToDictSlice(denied)
			if err != nil {
				return err
			}
			firewallLogConfigDict, err := convert.JsonToDict(firewall.LogConfig)
			if err != nil {
				return err
			}
			var firewallLogConfigMetadata string
			if firewall.LogConfig != nil {
				firewallLogConfigMetadata = firewall.LogConfig.Metadata
			}

			mqlFirewall, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.firewall", map[string]*llx.RawData{
				"id":                    llx.StringData(strconv.FormatUint(firewall.Id, 10)),
				"projectId":             llx.StringData(projectId),
				"name":                  llx.StringData(firewall.Name),
				"description":           llx.StringData(firewall.Description),
				"priority":              llx.IntData(firewall.Priority),
				"disabled":              llx.BoolData(firewall.Disabled),
				"direction":             llx.StringData(firewall.Direction),
				"sourceRanges":          llx.ArrayData(convert.SliceAnyToInterface(firewall.SourceRanges), types.String),
				"sourceServiceAccounts": llx.ArrayData(convert.SliceAnyToInterface(firewall.SourceServiceAccounts), types.String),
				"sourceTags":            llx.ArrayData(convert.SliceAnyToInterface(firewall.SourceTags), types.String),
				"destinationRanges":     llx.ArrayData(convert.SliceAnyToInterface(firewall.DestinationRanges), types.String),
				"targetServiceAccounts": llx.ArrayData(convert.SliceAnyToInterface(firewall.TargetServiceAccounts), types.String),
				"created":               llx.TimeDataPtr(parseTime(firewall.CreationTimestamp)),
				"allowed":               llx.ArrayData(allowedDict, types.Dict),
				"denied":                llx.ArrayData(deniedDict, types.Dict),
				"allowedProtocols":      llx.MapData(firewallAllowedProtocolPorts(firewall.Allowed), types.Array(types.String)),
				"deniedProtocols":       llx.MapData(firewallDeniedProtocolPorts(firewall.Denied), types.Array(types.String)),
				"targetTags":            llx.ArrayData(convert.SliceAnyToInterface(firewall.TargetTags), types.String),
				"loggingEnabled":        llx.BoolData(firewall.LogConfig != nil && firewall.LogConfig.Enable),
				"logConfig":             llx.DictData(firewallLogConfigDict),
				"logConfigMetadata":     llx.StringData(firewallLogConfigMetadata),
			})
			if err != nil {
				return err
			}
			mqlFw := mqlFirewall.(*mqlGcpProjectComputeServiceFirewall)
			mqlFw.cacheNetworkUrl = firewall.Network
			mqlFw.cacheSelfLink = firewall.SelfLink
			res = append(res, mqlFirewall)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectComputeServiceSnapshot) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.snapshot/" + id, nil
}

func (g *mqlGcpProjectComputeServiceSnapshot) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func (g *mqlGcpProjectComputeService) snapshots() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := computeSvc.Snapshots.List(projectId)
	if err := req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			var snapshotKmsKeyName string
			if snapshot.SnapshotEncryptionKey != nil {
				snapshotKmsKeyName = snapshot.SnapshotEncryptionKey.KmsKeyName
			}
			snapshotEncryption, err := newMqlCustomerEncryptionKey(g.MqlRuntime, "gcp.project.computeService.snapshot/"+strconv.FormatUint(snapshot.Id, 10), "snapshotEncryption", snapshot.SnapshotEncryptionKey)
			if err != nil {
				return err
			}
			mqlSnapshpt, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.snapshot", map[string]*llx.RawData{
				"id":                             llx.StringData(strconv.FormatUint(snapshot.Id, 10)),
				"projectId":                      llx.StringData(projectId),
				"name":                           llx.StringData(snapshot.Name),
				"description":                    llx.StringData(snapshot.Description),
				"architecture":                   llx.StringData(snapshot.Architecture),
				"autoCreated":                    llx.BoolData(snapshot.AutoCreated),
				"chainName":                      llx.StringData(snapshot.ChainName),
				"creationSizeBytes":              llx.IntData(snapshot.CreationSizeBytes),
				"diskSizeGb":                     llx.IntData(snapshot.DiskSizeGb),
				"downloadBytes":                  llx.IntData(snapshot.DownloadBytes),
				"storageBytes":                   llx.IntData(snapshot.StorageBytes),
				"storageBytesStatus":             llx.StringData(snapshot.StorageBytesStatus),
				"snapshotType":                   llx.StringData(snapshot.SnapshotType),
				"licenses":                       llx.ArrayData(convert.SliceAnyToInterface(snapshot.Licenses), types.String),
				"labels":                         llx.MapData(convert.MapToInterfaceMap(snapshot.Labels), types.String),
				"status":                         llx.StringData(snapshot.Status),
				"created":                        llx.TimeDataPtr(parseTime(snapshot.CreationTimestamp)),
				"storageLocations":               llx.ArrayData(convert.SliceAnyToInterface(snapshot.StorageLocations), types.String),
				"enableConfidentialCompute":      llx.BoolData(snapshot.EnableConfidentialCompute),
				"satisfiesPzi":                   llx.BoolData(snapshot.SatisfiesPzi),
				"satisfiesPzs":                   llx.BoolData(snapshot.SatisfiesPzs),
				"sourceDisk":                     llx.StringData(snapshot.SourceDisk),
				"sourceSnapshotSchedulePolicy":   llx.StringData(snapshot.SourceSnapshotSchedulePolicy),
				"sourceSnapshotSchedulePolicyId": llx.StringData(snapshot.SourceSnapshotSchedulePolicyId),
				"snapshotEncryptionKey":          llx.DictData(customerEncryptionKeyToDict(snapshot.SnapshotEncryptionKey)),
				"snapshotEncryption":             snapshotEncryption,
			})
			if err != nil {
				return err
			}

			mqlSnap := mqlSnapshpt.(*mqlGcpProjectComputeServiceSnapshot)
			mqlSnap.cacheKmsKeyName = snapshotKmsKeyName
			mqlSnap.cacheSourceDiskUrl = snapshot.SourceDisk
			res = append(res, mqlSnapshpt)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectComputeServiceImage) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.image/" + id, nil
}

func (g *mqlGcpProjectComputeServiceImage) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func initGcpProjectComputeServiceImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: a missing projectId would nil-deref
	// (and blow the type assertion) rather than return an error.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.image requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	images := computeSvc.GetImages()
	if images.Error != nil {
		return nil, nil, images.Error
	}

	// Guard every arg this lookup dereferences: args["x"] on an absent key is a
	// nil *llx.RawData, and dereferencing it panics the provider, which kills
	// the whole scan rather than failing one query.
	if args["name"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.image requires a \"name\" argument")
	}
	for _, i := range images.Data {
		image := i.(*mqlGcpProjectComputeServiceImage)
		if image.Name.Error != nil {
			return nil, nil, image.Name.Error
		}
		name := image.Name.Data
		projectId := image.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if name == args["name"].Value && projectId.Data == args["projectId"].Value {
			return args, image, nil
		}
	}
	return nil, nil, errors.New("image not found")
}

type mqlGcpProjectComputeServiceImageInternal struct {
	cacheSourceDiskUrl     string
	cacheSourceImageUrl    string
	cacheSourceSnapshotUrl string
	cacheKmsKeyName        string
}

func (g *mqlGcpProjectComputeServiceImage) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

type mqlGcpProjectComputeServiceSnapshotInternal struct {
	cacheKmsKeyName    string
	cacheSourceDiskUrl string
}

func (g *mqlGcpProjectComputeServiceSnapshot) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectComputeServiceSnapshot) sourceDiskRef() (*mqlGcpProjectComputeServiceDisk, error) {
	if g.cacheSourceDiskUrl == "" {
		g.SourceDiskRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	disk, err := getDiskByUrl(g.cacheSourceDiskUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if disk == nil {
		g.SourceDiskRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return disk, nil
}

func (g *mqlGcpProjectComputeServiceImage) sourceDisk() (*mqlGcpProjectComputeServiceDisk, error) {
	if g.cacheSourceDiskUrl == "" {
		g.SourceDisk.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	disk, err := getDiskByUrl(g.cacheSourceDiskUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if disk == nil {
		g.SourceDisk.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return disk, nil
}

func (g *mqlGcpProjectComputeServiceImage) sourceImage() (*mqlGcpProjectComputeServiceImage, error) {
	url := g.cacheSourceImageUrl
	if url == "" {
		g.SourceImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// URL format: https://www.googleapis.com/compute/v1/projects/{project}/global/images/{image}
	const computePrefix = "https://www.googleapis.com/compute/v1/"
	if !strings.HasPrefix(url, computePrefix) {
		return nil, errors.New("invalid source image URL: " + url)
	}
	parts := strings.Split(strings.TrimPrefix(url, computePrefix), "/")
	if len(parts) < 5 {
		return nil, errors.New("invalid source image URL: " + url)
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.computeService.image", map[string]*llx.RawData{
		"name":      llx.StringData(parts[len(parts)-1]),
		"projectId": llx.StringData(parts[1]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceImage), nil
}

func (g *mqlGcpProjectComputeServiceImage) sourceSnapshot() (*mqlGcpProjectComputeServiceSnapshot, error) {
	url := g.cacheSourceSnapshotUrl
	if url == "" {
		g.SourceSnapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// URL format: https://www.googleapis.com/compute/v1/projects/{project}/global/snapshots/{snapshot}
	const computePrefix = "https://www.googleapis.com/compute/v1/"
	if !strings.HasPrefix(url, computePrefix) {
		return nil, errors.New("invalid source snapshot URL: " + url)
	}
	parts := strings.Split(strings.TrimPrefix(url, computePrefix), "/")
	if len(parts) < 5 || parts[0] != "projects" {
		return nil, errors.New("invalid source snapshot URL: " + url)
	}
	snap, err := resolveComputeSnapshotByName(g.MqlRuntime, parts[1], parts[len(parts)-1])
	if err != nil {
		return nil, err
	}
	if snap == nil {
		g.SourceSnapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return snap, nil
}

func (g *mqlGcpProjectComputeService) images() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := computeSvc.Images.List(projectId)
	if err := req.Pages(ctx, func(page *compute.ImageList) error {
		for _, image := range page.Items {
			var shieldedInitialState map[string]any
			if image.ShieldedInstanceInitialState != nil {
				d, err := convert.JsonToDict(image.ShieldedInstanceInitialState)
				if err != nil {
					return err
				}
				shieldedInitialState = d
			}
			imageEncryption, err := newMqlCustomerEncryptionKey(g.MqlRuntime, "gcp.project.computeService.image/"+strconv.FormatUint(image.Id, 10), "imageEncryption", image.ImageEncryptionKey)
			if err != nil {
				return err
			}
			mqlImage, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.image", map[string]*llx.RawData{
				"id":                           llx.StringData(strconv.FormatUint(image.Id, 10)),
				"projectId":                    llx.StringData(projectId),
				"name":                         llx.StringData(image.Name),
				"description":                  llx.StringData(image.Description),
				"architecture":                 llx.StringData(image.Architecture),
				"archiveSizeBytes":             llx.IntData(image.ArchiveSizeBytes),
				"diskSizeGb":                   llx.IntData(image.DiskSizeGb),
				"family":                       llx.StringData(image.Family),
				"licenses":                     llx.ArrayData(convert.SliceAnyToInterface(image.Licenses), types.String),
				"labels":                       llx.MapData(convert.MapToInterfaceMap(image.Labels), types.String),
				"status":                       llx.StringData(image.Status),
				"created":                      llx.TimeDataPtr(parseTime(image.CreationTimestamp)),
				"enableConfidentialCompute":    llx.BoolData(image.EnableConfidentialCompute),
				"satisfiesPzi":                 llx.BoolData(image.SatisfiesPzi),
				"satisfiesPzs":                 llx.BoolData(image.SatisfiesPzs),
				"storageLocations":             llx.ArrayData(convert.SliceAnyToInterface(image.StorageLocations), types.String),
				"imageEncryptionKey":           llx.DictData(customerEncryptionKeyToDict(image.ImageEncryptionKey)),
				"imageEncryption":              imageEncryption,
				"shieldedInstanceInitialState": llx.DictData(shieldedInitialState),
			})
			if err != nil {
				return err
			}
			mqlI := mqlImage.(*mqlGcpProjectComputeServiceImage)
			mqlI.cacheSourceDiskUrl = image.SourceDisk
			mqlI.cacheSourceImageUrl = image.SourceImage
			mqlI.cacheSourceSnapshotUrl = image.SourceSnapshot
			if image.ImageEncryptionKey != nil {
				mqlI.cacheKmsKeyName = image.ImageEncryptionKey.KmsKeyName
			}
			res = append(res, mqlImage)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

type mqlGcpProjectComputeServiceNetworkInternal struct {
	cachePeerings []*compute.NetworkPeering
	cacheSelfLink string
}

func (g *mqlGcpProjectComputeServiceNetwork) effectiveTags() ([]any, error) {
	return effectiveTagsForResource(g.MqlRuntime, computeSelfLinkToResourceName(g.cacheSelfLink))
}

func (g *mqlGcpProjectComputeServiceNetwork) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.network/" + id, nil
}

func (g *mqlGcpProjectComputeServiceNetwork) firewallPolicyRef() (*mqlGcpProjectComputeServiceFirewallPolicy, error) {
	if g.FirewallPolicy.Error != nil {
		return nil, g.FirewallPolicy.Error
	}
	url := g.FirewallPolicy.Data
	if url == "" {
		g.FirewallPolicyRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}

	obj, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.ProjectId.Data),
	})
	if err != nil {
		return nil, err
	}
	policies := obj.(*mqlGcpProjectComputeService).GetFirewallPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}

	// The network's firewallPolicy is a self-link URL; match it against the
	// listed policies by selfLink, then fall back to the trailing name/id
	// segment for shapes that omit the full self-link.
	lastSegment := url[strings.LastIndex(url, "/")+1:]
	for _, p := range policies.Data {
		policy := p.(*mqlGcpProjectComputeServiceFirewallPolicy)
		if policy.SelfLink.Error == nil && policy.SelfLink.Data == url {
			return policy, nil
		}
		if policy.Name.Error == nil && policy.Name.Data == lastSegment {
			return policy, nil
		}
		if policy.Id.Error == nil && policy.Id.Data == lastSegment {
			return policy, nil
		}
	}

	g.FirewallPolicyRef.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (g *mqlGcpProjectComputeServiceNetwork) networkPeerings() ([]any, error) {
	if g.cachePeerings == nil {
		return []any{}, nil
	}
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	networkId := g.Id.Data
	res := make([]any, 0, len(g.cachePeerings))
	for _, p := range g.cachePeerings {
		mqlPeering, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.network.peering", map[string]*llx.RawData{
			"id":                             llx.StringData(fmt.Sprintf("gcloud.compute.network/%s/peering/%s", networkId, p.Name)),
			"name":                           llx.StringData(p.Name),
			"state":                          llx.StringData(p.State),
			"stateDetails":                   llx.StringData(p.StateDetails),
			"autoCreateRoutes":               llx.BoolData(p.AutoCreateRoutes),
			"exchangeSubnetRoutes":           llx.BoolData(p.ExchangeSubnetRoutes),
			"exportCustomRoutes":             llx.BoolData(p.ExportCustomRoutes),
			"importCustomRoutes":             llx.BoolData(p.ImportCustomRoutes),
			"exportSubnetRoutesWithPublicIp": llx.BoolData(p.ExportSubnetRoutesWithPublicIp),
			"importSubnetRoutesWithPublicIp": llx.BoolData(p.ImportSubnetRoutesWithPublicIp),
		})
		if err != nil {
			return nil, err
		}
		mqlRef := mqlPeering.(*mqlGcpProjectComputeServiceNetworkPeering)
		mqlRef.cacheNetworkUrl = p.Network
		res = append(res, mqlPeering)
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceNetworkPeering) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceNetworkPeering) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	url := g.cacheNetworkUrl
	if url == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	net, err := getNetworkByUrl(url, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return net, nil
}

func (g *mqlGcpProjectComputeServiceNetwork) subnetworks() ([]any, error) {
	if g.SubnetworkUrls.Error != nil {
		return nil, g.SubnetworkUrls.Error
	}
	subnetUrls := g.SubnetworkUrls.Data
	subnets := make([]any, 0, len(subnetUrls))
	for _, subnetUrl := range subnetUrls {
		// Resolve through the shared helper so it uses NewResource and the
		// subnetwork init populates every field (and a stable __id) instead of
		// leaving a partially-set husk that collides in the resource cache.
		subnet, err := getSubnetworkByUrl(subnetUrl.(string), g.MqlRuntime)
		if err != nil {
			return nil, err
		}
		if subnet == nil {
			continue
		}
		subnets = append(subnets, subnet)
	}
	return subnets, nil
}

func initGcpProjectComputeServiceNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Try to find the network in the MQL cache first
	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.network requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	networks := computeSvc.GetNetworks()
	if networks.Error != nil {
		return nil, nil, networks.Error
	}

	// Guard every arg this lookup dereferences: args["x"] on an absent key is a
	// nil *llx.RawData, and dereferencing it panics the provider, which kills
	// the whole scan rather than failing one query.
	if args["name"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.network requires a \"name\" argument")
	}
	for _, n := range networks.Data {
		network := n.(*mqlGcpProjectComputeServiceNetwork)
		name := network.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		projectId := network.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if name.Data == args["name"].Value && projectId.Data == args["projectId"].Value {
			return args, network, nil
		}
	}

	// Fallback: fetch directly from the GCP API
	networkName, _ := args["name"].Value.(string)
	projectId, _ := args["projectId"].Value.(string)

	conn := runtime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	gcpComputeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}

	network, err := gcpComputeSvc.Networks.Get(projectId, networkName).Do()
	if err != nil {
		return nil, nil, err
	}

	var routingMode string
	if network.RoutingConfig != nil {
		routingMode = network.RoutingConfig.RoutingMode
	}

	mqlNetwork, err := CreateResource(runtime, "gcp.project.computeService.network", map[string]*llx.RawData{
		"id":                                    llx.StringData(strconv.FormatUint(network.Id, 10)),
		"projectId":                             llx.StringData(projectId),
		"name":                                  llx.StringData(network.Name),
		"description":                           llx.StringData(network.Description),
		"autoCreateSubnetworks":                 llx.BoolData(network.AutoCreateSubnetworks),
		"enableUlaInternalIpv6":                 llx.BoolData(network.EnableUlaInternalIpv6),
		"gatewayIPv4":                           llx.StringData(network.GatewayIPv4),
		"mtu":                                   llx.IntData(network.Mtu),
		"networkFirewallPolicyEnforcementOrder": llx.StringData(network.NetworkFirewallPolicyEnforcementOrder),
		"created":                               llx.TimeDataPtr(parseTime(network.CreationTimestamp)),
		"routingMode":                           llx.StringData(routingMode),
		"mode":                                  llx.StringData(networkMode(network)),
		"subnetworkUrls":                        llx.ArrayData(convert.SliceAnyToInterface(network.Subnetworks), types.String),
	})
	if err != nil {
		return nil, nil, err
	}
	mqlNet := mqlNetwork.(*mqlGcpProjectComputeServiceNetwork)
	mqlNet.cacheSelfLink = network.SelfLink
	return args, mqlNet, nil
}

func (g *mqlGcpProjectComputeService) networks() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := computeSvc.Networks.List(projectId)
	if err := req.Pages(ctx, func(page *compute.NetworkList) error {
		for _, network := range page.Items {
			var routingMode string
			if network.RoutingConfig != nil {
				routingMode = network.RoutingConfig.RoutingMode
			}

			mqlNetwork, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.network", map[string]*llx.RawData{
				"id":                                    llx.StringData(strconv.FormatUint(network.Id, 10)),
				"projectId":                             llx.StringData(projectId),
				"name":                                  llx.StringData(network.Name),
				"description":                           llx.StringData(network.Description),
				"autoCreateSubnetworks":                 llx.BoolData(network.AutoCreateSubnetworks),
				"enableUlaInternalIpv6":                 llx.BoolData(network.EnableUlaInternalIpv6),
				"gatewayIPv4":                           llx.StringData(network.GatewayIPv4),
				"mtu":                                   llx.IntData(network.Mtu),
				"networkFirewallPolicyEnforcementOrder": llx.StringData(network.NetworkFirewallPolicyEnforcementOrder),
				"created":                               llx.TimeDataPtr(parseTime(network.CreationTimestamp)),
				"routingMode":                           llx.StringData(routingMode),
				"mode":                                  llx.StringData(networkMode(network)),
				"subnetworkUrls":                        llx.ArrayData(convert.SliceAnyToInterface(network.Subnetworks), types.String),
				"internalIpv6Range":                     llx.StringData(network.InternalIpv6Range),
				"firewallPolicy":                        llx.StringData(network.FirewallPolicy),
				"networkProfile":                        llx.StringData(network.NetworkProfile),
			})
			if err != nil {
				return err
			}
			mqlNet := mqlNetwork.(*mqlGcpProjectComputeServiceNetwork)
			mqlNet.cachePeerings = network.Peerings
			mqlNet.cacheSelfLink = network.SelfLink
			res = append(res, mqlNetwork)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectComputeServiceSubnetwork) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.subnetwork/" + id, nil
}

func initGcpProjectComputeServiceSubnetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	region := ""
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			region = ids.region
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	} else {
		if args["regionUrl"] != nil {
			regionUrlVal, _ := args["regionUrl"].Value.(string)
			region = RegionNameFromRegionUrl(regionUrlVal)
		}
	}

	// Try to find the subnetwork in the MQL cache first
	// Guard before building the parent: a missing projectId would nil-deref
	// (and blow the type assertion) rather than return an error.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.subnetwork requires a \"projectId\" argument")
	}

	obj, err := NewResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	subnetworks := computeSvc.GetSubnetworks()
	if subnetworks.Error != nil {
		return nil, nil, subnetworks.Error
	}

	// Guard every arg this lookup dereferences: args["x"] on an absent key is a
	// nil *llx.RawData, and dereferencing it panics the provider, which kills
	// the whole scan rather than failing one query.
	if args["name"] == nil {
		return nil, nil, errors.New("gcp.project.computeService.subnetwork requires a \"name\" argument")
	}
	for _, n := range subnetworks.Data {
		subnetwork := n.(*mqlGcpProjectComputeServiceSubnetwork)
		name := subnetwork.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		subnetRegion := RegionNameFromRegionUrl(subnetwork.cacheRegionUrl)
		projectId := subnetwork.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if name.Data == args["name"].Value && projectId.Data == args["projectId"].Value && subnetRegion == region {
			return args, subnetwork, nil
		}
	}

	// Fallback: fetch directly from the GCP API
	subnetworkName, _ := args["name"].Value.(string)
	projectId, _ := args["projectId"].Value.(string)

	conn := runtime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	subnetSvc, err := computev1.NewSubnetworksRESTClient(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}

	gcpSubnetwork, err := subnetSvc.Get(ctx, &computepb.GetSubnetworkRequest{
		Project:    projectId,
		Region:     region,
		Subnetwork: subnetworkName,
	})
	if err != nil {
		return nil, nil, err
	}

	mqlSubnetwork, err := newMqlSubnetwork(projectId, runtime, gcpSubnetwork, nil)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlSubnetwork.(*mqlGcpProjectComputeServiceSubnetwork), nil
}

func (g *mqlGcpProjectComputeServiceSubnetworkLogConfig) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.subnetwork.logConfig/" + id, nil
}

func (g *mqlGcpProjectComputeServiceSubnetwork) region() (*mqlGcpProjectComputeServiceRegion, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	regionName := RegionNameFromRegionUrl(g.cacheRegionUrl)

	// Find regionName for projectId
	obj, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	gcpCompute := obj.(*mqlGcpProjectComputeService)
	regions := gcpCompute.GetRegions()
	if regions.Error != nil {
		return nil, regions.Error
	}

	for _, r := range regions.Data {
		region := r.(*mqlGcpProjectComputeServiceRegion)
		name := region.GetName()
		if name.Error != nil {
			return nil, name.Error
		}
		if name.Data == regionName {
			return region, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("region %s not found", regionName))
}

func (g *mqlGcpProjectComputeServiceSubnetwork) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	url := g.cacheNetworkUrl
	if url == "" {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	net, err := getNetworkByUrl(url, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return net, nil
}

func newMqlRegion(runtime *plugin.Runtime, projectId string, r *compute.Region) (any, error) {
	deprecated, err := convert.JsonToDict(r.Deprecated)
	if err != nil {
		return nil, err
	}

	quotas := map[string]any{}
	for i := range r.Quotas {
		q := r.Quotas[i]
		quotas[q.Metric] = q.Limit
	}

	return CreateResource(runtime, "gcp.project.computeService.region", map[string]*llx.RawData{
		// A region resource carries per-project quotas, so the cache key must
		// include the project. Keying on the region name alone made every
		// project after the first report the first project's quota limits.
		"__id":        llx.StringData("gcp.project.computeService.region/" + projectId + "/" + r.Name),
		"id":          llx.StringData(strconv.FormatInt(int64(r.Id), 10)),
		"name":        llx.StringData(r.Name),
		"description": llx.StringData(r.Description),
		"status":      llx.StringData(r.Status),
		"created":     llx.TimeDataPtr(parseTime(r.CreationTimestamp)),
		"quotas":      llx.MapData(quotas, types.Float),
		"deprecated":  llx.DictData(deprecated),
		"supportsPzs": llx.BoolData(r.SupportsPzs),
	})
}

func newMqlSubnetwork(projectId string, runtime *plugin.Runtime, subnetwork *computepb.Subnetwork, region *mqlGcpProjectComputeServiceRegion) (any, error) {
	subnetId := strconv.FormatUint(subnetwork.GetId(), 10)
	var mqlLogConfig plugin.Resource
	var err error
	if subnetwork.LogConfig != nil {
		mqlLogConfig, err = CreateResource(runtime, "gcp.project.computeService.subnetwork.logConfig", map[string]*llx.RawData{
			"id":                  llx.StringData(fmt.Sprintf("%s/logConfig", subnetId)),
			"aggregationInterval": llx.StringData(subnetwork.LogConfig.GetAggregationInterval()),
			"enable":              llx.BoolData(subnetwork.LogConfig.GetEnable()),
			"filterExpression":    llx.StringData(subnetwork.LogConfig.GetFilterExpr()),
			"flowSampling":        llx.FloatData(float64(subnetwork.LogConfig.GetFlowSampling())),
			"metadata":            llx.StringData(subnetwork.LogConfig.GetMetadata()),
			"metadataFields":      llx.ArrayData(convert.SliceAnyToInterface(subnetwork.LogConfig.MetadataFields), types.String),
		})
		if err != nil {
			return nil, err
		}
	}

	secondaryIpRanges := make([]any, 0, len(subnetwork.GetSecondaryIpRanges()))
	for _, r := range subnetwork.GetSecondaryIpRanges() {
		secondaryIpRanges = append(secondaryIpRanges, map[string]any{
			"rangeName":             r.GetRangeName(),
			"ipCidrRange":           r.GetIpCidrRange(),
			"reservedInternalRange": r.GetReservedInternalRange(),
		})
	}

	utilizationDetails, err := protoToDict(subnetwork.GetUtilizationDetails())
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                               llx.StringData(subnetId),
		"projectId":                        llx.StringData(projectId),
		"name":                             llx.StringData(subnetwork.GetName()),
		"description":                      llx.StringData(subnetwork.GetDescription()),
		"enableFlowLogs":                   llx.BoolData(subnetwork.GetEnableFlowLogs()),
		"externalIpv6Prefix":               llx.StringData(subnetwork.GetExternalIpv6Prefix()),
		"fingerprint":                      llx.StringData(subnetwork.GetFingerprint()),
		"gatewayAddress":                   llx.StringData(subnetwork.GetGatewayAddress()),
		"internalIpv6Prefix":               llx.StringData(subnetwork.GetInternalIpv6Prefix()),
		"ipCidrRange":                      llx.StringData(subnetwork.GetIpCidrRange()),
		"ipv6AccessType":                   llx.StringData(subnetwork.GetIpv6AccessType()),
		"ipv6CidrRange":                    llx.StringData(subnetwork.GetIpv6CidrRange()),
		"logConfig":                        llx.ResourceData(mqlLogConfig, "gcp.project.computeService.subnetwork.logConfig"),
		"privateIpGoogleAccess":            llx.BoolData(subnetwork.GetPrivateIpGoogleAccess()),
		"privateIpv6GoogleAccess":          llx.StringData(subnetwork.GetPrivateIpv6GoogleAccess()),
		"purpose":                          llx.StringData(subnetwork.GetPurpose()),
		"role":                             llx.StringData(subnetwork.GetRole()),
		"stackType":                        llx.StringData(subnetwork.GetStackType()),
		"state":                            llx.StringData(subnetwork.GetState()),
		"created":                          llx.TimeDataPtr(parseTime(subnetwork.GetCreationTimestamp())),
		"reservedInternalRange":            llx.StringData(subnetwork.GetReservedInternalRange()),
		"allowSubnetCidrRoutesOverlap":     llx.BoolData(subnetwork.GetAllowSubnetCidrRoutesOverlap()),
		"secondaryIpRanges":                llx.ArrayData(secondaryIpRanges, types.Dict),
		"ipCollection":                     llx.StringData(subnetwork.GetIpCollection()),
		"resolveSubnetMask":                llx.StringData(subnetwork.GetResolveSubnetMask()),
		"systemReservedInternalIpv6Ranges": llx.ArrayData(convert.SliceAnyToInterface(subnetwork.GetSystemReservedInternalIpv6Ranges()), types.String),
		"systemReservedExternalIpv6Ranges": llx.ArrayData(convert.SliceAnyToInterface(subnetwork.GetSystemReservedExternalIpv6Ranges()), types.String),
		"utilizationDetails":               llx.DictData(utilizationDetails),
	}
	if region != nil {
		args["region"] = llx.ResourceData(region, "gcp.project.computeService.region")
	}
	res, err := CreateResource(runtime, "gcp.project.computeService.subnetwork", args)
	if err != nil {
		return nil, err
	}
	mqlSubnet := res.(*mqlGcpProjectComputeServiceSubnetwork)
	mqlSubnet.cacheRegionUrl = subnetwork.GetRegion()
	mqlSubnet.cacheNetworkUrl = subnetwork.GetNetwork()
	mqlSubnet.cacheSelfLink = subnetwork.GetSelfLink()
	return res, nil
}

func (g *mqlGcpProjectComputeServiceSubnetwork) effectiveTags() ([]any, error) {
	return effectiveTagsForResource(g.MqlRuntime, computeSelfLinkToResourceName(g.cacheSelfLink))
}

func (g *mqlGcpProjectComputeService) subnetworks() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	subnetSvc, err := computev1.NewSubnetworksRESTClient(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	it := subnetSvc.AggregatedList(ctx, &computepb.AggregatedListSubnetworksRequest{Project: projectId})
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		subnets := resp.Value.GetSubnetworks()
		for _, subnet := range subnets {
			mqlSubnetwork, err := newMqlSubnetwork(projectId, g.MqlRuntime, subnet, nil)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSubnetwork)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceRouter) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.router/" + id, nil
}

type mqlGcpProjectComputeServiceRouterInternal struct {
	cacheNetworkUrl string
}

func (g *mqlGcpProjectComputeServiceRouter) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.cacheNetworkUrl == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return getNetworkByUrl(g.cacheNetworkUrl, g.MqlRuntime)
}

func newMqlRouter(projectId string, region *mqlGcpProjectComputeServiceRegion, runtime *plugin.Runtime, router *compute.Router) (any, error) {
	bgp, err := convert.JsonToDict(router.Bgp)
	if err != nil {
		return nil, err
	}

	bgpPeers, err := convert.JsonToDictSlice(router.BgpPeers)
	if err != nil {
		return nil, err
	}

	routerId := strconv.FormatUint(router.Id, 10)
	natResources := make([]any, 0, len(router.Nats))
	for _, nat := range router.Nats {
		logConfig, err := convert.JsonToDict(nat.LogConfig)
		if err != nil {
			return nil, err
		}
		subnetworks, err := convert.JsonToDictSlice(nat.Subnetworks)
		if err != nil {
			return nil, err
		}
		rules, err := convert.JsonToDictSlice(nat.Rules)
		if err != nil {
			return nil, err
		}
		mqlNat, err := CreateResource(runtime, "gcp.project.computeService.router.nat", map[string]*llx.RawData{
			"id":                               llx.StringData(fmt.Sprintf("gcp.project.computeService.router.nat/%s/%s", routerId, nat.Name)),
			"name":                             llx.StringData(nat.Name),
			"natIpAllocateOption":              llx.StringData(nat.NatIpAllocateOption),
			"sourceSubnetworkIpRangesToNat":    llx.StringData(nat.SourceSubnetworkIpRangesToNat),
			"enableDynamicPortAllocation":      llx.BoolData(nat.EnableDynamicPortAllocation),
			"enableEndpointIndependentMapping": llx.BoolData(nat.EnableEndpointIndependentMapping),
			"minPortsPerVm":                    llx.IntData(nat.MinPortsPerVm),
			"maxPortsPerVm":                    llx.IntData(nat.MaxPortsPerVm),
			"natIps":                           llx.ArrayData(convert.SliceAnyToInterface(nat.NatIps), types.String),
			"subnetworks":                      llx.ArrayData(subnetworks, types.Dict),
			"rules":                            llx.ArrayData(rules, types.Dict),
			"logConfig":                        llx.DictData(logConfig),
			"endpointTypes":                    llx.ArrayData(convert.SliceAnyToInterface(nat.EndpointTypes), types.String),
			"autoNetworkTier":                  llx.StringData(nat.AutoNetworkTier),
			"icmpIdleTimeoutSec":               llx.IntData(nat.IcmpIdleTimeoutSec),
			"tcpEstablishedIdleTimeoutSec":     llx.IntData(nat.TcpEstablishedIdleTimeoutSec),
			"tcpTransitoryIdleTimeoutSec":      llx.IntData(nat.TcpTransitoryIdleTimeoutSec),
			"tcpTimeWaitTimeoutSec":            llx.IntData(nat.TcpTimeWaitTimeoutSec),
			"udpIdleTimeoutSec":                llx.IntData(nat.UdpIdleTimeoutSec),
		})
		if err != nil {
			return nil, err
		}
		natResources = append(natResources, mqlNat)
	}

	res, err := CreateResource(runtime, "gcp.project.computeService.router", map[string]*llx.RawData{
		"id":                          llx.StringData(routerId),
		"name":                        llx.StringData(router.Name),
		"description":                 llx.StringData(router.Description),
		"bgp":                         llx.DictData(bgp),
		"bgpPeers":                    llx.ArrayData(bgpPeers, types.Dict),
		"encryptedInterconnectRouter": llx.BoolData(router.EncryptedInterconnectRouter),
		"natServices":                 llx.ArrayData(natResources, types.Resource("gcp.project.computeService.router.nat")),
		"created":                     llx.TimeDataPtr(parseTime(router.CreationTimestamp)),
	})
	if err != nil {
		return nil, err
	}
	mqlRouter := res.(*mqlGcpProjectComputeServiceRouter)
	mqlRouter.cacheNetworkUrl = router.Network
	return res, nil
}

func (g *mqlGcpProjectComputeService) routers() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	regions := g.GetRegions()
	if regions.Error != nil {
		return nil, regions.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	regionsByName := make(map[string]*mqlGcpProjectComputeServiceRegion, len(regions.Data))
	for _, r := range regions.Data {
		region := r.(*mqlGcpProjectComputeServiceRegion)
		name := region.GetName()
		if name.Error != nil {
			return nil, name.Error
		}
		regionsByName[name.Data] = region
	}

	var res []any
	req := computeSvc.Routers.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.RouterAggregatedList) error {
		for scope, scopedList := range page.Items {
			regionName, ok := strings.CutPrefix(scope, "regions/")
			if !ok {
				continue
			}
			region, ok := regionsByName[regionName]
			if !ok {
				continue
			}
			for _, router := range scopedList.Routers {
				mqlRouter, err := newMqlRouter(projectId, region, g.MqlRuntime, router)
				if err != nil {
					return err
				}
				res = append(res, mqlRouter)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectComputeService) backendServices() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.BackendServices.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.BackendServiceAggregatedList) error {
		for _, sb := range page.Items {
			for _, b := range sb.BackendServices {
				backendServiceId := strconv.FormatUint(b.Id, 10)
				mqlBackends := make([]any, 0, len(b.Backends))
				for _, backend := range b.Backends {
					mqlBackend, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.backendService.backend", map[string]*llx.RawData{
						"id":                        llx.StringData(fmt.Sprintf("gcp.project.computeService.backendService.backend/%s/%s", backendServiceId, backend.Group)),
						"balancingMode":             llx.StringData(backend.BalancingMode),
						"capacityScaler":            llx.FloatData(backend.CapacityScaler),
						"description":               llx.StringData(backend.Description),
						"failover":                  llx.BoolData(backend.Failover),
						"maxConnections":            llx.IntData(backend.MaxConnections),
						"maxConnectionsPerEndpoint": llx.IntData(backend.MaxConnectionsPerEndpoint),
						"maxConnectionsPerInstance": llx.IntData(backend.MaxConnectionsPerInstance),
						"maxRate":                   llx.IntData(backend.MaxRate),
						"maxRatePerEndpoint":        llx.FloatData(backend.MaxRatePerEndpoint),
						"maxRatePerInstance":        llx.FloatData(backend.MaxRatePerInstance),
						"maxUtilization":            llx.FloatData(backend.MaxUtilization),
					})
					if err != nil {
						return err
					}
					mqlRef := mqlBackend.(*mqlGcpProjectComputeServiceBackendServiceBackend)
					mqlRef.cacheGroupUrl = backend.Group
					mqlBackends = append(mqlBackends, mqlBackend)
				}

				var cdnPolicy plugin.Resource
				if b.CdnPolicy != nil {
					bypassCacheOnRequestHeaders := make([]any, 0, len(b.CdnPolicy.BypassCacheOnRequestHeaders))
					for _, h := range b.CdnPolicy.BypassCacheOnRequestHeaders {
						mqlH := map[string]any{"headerName": h.HeaderName}
						bypassCacheOnRequestHeaders = append(bypassCacheOnRequestHeaders, mqlH)
					}

					var mqlCacheKeyPolicy any
					if b.CdnPolicy.CacheKeyPolicy != nil {
						mqlCacheKeyPolicy = map[string]any{
							"includeHost":          b.CdnPolicy.CacheKeyPolicy.IncludeHost,
							"includeHttpHeaders":   convert.SliceAnyToInterface(b.CdnPolicy.CacheKeyPolicy.IncludeHttpHeaders),
							"includeNamedCookies":  convert.SliceAnyToInterface(b.CdnPolicy.CacheKeyPolicy.IncludeNamedCookies),
							"includeProtocol":      b.CdnPolicy.CacheKeyPolicy.IncludeProtocol,
							"includeQueryString":   b.CdnPolicy.CacheKeyPolicy.IncludeQueryString,
							"queryStringBlacklist": convert.SliceAnyToInterface(b.CdnPolicy.CacheKeyPolicy.QueryStringBlacklist),
							"queryStringWhitelist": convert.SliceAnyToInterface(b.CdnPolicy.CacheKeyPolicy.QueryStringWhitelist),
						}
					}

					mqlNegativeCachingPolicy := make([]any, 0, len(b.CdnPolicy.NegativeCachingPolicy))
					for _, p := range b.CdnPolicy.NegativeCachingPolicy {
						mqlP := map[string]any{
							"code": p.Code,
							"ttl":  p.Ttl,
						}
						mqlNegativeCachingPolicy = append(mqlNegativeCachingPolicy, mqlP)
					}

					var err error
					cdnPolicy, err = CreateResource(g.MqlRuntime, "gcp.project.computeService.backendService.cdnPolicy", map[string]*llx.RawData{
						"id":                          llx.StringData(fmt.Sprintf("gcp.project.computeService.backendService.cdnPolicy/%s", backendServiceId)),
						"bypassCacheOnRequestHeaders": llx.ArrayData(bypassCacheOnRequestHeaders, types.Dict),
						"cacheKeyPolicy":              llx.DictData(mqlCacheKeyPolicy),
						"cacheMode":                   llx.StringData(b.CdnPolicy.CacheMode),
						"clientTtl":                   llx.IntData(b.CdnPolicy.ClientTtl),
						"defaultTtl":                  llx.IntData(b.CdnPolicy.DefaultTtl),
						"maxTtl":                      llx.IntData(b.CdnPolicy.MaxTtl),
						"negativeCaching":             llx.BoolData(b.CdnPolicy.NegativeCaching),
						"negativeCachingPolicy":       llx.ArrayData(mqlNegativeCachingPolicy, types.Dict),
						"requestCoalescing":           llx.BoolData(b.CdnPolicy.RequestCoalescing),
						"serveWhileStale":             llx.IntData(b.CdnPolicy.ServeWhileStale),
						"signedUrlCacheMaxAgeSec":     llx.IntData(b.CdnPolicy.SignedUrlCacheMaxAgeSec),
						"signedUrlKeyNames":           llx.ArrayData(convert.SliceAnyToInterface(b.CdnPolicy.SignedUrlKeyNames), types.String),
					})
					if err != nil {
						return err
					}
				}

				var mqlCircuitBreakers any
				if b.CircuitBreakers != nil {
					mqlCircuitBreakers = map[string]any{
						"maxConnections":           b.CircuitBreakers.MaxConnections,
						"maxPendingRequests":       b.CircuitBreakers.MaxPendingRequests,
						"maxRequests":              b.CircuitBreakers.MaxRequests,
						"maxRequestsPerConnection": b.CircuitBreakers.MaxRequestsPerConnection,
						"maxRetries":               b.CircuitBreakers.MaxRetries,
					}
				}

				var mqlConnectionDraining any
				if b.ConnectionDraining != nil {
					mqlConnectionDraining = map[string]any{
						"drainingTimeoutSec": b.ConnectionDraining.DrainingTimeoutSec,
					}
				}

				var mqlConnectionTrackingPolicy any
				if b.ConnectionTrackingPolicy != nil {
					mqlConnectionTrackingPolicy = map[string]any{
						"connectionPersistenceOnUnhealthyBackends": b.ConnectionTrackingPolicy.ConnectionPersistenceOnUnhealthyBackends,
						"enableStrongAffinity":                     b.ConnectionTrackingPolicy.EnableStrongAffinity,
						"idleTimeoutSec":                           b.ConnectionTrackingPolicy.IdleTimeoutSec,
						"trackingMode":                             b.ConnectionTrackingPolicy.TrackingMode,
					}
				}

				var mqlConsistentHash any
				if b.ConsistentHash != nil {
					consistentHashMap := map[string]any{
						"httpHeaderName":  b.ConsistentHash.HttpHeaderName,
						"minimumRingSize": b.ConsistentHash.MinimumRingSize,
					}
					if b.ConsistentHash.HttpCookie != nil {
						cookieMap := map[string]any{
							"name": b.ConsistentHash.HttpCookie.Name,
							"path": b.ConsistentHash.HttpCookie.Path,
						}
						if b.ConsistentHash.HttpCookie.Ttl != nil {
							// Dict values must be JSON-native; an *llx.RawData
							// (what llx.TimeData returns) fails dict2primitive at
							// query time.
							cookieMap["ttlSeconds"] = b.ConsistentHash.HttpCookie.Ttl.Seconds
						}
						consistentHashMap["httpCookie"] = cookieMap
					}
					mqlConsistentHash = consistentHashMap
				}

				var mqlFailoverPolicy any
				if b.FailoverPolicy != nil {
					mqlFailoverPolicy = map[string]any{
						"disableConnectionDrainOnFailover": b.FailoverPolicy.DisableConnectionDrainOnFailover,
						"dropTrafficIfUnhealthy":           b.FailoverPolicy.DropTrafficIfUnhealthy,
						"failoverRatio":                    b.FailoverPolicy.FailoverRatio,
					}
				}

				var mqlIap any
				if b.Iap != nil {
					// Oauth2ClientSecret is deliberately not published. The
					// sha256 below is the form callers should compare against.
					mqlIap = map[string]any{
						"serviceEnabled":           b.Iap.Enabled,
						"oauth2ClientId":           b.Iap.Oauth2ClientId,
						"oauth2ClientSecretSha256": b.Iap.Oauth2ClientSecretSha256,
					}
				}

				mqlLocalityLbPolicy := make([]any, 0, len(b.LocalityLbPolicies))
				for _, p := range b.LocalityLbPolicies {
					var mqlCustomPolicy any
					if p.CustomPolicy != nil {
						mqlCustomPolicy = map[string]any{
							"data": p.CustomPolicy.Data,
							"name": p.CustomPolicy.Name,
						}
					}

					var mqlPolicy any
					if p.Policy != nil {
						mqlPolicy = map[string]any{
							"name": p.Policy.Name,
						}
					}
					mqlLocalityLbPolicy = append(mqlLocalityLbPolicy, map[string]any{
						"customPolicy": mqlCustomPolicy,
						"policy":       mqlPolicy,
					})
				}

				var mqlLogConfig any
				if b.LogConfig != nil {
					mqlLogConfig = map[string]any{
						"enable":     b.LogConfig.Enable,
						"sampleRate": b.LogConfig.SampleRate,
					}
				}

				var mqlSecuritySettings any
				var securitySettingsClientTlsPolicy string
				var securitySettingsSubjectAltNames []string
				if b.SecuritySettings != nil {
					mqlSecuritySettings = map[string]any{
						"clientTlsPolicy": b.SecuritySettings.ClientTlsPolicy,
						"subjectAltNames": convert.SliceAnyToInterface(b.SecuritySettings.SubjectAltNames),
					}
					securitySettingsClientTlsPolicy = b.SecuritySettings.ClientTlsPolicy
					securitySettingsSubjectAltNames = b.SecuritySettings.SubjectAltNames
				}

				var maxStreamDuration *time.Time
				if b.MaxStreamDuration != nil {
					v := llx.DurationToTime(b.MaxStreamDuration.Seconds)
					maxStreamDuration = &v
				}

				mqlB, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.backendService", map[string]*llx.RawData{
					"id":                              llx.StringData(backendServiceId),
					"affinityCookieTtlSec":            llx.IntData(b.AffinityCookieTtlSec),
					"backends":                        llx.ArrayData(mqlBackends, types.Resource("gcp.project.computeService.backendService.backend")),
					"cdnPolicy":                       llx.ResourceData(cdnPolicy, "gcp.project.computeService.backendService.cdnPolicy"),
					"circuitBreakers":                 llx.DictData(mqlCircuitBreakers),
					"compressionMode":                 llx.StringData(b.CompressionMode),
					"connectionDraining":              llx.DictData(mqlConnectionDraining),
					"connectionTrackingPolicy":        llx.DictData(mqlConnectionTrackingPolicy),
					"consistentHash":                  llx.DictData(mqlConsistentHash),
					"created":                         llx.TimeDataPtr(parseTime(b.CreationTimestamp)),
					"customRequestHeaders":            llx.ArrayData(convert.SliceAnyToInterface(b.CustomRequestHeaders), types.String),
					"customResponseHeaders":           llx.ArrayData(convert.SliceAnyToInterface(b.CustomResponseHeaders), types.String),
					"description":                     llx.StringData(b.Description),
					"enableCDN":                       llx.BoolData(b.EnableCDN),
					"failoverPolicy":                  llx.DictData(mqlFailoverPolicy),
					"healthChecks":                    llx.ArrayData(convert.SliceAnyToInterface(b.HealthChecks), types.String),
					"iap":                             llx.DictData(mqlIap),
					"loadBalancingScheme":             llx.StringData(b.LoadBalancingScheme),
					"localityLbPolicies":              llx.ArrayData(mqlLocalityLbPolicy, types.Dict),
					"localityLbPolicy":                llx.StringData(b.LocalityLbPolicy),
					"logConfig":                       llx.DictData(mqlLogConfig),
					"maxStreamDuration":               llx.TimeDataPtr(maxStreamDuration),
					"name":                            llx.StringData(b.Name),
					"portName":                        llx.StringData(b.PortName),
					"protocol":                        llx.StringData(b.Protocol),
					"securitySettings":                llx.DictData(mqlSecuritySettings),
					"securitySettingsClientTlsPolicy": llx.StringData(securitySettingsClientTlsPolicy),
					"securitySettingsSubjectAltNames": llx.ArrayData(convert.SliceAnyToInterface(securitySettingsSubjectAltNames), types.String),
					"serviceBindingUrls":              llx.ArrayData(convert.SliceAnyToInterface(b.ServiceBindings), types.String),
					"sessionAffinity":                 llx.StringData(b.SessionAffinity),
					"timeoutSec":                      llx.IntData(b.TimeoutSec),
					"port":                            llx.IntData(b.Port),
					"serviceLbPolicy":                 llx.StringData(b.ServiceLbPolicy),
					"ipAddressSelectionPolicy":        llx.StringData(b.IpAddressSelectionPolicy),
					"fingerprint":                     llx.StringData(b.Fingerprint),
					"selfLink":                        llx.StringData(b.SelfLink),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlB.(*mqlGcpProjectComputeServiceBackendService)
				mqlRef.cacheEdgeSecurityPolicyUrl = b.EdgeSecurityPolicy
				mqlRef.cacheNetworkUrl = b.Network
				mqlRef.cacheRegionUrl = b.Region
				mqlRef.cacheSecurityPolicyUrl = b.SecurityPolicy
				res = append(res, mqlB)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceBackendService) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcp.project.computeService.backendService/" + id, nil
}

func (g *mqlGcpProjectComputeServiceBackendServiceBackend) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceBackendServiceCdnPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func networkMode(n *compute.Network) string {
	if n.IPv4Range != "" {
		return "legacy"
	} else if n.AutoCreateSubnetworks {
		return "auto"
	} else {
		return "custom"
	}
}

func (g *mqlGcpProjectComputeService) addresses() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var mqlAddresses []any
	req := computeSvc.Addresses.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.AddressAggregatedList) error {
		for _, as := range page.Items {
			for _, a := range as.Addresses {
				mqlA, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.address", map[string]*llx.RawData{
					"id":               llx.StringData(fmt.Sprintf("%d", a.Id)),
					"address":          llx.StringData(a.Address),
					"addressType":      llx.StringData(a.AddressType),
					"created":          llx.TimeDataPtr(parseTime(a.CreationTimestamp)),
					"description":      llx.StringData(a.Description),
					"ipVersion":        llx.StringData(a.IpVersion),
					"ipv6EndpointType": llx.StringData(a.Ipv6EndpointType),
					"name":             llx.StringData(a.Name),
					"labels":           llx.MapData(convert.MapToInterfaceMap(a.Labels), types.String),
					"networkTier":      llx.StringData(a.NetworkTier),
					"prefixLength":     llx.IntData(a.PrefixLength),
					"purpose":          llx.StringData(a.Purpose),
					"status":           llx.StringData(a.Status),
					"resourceUrls":     llx.ArrayData(convert.SliceAnyToInterface(a.Users), types.String),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlA.(*mqlGcpProjectComputeServiceAddress)
				mqlRef.cacheNetworkUrl = a.Network
				mqlRef.cacheRegionUrl = a.Region
				mqlRef.cacheSubnetworkUrl = a.Subnetwork
				mqlAddresses = append(mqlAddresses, mqlA)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return mqlAddresses, nil
}

func (g *mqlGcpProjectComputeServiceAddress) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	networkUrl := g.cacheNetworkUrl
	net, err := getNetworkByUrl(networkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return net, nil
}

func (g *mqlGcpProjectComputeServiceAddress) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	subnetUrl := g.cacheSubnetworkUrl
	subnet, err := getSubnetworkByUrl(subnetUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		g.Subnetwork.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return subnet, nil
}

func (g *mqlGcpProjectComputeServiceAddress) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) forwardingRules() ([]any, error) {
	// when the service is not enabled, we return nil (mirrors the other 19
	// compute list accessors so an API-disabled project degrades to empty
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	fwrSvc, err := computev1.NewForwardingRulesRESTClient(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var fwRules []any
	it := fwrSvc.AggregatedList(ctx, &computepb.AggregatedListForwardingRulesRequest{Project: projectId, IncludeAllScopes: ptr.Bool(true)})
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		for _, fwr := range resp.Value.ForwardingRules {
			metadataFilters := make([]any, 0, len(fwr.GetMetadataFilters()))
			for _, m := range fwr.GetMetadataFilters() {
				filterLabels := make([]any, 0, len(m.GetFilterLabels()))
				for _, l := range m.GetFilterLabels() {
					filterLabels = append(filterLabels, map[string]any{
						"name":  l.GetName(),
						"value": l.GetValue(),
					})
				}
				metadataFilters = append(metadataFilters, map[string]any{
					"filterLabels":        filterLabels,
					"filterMatchCriteria": m.GetFilterMatchCriteria(),
				})
			}

			serviceDirRegs := make([]any, 0, len(fwr.GetServiceDirectoryRegistrations()))
			for _, s := range fwr.GetServiceDirectoryRegistrations() {
				serviceDirRegs = append(serviceDirRegs, map[string]any{
					"namespace":              s.GetNamespace(),
					"service":                s.GetService(),
					"serviceDirectoryRegion": s.GetServiceDirectoryRegion(),
				})
			}
			mqlFwr, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.forwardingRule", map[string]*llx.RawData{
				"id":                            llx.StringData(fmt.Sprintf("%d", fwr.GetId())),
				"ipAddress":                     llx.StringData(fwr.GetIPAddress()),
				"ipProtocol":                    llx.StringData(fwr.GetIPProtocol()),
				"allPorts":                      llx.BoolData(fwr.GetAllPorts()),
				"allowGlobalAccess":             llx.BoolData(fwr.GetAllowGlobalAccess()),
				"created":                       llx.TimeDataPtr(parseTime(fwr.GetCreationTimestamp())),
				"description":                   llx.StringData(fwr.GetDescription()),
				"ipVersion":                     llx.StringData(fwr.GetIpVersion()),
				"isMirroringCollector":          llx.BoolData(fwr.GetIsMirroringCollector()),
				"labels":                        llx.MapData(convert.MapToInterfaceMap(fwr.GetLabels()), types.String),
				"loadBalancingScheme":           llx.StringData(fwr.GetLoadBalancingScheme()),
				"metadataFilters":               llx.ArrayData(metadataFilters, types.Dict),
				"name":                          llx.StringData(fwr.GetName()),
				"networkTier":                   llx.StringData(fwr.GetNetworkTier()),
				"noAutomateDnsZone":             llx.BoolData(fwr.GetNoAutomateDnsZone()),
				"portRange":                     llx.StringData(fwr.GetPortRange()),
				"ports":                         llx.ArrayData(convert.SliceAnyToInterface(fwr.GetPorts()), types.String),
				"serviceDirectoryRegistrations": llx.ArrayData(serviceDirRegs, types.Dict),
				"serviceLabel":                  llx.StringData(fwr.GetServiceLabel()),
				"serviceName":                   llx.StringData(fwr.GetServiceName()),
				"targetUrl":                     llx.StringData(fwr.GetTarget()),
				"allowPscGlobalAccess":          llx.BoolData(fwr.GetAllowPscGlobalAccess()),
				"pscConnectionStatus":           llx.StringData(fwr.GetPscConnectionStatus()),
				"sourceIpRanges":                llx.ArrayData(convert.SliceAnyToInterface(fwr.GetSourceIpRanges()), types.String),
				"fingerprint":                   llx.StringData(fwr.GetFingerprint()),
				"ipCollection":                  llx.StringData(fwr.GetIpCollection()),
				"selfLink":                      llx.StringData(fwr.GetSelfLink()),
			})
			if err != nil {
				return nil, err
			}
			mqlRef := mqlFwr.(*mqlGcpProjectComputeServiceForwardingRule)
			mqlRef.cacheBackendServiceUrl = fwr.GetBackendService()
			mqlRef.cacheNetworkUrl = fwr.GetNetwork()
			mqlRef.cacheRegionUrl = fwr.GetRegion()
			mqlRef.cacheSubnetworkUrl = fwr.GetSubnetwork()
			fwRules = append(fwRules, mqlFwr)
		}
	}
	return fwRules, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceForwardingRule) isExternal() (bool, error) {
	if g.LoadBalancingScheme.Error != nil {
		return false, g.LoadBalancingScheme.Error
	}
	switch g.LoadBalancingScheme.Data {
	case "EXTERNAL", "EXTERNAL_MANAGED":
		return true, nil
	}
	return false, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	networkUrl := g.cacheNetworkUrl
	if networkUrl == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	net, err := getNetworkByUrl(networkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return net, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	subnetUrl := g.cacheSubnetworkUrl
	if subnetUrl == "" {
		g.Subnetwork.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	subnet, err := getSubnetworkByUrl(subnetUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		g.Subnetwork.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return subnet, nil
}

// Cloud NAT

func (g *mqlGcpProjectComputeServiceRouterNat) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

// Cloud Armor security policies

// mqlGcpProjectComputeServiceSecurityPolicyInternal carries what rules() needs
// to re-fetch the policy. The schema has no projectId field, and the policy's
// project is not derivable from the connection: on an organization or folder
// connection ResourceID() is not a project id, and `gcp.projects` walks many
// projects in one runtime. cacheRegion distinguishes global from regional
// policies, which live behind different endpoints.
type mqlGcpProjectComputeServiceSecurityPolicyInternal struct {
	cacheProjectId string
	cacheRegion    string
	cacheRegionUrl string
}

func (g *mqlGcpProjectComputeServiceSecurityPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceSecurityPolicyRule) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

// wafExpressionSets lists the preconfigured WAF rule sets a Cloud Armor
// security policy rule can reference.
//
// The sets are maintained by Google rather than by the project, so the same
// identifiers come back for every project. The cache key still carries the
// project id, or scanning two projects in one run would make the second
// project's sets resolve to the first project's resources.
func (g *mqlGcpProjectComputeService) wafExpressionSets() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	resp, err := computeSvc.SecurityPolicies.ListPreconfiguredExpressionSets(projectId).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, set := range wafExpressionSetsFromResponse(resp) {
		args, err := wafExpressionSetArgs(g.MqlRuntime, projectId, set)
		if err != nil {
			return nil, err
		}
		mqlSet, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.wafExpressionSet", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSet)
	}
	return res, nil
}

// wafExpressionSetsFromResponse walks to the expression sets inside the
// response. Every level is optional in the API, and a nil at any of them is an
// empty list rather than a failure.
func wafExpressionSetsFromResponse(resp *compute.SecurityPoliciesListPreconfiguredExpressionSetsResponse) []*compute.WafExpressionSet {
	if resp == nil || resp.PreconfiguredExpressionSets == nil || resp.PreconfiguredExpressionSets.WafRules == nil {
		return nil
	}
	return resp.PreconfiguredExpressionSets.WafRules.ExpressionSets
}

// wafExpressionSetExpressionArgs maps one expression of a set onto resource
// arguments.
//
// A sensitivity of 0 is a real paranoia level, marking an expression applied
// only when a rule opts into it by name, so it has to survive rather than be
// dropped as a zero value. The cache key carries the project because the sets
// are Google-maintained and identical across projects.
func wafExpressionSetExpressionArgs(setID string, e *compute.WafExpressionSetExpression) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData(setID + "/expression/" + e.Id),
		"id":          llx.StringData(e.Id),
		"sensitivity": llx.IntData(e.Sensitivity),
	}
}

// wafExpressionSetArgs maps one expression set onto resource arguments.
func wafExpressionSetArgs(runtime *plugin.Runtime, projectId string, set *compute.WafExpressionSet) (map[string]*llx.RawData, error) {
	aliases := make([]any, 0, len(set.Aliases))
	for _, a := range set.Aliases {
		aliases = append(aliases, a)
	}

	setID := projectId + "/wafExpressionSet/" + set.Id
	expressions := make([]any, 0, len(set.Expressions))
	for _, e := range set.Expressions {
		if e == nil {
			continue
		}
		mqlExpression, err := CreateResource(runtime, "gcp.project.computeService.wafExpressionSet.expression",
			wafExpressionSetExpressionArgs(setID, e))
		if err != nil {
			return nil, err
		}
		expressions = append(expressions, mqlExpression)
	}

	return map[string]*llx.RawData{
		"__id":        llx.StringData(setID),
		"id":          llx.StringData(set.Id),
		"aliases":     llx.ArrayData(aliases, types.String),
		"expressions": llx.ArrayData(expressions, types.Resource("gcp.project.computeService.wafExpressionSet.expression")),
	}, nil
}

func (g *mqlGcpProjectComputeService) securityPolicies() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.SecurityPolicies.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.SecurityPoliciesAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, policy := range scopedList.SecurityPolicies {
				adaptiveProtectionConfig, err := convert.JsonToDict(policy.AdaptiveProtectionConfig)
				if err != nil {
					return err
				}
				advancedOptionsConfig, err := convert.JsonToDict(policy.AdvancedOptionsConfig)
				if err != nil {
					return err
				}
				ddosProtectionConfig, err := convert.JsonToDict(policy.DdosProtectionConfig)
				if err != nil {
					return err
				}
				recaptchaOptionsConfig, err := convert.JsonToDict(policy.RecaptchaOptionsConfig)
				if err != nil {
					return err
				}

				userDefinedFields := make([]any, 0, len(policy.UserDefinedFields))
				for _, udf := range policy.UserDefinedFields {
					d, err := convert.JsonToDict(udf)
					if err != nil {
						return err
					}
					userDefinedFields = append(userDefinedFields, d)
				}

				policyId := strconv.FormatUint(policy.Id, 10)
				policyKey := "gcp.project.computeService.securityPolicy/" + policyId
				adaptiveProtection, err := newMqlSecurityPolicyAdaptiveProtection(g.MqlRuntime, policyKey, policy.AdaptiveProtectionConfig)
				if err != nil {
					return err
				}
				advancedOptions, err := newMqlSecurityPolicyAdvancedOptions(g.MqlRuntime, policyKey, policy.AdvancedOptionsConfig)
				if err != nil {
					return err
				}
				networkDdosProtection, err := newMqlSecurityPolicyDdosProtection(g.MqlRuntime, policyKey, policy.DdosProtectionConfig)
				if err != nil {
					return err
				}
				mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.securityPolicy", map[string]*llx.RawData{
					"id":                       llx.StringData(policyId),
					"name":                     llx.StringData(policy.Name),
					"description":              llx.StringData(policy.Description),
					"type":                     llx.StringData(policy.Type),
					"labels":                   llx.MapData(convert.MapToInterfaceMap(policy.Labels), types.String),
					"adaptiveProtectionConfig": llx.DictData(adaptiveProtectionConfig),
					"adaptiveProtection":       adaptiveProtection,
					"advancedOptionsConfig":    llx.DictData(advancedOptionsConfig),
					"advancedOptions":          advancedOptions,
					"ddosProtectionConfig":     llx.DictData(ddosProtectionConfig),
					"networkDdosProtection":    networkDdosProtection,
					"recaptchaOptionsConfig":   llx.DictData(recaptchaOptionsConfig),
					"fingerprint":              llx.StringData(policy.Fingerprint),
					"userDefinedFields":        llx.ArrayData(userDefinedFields, types.Dict),
					"selfLink":                 llx.StringData(policy.SelfLink),
					"createdAt":                llx.TimeDataPtr(parseTime(policy.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlPolicy.(*mqlGcpProjectComputeServiceSecurityPolicy)
				mqlRef.cacheRegionUrl = policy.Region
				sp := mqlPolicy.(*mqlGcpProjectComputeServiceSecurityPolicy)
				sp.cacheProjectId = projectId
				sp.cacheRegion = RegionNameFromRegionUrl(policy.Region)
				res = append(res, mqlPolicy)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceSecurityPolicy) rules() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	policyId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// Get the policy name to fetch its rules
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	policyName := g.Name.Data

	// Use the project the policy was listed from. conn.ResourceID() is the
	// connection scope, which is an organization or folder id on a non-project
	// connection and the wrong project when `gcp.projects` walks many projects.
	projectId := g.cacheProjectId
	if projectId == "" {
		projectId = conn.ResourceID()
	}

	// securityPolicies() lists via AggregatedList, which returns regional
	// policies too. Those are served by RegionSecurityPolicies; asking the
	// global endpoint for them 404s.
	var policy *compute.SecurityPolicy
	if g.cacheRegion != "" {
		policy, err = computeSvc.RegionSecurityPolicies.Get(projectId, g.cacheRegion, policyName).Context(ctx).Do()
	} else {
		policy, err = computeSvc.SecurityPolicies.Get(projectId, policyName).Context(ctx).Do()
	}
	if err != nil {
		if isSkippable(err) {
			log.Warn().Str("policy", policyName).Err(err).Msg("could not fetch security policy rules")
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for _, rule := range policy.Rules {
		matchDict, err := convert.JsonToDict(rule.Match)
		if err != nil {
			return nil, err
		}
		networkMatch, err := convert.JsonToDict(rule.NetworkMatch)
		if err != nil {
			return nil, err
		}
		rateLimitOptions, err := convert.JsonToDict(rule.RateLimitOptions)
		if err != nil {
			return nil, err
		}
		redirectOptions, err := convert.JsonToDict(rule.RedirectOptions)
		if err != nil {
			return nil, err
		}
		headerAction, err := convert.JsonToDict(rule.HeaderAction)
		if err != nil {
			return nil, err
		}
		preconfiguredWafConfig, err := convert.JsonToDict(rule.PreconfiguredWafConfig)
		if err != nil {
			return nil, err
		}

		ruleId := fmt.Sprintf("gcp.project.computeService.securityPolicy.rule/%s/%d", policyId, rule.Priority)
		matcher, err := newMqlSecurityPolicyRuleMatcher(g.MqlRuntime, ruleId, rule.Match)
		if err != nil {
			return nil, err
		}

		mqlRule, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.securityPolicy.rule", map[string]*llx.RawData{
			"id":                     llx.StringData(ruleId),
			"action":                 llx.StringData(rule.Action),
			"description":            llx.StringData(rule.Description),
			"priority":               llx.IntData(rule.Priority),
			"preview":                llx.BoolData(rule.Preview),
			"match":                  llx.DictData(matchDict),
			"matcher":                matcher,
			"networkMatch":           llx.DictData(networkMatch),
			"rateLimitOptions":       llx.DictData(rateLimitOptions),
			"redirectOptions":        llx.DictData(redirectOptions),
			"headerAction":           llx.DictData(headerAction),
			"preconfiguredWafConfig": llx.DictData(preconfiguredWafConfig),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

// SSL Policies

func (g *mqlGcpProjectComputeServiceSslPolicy) weakTls() (bool, error) {
	if g.MinTlsVersion.Error != nil {
		return false, g.MinTlsVersion.Error
	}
	switch g.MinTlsVersion.Data {
	case "TLS_1_0", "TLS_1_1":
		return true, nil
	}
	if g.Profile.Error != nil {
		return false, g.Profile.Error
	}
	return g.Profile.Data == "COMPATIBLE", nil
}

func (g *mqlGcpProjectComputeServiceSslPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) sslPolicies() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.SslPolicies.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.SslPoliciesAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, policy := range scopedList.SslPolicies {
				warnings := make([]any, 0, len(policy.Warnings))
				for _, w := range policy.Warnings {
					wDict, err := convert.JsonToDict(w)
					if err != nil {
						return err
					}
					warnings = append(warnings, wDict)
				}

				mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.sslPolicy", map[string]*llx.RawData{
					"id":              llx.StringData(strconv.FormatUint(policy.Id, 10)),
					"name":            llx.StringData(policy.Name),
					"description":     llx.StringData(policy.Description),
					"profile":         llx.StringData(policy.Profile),
					"minTlsVersion":   llx.StringData(policy.MinTlsVersion),
					"customFeatures":  llx.ArrayData(convert.SliceAnyToInterface(policy.CustomFeatures), types.String),
					"enabledFeatures": llx.ArrayData(convert.SliceAnyToInterface(policy.EnabledFeatures), types.String),
					"selfLink":        llx.StringData(policy.SelfLink),
					"warnings":        llx.ArrayData(warnings, types.Dict),
					"createdAt":       llx.TimeDataPtr(parseTime(policy.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlPolicy.(*mqlGcpProjectComputeServiceSslPolicy)
				mqlRef.cacheRegionUrl = policy.Region
				res = append(res, mqlPolicy)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// SSL Certificates

func (g *mqlGcpProjectComputeServiceSslCertificate) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceSslCertificate) expired() (bool, error) {
	if g.ExpireTime.Error != nil {
		return false, g.ExpireTime.Error
	}
	if g.ExpireTime.Data == "" {
		return false, nil
	}
	t, err := time.Parse(time.RFC3339, g.ExpireTime.Data)
	if err != nil {
		return false, fmt.Errorf("parsing ssl certificate expireTime %q: %w", g.ExpireTime.Data, err)
	}
	return t.Before(time.Now()), nil
}

func (g *mqlGcpProjectComputeService) sslCertificates() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.SslCertificates.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.SslCertificateAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, cert := range scopedList.SslCertificates {
				managed, err := convert.JsonToDict(cert.Managed)
				if err != nil {
					return err
				}

				var managedStatus string
				if cert.Managed != nil {
					managedStatus = cert.Managed.Status
				}

				mqlCert, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.sslCertificate", map[string]*llx.RawData{
					"id":                      llx.StringData(strconv.FormatUint(cert.Id, 10)),
					"name":                    llx.StringData(cert.Name),
					"description":             llx.StringData(cert.Description),
					"type":                    llx.StringData(cert.Type),
					"subjectAlternativeNames": llx.ArrayData(convert.SliceAnyToInterface(cert.SubjectAlternativeNames), types.String),
					"managed":                 llx.DictData(managed),
					"managedStatus":           llx.StringData(managedStatus),
					"selfLink":                llx.StringData(cert.SelfLink),
					"expireTime":              llx.StringData(cert.ExpireTime),
					"createdAt":               llx.TimeDataPtr(parseTime(cert.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlCert.(*mqlGcpProjectComputeServiceSslCertificate)
				mqlRef.cacheRegionUrl = cert.Region
				res = append(res, mqlCert)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceVpnGateway) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

type mqlGcpProjectComputeServiceVpnGatewayInternal struct {
	cacheNetworkUrl string
	cacheRegionUrl  string
	cacheSelfLink   string
}

func (g *mqlGcpProjectComputeServiceVpnGateway) effectiveTags() ([]any, error) {
	return effectiveTagsForResource(g.MqlRuntime, computeSelfLinkToResourceName(g.cacheSelfLink))
}

func (g *mqlGcpProjectComputeServiceVpnTunnel) effectiveTags() ([]any, error) {
	if g.SelfLink.Error != nil {
		return nil, g.SelfLink.Error
	}
	return effectiveTagsForResource(g.MqlRuntime, computeSelfLinkToResourceName(g.SelfLink.Data))
}

func (g *mqlGcpProjectComputeServiceVpnGateway) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.cacheNetworkUrl == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return getNetworkByUrl(g.cacheNetworkUrl, g.MqlRuntime)
}

func (g *mqlGcpProjectComputeService) vpnGateways() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.VpnGateways.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.VpnGatewayAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, gw := range scopedList.VpnGateways {
				vpnInterfaces := make([]any, 0, len(gw.VpnInterfaces))
				for _, iface := range gw.VpnInterfaces {
					ifaceDict, err := convert.JsonToDict(iface)
					if err != nil {
						return err
					}
					vpnInterfaces = append(vpnInterfaces, ifaceDict)
				}

				var gwResourceManagerTags map[string]any
				if gw.Params != nil {
					gwResourceManagerTags = convert.MapToInterfaceMap(gw.Params.ResourceManagerTags)
				}

				mqlGw, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.vpnGateway", map[string]*llx.RawData{
					"id":                  llx.StringData(fmt.Sprintf("%d", gw.Id)),
					"name":                llx.StringData(gw.Name),
					"description":         llx.StringData(gw.Description),
					"created":             llx.TimeDataPtr(parseTime(gw.CreationTimestamp)),
					"labels":              llx.MapData(convert.MapToInterfaceMap(gw.Labels), types.String),
					"gatewayIpVersion":    llx.StringData(gw.GatewayIpVersion),
					"stackType":           llx.StringData(gw.StackType),
					"vpnInterfaces":       llx.ArrayData(vpnInterfaces, types.Dict),
					"resourceManagerTags": llx.MapData(gwResourceManagerTags, types.String),
				})
				if err != nil {
					return err
				}
				mqlGwRes := mqlGw.(*mqlGcpProjectComputeServiceVpnGateway)
				mqlGwRes.cacheRegionUrl = gw.Region
				mqlGwRes.cacheNetworkUrl = gw.Network
				mqlGwRes.cacheSelfLink = gw.SelfLink
				res = append(res, mqlGw)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceVpnTunnel) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) vpnTunnels() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.VpnTunnels.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.VpnTunnelAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, t := range scopedList.VpnTunnels {
				var tunnelResourceManagerTags map[string]any
				if t.Params != nil {
					tunnelResourceManagerTags = convert.MapToInterfaceMap(t.Params.ResourceManagerTags)
				}

				mqlTunnel, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.vpnTunnel", map[string]*llx.RawData{
					"id":                           llx.StringData(fmt.Sprintf("%d", t.Id)),
					"name":                         llx.StringData(t.Name),
					"description":                  llx.StringData(t.Description),
					"created":                      llx.TimeDataPtr(parseTime(t.CreationTimestamp)),
					"labels":                       llx.MapData(convert.MapToInterfaceMap(t.Labels), types.String),
					"detailedStatus":               llx.StringData(t.DetailedStatus),
					"ikeVersion":                   llx.IntData(t.IkeVersion),
					"localTrafficSelector":         llx.ArrayData(convert.SliceAnyToInterface(t.LocalTrafficSelector), types.String),
					"remoteTrafficSelector":        llx.ArrayData(convert.SliceAnyToInterface(t.RemoteTrafficSelector), types.String),
					"peerExternalGatewayInterface": llx.IntData(t.PeerExternalGatewayInterface),
					"peerIp":                       llx.StringData(t.PeerIp),
					"sharedSecretHash":             llx.StringData(t.SharedSecretHash),
					"status":                       llx.StringData(t.Status),
					"targetVpnGateway":             llx.StringData(t.TargetVpnGateway),
					"vpnGatewayInterface":          llx.IntData(int64(t.VpnGatewayInterface)),
					"resourceManagerTags":          llx.MapData(tunnelResourceManagerTags, types.String),
					"selfLink":                     llx.StringData(t.SelfLink),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlTunnel.(*mqlGcpProjectComputeServiceVpnTunnel)
				mqlRef.cachePeerExternalGateway = t.PeerExternalGateway
				mqlRef.cachePeerGcpGateway = t.PeerGcpGateway
				mqlRef.cacheRegionUrl = t.Region
				mqlRef.cacheRouterUrl = t.Router
				mqlRef.cacheVpnGatewayUrl = t.VpnGateway
				res = append(res, mqlTunnel)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceStoragePool) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

// storagePoolSharedProjectIds returns the sorted project IDs a storage pool is
// shared with. The share settings carry a project map whose values only repeat
// the key, so the keys alone describe which projects may create disks from the
// pool.
func storagePoolSharedProjectIds(shareSettings *compute.StoragePoolShareSettings) []any {
	if shareSettings == nil {
		return []any{}
	}
	ids := make([]string, 0, len(shareSettings.ProjectMap))
	for projectId := range shareSettings.ProjectMap {
		ids = append(ids, projectId)
	}
	sort.Strings(ids)
	return convert.SliceAnyToInterface(ids)
}

func (g *mqlGcpProjectComputeService) storagePools() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.StoragePools.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.StoragePoolAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, sp := range scopedList.StoragePools {
				mqlSp, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.storagePool", map[string]*llx.RawData{
					"id":                          llx.StringData(fmt.Sprintf("%d", sp.Id)),
					"name":                        llx.StringData(sp.Name),
					"description":                 llx.StringData(sp.Description),
					"created":                     llx.TimeDataPtr(parseTime(sp.CreationTimestamp)),
					"labels":                      llx.MapData(convert.MapToInterfaceMap(sp.Labels), types.String),
					"capacityProvisioningType":    llx.StringData(sp.CapacityProvisioningType),
					"performanceProvisioningType": llx.StringData(sp.PerformanceProvisioningType),
					"poolProvisionedCapacityGb":   llx.IntData(sp.PoolProvisionedCapacityGb),
					"poolProvisionedIops":         llx.IntData(sp.PoolProvisionedIops),
					"poolProvisionedThroughput":   llx.IntData(sp.PoolProvisionedThroughput),
					"state":                       llx.StringData(sp.State),
					"storagePoolType":             llx.StringData(sp.StoragePoolType),
					"zone":                        llx.StringData(sp.Zone),
					"sharedWithProjectIds":        llx.ArrayData(storagePoolSharedProjectIds(sp.ShareSettings), types.String),
				})
				if err != nil {
					return err
				}
				res = append(res, mqlSp)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func computeIamBindingsToResources(runtime *plugin.Runtime, idPrefix string, bindings []*compute.Binding) ([]any, error) {
	res := make([]any, 0, len(bindings))
	for i, b := range bindings {
		condTitle, condExpr, condDesc := "", "", ""
		if b.Condition != nil {
			condTitle = b.Condition.Title
			condExpr = b.Condition.Expression
			condDesc = b.Condition.Description
		}

		mqlBinding, err := CreateResource(runtime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(idPrefix + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(condTitle),
			"conditionExpression":  llx.StringData(condExpr),
			"conditionDescription": llx.StringData(condDesc),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceImage) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	policy, err := svc.Images.GetIamPolicy(projectId, name).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	// Qualify the binding ids by resource type and project. Keying on the bare
	// name aliased an image and a snapshot that share a name (and the same
	// image name across two scanned projects) onto one set of bindings, so a
	// public image could read as private from whichever resolved first.
	return computeIamBindingsToResources(g.MqlRuntime,
		"gcp.project.computeService.image/"+projectId+"/"+name, policy.Bindings)
}

func (g *mqlGcpProjectComputeServiceInstance) hasPublicIp() (bool, error) {
	nics := g.GetNics()
	if nics.Error != nil {
		return false, nics.Error
	}
	for _, n := range nics.Data {
		nic, ok := n.(*mqlGcpProjectComputeServiceInstanceNetworkInterface)
		if !ok {
			continue
		}
		accessConfigs := nic.GetAccessConfigs()
		if accessConfigs.Error != nil {
			return false, accessConfigs.Error
		}
		if len(accessConfigs.Data) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (g *mqlGcpProjectComputeServiceFirewall) openToInternet() (bool, error) {
	if g.Disabled.Error != nil {
		return false, g.Disabled.Error
	}
	if g.Disabled.Data {
		return false, nil
	}
	if g.Direction.Error != nil {
		return false, g.Direction.Error
	}
	if !strings.EqualFold(g.Direction.Data, "INGRESS") {
		return false, nil
	}
	if g.Allowed.Error != nil {
		return false, g.Allowed.Error
	}
	if len(g.Allowed.Data) == 0 {
		return false, nil
	}
	if g.SourceRanges.Error != nil {
		return false, g.SourceRanges.Error
	}
	for _, r := range g.SourceRanges.Data {
		s, ok := r.(string)
		if !ok {
			continue
		}
		if s == "0.0.0.0/0" || s == "::/0" {
			return true, nil
		}
	}
	return false, nil
}

func (g *mqlGcpProjectComputeServiceSnapshot) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	policy, err := svc.Snapshots.GetIamPolicy(projectId, name).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return computeIamBindingsToResources(g.MqlRuntime,
		"gcp.project.computeService.snapshot/"+projectId+"/"+name, policy.Bindings)
}

func (g *mqlGcpProjectComputeServiceSnapshot) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

func (g *mqlGcpProjectComputeServiceImage) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

var defaultComputeServiceAccountRe = regexp.MustCompile(`^\d+-compute@developer\.gserviceaccount\.com$`)

func (g *mqlGcpProjectComputeServiceInstance) usesDefaultServiceAccount() (bool, error) {
	sas := g.GetServiceAccounts()
	if sas.Error != nil {
		return false, sas.Error
	}
	for _, raw := range sas.Data {
		sa, ok := raw.(*mqlGcpProjectComputeServiceServiceaccount)
		if !ok || sa == nil {
			continue
		}
		email := sa.GetEmail()
		if email.Error != nil {
			return false, email.Error
		}
		if defaultComputeServiceAccountRe.MatchString(email.Data) {
			return true, nil
		}
	}
	return false, nil
}

const cloudPlatformOAuthScope = "https://www.googleapis.com/auth/cloud-platform"

func (g *mqlGcpProjectComputeServiceInstance) hasFullCloudPlatformScope() (bool, error) {
	sas := g.GetServiceAccounts()
	if sas.Error != nil {
		return false, sas.Error
	}
	for _, raw := range sas.Data {
		sa, ok := raw.(*mqlGcpProjectComputeServiceServiceaccount)
		if !ok || sa == nil {
			continue
		}
		scopes := sa.GetScopes()
		if scopes.Error != nil {
			return false, scopes.Error
		}
		for _, s := range scopes.Data {
			if str, ok := s.(string); ok && str == cloudPlatformOAuthScope {
				return true, nil
			}
		}
	}
	return false, nil
}

func metadataBoolFlag(metadata map[string]any, key string) bool {
	v, ok := metadata[key]
	if !ok {
		return false
	}
	s, ok := v.(string)
	if !ok {
		return false
	}
	switch strings.ToLower(s) {
	case "true", "1":
		return true
	}
	return false
}

func (g *mqlGcpProjectComputeServiceInstance) blockProjectSshKeysEnabled() (bool, error) {
	md := g.GetMetadata()
	if md.Error != nil {
		return false, md.Error
	}
	return metadataBoolFlag(md.Data, "block-project-ssh-keys"), nil
}

func (g *mqlGcpProjectComputeServiceInstance) hasInstanceSshKeys() (bool, error) {
	md := g.GetMetadata()
	if md.Error != nil {
		return false, md.Error
	}
	s, _ := md.Data["ssh-keys"].(string)
	return s != "", nil
}

func (g *mqlGcpProjectComputeServiceInstance) instanceSshKeys() ([]any, error) {
	md := g.GetMetadata()
	if md.Error != nil {
		return nil, md.Error
	}
	raw, _ := md.Data["ssh-keys"].(string)
	return parseInstanceSSHKeys(raw), nil
}

func (g *mqlGcpProjectComputeServiceInstance) osLoginEnabled() (bool, error) {
	md := g.GetMetadata()
	if md.Error != nil {
		return false, md.Error
	}
	if _, set := md.Data["enable-oslogin"]; set {
		return metadataBoolFlag(md.Data, "enable-oslogin"), nil
	}
	return g.projectMetadataFlag("enable-oslogin")
}

// serialPortEnabled reports whether interactive serial console access is
// enabled for this instance, which is what an audit of the control needs to
// know.
//
// Compute Engine resolves the setting the same way it resolves OS Login: the
// instance's own serial-port-enable metadata wins, and an instance that does
// not set the key inherits the project's commonInstanceMetadata value. Reading
// only the instance metadata therefore reported false for every VM in a
// project that had switched serial console access on project-wide -- the exact
// case the control exists to catch, and one where a false answer is
// indistinguishable from a VM that genuinely has it off.
func (g *mqlGcpProjectComputeServiceInstance) serialPortEnabled() (bool, error) {
	md := g.GetMetadata()
	if md.Error != nil {
		return false, md.Error
	}
	if _, set := md.Data["serial-port-enable"]; set {
		return metadataBoolFlag(md.Data, "serial-port-enable"), nil
	}
	return g.projectMetadataFlag("serial-port-enable")
}

// projectMetadataFlag reads a boolean key from the project's
// commonInstanceMetadata, for the instance-level accessors whose setting falls
// back to the project when the instance does not set it.
func (g *mqlGcpProjectComputeServiceInstance) projectMetadataFlag(key string) (bool, error) {
	if g.ProjectId.Error != nil {
		return false, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if projectId == "" {
		return false, nil
	}
	projRes, err := NewResource(g.MqlRuntime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(projectId),
	})
	if err != nil {
		return false, err
	}
	projMd := projRes.(*mqlGcpProject).GetCommonInstanceMetadata()
	if projMd.Error != nil {
		return false, projMd.Error
	}
	if projMd.Data == nil {
		return false, nil
	}
	return metadataBoolFlag(projMd.Data, key), nil
}

func (g *mqlGcpProjectComputeService) projectMetadataFlag(key string) (bool, error) {
	if g.ProjectId.Error != nil {
		return false, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if projectId == "" {
		return false, nil
	}
	projRes, err := NewResource(g.MqlRuntime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(projectId),
	})
	if err != nil {
		return false, err
	}
	proj := projRes.(*mqlGcpProject)
	projMd := proj.GetCommonInstanceMetadata()
	if projMd.Error != nil {
		return false, projMd.Error
	}
	if projMd.Data == nil {
		return false, nil
	}
	return metadataBoolFlag(projMd.Data, key), nil
}

func (g *mqlGcpProjectComputeService) projectOsLoginEnabled() (bool, error) {
	return g.projectMetadataFlag("enable-oslogin")
}

func (g *mqlGcpProjectComputeService) projectBlockProjectSshKeys() (bool, error) {
	return g.projectMetadataFlag("block-project-ssh-keys")
}

func (g *mqlGcpProjectComputeService) projectSerialPortEnabled() (bool, error) {
	return g.projectMetadataFlag("serial-port-enable")
}

func (g *mqlGcpProjectComputeService) hasDefaultNetwork() (bool, error) {
	networks := g.GetNetworks()
	if networks.Error != nil {
		return false, networks.Error
	}
	for _, raw := range networks.Data {
		n, ok := raw.(*mqlGcpProjectComputeServiceNetwork)
		if !ok || n == nil {
			continue
		}
		name := n.GetName()
		if name.Error != nil {
			return false, name.Error
		}
		if name.Data == "default" {
			return true, nil
		}
	}
	return false, nil
}

func (g *mqlGcpProjectComputeServiceNetwork) legacy() (bool, error) {
	if g.Mode.Error != nil {
		return false, g.Mode.Error
	}
	return g.Mode.Data == "legacy", nil
}

func firewallSourceRangesContainPublic(ranges []any) bool {
	for _, r := range ranges {
		s, ok := r.(string)
		if !ok {
			continue
		}
		if s == "0.0.0.0/0" || s == "::/0" {
			return true
		}
	}
	return false
}

func allowedRulePermitsPort(rule map[string]any, port int) bool {
	proto, _ := rule["ipProtocol"].(string)
	if proto == "" {
		proto, _ = rule["IPProtocol"].(string)
	}
	switch strings.ToLower(proto) {
	case "tcp", "6", "all":
	default:
		return false
	}
	portsRaw, ok := rule["ports"].([]any)
	if !ok || len(portsRaw) == 0 {
		return true
	}
	for _, p := range portsRaw {
		ps, ok := p.(string)
		if !ok {
			continue
		}
		if portMatches(ps, port) {
			return true
		}
	}
	return false
}

func portMatches(spec string, port int) bool {
	if !strings.Contains(spec, "-") {
		n, err := strconv.Atoi(spec)
		if err != nil {
			return false
		}
		return n == port
	}
	parts := strings.SplitN(spec, "-", 2)
	low, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	high, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return port >= low && port <= high
}

func (g *mqlGcpProjectComputeServiceFirewall) firewallOpenToInternetTcp(port int) (bool, error) {
	if g.Disabled.Error != nil {
		return false, g.Disabled.Error
	}
	if g.Disabled.Data {
		return false, nil
	}
	if g.Direction.Error != nil {
		return false, g.Direction.Error
	}
	if !strings.EqualFold(g.Direction.Data, "INGRESS") {
		return false, nil
	}
	if g.SourceRanges.Error != nil {
		return false, g.SourceRanges.Error
	}
	if !firewallSourceRangesContainPublic(g.SourceRanges.Data) {
		return false, nil
	}
	if g.Allowed.Error != nil {
		return false, g.Allowed.Error
	}
	for _, raw := range g.Allowed.Data {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if allowedRulePermitsPort(rule, port) {
			return true, nil
		}
	}
	return false, nil
}

func (g *mqlGcpProjectComputeServiceFirewall) allowsSshFromInternet() (bool, error) {
	return g.firewallOpenToInternetTcp(22)
}

func (g *mqlGcpProjectComputeServiceFirewall) allowsRdpFromInternet() (bool, error) {
	return g.firewallOpenToInternetTcp(3389)
}

func (g *mqlGcpProjectComputeServiceBackendService) cloudArmorEnabled() (bool, error) {
	policy, err := g.securityPolicy()
	if err != nil {
		return false, err
	}
	return policy != nil, nil
}

func (g *mqlGcpProjectComputeServiceBackendService) iapEnabled() (bool, error) {
	if g.Iap.Error != nil {
		return false, g.Iap.Error
	}
	if g.Iap.Data == nil {
		return false, nil
	}
	iapMap, ok := g.Iap.Data.(map[string]any)
	if !ok {
		return false, nil
	}
	enabled, _ := iapMap["serviceEnabled"].(bool)
	return enabled, nil
}

func (g *mqlGcpProjectComputeServiceBackendService) loggingEnabled() (bool, error) {
	if g.LogConfig.Error != nil {
		return false, g.LogConfig.Error
	}
	logMap, ok := g.LogConfig.Data.(map[string]any)
	if !ok {
		return false, nil
	}
	enabled, _ := logMap["enable"].(bool)
	return enabled, nil
}
