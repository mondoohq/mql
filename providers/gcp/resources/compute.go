// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/smithy-go/ptr"

	computev1 "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"go.mondoo.com/mql/v13/types"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func initGcpProjectComputeService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

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

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

func (g *mqlGcpProjectComputeService) regions() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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

	req, err := computeSvc.Regions.List(projectId).Do()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(req.Items))
	for _, r := range req.Items {
		mqlRegion, err := newMqlRegion(g.MqlRuntime, r)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRegion)
	}

	return res, nil
}

func (g *mqlGcpProjectComputeServiceZone) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcp.project.computeService.zone/" + id, nil
}

func (g *mqlGcpProjectComputeServiceZone) region() (any, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (g *mqlGcpProjectComputeService) zones() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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
			mqlZone, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.zone", map[string]*llx.RawData{
				"id":          llx.StringData(strconv.FormatInt(int64(zone.Id), 10)),
				"name":        llx.StringData(zone.Name),
				"description": llx.StringData(zone.Description),
				"status":      llx.StringData(zone.Status),
				"created":     llx.TimeDataPtr(parseTime(zone.CreationTimestamp)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlZone)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

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
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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

	var wg sync.WaitGroup
	res := []any{}
	wg.Add(len(zones.Data))
	mux := &sync.Mutex{}

	for i := range zones.Data {
		z := zones.Data[i].(*mqlGcpProjectComputeServiceZone)
		zoneName := z.GetName()
		if zoneName.Error != nil {
			return nil, zoneName.Error
		}

		go func(svc *compute.Service, projectId string, zone *mqlGcpProjectComputeServiceZone, zoneName string) {
			req := computeSvc.MachineTypes.List(projectId, zoneName)
			if err := req.Pages(ctx, func(page *compute.MachineTypeList) error {
				for _, machinetype := range page.Items {
					mqlMachineType, err := newMqlMachineType(g.MqlRuntime, machinetype, projectId, zone)
					if err != nil {
						return err
					} else {
						mux.Lock()
						res = append(res, mqlMachineType)
						mux.Unlock()
					}
				}
				return nil
			}); err != nil {
				log.Error().Err(err).Send()
			}
			wg.Done()
		}(computeSvc, projectId, z, zoneName.Data)
	}
	wg.Wait()
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

		if instanceZone.Data.Name.Data == args["region"].Value && name.Data == args["name"].Value && projectId.Data == args["projectId"].Value {
			return args, instance, nil
		}
	}

	return nil, nil, errors.New("instance not found")
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

	// TODO: we can save calls if we move it to the into method
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

func newMqlServiceAccount(runtime *plugin.Runtime, sa *compute.ServiceAccount) (any, error) {
	return CreateResource(runtime, "gcp.project.computeService.serviceaccount", map[string]*llx.RawData{
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

	mqlAttachedDisk, err := CreateResource(runtime, "gcp.project.computeService.attachedDisk", map[string]*llx.RawData{
		"id":              llx.StringData(id),
		"projectId":       llx.StringData(projectId),
		"architecture":    llx.StringData(attachedDisk.Architecture),
		"autoDelete":      llx.BoolData(attachedDisk.AutoDelete),
		"boot":            llx.BoolData(attachedDisk.Boot),
		"deviceName":      llx.StringData(attachedDisk.DeviceName),
		"diskSizeGb":      llx.IntData(attachedDisk.DiskSizeGb),
		"forceAttach":     llx.BoolData(attachedDisk.ForceAttach),
		"guestOsFeatures": llx.ArrayData(convert.SliceAnyToInterface(guestOsFeatures), types.String),
		"index":           llx.IntData(attachedDisk.Index),
		"interface":       llx.StringData(attachedDisk.Interface),
		"licenses":        llx.ArrayData(convert.SliceAnyToInterface(attachedDisk.Licenses), types.String),
		"mode":            llx.StringData(attachedDisk.Mode),
		"type":            llx.StringData(attachedDisk.Type),
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
		if disk.Zone.Data.GetName().Data == diskId.Region && disk.Name.Data == diskId.Name {
			return disk, nil
		}

	}
	return nil, errors.New("disk not found")
}

type mqlGcpProjectComputeServiceInstanceInternal struct {
	instanceMachineType string
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

		mqlServiceAccount, err := newMqlServiceAccount(runtime, sa)
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

	networkInterfaces, err := convert.JsonToDictSlice(instance.NetworkInterfaces)
	if err != nil {
		return nil, err
	}

	reservationAffinity, err := convert.JsonToDict(instance.ReservationAffinity)
	if err != nil {
		return nil, err
	}

	scheduling, err := convert.JsonToDict(instance.Scheduling)
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

	var mqlConfCompute map[string]any
	if instance.ConfidentialInstanceConfig != nil {
		type mqlConfidentialInstanceConfig struct {
			Enabled bool `json:"serviceEnabled,omitempty"`
		}
		mqlConfCompute, err = convert.JsonToDict(
			mqlConfidentialInstanceConfig{Enabled: instance.ConfidentialInstanceConfig.EnableConfidentialCompute})
		if err != nil {
			return nil, err
		}
	}

	var tagsItems []string
	if instance.Tags != nil {
		tagsItems = instance.Tags.Items
	}

	entry, err := CreateResource(runtime, "gcp.project.computeService.instance", map[string]*llx.RawData{
		"id":                         llx.StringData(instanceId),
		"projectId":                  llx.StringData(projectId),
		"name":                       llx.StringData(instance.Name),
		"description":                llx.StringData(instance.Description),
		"confidentialInstanceConfig": llx.DictData(mqlConfCompute),
		"canIpForward":               llx.BoolData(instance.CanIpForward),
		"cpuPlatform":                llx.StringData(instance.CpuPlatform),
		"created":                    llx.TimeDataPtr(parseTime(instance.CreationTimestamp)),
		"deletionProtection":         llx.BoolData(instance.DeletionProtection),
		"enableDisplay":              llx.BoolData(enableDisplay),
		"guestAccelerators":          llx.ArrayData(guestAccelerators, types.Dict),
		"fingerprint":                llx.StringData(instance.Fingerprint),
		"hostname":                   llx.StringData(instance.Hostname),
		"keyRevocationActionType":    llx.StringData(instance.KeyRevocationActionType),
		"labels":                     llx.MapData(convert.MapToInterfaceMap(instance.Labels), types.String),
		"lastStartTimestamp":         llx.TimeDataPtr(parseTime(instance.LastStartTimestamp)),
		"lastStopTimestamp":          llx.TimeDataPtr(parseTime(instance.LastStopTimestamp)),
		"lastSuspendedTimestamp":     llx.TimeDataPtr(parseTime(instance.LastSuspendedTimestamp)),
		"metadata":                   llx.MapData(convert.MapToInterfaceMap(metadata), types.String),
		"minCpuPlatform":             llx.StringData(instance.MinCpuPlatform),
		"networkInterfaces":          llx.ArrayData(networkInterfaces, types.Dict),
		"privateIpv6GoogleAccess":    llx.StringData(instance.PrivateIpv6GoogleAccess),
		"reservationAffinity":        llx.DictData(reservationAffinity),
		"resourcePolicies":           llx.ArrayData(convert.SliceAnyToInterface(instance.ResourcePolicies), types.String),
		"physicalHostResourceStatus": llx.StringData(physicalHost),
		"scheduling":                 llx.DictData(scheduling),
		"shieldedInstanceConfig":     llx.ResourceData(mqlShieldedInstanceConfig, "gcp.project.computeService.instance.shieldedInstanceConfig"),
		"enableIntegrityMonitoring":  llx.BoolData(enableIntegrityMonitoring),
		"enableSecureBoot":           llx.BoolData(enableSecureBoot),
		"enableVtpm":                 llx.BoolData(enableVtpm),
		"startRestricted":            llx.BoolData(instance.StartRestricted),
		"status":                     llx.StringData(instance.Status),
		"statusMessage":              llx.StringData(instance.StatusMessage),
		"sourceMachineImage":         llx.StringData(instance.SourceMachineImage),
		"tags":                       llx.ArrayData(convert.SliceAnyToInterface(tagsItems), types.String),
		"totalEgressBandwidthTier":   llx.StringData(totalEgressBandwidthTier),
		"serviceAccounts":            llx.ArrayData(mqlServiceAccounts, types.Resource("gcp.project.computeService.serviceaccount")),
		"disks":                      llx.ArrayData(attachedDisks, types.Resource("gcp.project.computeService.attachedDisk")),
		"zone":                       llx.ResourceData(zone, "gcp.project.computeService.zone"),
		"satisfiesPzi":               llx.BoolData(instance.SatisfiesPzi),
		"satisfiesPzs":               llx.BoolData(instance.SatisfiesPzs),
	})
	if err != nil {
		return nil, err
	}
	mqlR := entry.(*mqlGcpProjectComputeServiceInstance)
	mqlR.instanceMachineType = instance.MachineType
	return mqlR, nil
}

func (g *mqlGcpProjectComputeService) instances() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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

	var wg sync.WaitGroup
	res := []any{}
	wg.Add(len(zones.Data))
	mux := &sync.Mutex{}

	for i := range zones.Data {
		z := zones.Data[i].(*mqlGcpProjectComputeServiceZone)
		zoneName := z.GetName()
		if zoneName.Error != nil {
			return nil, zoneName.Error
		}
		go func(svc *compute.Service, project string, zone *mqlGcpProjectComputeServiceZone, zoneName string) {
			req := computeSvc.Instances.List(projectId, zoneName)
			if err := req.Pages(ctx, func(page *compute.InstanceList) error {
				for _, instance := range page.Items {

					mqlInstance, err := newMqlComputeServiceInstance(projectId, zone, g.MqlRuntime, instance)
					if err != nil {
						return err
					} else {
						mux.Lock()
						res = append(res, mqlInstance)
						mux.Unlock()
					}
				}
				return nil
			}); err != nil {
				log.Error().Err(err).Send()
			}
			wg.Done()
		}(computeSvc, projectId, z, zoneName.Data)
	}

	wg.Wait()
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

type mqlGcpProjectComputeServiceDiskInternal struct {
	cacheSourceImageUrl    string
	cacheSourceSnapshotUrl string
	cacheStoragePoolUrl    string
}

func (g *mqlGcpProjectComputeServiceDisk) zone() (any, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
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
		"name":      llx.StringData(parts[4]),
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
	if len(parts) < 5 {
		return nil, errors.New("invalid source snapshot URL: " + url)
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.computeService.snapshot", map[string]*llx.RawData{
		"name": llx.StringData(parts[4]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceSnapshot), nil
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
	if len(parts) < 6 {
		return nil, errors.New("invalid storage pool URL: " + url)
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.computeService.storagePool", map[string]*llx.RawData{
		"name": llx.StringData(parts[5]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceStoragePool), nil
}

func (g *mqlGcpProjectComputeService) disks() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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

	var wg sync.WaitGroup
	res := []any{}
	wg.Add(len(zones.Data))
	mux := &sync.Mutex{}

	var result error
	for i := range zones.Data {
		z := zones.Data[i].(*mqlGcpProjectComputeServiceZone)
		zoneName := z.GetName()
		if zoneName.Error != nil {
			return nil, zoneName.Error
		}

		go func(svc *compute.Service, project string, zone *mqlGcpProjectComputeServiceZone, zoneName string) {
			req := computeSvc.Disks.List(projectId, zoneName)
			if err := req.Pages(ctx, func(page *compute.DiskList) error {
				for _, disk := range page.Items {
					guestOsFeatures := []string{}
					for i := range disk.GuestOsFeatures {
						entry := disk.GuestOsFeatures[i]
						guestOsFeatures = append(guestOsFeatures, entry.Type)
					}

					var mqlDiskEnc map[string]any
					if disk.DiskEncryptionKey != nil {
						mqlDiskEnc = map[string]any{
							"kmsKeyName":           disk.DiskEncryptionKey.KmsKeyName,
							"kmsKeyServiceAccount": disk.DiskEncryptionKey.KmsKeyServiceAccount,
							"rawKey":               disk.DiskEncryptionKey.RawKey,
							"rsaEncryptedKey":      disk.DiskEncryptionKey.RsaEncryptedKey,
							"sha256":               disk.DiskEncryptionKey.Sha256,
						}
					}

					mqlDisk, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.disk", map[string]*llx.RawData{
						"id":                        llx.StringData(strconv.FormatUint(disk.Id, 10)),
						"name":                      llx.StringData(disk.Name),
						"architecture":              llx.StringData(disk.Architecture),
						"description":               llx.StringData(disk.Description),
						"guestOsFeatures":           llx.ArrayData(convert.SliceAnyToInterface(guestOsFeatures), types.String),
						"labels":                    llx.MapData(convert.MapToInterfaceMap(disk.Labels), types.String),
						"lastAttachTimestamp":       llx.TimeDataPtr(parseTime(disk.LastAttachTimestamp)),
						"lastDetachTimestamp":       llx.TimeDataPtr(parseTime(disk.LastDetachTimestamp)),
						"locationHint":              llx.StringData(disk.LocationHint),
						"licenses":                  llx.ArrayData(convert.SliceAnyToInterface(disk.Licenses), types.String),
						"physicalBlockSizeBytes":    llx.IntData(disk.PhysicalBlockSizeBytes),
						"provisionedIops":           llx.IntData(disk.ProvisionedIops),
						"region":                    llx.StringData(RegionNameFromRegionUrl(disk.Region)),
						"replicaZones":              llx.ArrayData(convert.SliceAnyToInterface(disk.ReplicaZones), types.String),
						"resourcePolicies":          llx.ArrayData(convert.SliceAnyToInterface(disk.ResourcePolicies), types.String),
						"satisfiesPzi":              llx.BoolData(disk.SatisfiesPzi),
						"satisfiesPzs":              llx.BoolData(disk.SatisfiesPzs),
						"sourceDiskId":              llx.StringData(disk.SourceDiskId),
						"sizeGb":                    llx.IntData(disk.SizeGb),
						"status":                    llx.StringData(disk.Status),
						"zone":                      llx.ResourceData(zone, "gcp.project.computeService.zone"),
						"created":                   llx.TimeDataPtr(parseTime(disk.CreationTimestamp)),
						"diskEncryptionKey":         llx.DictData(mqlDiskEnc),
						"enableConfidentialCompute": llx.BoolData(disk.EnableConfidentialCompute),
						"type":                      llx.StringData(disk.Type),
						"users":                     llx.ArrayData(convert.SliceAnyToInterface(disk.Users), types.String),
						"accessMode":                llx.StringData(disk.AccessMode),
						"provisionedThroughput":     llx.IntData(disk.ProvisionedThroughput),
					})
					if err != nil {
						return err
					}
					mqlD := mqlDisk.(*mqlGcpProjectComputeServiceDisk)
					mqlD.cacheSourceImageUrl = disk.SourceImage
					mqlD.cacheSourceSnapshotUrl = disk.SourceSnapshot
					mqlD.cacheStoragePoolUrl = disk.StoragePool
					mux.Lock()
					res = append(res, mqlDisk)
					mux.Unlock()
				}
				return nil
			}); err != nil {
				log.Error().Err(err).Send()
			}
			wg.Done()
		}(computeSvc, projectId, z, zoneName.Data)
	}

	wg.Wait()
	return res, result
}

func (g *mqlGcpProjectComputeServiceFirewall) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.firewall/" + id, nil
}

func (g *mqlGcpProjectComputeServiceFirewall) network() (any, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
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

	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(args["projectId"].Value.(string)),
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	firewalls := computeSvc.GetFirewalls()
	if firewalls.Error != nil {
		return nil, nil, firewalls.Error
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
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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
				"targetTags":            llx.ArrayData(convert.SliceAnyToInterface(firewall.TargetTags), types.String),
				"loggingEnabled":        llx.BoolData(firewall.LogConfig != nil && firewall.LogConfig.Enable),
				"network":               llx.StringData(firewall.Network),
			})
			if err != nil {
				return err
			} else {
				res = append(res, mqlFirewall)
			}
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

func (g *mqlGcpProjectComputeServiceSnapshot) sourceDisk() (any, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (g *mqlGcpProjectComputeService) snapshots() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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
			mqlSnapshpt, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.snapshot", map[string]*llx.RawData{
				"id":                             llx.StringData(strconv.FormatUint(snapshot.Id, 10)),
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
				"sourceDiskId":                   llx.StringData(snapshot.SourceDiskId),
				"sourceSnapshotSchedulePolicy":   llx.StringData(snapshot.SourceSnapshotSchedulePolicy),
				"sourceSnapshotSchedulePolicyId": llx.StringData(snapshot.SourceSnapshotSchedulePolicyId),
			})
			if err != nil {
				return err
			}

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

	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(args["projectId"].Value.(string)),
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	images := computeSvc.GetImages()
	if images.Error != nil {
		return nil, nil, images.Error
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

func (g *mqlGcpProjectComputeServiceImage) sourceDisk() (any, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func (g *mqlGcpProjectComputeService) images() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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
			mqlImage, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.image", map[string]*llx.RawData{
				"id":                        llx.StringData(strconv.FormatUint(image.Id, 10)),
				"projectId":                 llx.StringData(projectId),
				"name":                      llx.StringData(image.Name),
				"description":               llx.StringData(image.Description),
				"architecture":              llx.StringData(image.Architecture),
				"archiveSizeBytes":          llx.IntData(image.ArchiveSizeBytes),
				"diskSizeGb":                llx.IntData(image.DiskSizeGb),
				"family":                    llx.StringData(image.Family),
				"licenses":                  llx.ArrayData(convert.SliceAnyToInterface(image.Licenses), types.String),
				"labels":                    llx.MapData(convert.MapToInterfaceMap(image.Labels), types.String),
				"status":                    llx.StringData(image.Status),
				"created":                   llx.TimeDataPtr(parseTime(image.CreationTimestamp)),
				"enableConfidentialCompute": llx.BoolData(image.EnableConfidentialCompute),
				"satisfiesPzi":              llx.BoolData(image.SatisfiesPzi),
				"satisfiesPzs":              llx.BoolData(image.SatisfiesPzs),
				"storageLocations":          llx.ArrayData(convert.SliceAnyToInterface(image.StorageLocations), types.String),
				"sourceDisk":                llx.StringData(image.SourceDisk),
				"sourceDiskId":              llx.StringData(image.SourceDiskId),
				"sourceImage":               llx.StringData(image.SourceImage),
				"sourceImageId":             llx.StringData(image.SourceImageId),
				"sourceSnapshot":            llx.StringData(image.SourceSnapshot),
				"sourceSnapshotId":          llx.StringData(image.SourceSnapshotId),
			})
			if err != nil {
				return err
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
}

func (g *mqlGcpProjectComputeServiceNetwork) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "gcloud.compute.network/" + id, nil
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
	for i, p := range g.cachePeerings {
		mqlPeering, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.network.peering", map[string]*llx.RawData{
			"id":                             llx.StringData(fmt.Sprintf("gcloud.compute.network/%s/peering/%d", networkId, i)),
			"name":                           llx.StringData(p.Name),
			"networkUrl":                     llx.StringData(p.Network),
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
		res = append(res, mqlPeering)
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceNetworkPeering) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceNetworkPeering) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.NetworkUrl.Error != nil {
		return nil, g.NetworkUrl.Error
	}
	url := g.NetworkUrl.Data
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
	type resourceId struct {
		Project string
		Region  string
		Name    string
	}
	subnets := make([]any, 0, len(subnetUrls))
	for _, subnetUrl := range subnetUrls {
		// Format is https://www.googleapis.com/compute/v1/projects/project1regions/us-central1/subnetworks/subnet-1
		params := strings.TrimPrefix(subnetUrl.(string), "https://www.googleapis.com/compute/v1/")
		parts := strings.Split(params, "/")
		resId := resourceId{Project: parts[1], Region: parts[3], Name: parts[5]}
		regionUrl := strings.SplitN(subnetUrl.(string), "/subnetworks", 2)

		subnet, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.subnetwork", map[string]*llx.RawData{
			"name":      llx.StringData(resId.Name),
			"projectId": llx.StringData(resId.Project),
			"regionUrl": llx.StringData(regionUrl[0]),
		})
		if err != nil {
			return nil, err
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
	networkName := args["name"].Value.(string)
	projectId := args["projectId"].Value.(string)

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

	peerings, err := convert.JsonToDictSlice(network.Peerings)
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
		"peerings":                              llx.ArrayData(peerings, types.Dict),
		"routingMode":                           llx.StringData(routingMode),
		"mode":                                  llx.StringData(networkMode(network)),
		"subnetworkUrls":                        llx.ArrayData(convert.SliceAnyToInterface(network.Subnetworks), types.String),
	})
	if err != nil {
		return nil, nil, err
	}
	return args, mqlNetwork.(*mqlGcpProjectComputeServiceNetwork), nil
}

func (g *mqlGcpProjectComputeService) networks() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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
			peerings, err := convert.JsonToDictSlice(network.Peerings)
			if err != nil {
				return err
			}

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
				"peerings":                              llx.ArrayData(peerings, types.Dict),
				"internalIpv6Range":                     llx.StringData(network.InternalIpv6Range),
				"firewallPolicy":                        llx.StringData(network.FirewallPolicy),
			})
			if err != nil {
				return err
			}
			mqlNet := mqlNetwork.(*mqlGcpProjectComputeServiceNetwork)
			mqlNet.cachePeerings = network.Peerings
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
			region = RegionNameFromRegionUrl(args["regionUrl"].Value.(string))
		}
	}

	// Try to find the subnetwork in the MQL cache first
	obj, err := NewResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(args["projectId"].Value.(string)),
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	subnetworks := computeSvc.GetSubnetworks()
	if subnetworks.Error != nil {
		return nil, nil, subnetworks.Error
	}

	for _, n := range subnetworks.Data {
		subnetwork := n.(*mqlGcpProjectComputeServiceSubnetwork)
		name := subnetwork.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		regionUrl := subnetwork.GetRegionUrl()
		if regionUrl.Error != nil {
			return nil, nil, regionUrl.Error
		}
		subnetRegion := RegionNameFromRegionUrl(regionUrl.Data)
		projectId := subnetwork.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if name.Data == args["name"].Value && projectId.Data == args["projectId"].Value && subnetRegion == region {
			return args, subnetwork, nil
		}
	}

	// Fallback: fetch directly from the GCP API
	subnetworkName := args["name"].Value.(string)
	projectId := args["projectId"].Value.(string)

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

	regionUrl := g.GetRegionUrl()
	if regionUrl.Error != nil {
		return nil, regionUrl.Error
	}

	regionName := RegionNameFromRegionUrl(regionUrl.Data)

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

func (g *mqlGcpProjectComputeServiceSubnetwork) network() ([]any, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
}

func newMqlRegion(runtime *plugin.Runtime, r *compute.Region) (any, error) {
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

	args := map[string]*llx.RawData{
		"id":                      llx.StringData(subnetId),
		"projectId":               llx.StringData(projectId),
		"name":                    llx.StringData(subnetwork.GetName()),
		"description":             llx.StringData(subnetwork.GetDescription()),
		"enableFlowLogs":          llx.BoolData(subnetwork.GetEnableFlowLogs()),
		"externalIpv6Prefix":      llx.StringData(subnetwork.GetExternalIpv6Prefix()),
		"fingerprint":             llx.StringData(subnetwork.GetFingerprint()),
		"gatewayAddress":          llx.StringData(subnetwork.GetGatewayAddress()),
		"internalIpv6Prefix":      llx.StringData(subnetwork.GetInternalIpv6Prefix()),
		"ipCidrRange":             llx.StringData(subnetwork.GetIpCidrRange()),
		"ipv6AccessType":          llx.StringData(subnetwork.GetIpv6AccessType()),
		"ipv6CidrRange":           llx.StringData(subnetwork.GetIpv6CidrRange()),
		"logConfig":               llx.ResourceData(mqlLogConfig, "gcp.project.computeService.subnetwork.logConfig"),
		"privateIpGoogleAccess":   llx.BoolData(subnetwork.GetPrivateIpGoogleAccess()),
		"privateIpv6GoogleAccess": llx.StringData(subnetwork.GetPrivateIpv6GoogleAccess()),
		"purpose":                 llx.StringData(subnetwork.GetPurpose()),
		"regionUrl":               llx.StringData(subnetwork.GetRegion()),
		"role":                    llx.StringData(subnetwork.GetRole()),
		"stackType":               llx.StringData(subnetwork.GetStackType()),
		"state":                   llx.StringData(subnetwork.GetState()),
		"created":                 llx.TimeDataPtr(parseTime(subnetwork.GetCreationTimestamp())),
		"reservedInternalRange":   llx.StringData(subnetwork.GetReservedInternalRange()),
	}
	if region != nil {
		args["region"] = llx.ResourceData(region, "gcp.project.computeService.region")
	}
	return CreateResource(runtime, "gcp.project.computeService.subnetwork", args)
}

func (g *mqlGcpProjectComputeService) subnetworks() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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

func (g *mqlGcpProjectComputeServiceRouter) region() ([]any, error) {
	// TODO: implement
	return nil, errors.New("not implemented")
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

	nats, err := convert.JsonToDictSlice(router.Nats)
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
		"nats":                        llx.ArrayData(nats, types.Dict),
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
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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

	var wg sync.WaitGroup
	res := []any{}
	wg.Add(len(regions.Data))
	mux := &sync.Mutex{}

	for i := range regions.Data {
		r := regions.Data[i].(*mqlGcpProjectComputeServiceRegion)
		regionName := r.GetName()
		if err != nil {
			return nil, err
		}
		go func(svc *compute.Service, project string, region *mqlGcpProjectComputeServiceRegion, regionName string) {
			req := computeSvc.Routers.List(projectId, regionName)
			if err := req.Pages(ctx, func(page *compute.RouterList) error {
				for _, router := range page.Items {

					mqlRouter, err := newMqlRouter(projectId, region, g.MqlRuntime, router)
					if err != nil {
						return err
					} else {
						mux.Lock()
						res = append(res, mqlRouter)
						mux.Unlock()
					}
				}
				return nil
			}); err != nil {
				log.Error().Err(err).Send()
			}
			wg.Done()
		}(computeSvc, projectId, r, regionName.Data)
	}

	wg.Wait()
	return res, nil
}

func (g *mqlGcpProjectComputeService) backendServices() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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

	list, err := computeSvc.BackendServices.AggregatedList(projectId).Do()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(list.Items))
	for _, sb := range list.Items {
		for _, b := range sb.BackendServices {
			backendServiceId := strconv.FormatUint(b.Id, 10)
			mqlBackends := make([]any, 0, len(b.Backends))
			for i, backend := range b.Backends {
				mqlBackend, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.backendService.backend", map[string]*llx.RawData{
					"id":                        llx.StringData(fmt.Sprintf("gcp.project.computeService.backendService.backend/%s/%d", backendServiceId, i)),
					"balancingMode":             llx.StringData(backend.BalancingMode),
					"capacityScaler":            llx.FloatData(backend.CapacityScaler),
					"description":               llx.StringData(backend.Description),
					"failover":                  llx.BoolData(backend.Failover),
					"groupUrl":                  llx.StringData(backend.Group),
					"maxConnections":            llx.IntData(backend.MaxConnections),
					"maxConnectionsPerEndpoint": llx.IntData(backend.MaxConnectionsPerEndpoint),
					"maxConnectionsPerInstance": llx.IntData(backend.MaxConnectionsPerInstance),
					"maxRate":                   llx.IntData(backend.MaxRate),
					"maxRatePerEndpoint":        llx.FloatData(backend.MaxRatePerEndpoint),
					"maxRatePerInstance":        llx.FloatData(backend.MaxRatePerInstance),
					"maxUtilization":            llx.FloatData(backend.MaxUtilization),
				})
				if err != nil {
					return nil, err
				}
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
					return nil, err
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
						cookieMap["ttl"] = llx.TimeData(llx.DurationToTime(b.ConsistentHash.HttpCookie.Ttl.Seconds))
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
				mqlIap = map[string]any{
					"serviceEnabled":           b.Iap.Enabled,
					"oauth2ClientId":           b.Iap.Oauth2ClientId,
					"oauth2ClientSecret":       b.Iap.Oauth2ClientSecret,
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
			if b.SecuritySettings != nil {
				mqlSecuritySettings = map[string]any{
					"clientTlsPolicy": b.SecuritySettings.ClientTlsPolicy,
					"subjectAltNames": convert.SliceAnyToInterface(b.SecuritySettings.SubjectAltNames),
				}
			}

			var maxStreamDuration *time.Time
			if b.MaxStreamDuration != nil {
				v := llx.DurationToTime(b.MaxStreamDuration.Seconds)
				maxStreamDuration = &v
			}

			mqlB, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.backendService", map[string]*llx.RawData{
				"id":                       llx.StringData(backendServiceId),
				"affinityCookieTtlSec":     llx.IntData(b.AffinityCookieTtlSec),
				"backends":                 llx.ArrayData(mqlBackends, types.Resource("gcp.project.computeService.backendService.backend")),
				"cdnPolicy":                llx.ResourceData(cdnPolicy, " gcp.project.computeService.backendService.cdnPolicy"),
				"circuitBreakers":          llx.DictData(mqlCircuitBreakers),
				"compressionMode":          llx.StringData(b.CompressionMode),
				"connectionDraining":       llx.DictData(mqlConnectionDraining),
				"connectionTrackingPolicy": llx.DictData(mqlConnectionTrackingPolicy),
				"consistentHash":           llx.DictData(mqlConsistentHash),
				"created":                  llx.TimeDataPtr(parseTime(b.CreationTimestamp)),
				"customRequestHeaders":     llx.ArrayData(convert.SliceAnyToInterface(b.CustomRequestHeaders), types.String),
				"customResponseHeaders":    llx.ArrayData(convert.SliceAnyToInterface(b.CustomResponseHeaders), types.String),
				"description":              llx.StringData(b.Description),
				"edgeSecurityPolicy":       llx.StringData(b.EdgeSecurityPolicy),
				"enableCDN":                llx.BoolData(b.EnableCDN),
				"failoverPolicy":           llx.DictData(mqlFailoverPolicy),
				"healthChecks":             llx.ArrayData(convert.SliceAnyToInterface(b.HealthChecks), types.String),
				"iap":                      llx.DictData(mqlIap),
				"loadBalancingScheme":      llx.StringData(b.LoadBalancingScheme),
				"localityLbPolicies":       llx.ArrayData(mqlLocalityLbPolicy, types.Dict),
				"localityLbPolicy":         llx.StringData(b.LocalityLbPolicy),
				"logConfig":                llx.DictData(mqlLogConfig),
				"maxStreamDuration":        llx.TimeDataPtr(maxStreamDuration),
				"name":                     llx.StringData(b.Name),
				"networkUrl":               llx.StringData(b.Network),
				"portName":                 llx.StringData(b.PortName),
				"protocol":                 llx.StringData(b.Protocol),
				"regionUrl":                llx.StringData(b.Region),
				"securityPolicyUrl":        llx.StringData(b.SecurityPolicy),
				"securitySettings":         llx.DictData(mqlSecuritySettings),
				"serviceBindingUrls":       llx.ArrayData(convert.SliceAnyToInterface(b.ServiceBindings), types.String),
				"sessionAffinity":          llx.StringData(b.SessionAffinity),
				"timeoutSec":               llx.IntData(b.TimeoutSec),
				"port":                     llx.IntData(b.Port),
				"serviceLbPolicy":          llx.StringData(b.ServiceLbPolicy),
				"ipAddressSelectionPolicy": llx.StringData(b.IpAddressSelectionPolicy),
				"fingerprint":              llx.StringData(b.Fingerprint),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlB)
		}
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
	// when the service is not enabled, we return nil
	if !g.GetEnabled().Data {
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

	list, err := computeSvc.Addresses.AggregatedList(projectId).Do()
	if err != nil {
		return nil, err
	}
	var mqlAddresses []any
	for _, as := range list.Items {
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
				"networkUrl":       llx.StringData(a.Network),
				"networkTier":      llx.StringData(a.NetworkTier),
				"prefixLength":     llx.IntData(a.PrefixLength),
				"purpose":          llx.StringData(a.Purpose),
				"regionUrl":        llx.StringData(a.Region),
				"status":           llx.StringData(a.Status),
				"subnetworkUrl":    llx.StringData(a.Subnetwork),
				"resourceUrls":     llx.ArrayData(convert.SliceAnyToInterface(a.Users), types.String),
			})
			if err != nil {
				return nil, err
			}
			mqlAddresses = append(mqlAddresses, mqlA)
		}
	}
	return mqlAddresses, nil
}

func (g *mqlGcpProjectComputeServiceAddress) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.NetworkUrl.Error != nil {
		return nil, g.NetworkUrl.Error
	}
	networkUrl := g.NetworkUrl.Data
	return getNetworkByUrl(networkUrl, g.MqlRuntime)
}

func (g *mqlGcpProjectComputeServiceAddress) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	if g.SubnetworkUrl.Error != nil {
		return nil, g.SubnetworkUrl.Error
	}
	subnetUrl := g.SubnetworkUrl.Data
	return getSubnetworkByUrl(subnetUrl, g.MqlRuntime)
}

func (g *mqlGcpProjectComputeServiceAddress) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) forwardingRules() ([]any, error) {
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
				"backendService":                llx.StringData(fwr.GetBackendService()),
				"created":                       llx.TimeDataPtr(parseTime(fwr.GetCreationTimestamp())),
				"description":                   llx.StringData(fwr.GetDescription()),
				"ipVersion":                     llx.StringData(fwr.GetIpVersion()),
				"isMirroringCollector":          llx.BoolData(fwr.GetIsMirroringCollector()),
				"labels":                        llx.MapData(convert.MapToInterfaceMap(fwr.GetLabels()), types.String),
				"loadBalancingScheme":           llx.StringData(fwr.GetLoadBalancingScheme()),
				"metadataFilters":               llx.ArrayData(metadataFilters, types.Dict),
				"name":                          llx.StringData(fwr.GetName()),
				"networkUrl":                    llx.StringData(fwr.GetNetwork()),
				"networkTier":                   llx.StringData(fwr.GetNetworkTier()),
				"noAutomateDnsZone":             llx.BoolData(fwr.GetNoAutomateDnsZone()),
				"portRange":                     llx.StringData(fwr.GetPortRange()),
				"ports":                         llx.ArrayData(convert.SliceAnyToInterface(fwr.GetPorts()), types.String),
				"regionUrl":                     llx.StringData(fwr.GetRegion()),
				"serviceDirectoryRegistrations": llx.ArrayData(serviceDirRegs, types.Dict),
				"serviceLabel":                  llx.StringData(fwr.GetServiceLabel()),
				"serviceName":                   llx.StringData(fwr.GetServiceName()),
				"subnetworkUrl":                 llx.StringData(fwr.GetSubnetwork()),
				"targetUrl":                     llx.StringData(fwr.GetTarget()),
				"allowPscGlobalAccess":          llx.BoolData(fwr.GetAllowPscGlobalAccess()),
				"pscConnectionStatus":           llx.StringData(fwr.GetPscConnectionStatus()),
				"sourceIpRanges":                llx.ArrayData(convert.SliceAnyToInterface(fwr.GetSourceIpRanges()), types.String),
				"fingerprint":                   llx.StringData(fwr.GetFingerprint()),
				"ipCollection":                  llx.StringData(fwr.GetIpCollection()),
			})
			if err != nil {
				return nil, err
			}
			fwRules = append(fwRules, mqlFwr)
		}
	}
	return fwRules, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceForwardingRule) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.NetworkUrl.Error != nil {
		return nil, g.NetworkUrl.Error
	}
	networkUrl := g.NetworkUrl.Data
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
	if g.SubnetworkUrl.Error != nil {
		return nil, g.SubnetworkUrl.Error
	}
	subnetUrl := g.SubnetworkUrl.Data
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

func (g *mqlGcpProjectComputeServiceSecurityPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceSecurityPolicyRule) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) securityPolicies() ([]any, error) {
	if !g.GetEnabled().Data {
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
				mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.securityPolicy", map[string]*llx.RawData{
					"id":                       llx.StringData(policyId),
					"name":                     llx.StringData(policy.Name),
					"description":              llx.StringData(policy.Description),
					"type":                     llx.StringData(policy.Type),
					"labels":                   llx.MapData(convert.MapToInterfaceMap(policy.Labels), types.String),
					"adaptiveProtectionConfig": llx.DictData(adaptiveProtectionConfig),
					"advancedOptionsConfig":    llx.DictData(advancedOptionsConfig),
					"ddosProtectionConfig":     llx.DictData(ddosProtectionConfig),
					"recaptchaOptionsConfig":   llx.DictData(recaptchaOptionsConfig),
					"fingerprint":              llx.StringData(policy.Fingerprint),
					"userDefinedFields":        llx.ArrayData(userDefinedFields, types.Dict),
					"regionUrl":                llx.StringData(policy.Region),
					"selfLink":                 llx.StringData(policy.SelfLink),
					"createdAt":                llx.TimeDataPtr(parseTime(policy.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
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

	// We need the project ID from the connection since the policy doesn't store it
	projectId := conn.ResourceID()

	policy, err := computeSvc.SecurityPolicies.Get(projectId, policyName).Context(ctx).Do()
	if err != nil {
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

		mqlRule, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.securityPolicy.rule", map[string]*llx.RawData{
			"id":                     llx.StringData(fmt.Sprintf("gcp.project.computeService.securityPolicy.rule/%s/%d", policyId, rule.Priority)),
			"action":                 llx.StringData(rule.Action),
			"description":            llx.StringData(rule.Description),
			"priority":               llx.IntData(rule.Priority),
			"preview":                llx.BoolData(rule.Preview),
			"match":                  llx.DictData(matchDict),
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

func (g *mqlGcpProjectComputeServiceSslPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) sslPolicies() ([]any, error) {
	if !g.GetEnabled().Data {
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
					"regionUrl":       llx.StringData(policy.Region),
					"selfLink":        llx.StringData(policy.SelfLink),
					"warnings":        llx.ArrayData(warnings, types.Dict),
					"createdAt":       llx.TimeDataPtr(parseTime(policy.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
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

func (g *mqlGcpProjectComputeService) sslCertificates() ([]any, error) {
	if !g.GetEnabled().Data {
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

				mqlCert, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.sslCertificate", map[string]*llx.RawData{
					"id":                      llx.StringData(strconv.FormatUint(cert.Id, 10)),
					"name":                    llx.StringData(cert.Name),
					"description":             llx.StringData(cert.Description),
					"type":                    llx.StringData(cert.Type),
					"subjectAlternativeNames": llx.ArrayData(convert.SliceAnyToInterface(cert.SubjectAlternativeNames), types.String),
					"managed":                 llx.DictData(managed),
					"regionUrl":               llx.StringData(cert.Region),
					"selfLink":                llx.StringData(cert.SelfLink),
					"expireTime":              llx.StringData(cert.ExpireTime),
					"createdAt":               llx.TimeDataPtr(parseTime(cert.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
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
}

func (g *mqlGcpProjectComputeServiceVpnGateway) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.cacheNetworkUrl == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return getNetworkByUrl(g.cacheNetworkUrl, g.MqlRuntime)
}

func (g *mqlGcpProjectComputeService) vpnGateways() ([]any, error) {
	if !g.GetEnabled().Data {
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

				mqlGw, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.vpnGateway", map[string]*llx.RawData{
					"id":               llx.StringData(fmt.Sprintf("%d", gw.Id)),
					"name":             llx.StringData(gw.Name),
					"description":      llx.StringData(gw.Description),
					"created":          llx.TimeDataPtr(parseTime(gw.CreationTimestamp)),
					"labels":           llx.MapData(convert.MapToInterfaceMap(gw.Labels), types.String),
					"gatewayIpVersion": llx.StringData(gw.GatewayIpVersion),
					"stackType":        llx.StringData(gw.StackType),
					"regionUrl":        llx.StringData(gw.Region),
					"vpnInterfaces":    llx.ArrayData(vpnInterfaces, types.Dict),
				})
				if err != nil {
					return err
				}
				mqlGw.(*mqlGcpProjectComputeServiceVpnGateway).cacheNetworkUrl = gw.Network
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
	if !g.GetEnabled().Data {
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
					"peerExternalGateway":          llx.StringData(t.PeerExternalGateway),
					"peerExternalGatewayInterface": llx.IntData(t.PeerExternalGatewayInterface),
					"peerGcpGateway":               llx.StringData(t.PeerGcpGateway),
					"peerIp":                       llx.StringData(t.PeerIp),
					"regionUrl":                    llx.StringData(t.Region),
					"routerUrl":                    llx.StringData(t.Router),
					"sharedSecretHash":             llx.StringData(t.SharedSecretHash),
					"status":                       llx.StringData(t.Status),
					"targetVpnGateway":             llx.StringData(t.TargetVpnGateway),
					"vpnGatewayUrl":                llx.StringData(t.VpnGateway),
					"vpnGatewayInterface":          llx.IntData(int64(t.VpnGatewayInterface)),
				})
				if err != nil {
					return err
				}
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

func (g *mqlGcpProjectComputeService) storagePools() ([]any, error) {
	if !g.GetEnabled().Data {
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
