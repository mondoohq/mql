// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (e *mqlOciCompute) id() (string, error) {
	return "oci.compute", nil
}

func (o *mqlOciCompute) instances() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// The lister receives the region as a key, so index the oci.regions
	// collection to let it set a typed region field on each instance.
	regions, err := ociRegionsFor(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	regionsByID, err := ociRegionsByID(regions)
	if err != nil {
		return nil, err
	}

	// Compute instances are the resource most often placed in a per-team or
	// per-environment compartment, and ListInstances only ever answers for the
	// one compartment it is handed. Restricting the scan to the tenancy root
	// meant a fleet of hundreds of hosts reported as zero instances, taking
	// every patch, agent, and IMDS check down with it.
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			// Guarded rather than indexed blindly: a miss would put a typed nil
			// into the region field, and a nil *mqlOciRegion inside an interface
			// is not the untyped nil the runtime treats as absent, so it panics
			// on read instead of reporting null. The pool iterates the same
			// regions this index was built from, so a miss means the two have
			// drifted and is worth saying out loud.
			regionResource, ok := regionsByID[region]
			if !ok {
				return nil, errors.New("no oci.region resource for region " + region)
			}

			svc, err := conn.ComputeClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			instances, err := o.getComputeInstancesForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range instances {
				instance := instances[i]

				var created *time.Time
				if instance.TimeCreated != nil {
					created = &instance.TimeCreated.Time
				}

				metadata := make(map[string]interface{}, len(instance.Metadata))
				for k, v := range instance.Metadata {
					metadata[k] = v
				}

				platformConfig, err := convert.JsonToDict(instance.PlatformConfig)
				if err != nil {
					return nil, err
				}

				launchOptions, err := convert.JsonToDict(instance.LaunchOptions)
				if err != nil {
					return nil, err
				}

				instanceOptions, err := convert.JsonToDict(instance.InstanceOptions)
				if err != nil {
					return nil, err
				}

				shapeConfig, err := convert.JsonToDict(instance.ShapeConfig)
				if err != nil {
					return nil, err
				}

				sourceDetails, err := convert.JsonToDict(instance.SourceDetails)
				if err != nil {
					return nil, err
				}

				// Nested values, so it cannot ride metadata's map[string]string.
				// Left null rather than emptied when the instance carries none,
				// so "no extended metadata" and "an empty object" stay apart.
				extendedMetadata, err := convert.JsonToDict(instance.ExtendedMetadata)
				if err != nil {
					return nil, err
				}

				var timeMaintenanceRebootDue *time.Time
				if instance.TimeMaintenanceRebootDue != nil {
					timeMaintenanceRebootDue = &instance.TimeMaintenanceRebootDue.Time
				}

				// OCI omits instanceOptions entirely on instances launched
				// before IMDSv2 existed - exactly the instances where the
				// legacy /v1 endpoints ARE reachable. Leaving this null would
				// let `all(legacyImdsEndpointsDisabled && ...)` pass on them,
				// because MQL evaluates `null && null` as true. Default to the
				// documented false so a miss fails.
				legacyImdsDisabled := false
				if instance.InstanceOptions != nil && instance.InstanceOptions.AreLegacyImdsEndpointsDisabled != nil {
					legacyImdsDisabled = *instance.InstanceOptions.AreLegacyImdsEndpointsDisabled
				}

				// Same reasoning: an absent agentConfig means the agent
				// controls are not disabled, which is false, not unknown.
				monitoringDisabled, managementDisabled, allPluginsDisabled := false, false, false
				agentPlugins := map[string]any{}
				if instance.AgentConfig != nil {
					monitoringDisabled = boolValue(instance.AgentConfig.IsMonitoringDisabled)
					managementDisabled = boolValue(instance.AgentConfig.IsManagementDisabled)
					allPluginsDisabled = boolValue(instance.AgentConfig.AreAllPluginsDisabled)
					agentPlugins = make(map[string]any, len(instance.AgentConfig.PluginsConfig))
					for _, p := range instance.AgentConfig.PluginsConfig {
						agentPlugins[stringValue(p.Name)] = string(p.DesiredState)
					}
				}

				// Never a bare CreateResource from the id alone:
				// oci.compartment carries name/description/created/state, and
				// caching an id-only husk under the compartment's real OCID
				// hands that husk to a later oci.compartments query. The tree
				// the connection already holds carries those fields, so this
				// is populated without a per-instance GetCompartment call and
				// falls back to the direct read for an OCID it lacks.
				compartment, err := ociCompartmentResource(o.MqlRuntime, instance.CompartmentId)
				if err != nil {
					return nil, err
				}

				mqlInstance, err := CreateResource(o.MqlRuntime, "oci.compute.instance", map[string]*llx.RawData{
					"id":                          llx.StringDataPtr(instance.Id),
					"name":                        llx.StringDataPtr(instance.DisplayName),
					"region":                      llx.ResourceData(regionResource, "oci.region"),
					"created":                     llx.TimeDataPtr(created),
					"state":                       llx.StringData(string(instance.LifecycleState)),
					"shape":                       llx.StringDataPtr(instance.Shape),
					"availabilityDomain":          llx.StringDataPtr(instance.AvailabilityDomain),
					"compartment":                 llx.ResourceData(compartment, "oci.compartment"),
					"faultDomain":                 llx.StringDataPtr(instance.FaultDomain),
					"dedicatedVmHostId":           llx.StringDataPtr(instance.DedicatedVmHostId),
					"platformConfig":              llx.DictData(platformConfig),
					"launchOptions":               llx.DictData(launchOptions),
					"instanceOptions":             llx.DictData(instanceOptions),
					"legacyImdsEndpointsDisabled": llx.BoolData(legacyImdsDisabled),
					"monitoringDisabled":          llx.BoolData(monitoringDisabled),
					"managementDisabled":          llx.BoolData(managementDisabled),
					"allPluginsDisabled":          llx.BoolData(allPluginsDisabled),
					"agentPlugins":                llx.MapData(agentPlugins, types.String),
					"shapeConfig":                 llx.DictData(shapeConfig),
					"sourceDetails":               llx.DictData(sourceDetails),
					"metadata":                    llx.MapData(metadata, types.String),
					"extendedMetadata":            llx.DictData(extendedMetadata),
					"ipxeScript":                  llx.StringDataPtr(instance.IpxeScript),
					"timeMaintenanceRebootDue":    llx.TimeDataPtr(timeMaintenanceRebootDue),
					"securityAttributes":          llx.MapData(definedTagsToAny(instance.SecurityAttributes), types.Dict),
					"securityAttributesState":     llx.StringData(string(instance.SecurityAttributesState)),
					"freeformTags":                llx.MapData(strMapToAny(instance.FreeformTags), types.String),
					"definedTags":                 llx.MapData(definedTagsToAny(instance.DefinedTags), types.Any),
					"systemTags":                  llx.MapData(definedTagsToAny(instance.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlInst := mqlInstance.(*mqlOciComputeInstance)
				mqlInst.cacheRegion = region
				mqlInst.cacheImageID = stringValue(instance.ImageId)
				mqlInst.cacheCompartmentID = stringValue(instance.CompartmentId)
				mqlInst.cachePlatformConfig = instance.PlatformConfig
				mqlInst.cacheLaunchOptions = instance.LaunchOptions
				mqlInst.cacheShapeConfig = instance.ShapeConfig
				mqlInst.cacheBootVolumeID, mqlInst.cacheImageSource = ociInstanceSource(instance.SourceDetails)
				res = append(res, mqlInst)
			}

			return res, nil
		})
}

func (o *mqlOciCompute) getComputeInstancesForRegion(ctx context.Context, computeClient *core.ComputeClient, compartmentID string) ([]core.Instance, error) {
	instances, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.Instance, *string, error) {
		request := core.ListInstancesRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := computeClient.ListInstances(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return instances, nil
}

// ociShieldedInstanceFlags reads the shielded-instance and
// confidential-computing settings off an instance's platform configuration.
//
// core.PlatformConfig is an interface with a member per platform variant, but
// these four getters are declared on the interface itself, so a variant the
// pinned SDK does not know about still answers them and no type switch is
// needed. A shape that does not offer these features carries no platform
// configuration at all, and every flag stays nil so the schema reports null
// rather than reporting Secure Boot as disabled on a shape that cannot run it.
func ociShieldedInstanceFlags(pc core.PlatformConfig) (secureBoot, trustedPlatformModule, measuredBoot, memoryEncryption *bool) {
	if pc == nil {
		return nil, nil, nil, nil
	}
	return pc.GetIsSecureBootEnabled(),
		pc.GetIsTrustedPlatformModuleEnabled(),
		pc.GetIsMeasuredBootEnabled(),
		pc.GetIsMemoryEncryptionEnabled()
}

// ociInstanceSource splits an instance's source union into its two branches.
//
// The SDK unmarshals both branches as values rather than pointers, so the type
// switch has to name the value types. Naming the pointer types instead matches
// nothing, and an instance would report neither a boot volume nor an image
// source while still looking like it had been read.
func ociInstanceSource(src core.InstanceSourceDetails) (bootVolumeID string, image *core.InstanceSourceViaImageDetails) {
	switch s := src.(type) {
	case core.InstanceSourceViaBootVolumeDetails:
		return stringValue(s.BootVolumeId), nil
	case core.InstanceSourceViaImageDetails:
		return "", &s
	}
	return "", nil
}

type mqlOciComputeInstanceInternal struct {
	cacheImageID       string
	cacheRegion        string
	cacheBootVolumeID  string
	cacheCompartmentID string

	cachePlatformConfig core.PlatformConfig
	cacheLaunchOptions  *core.LaunchOptions
	cacheShapeConfig    *core.InstanceShapeConfig
	cacheImageSource    *core.InstanceSourceViaImageDetails
}

// platformSecurity builds the shielded-instance and confidential-computing
// settings the instance runs with.
//
// A shape that offers none of these features carries no platform configuration
// at all, and the whole structure is null rather than four flags reading false
// on hardware that cannot run them.
func (o *mqlOciComputeInstance) platformSecurity() (*mqlOciComputePlatformSecurity, error) {
	if o.cachePlatformConfig == nil {
		o.PlatformSecurity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	secureBoot, trustedPlatformModule, measuredBoot, memoryEncryption := ociShieldedInstanceFlags(o.cachePlatformConfig)

	res, err := CreateResource(o.MqlRuntime, "oci.compute.platformSecurity", map[string]*llx.RawData{
		"__id":                         llx.StringData(o.Id.Data + "/platformSecurity"),
		"secureBootEnabled":            llx.BoolDataPtr(secureBoot),
		"trustedPlatformModuleEnabled": llx.BoolDataPtr(trustedPlatformModule),
		"measuredBootEnabled":          llx.BoolDataPtr(measuredBoot),
		"memoryEncryptionEnabled":      llx.BoolDataPtr(memoryEncryption),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciComputePlatformSecurity), nil
}

// launchConfig builds the emulation and I/O settings the instance was launched
// with.
func (o *mqlOciComputeInstance) launchConfig() (*mqlOciComputeLaunchConfig, error) {
	lo := o.cacheLaunchOptions
	if lo == nil {
		o.LaunchConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.compute.launchConfig", map[string]*llx.RawData{
		"__id":                          llx.StringData(o.Id.Data + "/launchConfig"),
		"bootVolumeType":                llx.StringData(string(lo.BootVolumeType)),
		"firmware":                      llx.StringData(string(lo.Firmware)),
		"networkType":                   llx.StringData(string(lo.NetworkType)),
		"remoteDataVolumeType":          llx.StringData(string(lo.RemoteDataVolumeType)),
		"pvEncryptionInTransitEnabled":  llx.BoolDataPtr(lo.IsPvEncryptionInTransitEnabled),
		"consistentVolumeNamingEnabled": llx.BoolDataPtr(lo.IsConsistentVolumeNamingEnabled),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciComputeLaunchConfig), nil
}

// sizing builds the resource allocation of a flexible-shape instance.
//
// A fixed shape carries no shape configuration, because the shape name alone
// fixes the allocation, and the whole structure is null rather than a set of
// zeroes.
func (o *mqlOciComputeInstance) sizing() (*mqlOciComputeInstanceSizing, error) {
	shape := o.cacheShapeConfig
	if shape == nil {
		o.Sizing.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.compute.instanceSizing", map[string]*llx.RawData{
		"__id":                      llx.StringData(o.Id.Data + "/sizing"),
		"ocpus":                     llx.FloatDataPtr(shape.Ocpus),
		"memoryInGBs":               llx.FloatDataPtr(shape.MemoryInGBs),
		"baselineOcpuUtilization":   llx.StringData(string(shape.BaselineOcpuUtilization)),
		"processorDescription":      llx.StringDataPtr(shape.ProcessorDescription),
		"networkingBandwidthInGbps": llx.FloatDataPtr(shape.NetworkingBandwidthInGbps),
		"maxVnicAttachments":        llx.IntDataPtr(shape.MaxVnicAttachments),
		"gpus":                      llx.IntDataPtr(shape.Gpus),
		"gpuDescription":            llx.StringDataPtr(shape.GpuDescription),
		"localDisks":                llx.IntDataPtr(shape.LocalDisks),
		"localDisksTotalSizeInGBs":  llx.FloatDataPtr(shape.LocalDisksTotalSizeInGBs),
		"localDiskDescription":      llx.StringDataPtr(shape.LocalDiskDescription),
		"vcpus":                     llx.IntDataPtr(shape.Vcpus),
		"localVolumeSizeInGBs":      llx.IntDataPtr(shape.LocalVolumeSizeInGBs),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciComputeInstanceSizing), nil
}

// bootSource builds the image branch of the instance's source union.
//
// An instance launched from an existing boot volume reports null: that volume
// was sized, tiered and keyed when it was created rather than at launch, and
// bootVolume is what resolves it.
func (o *mqlOciComputeInstance) bootSource() (*mqlOciComputeImageSource, error) {
	src := o.cacheImageSource
	if src == nil {
		o.BootSource.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.compute.imageSource", map[string]*llx.RawData{
		"__id":                llx.StringData(o.Id.Data + "/bootSource"),
		"bootVolumeSizeInGBs": llx.IntDataPtr(src.BootVolumeSizeInGBs),
		"bootVolumeVpusPerGB": llx.IntDataPtr(src.BootVolumeVpusPerGB),
	})
	if err != nil {
		return nil, err
	}
	mqlSrc := res.(*mqlOciComputeImageSource)
	mqlSrc.cacheImageID = stringValue(src.ImageId)
	mqlSrc.cacheKmsKeyID = stringValue(src.KmsKeyId)
	return mqlSrc, nil
}

type mqlOciComputeImageSourceInternal struct {
	cacheImageID  string
	cacheKmsKeyID string
}

// image resolves the image the boot volume was created from.
func (o *mqlOciComputeImageSource) image() (*mqlOciComputeImage, error) {
	return resolveOciImage(o.MqlRuntime, ocidOrEmpty(o.cacheImageID), &o.Image)
}

// kmsKey resolves the customer-managed key the boot volume was created with.
//
// Null when the boot volume is encrypted with an Oracle-managed key, which is
// the default and carries no key the tenancy controls.
func (o *mqlOciComputeImageSource) kmsKey() (*mqlOciKmsKey, error) {
	return resolveOciKmsKey(o.MqlRuntime, ocidOrEmpty(o.cacheKmsKeyID), &o.KmsKey)
}

func (o *mqlOciComputeInstance) id() (string, error) {
	return "oci.compute.instance/" + o.Id.Data, nil
}

func (o *mqlOciComputeInstance) sshAuthorizedKeys() ([]any, error) {
	md := o.GetMetadata()
	if md.Error != nil {
		return nil, md.Error
	}
	raw, _ := md.Data["ssh_authorized_keys"].(string)
	return parseAuthorizedKeys(raw), nil
}

func (o *mqlOciComputeInstance) vnics() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	computeSvc, err := conn.ComputeClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	networkSvc, err := conn.NetworkClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	// List VNIC attachments for this instance.
	//
	// Scoped to the instance's own compartment, not the tenancy root:
	// ListVnicAttachments filters on the compartment as well as the instance,
	// so asking the root about an instance that lives in a child compartment
	// returned no attachments at all. That left the instance with no IPs, no
	// subnet and no security groups, which the exposure checks then read as
	// "not reachable" for exactly the instances nobody had looked at.
	compartmentID := o.cacheCompartmentID
	if compartmentID == "" {
		compartmentID = conn.TenantID()
	}

	attachments, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.VnicAttachment, *string, error) {
		response, err := computeSvc.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
			CompartmentId: common.String(compartmentID),
			InstanceId:    common.String(o.Id.Data),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(attachments))
	for i := range attachments {
		att := attachments[i]
		if att.VnicId == nil || att.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
			continue
		}

		// OCI has no batch GetVnic API, so each attachment requires a separate call.
		vnicResp, err := networkSvc.GetVnic(ctx, core.GetVnicRequest{
			VnicId: att.VnicId,
		})
		if err != nil {
			log.Debug().Err(err).Msgf("failed to get VNIC %s", *att.VnicId)
			continue
		}
		// Shared with initOciComputeVnic so the collection path and the
		// single-VNIC lookup cannot drift apart field by field.
		mqlVnic, err := ociVnicToMql(o.MqlRuntime, vnicResp.Vnic)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVnic)
	}

	return res, nil
}

type mqlOciComputeVnicInternal struct {
	ociCompartmentRef
	cacheNsgIDs       []any
	cacheSubnetID     string
	cacheRouteTableID string
}

func (o *mqlOciComputeVnic) id() (string, error) {
	return "oci.compute.vnic/" + o.Id.Data, nil
}

func (o *mqlOciComputeVnic) subnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheSubnetID == "" {
		o.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlSubnet, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return mqlSubnet.(*mqlOciNetworkSubnet), nil
}

// routeTable resolves the route table the VNIC routes through, which OCI calls
// per-resource routing. Null when the VNIC sets none, in which case its subnet's
// route table governs the interface.
//
// A route table the VNIC names but that cannot be resolved is reported as an
// error rather than as null, the same way the subnet reference behaves: the
// exposure verdict reads this field, and an unread route table must not be
// indistinguishable from a VNIC that overrides nothing.
func (o *mqlOciComputeVnic) routeTable() (*mqlOciNetworkRouteTable, error) {
	if o.cacheRouteTableID == "" {
		o.RouteTable.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRouteTable, err := NewResource(o.MqlRuntime, "oci.network.routeTable", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheRouteTableID),
	})
	if err != nil {
		return nil, err
	}
	return mqlRouteTable.(*mqlOciNetworkRouteTable), nil
}

func (o *mqlOciCompute) images() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// The lister receives the region as a key, so index the oci.regions
	// collection to let it set a typed region field on each image.
	regions, err := ociRegionsFor(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	regionsByID, err := ociRegionsByID(regions)
	if err != nil {
		return nil, err
	}

	// Platform images are returned from every compartment that is asked,
	// so they would repeat once per compartment.
	items, err := ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			regionResource, ok := regionsByID[region]
			if !ok {
				return nil, errors.New("no oci.region resource for region " + region)
			}

			svc, err := conn.ComputeClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			images, err := o.getComputeImagesForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range images {
				image := images[i]

				var created *time.Time
				if image.TimeCreated != nil {
					created = &image.TimeCreated.Time
				}

				compartment, err := ociCompartmentResource(o.MqlRuntime, image.CompartmentId)
				if err != nil {
					return nil, err
				}

				mqlInstance, err := CreateResource(o.MqlRuntime, "oci.compute.image", map[string]*llx.RawData{
					"id":                     llx.StringDataPtr(image.Id),
					"name":                   llx.StringDataPtr(image.DisplayName),
					"region":                 llx.ResourceData(regionResource, "oci.region"),
					"created":                llx.TimeDataPtr(created),
					"state":                  llx.StringData(string(image.LifecycleState)),
					"compartment":            llx.ResourceData(compartment, "oci.compartment"),
					"operatingSystem":        llx.StringDataPtr(image.OperatingSystem),
					"operatingSystemVersion": llx.StringDataPtr(image.OperatingSystemVersion),
					"sizeInMBs":              llx.IntDataPtr(image.SizeInMBs),
					"freeformTags":           llx.MapData(strMapToAny(image.FreeformTags), types.String),
					"definedTags":            llx.MapData(definedTagsToAny(image.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlInstance.(*mqlOciComputeImage).cacheBaseImageID = stringValue(image.BaseImageId)
				res = append(res, mqlInstance)
			}

			return res, nil
		})
	if err != nil {
		return nil, err
	}
	return ociDedupeByID(items), nil
}

func (o *mqlOciCompute) getComputeImagesForRegion(ctx context.Context, computeClient *core.ComputeClient, compartmentID string) ([]core.Image, error) {
	images, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.Image, *string, error) {
		request := core.ListImagesRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := computeClient.ListImages(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return images, nil
}

type mqlOciComputeImageInternal struct {
	cacheBaseImageID string
}

func (o *mqlOciComputeImage) id() (string, error) {
	return "oci.compute.image/" + o.Id.Data, nil
}

func (o *mqlOciCompute) blockVolumes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			svc, err := conn.BlockstorageClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			volumes, err := o.getBlockVolumesForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range volumes {
				vol := volumes[i]

				var created *time.Time
				if vol.TimeCreated != nil {
					created = &vol.TimeCreated.Time
				}

				var sourceVolumeID, sourceVolumeBackupID string
				switch d := vol.SourceDetails.(type) {
				case core.VolumeSourceFromVolumeDetails:
					sourceVolumeID = stringValue(d.Id)
				case core.VolumeSourceFromVolumeBackupDetails:
					sourceVolumeBackupID = stringValue(d.Id)
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.compute.blockVolume", stringValue(vol.CompartmentId), map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(vol.Id),
					"name":                 llx.StringDataPtr(vol.DisplayName),
					"availabilityDomain":   llx.StringDataPtr(vol.AvailabilityDomain),
					"sizeInGBs":            llx.IntDataPtr(vol.SizeInGBs),
					"vpusPerGB":            llx.IntDataPtr(vol.VpusPerGB),
					"state":                llx.StringData(string(vol.LifecycleState)),
					"isHydrated":           llx.BoolDataPtr(vol.IsHydrated),
					"isAutoTuneEnabled":    llx.BoolDataPtr(vol.IsAutoTuneEnabled),
					"sourceVolumeBackupId": llx.StringData(sourceVolumeBackupID),
					"created":              llx.TimeDataPtr(created),
					"freeformTags":         llx.MapData(strMapToAny(vol.FreeformTags), types.String),
					"definedTags":          llx.MapData(definedTagsToAny(vol.DefinedTags), types.Any),
					"systemTags":           llx.MapData(definedTagsToAny(vol.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlBV := mqlInstance.(*mqlOciComputeBlockVolume)
				mqlBV.cacheKmsKeyID = stringValue(vol.KmsKeyId)
				mqlBV.cacheSourceVolumeID = sourceVolumeID
				mqlBV.cacheRegion = region
				mqlBV.cacheVolumeGroupID = stringValue(vol.VolumeGroupId)
				res = append(res, mqlBV)
			}

			return res, nil
		})
}

func (o *mqlOciCompute) getBlockVolumesForRegion(ctx context.Context, client *core.BlockstorageClient, compartmentID string) ([]core.Volume, error) {
	volumes, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.Volume, *string, error) {
		request := core.ListVolumesRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := client.ListVolumes(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return volumes, nil
}

type mqlOciComputeBlockVolumeInternal struct {
	ociCompartmentRef
	cacheKmsKeyID       string
	cacheSourceVolumeID string
	cacheRegion         string
	cacheVolumeGroupID  string
}

func (o *mqlOciComputeBlockVolume) id() (string, error) {
	return "oci.compute.blockVolume/" + o.Id.Data, nil
}

func (o *mqlOciComputeBlockVolume) kmsKey() (*mqlOciKmsKey, error) {
	if o.cacheKmsKeyID == "" {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKmsKeyID),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlOciKmsKey), nil
}

func (o *mqlOciCompute) bootVolumes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci with region %s", region)

			svc, err := conn.BlockstorageClient(region)
			if err != nil {
				return nil, err
			}

			var res []any
			bootVols, err := o.getBootVolumesForRegion(ctx, svc, compartmentID)
			if err != nil {
				return nil, err
			}

			for i := range bootVols {
				bv := bootVols[i]

				var created *time.Time
				if bv.TimeCreated != nil {
					created = &bv.TimeCreated.Time
				}

				var sourceBootVolumeID, sourceBootVolumeBackupID string
				switch d := bv.SourceDetails.(type) {
				case core.BootVolumeSourceFromBootVolumeDetails:
					sourceBootVolumeID = stringValue(d.Id)
				case core.BootVolumeSourceFromBootVolumeBackupDetails:
					sourceBootVolumeBackupID = stringValue(d.Id)
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.compute.bootVolume", stringValue(bv.CompartmentId), map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(bv.Id),
					"name":                     llx.StringDataPtr(bv.DisplayName),
					"availabilityDomain":       llx.StringDataPtr(bv.AvailabilityDomain),
					"sizeInGBs":                llx.IntDataPtr(bv.SizeInGBs),
					"state":                    llx.StringData(string(bv.LifecycleState)),
					"sourceBootVolumeBackupId": llx.StringData(sourceBootVolumeBackupID),
					"created":                  llx.TimeDataPtr(created),
					"freeformTags":             llx.MapData(strMapToAny(bv.FreeformTags), types.String),
					"definedTags":              llx.MapData(definedTagsToAny(bv.DefinedTags), types.Any),
					"systemTags":               llx.MapData(definedTagsToAny(bv.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlBV := mqlInstance.(*mqlOciComputeBootVolume)
				mqlBV.cacheImageID = stringValue(bv.ImageId)
				mqlBV.cacheKmsKeyID = stringValue(bv.KmsKeyId)
				mqlBV.cacheSourceBootVolumeID = sourceBootVolumeID
				mqlBV.cacheRegion = region
				mqlBV.cacheVolumeGroupID = stringValue(bv.VolumeGroupId)
				res = append(res, mqlBV)
			}

			return res, nil
		})
}

func (o *mqlOciCompute) getBootVolumesForRegion(ctx context.Context, client *core.BlockstorageClient, compartmentID string) ([]core.BootVolume, error) {
	bootVolumes, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.BootVolume, *string, error) {
		request := core.ListBootVolumesRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := client.ListBootVolumes(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return bootVolumes, nil
}

type mqlOciComputeBootVolumeInternal struct {
	ociCompartmentRef
	cacheImageID            string
	cacheKmsKeyID           string
	cacheSourceBootVolumeID string
	cacheRegion             string
	cacheVolumeGroupID      string
}

func (o *mqlOciComputeBootVolume) id() (string, error) {
	return "oci.compute.bootVolume/" + o.Id.Data, nil
}

func (o *mqlOciComputeBootVolume) kmsKey() (*mqlOciKmsKey, error) {
	if o.cacheKmsKeyID == "" {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKmsKeyID),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlOciKmsKey), nil
}
