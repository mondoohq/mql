// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/containerinstances"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// ociContainerSecurityView is the flattened Linux security context of a
// container.
type ociContainerSecurityView struct {
	runAsUser        *int
	runAsGroup       *int
	nonRootUserCheck bool
	readonlyRootFs   bool
	added            []any
	dropped          []any
}

// ociContainerSecurityContext flattens a container's polymorphic security
// context. The booleans resolve to false when there is no security context,
// because false is the insecure reading for both and MQL's three-valued logic
// makes `a && b` over two nulls evaluate to true - a container with no security
// context would otherwise pass a hardening check it was never measured for.
//
// runAsUser and runAsGroup stay null instead: OCI falls back to whatever the
// image declares, so reporting 0 would assert the container runs as root when
// that is simply unknown.
func ociContainerSecurityContext(sc containerinstances.SecurityContext) ociContainerSecurityView {
	view := ociContainerSecurityView{added: []any{}, dropped: []any{}}

	linux, ok := sc.(containerinstances.LinuxSecurityContext)
	if !ok {
		return view
	}
	view.runAsUser = linux.RunAsUser
	view.runAsGroup = linux.RunAsGroup
	view.nonRootUserCheck = boolValue(linux.IsNonRootUserCheckEnabled)
	view.readonlyRootFs = boolValue(linux.IsRootFileSystemReadonly)

	if linux.Capabilities != nil {
		for _, c := range linux.Capabilities.AddCapabilities {
			view.added = append(view.added, string(c))
		}
		for _, c := range linux.Capabilities.DropCapabilities {
			view.dropped = append(view.dropped, string(c))
		}
	}
	return view
}

func (o *mqlOciContainerInstances) id() (string, error) {
	return "oci.containerInstances", nil
}

func (o *mqlOciContainerInstances) instances() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci container instances with region %s", region)

			svc, err := conn.ContainerInstanceClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]containerinstances.ContainerInstanceSummary, *string, error) {
				response, err := svc.ListContainerInstances(ctx, containerinstances.ListContainerInstancesRequest{
					CompartmentId: new(compartmentID),
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

			var res []any
			for i := range items {
				ci := items[i]

				var created *time.Time
				if ci.TimeCreated != nil {
					created = &ci.TimeCreated.Time
				}
				var timeUpdated *time.Time
				if ci.TimeUpdated != nil {
					timeUpdated = &ci.TimeUpdated.Time
				}

				shapeConfig, err := convert.JsonToDict(ci.ShapeConfig)
				if err != nil {
					return nil, err
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.containerInstances.instance", stringValue(ci.CompartmentId), map[string]*llx.RawData{
					"id":                               llx.StringDataPtr(ci.Id),
					"name":                             llx.StringDataPtr(ci.DisplayName),
					"availabilityDomain":               llx.StringDataPtr(ci.AvailabilityDomain),
					"state":                            llx.StringData(string(ci.LifecycleState)),
					"shape":                            llx.StringDataPtr(ci.Shape),
					"shapeConfig":                      llx.DictData(shapeConfig),
					"containerCount":                   llx.IntData(intValue(ci.ContainerCount)),
					"containerRestartPolicy":           llx.StringData(string(ci.ContainerRestartPolicy)),
					"faultDomain":                      llx.StringDataPtr(ci.FaultDomain),
					"gracefulShutdownTimeoutInSeconds": llx.IntData(int64Value(ci.GracefulShutdownTimeoutInSeconds)),
					"volumeCount":                      llx.IntData(intValue(ci.VolumeCount)),
					"created":                          llx.TimeDataPtr(created),
					"timeUpdated":                      llx.TimeDataPtr(timeUpdated),
					"freeformTags":                     llx.MapData(strMapToAny(ci.FreeformTags), types.String),
					"definedTags":                      llx.MapData(definedTagsToAny(ci.DefinedTags), types.Any),
					"systemTags":                       llx.MapData(definedTagsToAny(ci.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlCI := mqlInstance.(*mqlOciContainerInstancesInstance)
				mqlCI.cacheRegion = region
				mqlCI.cacheShapeConfig = ci.ShapeConfig
				res = append(res, mqlCI)
			}

			return res, nil
		})
}

type mqlOciContainerInstancesInstanceInternal struct {
	ociCompartmentRef
	cacheRegion string

	cacheShapeConfig *containerinstances.ContainerInstanceShapeConfig
}

// sizing builds the compute, memory and network the instance is sized to.
//
// Null when the instance reports no shape configuration, rather than an
// instance that reads as sized to zero OCPUs.
func (o *mqlOciContainerInstancesInstance) sizing() (*mqlOciContainerInstancesShapeConfig, error) {
	shape := o.cacheShapeConfig
	if shape == nil {
		o.Sizing.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.containerInstances.shapeConfig", map[string]*llx.RawData{
		"__id":                      llx.StringData(o.Id.Data + "/shapeConfig"),
		"ocpus":                     llx.FloatDataPtr(shape.Ocpus),
		"memoryInGBs":               llx.FloatDataPtr(shape.MemoryInGBs),
		"processorDescription":      llx.StringDataPtr(shape.ProcessorDescription),
		"networkingBandwidthInGbps": llx.FloatDataPtr(shape.NetworkingBandwidthInGbps),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciContainerInstancesShapeConfig), nil
}

func (o *mqlOciContainerInstancesInstance) id() (string, error) {
	return "oci.containerInstances.instance/" + o.Id.Data, nil
}

func (o *mqlOciContainerInstancesInstance) containers() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	svc, err := conn.ContainerInstanceClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]containerinstances.ContainerSummary, *string, error) {
		response, err := svc.ListContainers(ctx, containerinstances.ListContainersRequest{
			CompartmentId:       new(o.cacheCompartmentID),
			ContainerInstanceId: new(o.Id.Data),
			Page:                page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		c := items[i]

		var created *time.Time
		if c.TimeCreated != nil {
			created = &c.TimeCreated.Time
		}
		var timeUpdated *time.Time
		if c.TimeUpdated != nil {
			timeUpdated = &c.TimeUpdated.Time
		}
		resourceConfig, err := convert.JsonToDict(c.ResourceConfig)
		if err != nil {
			return nil, err
		}

		sec := ociContainerSecurityContext(c.SecurityContext)

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.containerInstances.container", stringValue(c.CompartmentId), map[string]*llx.RawData{
			"id":                          llx.StringDataPtr(c.Id),
			"name":                        llx.StringDataPtr(c.DisplayName),
			"availabilityDomain":          llx.StringDataPtr(c.AvailabilityDomain),
			"state":                       llx.StringData(string(c.LifecycleState)),
			"containerInstanceId":         llx.StringDataPtr(c.ContainerInstanceId),
			"imageUrl":                    llx.StringDataPtr(c.ImageUrl),
			"isResourcePrincipalDisabled": llx.BoolDataPtr(c.IsResourcePrincipalDisabled),
			"resourceConfig":              llx.DictData(resourceConfig),
			"runAsUser":                   llx.IntDataPtr(sec.runAsUser),
			"runAsGroup":                  llx.IntDataPtr(sec.runAsGroup),
			"isNonRootUserCheckEnabled":   llx.BoolData(sec.nonRootUserCheck),
			"isRootFileSystemReadonly":    llx.BoolData(sec.readonlyRootFs),
			"addedCapabilities":           llx.ArrayData(sec.added, types.String),
			"droppedCapabilities":         llx.ArrayData(sec.dropped, types.String),
			"created":                     llx.TimeDataPtr(created),
			"timeUpdated":                 llx.TimeDataPtr(timeUpdated),
			"freeformTags":                llx.MapData(strMapToAny(c.FreeformTags), types.String),
			"definedTags":                 llx.MapData(definedTagsToAny(c.DefinedTags), types.Any),
			"systemTags":                  llx.MapData(definedTagsToAny(c.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		mqlInstance.(*mqlOciContainerInstancesContainer).cacheResourceConfig = c.ResourceConfig
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciContainerInstancesContainer) id() (string, error) {
	return "oci.containerInstances.container/" + o.Id.Data, nil
}

type mqlOciContainerInstancesContainerInternal struct {
	ociCompartmentRef

	cacheResourceConfig *containerinstances.ContainerResourceConfig
}

// resourceLimits builds the ceilings on what the container's process may
// consume.
//
// Null when the container declares no resource configuration: it then inherits
// the instance defaults, which is unbounded rather than a limit of zero.
func (o *mqlOciContainerInstancesContainer) resourceLimits() (*mqlOciContainerInstancesResourceConfig, error) {
	limits := o.cacheResourceConfig
	if limits == nil {
		o.ResourceLimits.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.containerInstances.resourceConfig", map[string]*llx.RawData{
		"__id":             llx.StringData(o.Id.Data + "/resourceConfig"),
		"vcpusLimit":       llx.FloatDataPtr(limits.VcpusLimit),
		"memoryLimitInGBs": llx.FloatDataPtr(limits.MemoryLimitInGBs),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciContainerInstancesResourceConfig), nil
}
