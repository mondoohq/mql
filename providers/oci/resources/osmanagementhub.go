// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/osmanagementhub"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
)

func (o *mqlOciOsManagementHub) id() (string, error) {
	return "oci.osManagementHub", nil
}

func (o *mqlOciOsManagementHub) managedInstances() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci OS Management Hub managed instances with region %s", region)

			svc, err := conn.OsManagementHubManagedInstanceClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]osmanagementhub.ManagedInstanceSummary, *string, error) {
				response, err := svc.ListManagedInstances(ctx, osmanagementhub.ListManagedInstancesRequest{
					CompartmentId: common.String(compartmentID),
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

			res := make([]any, 0, len(items))
			for i := range items {
				m := items[i]
				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.osManagementHub.managedInstance", stringValue(m.CompartmentId), ociManagedInstanceArgs(&m))
				if err != nil {
					return nil, err
				}
				mi := mqlInstance.(*mqlOciOsManagementHubManagedInstance)
				mi.cacheRegion = region
				mi.cacheNotificationTopicID = stringValue(m.NotificationTopicId)
				res = append(res, mi)
			}
			return res, nil
		})
}

// ociManagedInstanceArgs maps the fields the listing carries. The update
// counts by category, the OS release and the check-in times come only from
// GetManagedInstance and are read on demand.
func ociManagedInstanceArgs(m *osmanagementhub.ManagedInstanceSummary) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":                         llx.StringDataPtr(m.Id),
		"name":                       llx.StringDataPtr(m.DisplayName),
		"description":                llx.StringDataPtr(m.Description),
		"location":                   llx.StringData(string(m.Location)),
		"status":                     llx.StringData(string(m.Status)),
		"osFamily":                   llx.StringData(string(m.OsFamily)),
		"architecture":               llx.StringData(string(m.Architecture)),
		"isRebootRequired":           llx.BoolDataPtr(m.IsRebootRequired),
		"updatesAvailable":           llx.IntDataPtr(intPtrToInt64(m.UpdatesAvailable)),
		"isManagementStation":        llx.BoolData(boolValue(m.IsManagementStation)),
		"isManagedByAutonomousLinux": llx.BoolData(boolValue(m.IsManagedByAutonomousLinux)),
		"agentVersion":               llx.StringDataPtr(m.AgentVersion),
		"timeLastBoot":               sdkTimeData(m.TimeLastBoot),
	}
}

type mqlOciOsManagementHubManagedInstanceInternal struct {
	ociCompartmentRef
	cacheRegion              string
	cacheNotificationTopicID string
	detail                   ociLazy[*osmanagementhub.ManagedInstance]
}

func (o *mqlOciOsManagementHubManagedInstance) id() (string, error) {
	return "oci.osManagementHub.managedInstance/" + o.Id.Data, nil
}

func (o *mqlOciOsManagementHubManagedInstance) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciOsManagementHubManagedInstance) getDetail() (*osmanagementhub.ManagedInstance, error) {
	return o.detail.get(func() (*osmanagementhub.ManagedInstance, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		client, err := conn.OsManagementHubManagedInstanceClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		response, err := client.GetManagedInstance(context.Background(), osmanagementhub.GetManagedInstanceRequest{
			ManagedInstanceId: common.String(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &response.ManagedInstance, nil
	})
}

// instance resolves the compute instance behind the managed instance.
//
// For an OCI compute host the managed instance id is the instance OCID. The
// instance is looked up in the compute listing rather than resolved directly,
// so a managed instance whose instance has since been terminated reads null
// instead of failing.
func (o *mqlOciOsManagementHubManagedInstance) instance() (*mqlOciComputeInstance, error) {
	if o.Location.Data != string(osmanagementhub.ManagedInstanceLocationOciCompute) || !isOcid(o.Id.Data) {
		o.Instance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	items, err := ociServiceCollection(o.MqlRuntime, "oci.compute", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciCompute).GetInstances()
	})
	if err != nil {
		return nil, err
	}
	for _, raw := range items {
		if inst, ok := raw.(*mqlOciComputeInstance); ok && inst.Id.Data == o.Id.Data {
			return inst, nil
		}
	}
	o.Instance.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (o *mqlOciOsManagementHubManagedInstance) notificationTopic() (*mqlOciOnsTopic, error) {
	return resolveRef(o.MqlRuntime, "oci.ons.topic", ocidOrEmpty(o.cacheNotificationTopicID), &o.NotificationTopic)
}

// detailInt reports one of the counts only the full record carries, null when
// the service leaves it unset. A missing count is not zero: zero security
// updates is a claim that the host is patched.
func (o *mqlOciOsManagementHubManagedInstance) detailInt(field *plugin.TValue[int64], value func(*osmanagementhub.ManagedInstance) *int) (int64, error) {
	detail, err := o.getDetail()
	if err != nil {
		return 0, err
	}
	v := value(detail)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*v), nil
}

func (o *mqlOciOsManagementHubManagedInstance) detailString(field *plugin.TValue[string], value func(*osmanagementhub.ManagedInstance) *string) (string, error) {
	detail, err := o.getDetail()
	if err != nil {
		return "", err
	}
	v := value(detail)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

func (o *mqlOciOsManagementHubManagedInstance) securityUpdatesAvailable() (int64, error) {
	return o.detailInt(&o.SecurityUpdatesAvailable, func(m *osmanagementhub.ManagedInstance) *int { return m.SecurityUpdatesAvailable })
}

func (o *mqlOciOsManagementHubManagedInstance) bugUpdatesAvailable() (int64, error) {
	return o.detailInt(&o.BugUpdatesAvailable, func(m *osmanagementhub.ManagedInstance) *int { return m.BugUpdatesAvailable })
}

func (o *mqlOciOsManagementHubManagedInstance) enhancementUpdatesAvailable() (int64, error) {
	return o.detailInt(&o.EnhancementUpdatesAvailable, func(m *osmanagementhub.ManagedInstance) *int { return m.EnhancementUpdatesAvailable })
}

func (o *mqlOciOsManagementHubManagedInstance) otherUpdatesAvailable() (int64, error) {
	return o.detailInt(&o.OtherUpdatesAvailable, func(m *osmanagementhub.ManagedInstance) *int { return m.OtherUpdatesAvailable })
}

func (o *mqlOciOsManagementHubManagedInstance) installedPackages() (int64, error) {
	return o.detailInt(&o.InstalledPackages, func(m *osmanagementhub.ManagedInstance) *int { return m.InstalledPackages })
}

func (o *mqlOciOsManagementHubManagedInstance) installedWindowsUpdates() (int64, error) {
	return o.detailInt(&o.InstalledWindowsUpdates, func(m *osmanagementhub.ManagedInstance) *int { return m.InstalledWindowsUpdates })
}

func (o *mqlOciOsManagementHubManagedInstance) osName() (string, error) {
	return o.detailString(&o.OsName, func(m *osmanagementhub.ManagedInstance) *string { return m.OsName })
}

func (o *mqlOciOsManagementHubManagedInstance) osVersion() (string, error) {
	return o.detailString(&o.OsVersion, func(m *osmanagementhub.ManagedInstance) *string { return m.OsVersion })
}

func (o *mqlOciOsManagementHubManagedInstance) osKernelVersion() (string, error) {
	return o.detailString(&o.OsKernelVersion, func(m *osmanagementhub.ManagedInstance) *string { return m.OsKernelVersion })
}

func (o *mqlOciOsManagementHubManagedInstance) kspliceEffectiveKernelVersion() (string, error) {
	return o.detailString(&o.KspliceEffectiveKernelVersion, func(m *osmanagementhub.ManagedInstance) *string { return m.KspliceEffectiveKernelVersion })
}

func (o *mqlOciOsManagementHubManagedInstance) areSourcesManaged() (bool, error) {
	detail, err := o.getDetail()
	if err != nil {
		return false, err
	}
	if detail.AreSourcesManaged == nil {
		o.AreSourcesManaged.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *detail.AreSourcesManaged, nil
}

// detailTime reports one of the timestamps only the full record carries,
// null when the service leaves it unset.
func (o *mqlOciOsManagementHubManagedInstance) detailTime(field *plugin.TValue[*time.Time], value func(*osmanagementhub.ManagedInstance) *common.SDKTime) (*time.Time, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	v := value(detail)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t := v.Time
	return &t, nil
}

func (o *mqlOciOsManagementHubManagedInstance) timeLastCheckin() (*time.Time, error) {
	return o.detailTime(&o.TimeLastCheckin, func(m *osmanagementhub.ManagedInstance) *common.SDKTime { return m.TimeLastCheckin })
}

func (o *mqlOciOsManagementHubManagedInstance) timeLastSoftwareRefresh() (*time.Time, error) {
	return o.detailTime(&o.TimeLastSoftwareRefresh, func(m *osmanagementhub.ManagedInstance) *common.SDKTime { return m.TimeLastSoftwareRefresh })
}

func (o *mqlOciOsManagementHubManagedInstance) created() (*time.Time, error) {
	return o.detailTime(&o.Created, func(m *osmanagementhub.ManagedInstance) *common.SDKTime { return m.TimeCreated })
}

func (o *mqlOciOsManagementHubManagedInstance) timeUpdated() (*time.Time, error) {
	return o.detailTime(&o.TimeUpdated, func(m *osmanagementhub.ManagedInstance) *common.SDKTime { return m.TimeUpdated })
}

// managedInstance finds the OS Management Hub record for the instance.
//
// OS Management Hub keys an OCI compute host by its instance OCID, so the
// match is on the id alone. The service-wide listing is shared by every
// instance asking, rather than each instance issuing its own lookup.
func (o *mqlOciComputeInstance) managedInstance() (*mqlOciOsManagementHubManagedInstance, error) {
	items, err := ociServiceCollection(o.MqlRuntime, "oci.osManagementHub", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciOsManagementHub).GetManagedInstances()
	})
	if err != nil {
		return nil, err
	}
	for _, raw := range items {
		if mi, ok := raw.(*mqlOciOsManagementHubManagedInstance); ok && mi.Id.Data == o.Id.Data {
			return mi, nil
		}
	}
	o.ManagedInstance.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
