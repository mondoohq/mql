// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// ociListedRef resolves a reference through an already-listed collection and
// reads null when the target is not in it, such as the volume of a backup
// that outlived it. resolveRef would report that as a not-found error.
func ociListedRef[T plugin.Resource](list *plugin.TValue[[]any], id string, field *plugin.TValue[T]) (T, error) {
	var zero T
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return zero, nil
	}
	if list.Error != nil {
		return zero, list.Error
	}
	for _, raw := range list.Data {
		r, ok := raw.(T)
		if !ok {
			continue
		}
		if idField, ok := any(r).(interface{ GetId() *plugin.TValue[string] }); ok && idField.GetId().Data == id {
			return r, nil
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return zero, nil
}

func ociComputeService(runtime *plugin.Runtime) (*mqlOciCompute, error) {
	res, err := CreateResource(runtime, "oci.compute", nil)
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciCompute), nil
}

// ---- volume attachments ----

type mqlOciComputeVolumeAttachmentInternal struct {
	ociCompartmentRef
	cacheInstanceID string
	cacheVolumeID   string
}

func (o *mqlOciComputeVolumeAttachment) id() (string, error) {
	return "oci.compute.volumeAttachment/" + o.Id.Data, nil
}

func (o *mqlOciCompute) volumeAttachments() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.ComputeClient(region)
			if err != nil {
				return nil, err
			}
			attachments, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.VolumeAttachment, *string, error) {
				response, err := svc.ListVolumeAttachments(ctx, core.ListVolumeAttachmentsRequest{
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
			res := make([]any, 0, len(attachments))
			for _, a := range attachments {
				if a == nil {
					continue
				}
				m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.compute.volumeAttachment", stringValue(a.GetCompartmentId()), volumeAttachmentArgs(a))
				if err != nil {
					return nil, err
				}
				va := m.(*mqlOciComputeVolumeAttachment)
				va.cacheInstanceID = stringValue(a.GetInstanceId())
				va.cacheVolumeID = stringValue(a.GetVolumeId())
				res = append(res, va)
			}
			return res, nil
		})
}

// volumeAttachmentArgs maps every attachment variant. The iSCSI variant's
// CHAP secret is never read: only whether CHAP is in use.
func volumeAttachmentArgs(a core.VolumeAttachment) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"id":                             llx.StringDataPtr(a.GetId()),
		"name":                           llx.StringDataPtr(a.GetDisplayName()),
		"attachmentType":                 llx.StringData(""),
		"state":                          llx.StringData(string(a.GetLifecycleState())),
		"availabilityDomain":             llx.StringDataPtr(a.GetAvailabilityDomain()),
		"device":                         llx.StringData(stringValue(a.GetDevice())),
		"isReadOnly":                     llx.BoolDataPtr(a.GetIsReadOnly()),
		"isShareable":                    llx.BoolDataPtr(a.GetIsShareable()),
		"isPvEncryptionInTransitEnabled": llx.BoolDataPtr(a.GetIsPvEncryptionInTransitEnabled()),
		"encryptionInTransitType":        llx.StringData(""),
		"chapEnabled":                    llx.BoolFalse,
		"isMultipath":                    llx.BoolDataPtr(a.GetIsMultipath()),
		"isVolumeCreatedDuringLaunch":    llx.BoolDataPtr(a.GetIsVolumeCreatedDuringLaunch()),
		"created":                        sdkTimeData(a.GetTimeCreated()),
	}
	switch v := a.(type) {
	case core.IScsiVolumeAttachment:
		args["attachmentType"] = llx.StringData("iscsi")
		args["encryptionInTransitType"] = llx.StringData(string(v.EncryptionInTransitType))
		args["chapEnabled"] = llx.BoolData(v.ChapUsername != nil && *v.ChapUsername != "")
	case core.ParavirtualizedVolumeAttachment:
		args["attachmentType"] = llx.StringData("paravirtualized")
	case core.EmulatedVolumeAttachment:
		args["attachmentType"] = llx.StringData("emulated")
	}
	return args
}

func (o *mqlOciComputeVolumeAttachment) instance() (*mqlOciComputeInstance, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.GetInstances(), o.cacheInstanceID, &o.Instance)
}

func (o *mqlOciComputeVolumeAttachment) volume() (*mqlOciComputeBlockVolume, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.GetBlockVolumes(), o.cacheVolumeID, &o.Volume)
}

// attachmentsWhere filters the listed attachments.
func attachmentsWhere(runtime *plugin.Runtime, keep func(*mqlOciComputeVolumeAttachment) bool) ([]any, error) {
	svc, err := ociComputeService(runtime)
	if err != nil {
		return nil, err
	}
	list := svc.GetVolumeAttachments()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, raw := range list.Data {
		if a, ok := raw.(*mqlOciComputeVolumeAttachment); ok && keep(a) {
			out = append(out, a)
		}
	}
	return out, nil
}

func (o *mqlOciComputeInstance) volumeAttachments() ([]any, error) {
	return attachmentsWhere(o.MqlRuntime, func(a *mqlOciComputeVolumeAttachment) bool { return a.cacheInstanceID == o.Id.Data })
}

func (o *mqlOciComputeBlockVolume) attachments() ([]any, error) {
	return attachmentsWhere(o.MqlRuntime, func(a *mqlOciComputeVolumeAttachment) bool { return a.cacheVolumeID == o.Id.Data })
}

// ---- backup policies ----

type mqlOciComputeVolumeBackupPolicyInternal struct {
	ociCompartmentRef
	cacheSchedules []core.VolumeBackupSchedule
}

func (o *mqlOciComputeVolumeBackupPolicy) id() (string, error) {
	return "oci.compute.volumeBackupPolicy/" + o.Id.Data, nil
}

// volumeBackupPolicies lists Oracle's predefined policies, which the API
// returns when no compartment is given, and the custom policies of every
// admitted compartment.
func (o *mqlOciCompute) volumeBackupPolicies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	list := func(ctx context.Context, region string, compartmentID *string) ([]any, error) {
		svc, err := conn.BlockstorageClient(region)
		if err != nil {
			return nil, err
		}
		policies, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.VolumeBackupPolicy, *string, error) {
			response, err := svc.ListVolumeBackupPolicies(ctx, core.ListVolumeBackupPoliciesRequest{
				CompartmentId: compartmentID,
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
		res := make([]any, 0, len(policies))
		for i := range policies {
			p := policies[i]
			m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.compute.volumeBackupPolicy", stringValue(p.CompartmentId), volumeBackupPolicyArgs(p))
			if err != nil {
				return nil, err
			}
			m.(*mqlOciComputeVolumeBackupPolicy).cacheSchedules = p.Schedules
			res = append(res, m)
		}
		return res, nil
	}

	predefined, err := ociCollect(o.MqlRuntime, ociScopeSubtree, func(ctx context.Context, region string, _ string) ([]any, error) {
		return list(ctx, region, nil)
	})
	if err != nil {
		return nil, err
	}
	custom, err := ociCollect(o.MqlRuntime, ociScopeAllCompartments, func(ctx context.Context, region string, compartmentID string) ([]any, error) {
		return list(ctx, region, common.String(compartmentID))
	})
	if err != nil {
		return nil, err
	}
	return ociDedupeByID(append(predefined, custom...)), nil
}

func volumeBackupPolicyArgs(p core.VolumeBackupPolicy) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":                llx.StringDataPtr(p.Id),
		"name":              llx.StringDataPtr(p.DisplayName),
		"isOracleDefined":   llx.BoolData(stringValue(p.CompartmentId) == ""),
		"destinationRegion": llx.StringData(stringValue(p.DestinationRegion)),
		"created":           sdkTimeData(p.TimeCreated),
		"freeformTags":      llx.MapData(strMapToAny(p.FreeformTags), types.String),
		"definedTags":       llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
	}
}

func (o *mqlOciComputeVolumeBackupPolicy) schedules() ([]any, error) {
	out := make([]any, 0, len(o.cacheSchedules))
	for i, sch := range o.cacheSchedules {
		args := volumeBackupScheduleArgs(sch)
		args["__id"] = llx.StringData(o.Id.Data + "/schedule/" + strconv.Itoa(i))
		m, err := CreateResource(o.MqlRuntime, "oci.compute.volumeBackupPolicy.schedule", args)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// volumeBackupScheduleArgs maps a schedule; retention is reported in days,
// rounded down, since that is the unit backup requirements are written in.
func volumeBackupScheduleArgs(sch core.VolumeBackupSchedule) map[string]*llx.RawData {
	retention := llx.NilData
	if sch.RetentionSeconds != nil {
		retention = llx.IntData(int64(*sch.RetentionSeconds) / 86400)
	}
	return map[string]*llx.RawData{
		"backupType":               llx.StringData(string(sch.BackupType)),
		"period":                   llx.StringData(string(sch.Period)),
		"retentionDays":            retention,
		"hourOfDay":                intPtrData(sch.HourOfDay),
		"dayOfWeek":                llx.StringData(string(sch.DayOfWeek)),
		"dayOfMonth":               intPtrData(sch.DayOfMonth),
		"month":                    llx.StringData(string(sch.Month)),
		"timeZone":                 llx.StringData(string(sch.TimeZone)),
		"isPreventDeletionEnabled": llx.BoolData(sch.IsPreventDeletionEnabled != nil && *sch.IsPreventDeletionEnabled),
		"isRetentionLockEnabled":   llx.BoolData(sch.IsRetentionLockEnabled != nil && *sch.IsRetentionLockEnabled),
	}
}

func intPtrData(v *int) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.IntData(int64(*v))
}

func initOciComputeVolumeBackupPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.compute", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciCompute).GetVolumeBackupPolicies()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.compute.volumeBackupPolicy", id, items)
}

// assignedBackupPolicy reads the backup policy assigned to a volume, boot
// volume, or volume group: one call per asset, made only when the field is
// read. An asset without a policy reads null.
func assignedBackupPolicy(runtime *plugin.Runtime, region, assetID string, field *plugin.TValue[*mqlOciComputeVolumeBackupPolicy]) (*mqlOciComputeVolumeBackupPolicy, error) {
	if assetID == "" || region == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := runtime.Connection.(*connection.OciConnection)
	svc, err := conn.BlockstorageClient(region)
	if err != nil {
		return nil, err
	}
	resp, err := svc.GetVolumeBackupPolicyAssetAssignment(context.Background(), core.GetVolumeBackupPolicyAssetAssignmentRequest{
		AssetId: common.String(assetID),
	})
	if err != nil {
		return nil, err
	}
	policyID := ""
	if len(resp.Items) > 0 {
		policyID = stringValue(resp.Items[0].PolicyId)
	}
	compute, err := ociComputeService(runtime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(compute.GetVolumeBackupPolicies(), policyID, field)
}

func (o *mqlOciComputeBlockVolume) backupPolicy() (*mqlOciComputeVolumeBackupPolicy, error) {
	return assignedBackupPolicy(o.MqlRuntime, o.cacheRegion, o.Id.Data, &o.BackupPolicy)
}

func (o *mqlOciComputeBootVolume) backupPolicy() (*mqlOciComputeVolumeBackupPolicy, error) {
	return assignedBackupPolicy(o.MqlRuntime, o.cacheRegion, o.Id.Data, &o.BackupPolicy)
}

func (o *mqlOciComputeVolumeGroup) backupPolicy() (*mqlOciComputeVolumeBackupPolicy, error) {
	return assignedBackupPolicy(o.MqlRuntime, o.cacheRegion, o.Id.Data, &o.BackupPolicy)
}

// ---- backups ----

type mqlOciComputeVolumeBackupInternal struct {
	ociCompartmentRef
	cacheKmsKeyID string
	cacheVolumeID string
}

func (o *mqlOciComputeVolumeBackup) id() (string, error) {
	return "oci.compute.volumeBackup/" + o.Id.Data, nil
}

func (o *mqlOciCompute) volumeBackups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.BlockstorageClient(region)
			if err != nil {
				return nil, err
			}
			backups, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.VolumeBackup, *string, error) {
				response, err := svc.ListVolumeBackups(ctx, core.ListVolumeBackupsRequest{
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
			res := make([]any, 0, len(backups))
			for i := range backups {
				b := backups[i]
				m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.compute.volumeBackup", stringValue(b.CompartmentId), map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(b.Id),
					"name":                     llx.StringDataPtr(b.DisplayName),
					"type":                     llx.StringData(string(b.Type)),
					"sourceType":               llx.StringData(string(b.SourceType)),
					"state":                    llx.StringData(string(b.LifecycleState)),
					"sizeInGBs":                llx.IntDataPtr(b.SizeInGBs),
					"uniqueSizeInGBs":          llx.IntDataPtr(b.UniqueSizeInGBs),
					"expirationTime":           sdkTimeData(b.ExpirationTime),
					"retentionExpiresAt":       sdkTimeData(b.TimeRetentionExpiresAt),
					"isPreventDeletionEnabled": llx.BoolData(b.IsPreventDeletionEnabled != nil && *b.IsPreventDeletionEnabled),
					"isRetentionLockEnabled":   llx.BoolData(b.IsRetentionLockEnabled != nil && *b.IsRetentionLockEnabled),
					"created":                  sdkTimeData(b.TimeCreated),
					"freeformTags":             llx.MapData(strMapToAny(b.FreeformTags), types.String),
					"definedTags":              llx.MapData(definedTagsToAny(b.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				vb := m.(*mqlOciComputeVolumeBackup)
				vb.cacheKmsKeyID = stringValue(b.KmsKeyId)
				vb.cacheVolumeID = stringValue(b.VolumeId)
				res = append(res, vb)
			}
			return res, nil
		})
}

func (o *mqlOciComputeVolumeBackup) kmsKey() (*mqlOciKmsKey, error) {
	return resolveRef(o.MqlRuntime, "oci.kms.key", ocidOrEmpty(o.cacheKmsKeyID), &o.KmsKey)
}

func (o *mqlOciComputeVolumeBackup) volume() (*mqlOciComputeBlockVolume, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.GetBlockVolumes(), o.cacheVolumeID, &o.Volume)
}

func (o *mqlOciComputeBlockVolume) backups() ([]any, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := svc.GetVolumeBackups()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, raw := range list.Data {
		if b, ok := raw.(*mqlOciComputeVolumeBackup); ok && b.cacheVolumeID == o.Id.Data {
			out = append(out, b)
		}
	}
	return out, nil
}

type mqlOciComputeBootVolumeBackupInternal struct {
	ociCompartmentRef
	cacheKmsKeyID     string
	cacheBootVolumeID string
}

func (o *mqlOciComputeBootVolumeBackup) id() (string, error) {
	return "oci.compute.bootVolumeBackup/" + o.Id.Data, nil
}

func (o *mqlOciCompute) bootVolumeBackups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.BlockstorageClient(region)
			if err != nil {
				return nil, err
			}
			backups, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.BootVolumeBackup, *string, error) {
				response, err := svc.ListBootVolumeBackups(ctx, core.ListBootVolumeBackupsRequest{
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
			res := make([]any, 0, len(backups))
			for i := range backups {
				b := backups[i]
				m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.compute.bootVolumeBackup", stringValue(b.CompartmentId), map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(b.Id),
					"name":                     llx.StringDataPtr(b.DisplayName),
					"type":                     llx.StringData(string(b.Type)),
					"sourceType":               llx.StringData(string(b.SourceType)),
					"state":                    llx.StringData(string(b.LifecycleState)),
					"sizeInGBs":                llx.IntDataPtr(b.SizeInGBs),
					"uniqueSizeInGBs":          llx.IntDataPtr(b.UniqueSizeInGBs),
					"expirationTime":           sdkTimeData(b.ExpirationTime),
					"retentionExpiresAt":       sdkTimeData(b.TimeRetentionExpiresAt),
					"isPreventDeletionEnabled": llx.BoolData(b.IsPreventDeletionEnabled != nil && *b.IsPreventDeletionEnabled),
					"isRetentionLockEnabled":   llx.BoolData(b.IsRetentionLockEnabled != nil && *b.IsRetentionLockEnabled),
					"created":                  sdkTimeData(b.TimeCreated),
					"freeformTags":             llx.MapData(strMapToAny(b.FreeformTags), types.String),
					"definedTags":              llx.MapData(definedTagsToAny(b.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				bb := m.(*mqlOciComputeBootVolumeBackup)
				bb.cacheKmsKeyID = stringValue(b.KmsKeyId)
				bb.cacheBootVolumeID = stringValue(b.BootVolumeId)
				res = append(res, bb)
			}
			return res, nil
		})
}

func (o *mqlOciComputeBootVolumeBackup) kmsKey() (*mqlOciKmsKey, error) {
	return resolveRef(o.MqlRuntime, "oci.kms.key", ocidOrEmpty(o.cacheKmsKeyID), &o.KmsKey)
}

func (o *mqlOciComputeBootVolumeBackup) bootVolume() (*mqlOciComputeBootVolume, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.GetBootVolumes(), o.cacheBootVolumeID, &o.BootVolume)
}

func (o *mqlOciComputeBootVolume) backups() ([]any, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := svc.GetBootVolumeBackups()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, raw := range list.Data {
		if b, ok := raw.(*mqlOciComputeBootVolumeBackup); ok && b.cacheBootVolumeID == o.Id.Data {
			out = append(out, b)
		}
	}
	return out, nil
}

// ---- volume groups ----

type mqlOciComputeVolumeGroupInternal struct {
	ociCompartmentRef
	cacheRegion    string
	cacheVolumeIDs []string
}

func (o *mqlOciComputeVolumeGroup) id() (string, error) {
	return "oci.compute.volumeGroup/" + o.Id.Data, nil
}

func (o *mqlOciCompute) volumeGroups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.BlockstorageClient(region)
			if err != nil {
				return nil, err
			}
			groups, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]core.VolumeGroup, *string, error) {
				response, err := svc.ListVolumeGroups(ctx, core.ListVolumeGroupsRequest{
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
			res := make([]any, 0, len(groups))
			for i := range groups {
				g := groups[i]
				m, err := createOciResourceInCompartment(o.MqlRuntime, "oci.compute.volumeGroup", stringValue(g.CompartmentId), map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(g.Id),
					"name":               llx.StringDataPtr(g.DisplayName),
					"availabilityDomain": llx.StringDataPtr(g.AvailabilityDomain),
					"state":              llx.StringData(string(g.LifecycleState)),
					"sizeInGBs":          llx.IntDataPtr(g.SizeInGBs),
					"isHydrated":         llx.BoolDataPtr(g.IsHydrated),
					"created":            sdkTimeData(g.TimeCreated),
					"freeformTags":       llx.MapData(strMapToAny(g.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(g.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				vg := m.(*mqlOciComputeVolumeGroup)
				vg.cacheRegion = region
				vg.cacheVolumeIDs = g.VolumeIds
				res = append(res, vg)
			}
			return res, nil
		})
}

// splitVolumeIDs separates a volume group's members into block and boot
// volumes by their OCID kind.
func splitVolumeIDs(ids []string) (block, boot []string) {
	for _, id := range ids {
		switch {
		case strings.HasPrefix(id, "ocid1.bootvolume."):
			boot = append(boot, id)
		case strings.HasPrefix(id, "ocid1.volume."):
			block = append(block, id)
		}
	}
	return block, boot
}

func pickListed(list *plugin.TValue[[]any], ids []string) ([]any, error) {
	if list.Error != nil {
		return nil, list.Error
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	out := []any{}
	for _, raw := range list.Data {
		if r, ok := raw.(interface{ GetId() *plugin.TValue[string] }); ok && want[r.GetId().Data] {
			out = append(out, raw)
		}
	}
	return out, nil
}

func (o *mqlOciComputeVolumeGroup) blockVolumes() ([]any, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	block, _ := splitVolumeIDs(o.cacheVolumeIDs)
	return pickListed(svc.GetBlockVolumes(), block)
}

func (o *mqlOciComputeVolumeGroup) bootVolumes() ([]any, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	_, boot := splitVolumeIDs(o.cacheVolumeIDs)
	return pickListed(svc.GetBootVolumes(), boot)
}

func (o *mqlOciComputeBlockVolume) volumeGroup() (*mqlOciComputeVolumeGroup, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.GetVolumeGroups(), o.cacheVolumeGroupID, &o.VolumeGroup)
}

func (o *mqlOciComputeBootVolume) volumeGroup() (*mqlOciComputeVolumeGroup, error) {
	svc, err := ociComputeService(o.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return ociListedRef(svc.GetVolumeGroups(), o.cacheVolumeGroupID, &o.VolumeGroup)
}

func (o *mqlOciComputeVolumeAttachment) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciComputeVolumeBackupPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciComputeVolumeBackup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciComputeBootVolumeBackup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciComputeVolumeGroup) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}
