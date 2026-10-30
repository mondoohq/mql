// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/filestorage"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciFileStorage) id() (string, error) {
	return "oci.fileStorage", nil
}

func (o *mqlOciFileStorage) fileSystems() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			fsClient, err := conn.FileStorageClient(region)
			if err != nil {
				return nil, err
			}

			// File Storage lists per availability domain, so the domains have to
			// be resolved before the real question can be asked. A failure here
			// is returned rather than skipped: continuing would produce a list
			// missing every file system in the domains that were not read, and
			// a short list reads as a smaller estate rather than as a failure.
			availabilityDomains, err := ociAvailabilityDomains(ctx, conn, region, compartmentID)
			if err != nil {
				return nil, fmt.Errorf(
					"oci.fileStorage.fileSystems: cannot list availability domains in %s, so file systems "+
						"cannot be read and the result would omit them: %w", region, err)
			}

			var res []any
			for _, availabilityDomain := range availabilityDomains {
				fileSystems, err := ociListFileSystems(ctx, fsClient, compartmentID, availabilityDomain)
				if err != nil {
					return nil, err
				}

				for i := range fileSystems {
					fs := fileSystems[i]

					var parentFileSystemID string
					if fs.SourceDetails != nil {
						parentFileSystemID = stringValue(fs.SourceDetails.ParentFileSystemId)
					}

					mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.fileStorage.fileSystem", stringValue(fs.CompartmentId), map[string]*llx.RawData{
						"id":                    llx.StringDataPtr(fs.Id),
						"name":                  llx.StringDataPtr(fs.DisplayName),
						"availabilityDomain":    llx.StringDataPtr(fs.AvailabilityDomain),
						"state":                 llx.StringData(string(fs.LifecycleState)),
						"meteredBytes":          llx.IntDataPtr(fs.MeteredBytes),
						"isCloneParent":         llx.BoolDataPtr(fs.IsCloneParent),
						"quotaEnforcementState": llx.StringData(string(fs.QuotaEnforcementState)),
						"created":               sdkTimeData(fs.TimeCreated),
						"freeformTags":          llx.MapData(strMapToAny(fs.FreeformTags), types.String),
						"definedTags":           llx.MapData(definedTagsToAny(fs.DefinedTags), types.Any),
						"systemTags":            llx.MapData(definedTagsToAny(fs.SystemTags), types.Dict),
					})
					if err != nil {
						return nil, err
					}
					mqlFs := mqlInstance.(*mqlOciFileStorageFileSystem)
					mqlFs.cacheKmsKeyID = stringValue(fs.KmsKeyId)
					mqlFs.cacheParentFileSystemID = parentFileSystemID
					mqlFs.cacheRegion = region
					res = append(res, mqlFs)
				}
			}

			return res, nil
		})
}

// ociListFileSystems lists one compartment's file systems in one availability
// domain.
func ociListFileSystems(ctx context.Context, fsClient *filestorage.FileStorageClient, compartmentID string, availabilityDomain string) ([]filestorage.FileSystemSummary, error) {
	return ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.FileSystemSummary, *string, error) {
		response, err := fsClient.ListFileSystems(ctx, filestorage.ListFileSystemsRequest{
			CompartmentId:      new(compartmentID),
			AvailabilityDomain: new(availabilityDomain),
			Page:               page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
}

type mqlOciFileStorageFileSystemInternal struct {
	ociCompartmentRef
	cacheKmsKeyID           string
	cacheParentFileSystemID string
	cacheRegion             string
	detail                  ociRetryLazy[*filestorage.FileSystem]
}

func (o *mqlOciFileStorageFileSystem) id() (string, error) {
	return "oci.fileStorage.fileSystem/" + o.Id.Data, nil
}

func (o *mqlOciFileStorageFileSystem) kmsKey() (*mqlOciKmsKey, error) {
	return resolveOciKmsKey(o.MqlRuntime, ocidOrEmpty(o.cacheKmsKeyID), &o.KmsKey)
}

// fetchDetail reads the file system's full record.
//
// The listing omits the snapshot policy the file system is attached to, and
// that attachment is the only thing that says whether its snapshots are taken
// on a schedule at all, so it is worth a call - but only for a query that asks
// for it.
func (o *mqlOciFileStorageFileSystem) fetchDetail() (*filestorage.FileSystem, error) {
	return o.detail.get(func() (*filestorage.FileSystem, error) {
		svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetFileSystem(context.Background(), filestorage.GetFileSystemRequest{
			FileSystemId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.FileSystem, nil
	})
}

func (o *mqlOciFileStorageFileSystem) snapshotPolicy() (*mqlOciFileStorageSnapshotPolicy, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		o.SnapshotPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRef(o.MqlRuntime, "oci.fileStorage.snapshotPolicy",
		ocidOrEmpty(stringValue(detail.FilesystemSnapshotPolicyId)), &o.SnapshotPolicy)
}

// exports lists the exports publishing this file system.
//
// Scoped to the file system rather than filtered out of the tenancy-wide
// listing: ListExports accepts a fileSystemId, so asking for one file system's
// exports costs one call instead of walking every compartment.
func (o *mqlOciFileStorageFileSystem) exports() ([]any, error) {
	svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.ExportSummary, *string, error) {
		resp, err := svc.ListExports(ctx, filestorage.ListExportsRequest{
			FileSystemId: new(o.Id.Data),
			Page:         page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}
	return ociExportResources(o.MqlRuntime, items, o.cacheRegion)
}

func (o *mqlOciFileStorageFileSystem) snapshots() ([]any, error) {
	svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.SnapshotSummary, *string, error) {
		resp, err := svc.ListSnapshots(ctx, filestorage.ListSnapshotsRequest{
			FileSystemId: new(o.Id.Data),
			Page:         page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		s := items[i]

		mqlSnapshot, err := CreateResource(o.MqlRuntime, "oci.fileStorage.snapshot", map[string]*llx.RawData{
			"id":             llx.StringDataPtr(s.Id),
			"name":           llx.StringDataPtr(s.Name),
			"state":          llx.StringData(string(s.LifecycleState)),
			"snapshotType":   llx.StringData(string(s.SnapshotType)),
			"snapshotTime":   sdkTimeData(s.SnapshotTime),
			"expirationTime": sdkTimeData(s.ExpirationTime),
			"isCloneSource":  llx.BoolDataPtr(s.IsCloneSource),
			"exclusiveBytes": llx.IntDataPtr(s.ExclusiveBytes),
			"created":        sdkTimeData(s.TimeCreated),
			"freeformTags":   llx.MapData(strMapToAny(s.FreeformTags), types.String),
			"definedTags":    llx.MapData(definedTagsToAny(s.DefinedTags), types.Any),
			"systemTags":     llx.MapData(definedTagsToAny(s.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlSnapshot.(*mqlOciFileStorageSnapshot)
		typed.cacheFileSystemID = stringValue(s.FileSystemId)
		res = append(res, typed)
	}
	return res, nil
}

// ociQuotaRulePrincipalTypes are the scopes a quota rule can be written at.
//
// ListQuotaRules takes exactly one of them per call and has no "any" value, so
// reading a file system's rules means asking once per scope. Enumerated here
// rather than inline so a scope added by a later API version is one edit, and
// so the test can pin the set the SDK offers against the set this asks for -
// a scope missing from this list would silently drop every rule written at it.
var ociQuotaRulePrincipalTypes = []filestorage.ListQuotaRulesPrincipalTypeEnum{
	filestorage.ListQuotaRulesPrincipalTypeFileSystemLevel,
	filestorage.ListQuotaRulesPrincipalTypeDefaultUser,
	filestorage.ListQuotaRulesPrincipalTypeDefaultGroup,
	filestorage.ListQuotaRulesPrincipalTypeIndividualUser,
	filestorage.ListQuotaRulesPrincipalTypeIndividualGroup,
}

func (o *mqlOciFileStorageFileSystem) quotaRules() ([]any, error) {
	svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	res := []any{}
	for _, principalType := range ociQuotaRulePrincipalTypes {
		items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.QuotaRuleSummary, *string, error) {
			resp, err := svc.ListQuotaRules(ctx, filestorage.ListQuotaRulesRequest{
				FileSystemId:  new(o.Id.Data),
				PrincipalType: principalType,
				Page:          page,
			})
			if err != nil {
				return nil, nil, err
			}
			return resp.Items, resp.OpcNextPage, nil
		})
		if err != nil {
			return nil, err
		}

		for i := range items {
			rule := items[i]

			mqlRule, err := CreateResource(o.MqlRuntime, "oci.fileStorage.quotaRule", map[string]*llx.RawData{
				"__id":                  llx.StringData(ociQuotaRuleID(o.Id.Data, rule)),
				"id":                    llx.StringDataPtr(rule.Id),
				"name":                  llx.StringDataPtr(rule.DisplayName),
				"principalType":         llx.StringData(string(rule.PrincipalType)),
				"principalId":           ociOptionalInt(rule.PrincipalId),
				"isHardQuota":           llx.BoolDataPtr(rule.IsHardQuota),
				"quotaLimitInGigabytes": ociOptionalInt(rule.QuotaLimitInGigabytes),
				"usageInBytes":          llx.IntDataPtr(rule.UsageInBytes),
				"created":               sdkTimeData(rule.TimeCreated),
				"timeUpdated":           sdkTimeData(rule.TimeUpdated),
			})
			if err != nil {
				return nil, err
			}
			typed := mqlRule.(*mqlOciFileStorageQuotaRule)
			typed.cacheFileSystemID = stringValue(rule.FileSystemId)
			res = append(res, typed)
		}
	}
	return res, nil
}

// ociQuotaRuleID keys a quota rule in the runtime cache.
//
// The rule's own OCID is optional in the API, and a rule written at
// FILE_SYSTEM_LEVEL comes back without one. Falling back to the file system
// plus the scope keeps two such rules on different file systems apart, which
// an empty id would not.
func ociQuotaRuleID(fileSystemID string, rule filestorage.QuotaRuleSummary) string {
	if id := stringValue(rule.Id); id != "" {
		return id
	}
	principalID := 0
	if rule.PrincipalId != nil {
		principalID = *rule.PrincipalId
	}
	return fmt.Sprintf("%s/quotaRule/%s/%d", fileSystemID, rule.PrincipalType, principalID)
}

// ociFileStorageClient builds a File Storage client for one region.
func ociFileStorageClient(runtime *plugin.Runtime, region string) (*filestorage.FileStorageClient, error) {
	conn := runtime.Connection.(*connection.OciConnection)
	if region == "" {
		return nil, fmt.Errorf("oci.fileStorage: the region of the resource is not known")
	}
	return conn.FileStorageClient(region)
}

// ociFileStorageByDomain runs a File Storage lister over every availability
// domain of one (region, compartment) pair.
//
// Four of this service's list APIs take a mandatory availabilityDomain, so
// each of them would otherwise repeat the same domain resolution, the same
// error message, and the same accumulation loop.
func ociFileStorageByDomain[T any](
	ctx context.Context,
	conn *connection.OciConnection,
	collection string,
	region string,
	compartmentID string,
	list func(ctx context.Context, svc *filestorage.FileStorageClient, availabilityDomain string) ([]T, error),
) ([]T, error) {
	svc, err := conn.FileStorageClient(region)
	if err != nil {
		return nil, err
	}

	availabilityDomains, err := ociAvailabilityDomains(ctx, conn, region, compartmentID)
	if err != nil {
		return nil, fmt.Errorf(
			"%s: cannot list availability domains in %s, so the collection cannot be read and the "+
				"result would omit whatever lives in them: %w", collection, region, err)
	}

	var items []T
	for _, availabilityDomain := range availabilityDomains {
		perDomain, err := list(ctx, svc, availabilityDomain)
		if err != nil {
			return nil, err
		}
		items = append(items, perDomain...)
	}
	return items, nil
}
