// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/oracle/oci-go-sdk/v65/filestorage"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// Who is allowed to mount a file system.
//
// The file system resource on its own carries a size, a state and an
// encryption key, and says nothing about access. The authorization lives one
// level out, split across three objects: an export publishes a file system at
// a path and carries the client options that admit source addresses, an export
// set groups the exports served together, and a mount target places them on a
// subnet and decides how UNIX identities are mapped. A share open to
// 0.0.0.0/0 with root squash off is a statement made entirely in those three,
// and none of it was previously visible.

// ----- mount targets -----

type mqlOciFileStorageMountTargetInternal struct {
	cacheCompartmentID string
	cacheRegion        string
	cacheSubnetID      string
	cacheNsgIDs        []string
	cacheExportSetID   string
	detail             ociRetryLazy[*filestorage.MountTarget]
}

func (o *mqlOciFileStorage) mountTargets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			items, err := ociFileStorageByDomain(ctx, conn, "oci.fileStorage.mountTargets", region, compartmentID,
				func(ctx context.Context, svc *filestorage.FileStorageClient, availabilityDomain string) ([]filestorage.MountTargetSummary, error) {
					return ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.MountTargetSummary, *string, error) {
						resp, err := svc.ListMountTargets(ctx, filestorage.ListMountTargetsRequest{
							CompartmentId:      new(compartmentID),
							AvailabilityDomain: new(availabilityDomain),
							Page:               page,
						})
						if err != nil {
							return nil, nil, err
						}
						return resp.Items, resp.OpcNextPage, nil
					})
				})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				mt := items[i]

				mqlTarget, err := CreateResource(o.MqlRuntime, "oci.fileStorage.mountTarget", map[string]*llx.RawData{
					"id":                      llx.StringDataPtr(mt.Id),
					"name":                    llx.StringDataPtr(mt.DisplayName),
					"availabilityDomain":      llx.StringDataPtr(mt.AvailabilityDomain),
					"state":                   llx.StringData(string(mt.LifecycleState)),
					"privateIpIds":            llx.ArrayData(stringsToAny(mt.PrivateIpIds), types.String),
					"ipv6Ids":                 llx.ArrayData(stringsToAny(mt.MountTargetIpv6Ids), types.String),
					"requestedThroughput":     llx.IntDataPtr(mt.RequestedThroughput),
					"observedThroughput":      llx.IntDataPtr(mt.ObservedThroughput),
					"reservedStorageCapacity": llx.IntDataPtr(mt.ReservedStorageCapacity),
					"created":                 sdkTimeData(mt.TimeCreated),
					"securityAttributes":      llx.MapData(definedTagsToAny(mt.SecurityAttributes), types.Dict),
					"freeformTags":            llx.MapData(strMapToAny(mt.FreeformTags), types.String),
					"definedTags":             llx.MapData(definedTagsToAny(mt.DefinedTags), types.Any),
					"systemTags":              llx.MapData(definedTagsToAny(mt.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlTarget.(*mqlOciFileStorageMountTarget)
				typed.cacheCompartmentID = stringValue(mt.CompartmentId)
				typed.cacheRegion = region
				typed.cacheSubnetID = stringValue(mt.SubnetId)
				typed.cacheNsgIDs = mt.NsgIds
				typed.cacheExportSetID = stringValue(mt.ExportSetId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciFileStorageMountTarget) id() (string, error) {
	return "oci.fileStorage.mountTarget/" + o.Id.Data, nil
}

func (o *mqlOciFileStorageMountTarget) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciFileStorageMountTarget) subnet() (*mqlOciNetworkSubnet, error) {
	return resolveOciSubnet(o.MqlRuntime, ocidOrEmpty(o.cacheSubnetID), &o.Subnet)
}

func (o *mqlOciFileStorageMountTarget) securityGroups() ([]any, error) {
	return resolveOciSecurityGroups(o.MqlRuntime, stringsToAny(o.cacheNsgIDs))
}

func (o *mqlOciFileStorageMountTarget) exportSet() (*mqlOciFileStorageExportSet, error) {
	return resolveRef(o.MqlRuntime, "oci.fileStorage.exportSet", ocidOrEmpty(o.cacheExportSetID), &o.ExportSet)
}

func (o *mqlOciFileStorageMountTarget) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.SecurityAttributes.Data)
}

// fetchDetail reads the mount target's full record.
//
// The listing omits both identity-mapping configurations. Kerberos and the
// LDAP idmap are the whole authentication story for a mount target, so
// everything below comes from a Get rather than from the list, and only for a
// query that asks about it.
func (o *mqlOciFileStorageMountTarget) fetchDetail() (*filestorage.MountTarget, error) {
	return o.detail.get(func() (*filestorage.MountTarget, error) {
		svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetMountTarget(context.Background(), filestorage.GetMountTargetRequest{
			MountTargetId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.MountTarget, nil
	})
}

func (o *mqlOciFileStorageMountTarget) idmapType() (string, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(detail.IdmapType), nil
}

// ldapIdmap returns the mount target's LDAP identity mapping, or nil when it
// does not map identities through a directory.
func (o *mqlOciFileStorageMountTarget) ldapIdmap() (*filestorage.LdapIdmap, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	return detail.LdapIdmap, nil
}

func (o *mqlOciFileStorageMountTarget) ldapSchemaType() (string, error) {
	idmap, err := o.ldapIdmap()
	if err != nil {
		return "", err
	}
	if idmap == nil {
		o.LdapSchemaType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(idmap.SchemaType), nil
}

func (o *mqlOciFileStorageMountTarget) ldapUserSearchBase() (string, error) {
	idmap, err := o.ldapIdmap()
	if err != nil {
		return "", err
	}
	if idmap == nil || idmap.UserSearchBase == nil {
		o.LdapUserSearchBase.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *idmap.UserSearchBase, nil
}

func (o *mqlOciFileStorageMountTarget) ldapGroupSearchBase() (string, error) {
	idmap, err := o.ldapIdmap()
	if err != nil {
		return "", err
	}
	if idmap == nil || idmap.GroupSearchBase == nil {
		o.LdapGroupSearchBase.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *idmap.GroupSearchBase, nil
}

func (o *mqlOciFileStorageMountTarget) ldapCacheRefreshIntervalSeconds() (int64, error) {
	idmap, err := o.ldapIdmap()
	if err != nil {
		return 0, err
	}
	if idmap == nil || idmap.CacheRefreshIntervalSeconds == nil {
		o.LdapCacheRefreshIntervalSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*idmap.CacheRefreshIntervalSeconds), nil
}

func (o *mqlOciFileStorageMountTarget) ldapCacheLifetimeSeconds() (int64, error) {
	idmap, err := o.ldapIdmap()
	if err != nil {
		return 0, err
	}
	if idmap == nil || idmap.CacheLifetimeSeconds == nil {
		o.LdapCacheLifetimeSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*idmap.CacheLifetimeSeconds), nil
}

func (o *mqlOciFileStorageMountTarget) ldapNegativeCacheLifetimeSeconds() (int64, error) {
	idmap, err := o.ldapIdmap()
	if err != nil {
		return 0, err
	}
	if idmap == nil || idmap.NegativeCacheLifetimeSeconds == nil {
		o.LdapNegativeCacheLifetimeSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*idmap.NegativeCacheLifetimeSeconds), nil
}

// ldapOutboundConnectors resolves the directory servers the identity mapping
// binds to.
//
// The API models them as two named slots rather than a list, and either may be
// unset, so the pair is flattened into one collection of the connectors that
// are actually configured.
func (o *mqlOciFileStorageMountTarget) ldapOutboundConnectors() ([]any, error) {
	idmap, err := o.ldapIdmap()
	if err != nil {
		return nil, err
	}
	if idmap == nil {
		return []any{}, nil
	}

	ids := []any{}
	for _, id := range []*string{idmap.OutboundConnector1Id, idmap.OutboundConnector2Id} {
		if value := stringValue(id); value != "" {
			ids = append(ids, value)
		}
	}
	return ociResolveRefs(o.MqlRuntime, "oci.fileStorage.outboundConnector", "outbound connector", ids)
}

func (o *mqlOciFileStorageMountTarget) kerberosEnabled() (bool, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return false, err
	}
	// A mount target with no Kerberos block accepts AUTH_SYS only, which is
	// the same statement as Kerberos being off. False rather than null keeps
	// `kerberosEnabled == false` matching every mount target that does not
	// authenticate, not only those that configured it and turned it off.
	if detail.Kerberos == nil || detail.Kerberos.IsKerberosEnabled == nil {
		return false, nil
	}
	return *detail.Kerberos.IsKerberosEnabled, nil
}

func (o *mqlOciFileStorageMountTarget) kerberosRealm() (string, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail.Kerberos == nil || detail.Kerberos.KerberosRealm == nil {
		o.KerberosRealm.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *detail.Kerberos.KerberosRealm, nil
}

func (o *mqlOciFileStorageMountTarget) kerberosKeyTabSecret() (*mqlOciVaultSecret, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	id := ""
	if detail.Kerberos != nil {
		id = ocidOrEmpty(stringValue(detail.Kerberos.KeyTabSecretId))
	}
	return resolveRef(o.MqlRuntime, "oci.vault.secret", id, &o.KerberosKeyTabSecret)
}

func (o *mqlOciFileStorageMountTarget) kerberosKeyTabSecretVersion() (int64, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.Kerberos == nil || detail.Kerberos.CurrentKeyTabSecretVersion == nil {
		o.KerberosKeyTabSecretVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*detail.Kerberos.CurrentKeyTabSecretVersion), nil
}

func (o *mqlOciFileStorageMountTarget) kerberosBackupKeyTabSecretVersion() (int64, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.Kerberos == nil || detail.Kerberos.BackupKeyTabSecretVersion == nil {
		o.KerberosBackupKeyTabSecretVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*detail.Kerberos.BackupKeyTabSecretVersion), nil
}

// ----- export sets -----

type mqlOciFileStorageExportSetInternal struct {
	cacheCompartmentID string
	cacheRegion        string
	cacheVcnID         string
	detail             ociRetryLazy[*filestorage.ExportSet]
}

func (o *mqlOciFileStorage) exportSets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			items, err := ociFileStorageByDomain(ctx, conn, "oci.fileStorage.exportSets", region, compartmentID,
				func(ctx context.Context, svc *filestorage.FileStorageClient, availabilityDomain string) ([]filestorage.ExportSetSummary, error) {
					return ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.ExportSetSummary, *string, error) {
						resp, err := svc.ListExportSets(ctx, filestorage.ListExportSetsRequest{
							CompartmentId:      new(compartmentID),
							AvailabilityDomain: new(availabilityDomain),
							Page:               page,
						})
						if err != nil {
							return nil, nil, err
						}
						return resp.Items, resp.OpcNextPage, nil
					})
				})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				set := items[i]

				mqlSet, err := CreateResource(o.MqlRuntime, "oci.fileStorage.exportSet", map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(set.Id),
					"name":               llx.StringDataPtr(set.DisplayName),
					"availabilityDomain": llx.StringDataPtr(set.AvailabilityDomain),
					"state":              llx.StringData(string(set.LifecycleState)),
					"created":            sdkTimeData(set.TimeCreated),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlSet.(*mqlOciFileStorageExportSet)
				typed.cacheCompartmentID = stringValue(set.CompartmentId)
				typed.cacheRegion = region
				typed.cacheVcnID = stringValue(set.VcnId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciFileStorageExportSet) id() (string, error) {
	return "oci.fileStorage.exportSet/" + o.Id.Data, nil
}

func (o *mqlOciFileStorageExportSet) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciFileStorageExportSet) vcn() (*mqlOciNetworkVcn, error) {
	return resolveRef(o.MqlRuntime, "oci.network.vcn", ocidOrEmpty(o.cacheVcnID), &o.Vcn)
}

func (o *mqlOciFileStorageExportSet) fetchDetail() (*filestorage.ExportSet, error) {
	return o.detail.get(func() (*filestorage.ExportSet, error) {
		svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetExportSet(context.Background(), filestorage.GetExportSetRequest{
			ExportSetId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.ExportSet, nil
	})
}

func (o *mqlOciFileStorageExportSet) maxFsStatBytes() (int64, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.MaxFsStatBytes == nil {
		o.MaxFsStatBytes.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *detail.MaxFsStatBytes, nil
}

func (o *mqlOciFileStorageExportSet) maxFsStatFiles() (int64, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.MaxFsStatFiles == nil {
		o.MaxFsStatFiles.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *detail.MaxFsStatFiles, nil
}

func (o *mqlOciFileStorageExportSet) exports() ([]any, error) {
	svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.ExportSummary, *string, error) {
		resp, err := svc.ListExports(ctx, filestorage.ListExportsRequest{
			ExportSetId: new(o.Id.Data),
			Page:        page,
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

// ----- exports -----

type mqlOciFileStorageExportInternal struct {
	cacheRegion       string
	cacheFileSystemID string
	cacheExportSetID  string
	detail            ociRetryLazy[*filestorage.Export]
}

func (o *mqlOciFileStorage) exports() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.FileStorageClient(region)
			if err != nil {
				return nil, err
			}

			// Unlike the rest of this service, ListExports is not scoped to an
			// availability domain: one call covers the whole compartment.
			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.ExportSummary, *string, error) {
				resp, err := svc.ListExports(ctx, filestorage.ListExportsRequest{
					CompartmentId: new(compartmentID),
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
			return ociExportResources(o.MqlRuntime, items, region)
		})
}

// ociExportResources builds the export resources for one listing.
//
// Shared by the three ways an export is reached - the tenancy-wide listing, an
// export set's exports, and a file system's exports - so that all three agree
// on the cache key and on which references are carried forward.
func ociExportResources(runtime *plugin.Runtime, items []filestorage.ExportSummary, region string) ([]any, error) {
	res := make([]any, 0, len(items))
	for i := range items {
		export := items[i]

		mqlExport, err := CreateResource(runtime, "oci.fileStorage.export", map[string]*llx.RawData{
			"id":                      llx.StringDataPtr(export.Id),
			"path":                    llx.StringDataPtr(export.Path),
			"state":                   llx.StringData(string(export.LifecycleState)),
			"isIdmapGroupsForSysAuth": llx.BoolDataPtr(export.IsIdmapGroupsForSysAuth),
			"created":                 sdkTimeData(export.TimeCreated),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlExport.(*mqlOciFileStorageExport)
		typed.cacheRegion = region
		typed.cacheFileSystemID = stringValue(export.FileSystemId)
		typed.cacheExportSetID = stringValue(export.ExportSetId)
		res = append(res, typed)
	}
	return res, nil
}

func (o *mqlOciFileStorageExport) id() (string, error) {
	return "oci.fileStorage.export/" + o.Id.Data, nil
}

func (o *mqlOciFileStorageExport) fileSystem() (*mqlOciFileStorageFileSystem, error) {
	return resolveRef(o.MqlRuntime, "oci.fileStorage.fileSystem", ocidOrEmpty(o.cacheFileSystemID), &o.FileSystem)
}

func (o *mqlOciFileStorageExport) exportSet() (*mqlOciFileStorageExportSet, error) {
	return resolveRef(o.MqlRuntime, "oci.fileStorage.exportSet", ocidOrEmpty(o.cacheExportSetID), &o.ExportSet)
}

// options returns the client options that authorize access to the export.
//
// This is the reason the resource exists, and it is the one part the listing
// does not carry: ExportSummary has no exportOptions field at all, so the
// rules have to be read per export. An export whose options cannot be read
// therefore reports an error rather than an empty list, because an empty list
// of rules reads as an export nobody can mount, which is the opposite of what
// an unreadable one might be.
func (o *mqlOciFileStorageExport) options() ([]any, error) {
	detail, err := o.detail.get(func() (*filestorage.Export, error) {
		svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetExport(context.Background(), filestorage.GetExportRequest{
			ExportId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.Export, nil
	})
	if err != nil {
		return nil, err
	}
	return ociExportOptionResources(o.MqlRuntime, o.Id.Data, detail.ExportOptions)
}

// ociExportOptionResources builds one resource per client option on an export.
//
// Options are keyed by their position rather than by source: the API preserves
// their order, evaluates them in it, and does not forbid two rules naming the
// same source, so the index is the only stable identity a rule has.
func ociExportOptionResources(runtime *plugin.Runtime, exportID string, options []filestorage.ClientOptions) ([]any, error) {
	res := make([]any, 0, len(options))
	for i := range options {
		mqlOption, err := CreateResource(runtime, "oci.fileStorage.export.option",
			ociExportOptionFields(exportID, i, options[i]))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlOption)
	}
	return res, nil
}

// ociExportOptionFields flattens one client option into resource fields.
//
// Separated from the resource construction because this is the decode an audit
// actually rests on, and every one of these fields has a wrong reading that
// looks right. An absent requirePrivilegedSourcePort read as false says the
// export accepts unprivileged ports when it may not; an absent access read as
// the empty string is not READ_ONLY; an absent anonymousUid read as 0 names
// root, which is the single most consequential UID there is. So the pointer
// fields stay null when the API omits them rather than being flattened to
// their zero values.
func ociExportOptionFields(exportID string, index int, option filestorage.ClientOptions) map[string]*llx.RawData {
	allowedAuth := make([]string, 0, len(option.AllowedAuth))
	for _, auth := range option.AllowedAuth {
		allowedAuth = append(allowedAuth, string(auth))
	}

	return map[string]*llx.RawData{
		"__id":                        llx.StringData(fmt.Sprintf("%s/option/%d", exportID, index)),
		"source":                      llx.StringDataPtr(option.Source),
		"access":                      llx.StringData(string(option.Access)),
		"identitySquash":              llx.StringData(string(option.IdentitySquash)),
		"requirePrivilegedSourcePort": llx.BoolDataPtr(option.RequirePrivilegedSourcePort),
		"anonymousUid":                llx.IntDataPtr(option.AnonymousUid),
		"anonymousGid":                llx.IntDataPtr(option.AnonymousGid),
		"isAnonymousAccessAllowed":    llx.BoolDataPtr(option.IsAnonymousAccessAllowed),
		"allowedAuth":                 llx.ArrayData(stringsToAny(allowedAuth), types.String),
	}
}

// ----- snapshots -----

type mqlOciFileStorageSnapshotInternal struct {
	cacheFileSystemID string
}

func (o *mqlOciFileStorageSnapshot) id() (string, error) {
	return "oci.fileStorage.snapshot/" + o.Id.Data, nil
}

func (o *mqlOciFileStorageSnapshot) fileSystem() (*mqlOciFileStorageFileSystem, error) {
	return resolveRef(o.MqlRuntime, "oci.fileStorage.fileSystem", ocidOrEmpty(o.cacheFileSystemID), &o.FileSystem)
}

// ----- quota rules -----

type mqlOciFileStorageQuotaRuleInternal struct {
	cacheFileSystemID string
}

func (o *mqlOciFileStorageQuotaRule) fileSystem() (*mqlOciFileStorageFileSystem, error) {
	return resolveRef(o.MqlRuntime, "oci.fileStorage.fileSystem", ocidOrEmpty(o.cacheFileSystemID), &o.FileSystem)
}

// ----- snapshot policies -----

type mqlOciFileStorageSnapshotPolicyInternal struct {
	cacheCompartmentID string
	cacheRegion        string
	detail             ociRetryLazy[*filestorage.FilesystemSnapshotPolicy]
}

func (o *mqlOciFileStorage) snapshotPolicies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			items, err := ociFileStorageByDomain(ctx, conn, "oci.fileStorage.snapshotPolicies", region, compartmentID,
				func(ctx context.Context, svc *filestorage.FileStorageClient, availabilityDomain string) ([]filestorage.FilesystemSnapshotPolicySummary, error) {
					return ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.FilesystemSnapshotPolicySummary, *string, error) {
						resp, err := svc.ListFilesystemSnapshotPolicies(ctx, filestorage.ListFilesystemSnapshotPoliciesRequest{
							CompartmentId:      new(compartmentID),
							AvailabilityDomain: new(availabilityDomain),
							Page:               page,
						})
						if err != nil {
							return nil, nil, err
						}
						return resp.Items, resp.OpcNextPage, nil
					})
				})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				policy := items[i]

				mqlPolicy, err := CreateResource(o.MqlRuntime, "oci.fileStorage.snapshotPolicy", map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(policy.Id),
					"name":               llx.StringDataPtr(policy.DisplayName),
					"availabilityDomain": llx.StringDataPtr(policy.AvailabilityDomain),
					"state":              llx.StringData(string(policy.LifecycleState)),
					"policyPrefix":       llx.StringDataPtr(policy.PolicyPrefix),
					"created":            sdkTimeData(policy.TimeCreated),
					"freeformTags":       llx.MapData(strMapToAny(policy.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(policy.DefinedTags), types.Any),
					"systemTags":         llx.MapData(definedTagsToAny(policy.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlPolicy.(*mqlOciFileStorageSnapshotPolicy)
				typed.cacheCompartmentID = stringValue(policy.CompartmentId)
				typed.cacheRegion = region
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciFileStorageSnapshotPolicy) id() (string, error) {
	return "oci.fileStorage.snapshotPolicy/" + o.Id.Data, nil
}

func (o *mqlOciFileStorageSnapshotPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// schedules returns the recurrences the policy takes snapshots on.
//
// The listing reports that a policy exists and nothing about what it does, so
// the schedules - and with them every retention duration - come from a Get.
func (o *mqlOciFileStorageSnapshotPolicy) schedules() ([]any, error) {
	detail, err := o.detail.get(func() (*filestorage.FilesystemSnapshotPolicy, error) {
		svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetFilesystemSnapshotPolicy(context.Background(), filestorage.GetFilesystemSnapshotPolicyRequest{
			FilesystemSnapshotPolicyId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.FilesystemSnapshotPolicy, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(detail.Schedules))
	for i := range detail.Schedules {
		schedule := detail.Schedules[i]

		mqlSchedule, err := CreateResource(o.MqlRuntime, "oci.fileStorage.snapshotPolicy.schedule", map[string]*llx.RawData{
			"__id":                       llx.StringData(fmt.Sprintf("%s/schedule/%d", o.Id.Data, i)),
			"period":                     llx.StringData(string(schedule.Period)),
			"timeZone":                   llx.StringData(string(schedule.TimeZone)),
			"schedulePrefix":             llx.StringDataPtr(schedule.SchedulePrefix),
			"timeScheduleStart":          sdkTimeData(schedule.TimeScheduleStart),
			"retentionDurationInSeconds": llx.IntDataPtr(schedule.RetentionDurationInSeconds),
			"hourOfDay":                  ociOptionalInt(schedule.HourOfDay),
			"dayOfWeek":                  llx.StringData(string(schedule.DayOfWeek)),
			"dayOfMonth":                 ociOptionalInt(schedule.DayOfMonth),
			"month":                      llx.StringData(string(schedule.Month)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSchedule)
	}
	return res, nil
}

// ----- replications -----

type mqlOciFileStorageReplicationInternal struct {
	cacheCompartmentID string
	cacheRegion        string
	detail             ociRetryLazy[*filestorage.Replication]
}

func (o *mqlOciFileStorage) replications() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			items, err := ociFileStorageByDomain(ctx, conn, "oci.fileStorage.replications", region, compartmentID,
				func(ctx context.Context, svc *filestorage.FileStorageClient, availabilityDomain string) ([]filestorage.ReplicationSummary, error) {
					return ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.ReplicationSummary, *string, error) {
						resp, err := svc.ListReplications(ctx, filestorage.ListReplicationsRequest{
							CompartmentId:      new(compartmentID),
							AvailabilityDomain: new(availabilityDomain),
							Page:               page,
						})
						if err != nil {
							return nil, nil, err
						}
						return resp.Items, resp.OpcNextPage, nil
					})
				})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				replication := items[i]

				mqlReplication, err := CreateResource(o.MqlRuntime, "oci.fileStorage.replication", map[string]*llx.RawData{
					"id":                  llx.StringDataPtr(replication.Id),
					"name":                llx.StringDataPtr(replication.DisplayName),
					"availabilityDomain":  llx.StringDataPtr(replication.AvailabilityDomain),
					"state":               llx.StringData(string(replication.LifecycleState)),
					"replicationInterval": llx.IntDataPtr(replication.ReplicationInterval),
					"recoveryPointTime":   sdkTimeData(replication.RecoveryPointTime),
					"lifecycleDetails":    llx.StringDataPtr(replication.LifecycleDetails),
					"created":             sdkTimeData(replication.TimeCreated),
					"freeformTags":        llx.MapData(strMapToAny(replication.FreeformTags), types.String),
					"definedTags":         llx.MapData(definedTagsToAny(replication.DefinedTags), types.Any),
					"systemTags":          llx.MapData(definedTagsToAny(replication.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlReplication.(*mqlOciFileStorageReplication)
				typed.cacheCompartmentID = stringValue(replication.CompartmentId)
				typed.cacheRegion = region
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciFileStorageReplication) id() (string, error) {
	return "oci.fileStorage.replication/" + o.Id.Data, nil
}

func (o *mqlOciFileStorageReplication) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// fetchDetail reads the replication's full record.
//
// The listing carries the schedule and the progress but neither end of the
// copy, and which file systems a replication joins is the whole point of the
// resource, so both references come from a Get.
func (o *mqlOciFileStorageReplication) fetchDetail() (*filestorage.Replication, error) {
	return o.detail.get(func() (*filestorage.Replication, error) {
		svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetReplication(context.Background(), filestorage.GetReplicationRequest{
			ReplicationId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.Replication, nil
	})
}

func (o *mqlOciFileStorageReplication) deltaStatus() (string, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(detail.DeltaStatus), nil
}

func (o *mqlOciFileStorageReplication) sourceFileSystem() (*mqlOciFileStorageFileSystem, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}
	return resolveRef(o.MqlRuntime, "oci.fileStorage.fileSystem",
		ocidOrEmpty(stringValue(detail.SourceId)), &o.SourceFileSystem)
}

// targetFileSystem resolves the far end of the replication, or reports null
// when this scan cannot see it.
//
// Unlike every other reference in this file the target is expected to be
// somewhere else: replication exists to put a copy in another region, and a
// region outside the scan's subscriptions or its region filter is a normal
// configuration rather than a fault. Failing here would turn a working
// cross-region replication into an error on the whole collection, so the
// unreachable case is reported as null and logged.
func (o *mqlOciFileStorageReplication) targetFileSystem() (*mqlOciFileStorageFileSystem, error) {
	detail, err := o.fetchDetail()
	if err != nil {
		return nil, err
	}

	id := ocidOrEmpty(stringValue(detail.TargetId))
	if id == "" {
		o.TargetFileSystem.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(o.MqlRuntime, "oci.fileStorage.fileSystem", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		ociLogSkippedRef("replication target file system", id, err)
		o.TargetFileSystem.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	typed, ok := res.(*mqlOciFileStorageFileSystem)
	if !ok {
		return nil, fmt.Errorf("oci: oci.fileStorage.fileSystem resolved to an unexpected resource type")
	}
	return typed, nil
}

// ----- outbound connectors -----

type mqlOciFileStorageOutboundConnectorInternal struct {
	cacheCompartmentID string
	cacheRegion        string
	detail             ociRetryLazy[filestorage.OutboundConnector]
}

func (o *mqlOciFileStorage) outboundConnectors() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			items, err := ociFileStorageByDomain(ctx, conn, "oci.fileStorage.outboundConnectors", region, compartmentID,
				func(ctx context.Context, svc *filestorage.FileStorageClient, availabilityDomain string) ([]filestorage.OutboundConnectorSummary, error) {
					return ociPaginate(ctx, func(ctx context.Context, page *string) ([]filestorage.OutboundConnectorSummary, *string, error) {
						resp, err := svc.ListOutboundConnectors(ctx, filestorage.ListOutboundConnectorsRequest{
							CompartmentId:      new(compartmentID),
							AvailabilityDomain: new(availabilityDomain),
							Page:               page,
						})
						if err != nil {
							return nil, nil, err
						}
						return resp.Items, resp.OpcNextPage, nil
					})
				})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				fields, err := ociOutboundConnectorFields(items[i])
				if err != nil {
					return nil, err
				}

				mqlConnector, err := CreateResource(o.MqlRuntime, "oci.fileStorage.outboundConnector", fields)
				if err != nil {
					return nil, err
				}
				typed := mqlConnector.(*mqlOciFileStorageOutboundConnector)
				typed.cacheCompartmentID = stringValue(items[i].GetCompartmentId())
				typed.cacheRegion = region
				res = append(res, typed)
			}
			return res, nil
		})
}

// ociOutboundConnectorFields flattens one member of the OutboundConnectorSummary
// union into resource fields.
//
// LDAPBIND is the only member the service offers today. An unrecognised member
// is an error rather than a skip: a mount target's identity mapping points at
// a connector by OCID, so dropping one would leave that reference resolving to
// nothing and the mapping reading as unconfigured.
func ociOutboundConnectorFields(summary filestorage.OutboundConnectorSummary) (map[string]*llx.RawData, error) {
	ldap, ok := summary.(filestorage.LdapBindAccountSummary)
	if !ok {
		return nil, fmt.Errorf(
			"oci.fileStorage.outboundConnector: unhandled outbound connector type %T", summary)
	}

	endpoints, err := convert.JsonToDictSlice(ldap.Endpoints)
	if err != nil {
		return nil, err
	}

	return map[string]*llx.RawData{
		"id":                    llx.StringDataPtr(ldap.Id),
		"name":                  llx.StringDataPtr(ldap.DisplayName),
		"availabilityDomain":    llx.StringDataPtr(ldap.AvailabilityDomain),
		"state":                 llx.StringData(string(ldap.LifecycleState)),
		"connectorType":         llx.StringData(string(filestorage.OutboundConnectorConnectorTypeLdapbind)),
		"bindDistinguishedName": llx.StringDataPtr(ldap.BindDistinguishedName),
		"endpoints":             llx.ArrayData(endpoints, types.Dict),
		"created":               sdkTimeData(ldap.TimeCreated),
		"freeformTags":          llx.MapData(strMapToAny(ldap.FreeformTags), types.String),
		"definedTags":           llx.MapData(definedTagsToAny(ldap.DefinedTags), types.Any),
		"systemTags":            llx.MapData(definedTagsToAny(ldap.SystemTags), types.Dict),
	}, nil
}

func (o *mqlOciFileStorageOutboundConnector) id() (string, error) {
	return "oci.fileStorage.outboundConnector/" + o.Id.Data, nil
}

func (o *mqlOciFileStorageOutboundConnector) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// fetchLdapAccount reads the connector's full record.
//
// The listing carries the bind DN but not the secrets behind it, and the
// secrets are what make the connector a credential-bearing object worth
// inventorying, so they come from a Get.
func (o *mqlOciFileStorageOutboundConnector) fetchLdapAccount() (*filestorage.LdapBindAccount, error) {
	detail, err := o.detail.get(func() (filestorage.OutboundConnector, error) {
		svc, err := ociFileStorageClient(o.MqlRuntime, o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetOutboundConnector(context.Background(), filestorage.GetOutboundConnectorRequest{
			OutboundConnectorId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return resp.OutboundConnector, nil
	})
	if err != nil {
		return nil, err
	}

	ldap, ok := detail.(filestorage.LdapBindAccount)
	if !ok {
		return nil, fmt.Errorf(
			"oci.fileStorage.outboundConnector %q: unhandled outbound connector type %T", o.Id.Data, detail)
	}
	return &ldap, nil
}

func (o *mqlOciFileStorageOutboundConnector) passwordSecret() (*mqlOciVaultSecret, error) {
	ldap, err := o.fetchLdapAccount()
	if err != nil {
		return nil, err
	}
	return resolveRef(o.MqlRuntime, "oci.vault.secret",
		ocidOrEmpty(stringValue(ldap.PasswordSecretId)), &o.PasswordSecret)
}

func (o *mqlOciFileStorageOutboundConnector) passwordSecretVersion() (int64, error) {
	ldap, err := o.fetchLdapAccount()
	if err != nil {
		return 0, err
	}
	if ldap.PasswordSecretVersion == nil {
		o.PasswordSecretVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*ldap.PasswordSecretVersion), nil
}

func (o *mqlOciFileStorageOutboundConnector) trustedCertificateSecret() (*mqlOciVaultSecret, error) {
	ldap, err := o.fetchLdapAccount()
	if err != nil {
		return nil, err
	}
	return resolveRef(o.MqlRuntime, "oci.vault.secret",
		ocidOrEmpty(stringValue(ldap.TrustedCertificateSecretId)), &o.TrustedCertificateSecret)
}

func (o *mqlOciFileStorageOutboundConnector) trustedCertificateSecretVersion() (int64, error) {
	ldap, err := o.fetchLdapAccount()
	if err != nil {
		return 0, err
	}
	if ldap.TrustedCertificateSecretVersion == nil {
		o.TrustedCertificateSecretVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*ldap.TrustedCertificateSecretVersion), nil
}
