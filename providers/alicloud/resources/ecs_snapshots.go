// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	ecsclient "github.com/alibabacloud-go/ecs-20140526/v7/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// ecsSnapshotPageSize is the page size used when enumerating snapshots.
const ecsSnapshotPageSize = 100

// ecsImageSharePageGuard bounds the image share permission walk. The endpoint
// reports no cursor and its TotalCount cannot be attributed to either of the
// two lists it returns, so the walk ends on an empty page; this stops a server
// that ignores PageNumber from looping forever.
const ecsImageSharePageGuard = 100

// ecsImageIsShared reports whether an image is usable outside the owning
// account. Either a named account or a share group is enough; an image with
// neither is private to its owner.
func ecsImageIsShared(accounts, groups []any) bool {
	return len(accounts) > 0 || len(groups) > 0
}

// ecsSnapshotTagsToMap flattens the snapshot tag list into a string map.
func ecsSnapshotTagsToMap(tags *ecsclient.DescribeSnapshotsResponseBodySnapshotsSnapshotTags) map[string]any {
	out := map[string]any{}
	if tags == nil {
		return out
	}
	for _, t := range tags.Tag {
		if t == nil || t.TagKey == nil {
			continue
		}
		out[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
	}
	return out
}

// ---------------------------------------------------------------------------
// image sharing
// ---------------------------------------------------------------------------

// mqlAlicloudEcsImageInternal memoizes the image's share permissions, which the
// sharedAccounts, shareGroups and isShared fields all read.
type mqlAlicloudEcsImageInternal struct {
	shareOnce      sync.Once
	shareAccounts  []any
	shareGroupList []any
}

// sharePermission reads the image's share permissions once. An image whose
// permissions cannot be read yields empty lists, which isShared documents as
// insufficient evidence that an image is private.
func (r *mqlAlicloudEcsImage) sharePermission() ([]any, []any) {
	r.shareOnce.Do(func() {
		r.shareAccounts = []any{}
		r.shareGroupList = []any{}

		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		region := r.RegionId.Data
		client, err := conn.EcsClient(region)
		if err != nil {
			log.Debug().Err(err).Msg("alicloud> could not reach ECS to read image share permissions")
			return
		}

		pageNumber := int32(1)
		for {
			resp, err := client.DescribeImageSharePermission(&ecsclient.DescribeImageSharePermissionRequest{
				RegionId:   new(region),
				ImageId:    new(r.ImageId.Data),
				PageNumber: new(pageNumber),
				PageSize:   tea.Int32(ecsSnapshotPageSize),
			})
			if err != nil {
				// a public marketplace image is not owned by this account, so
				// its share permissions cannot be read; that is the answer
				// rather than a scan failure
				log.Debug().Err(err).Str("image", r.ImageId.Data).
					Msg("alicloud> could not read image share permissions")
				return
			}
			if resp == nil || resp.Body == nil {
				return
			}
			accounts := 0
			if resp.Body.Accounts != nil {
				for _, a := range resp.Body.Accounts.Account {
					if a == nil || tea.StringValue(a.AliyunId) == "" {
						continue
					}
					r.shareAccounts = append(r.shareAccounts, tea.StringValue(a.AliyunId))
					accounts++
				}
			}
			groups := 0
			if resp.Body.ShareGroups != nil {
				for _, g := range resp.Body.ShareGroups.ShareGroup {
					if g == nil || tea.StringValue(g.Group) == "" {
						continue
					}
					r.shareGroupList = append(r.shareGroupList, tea.StringValue(g.Group))
					groups++
				}
			}
			// Terminate on a page that carried nothing, not on a count compared
			// against TotalCount. The response documents TotalCount only as
			// "the total number of records" and the endpoint returns two
			// independent lists, so it is not knowable from the SDK whether it
			// counts accounts alone or accounts and groups together. Comparing
			// against it either stops early and drops shares, or never matches.
			// A page with neither an account nor a group is the honest end of
			// the walk, and pageGuard stops a server that ignores PageNumber.
			if accounts == 0 && groups == 0 {
				return
			}
			if pageNumber >= ecsImageSharePageGuard {
				log.Warn().Str("image", r.ImageId.Data).
					Msg("alicloud> stopped reading image share permissions at the page guard, the list may be incomplete")
				return
			}
			pageNumber++
		}
	})
	return r.shareAccounts, r.shareGroupList
}

func (r *mqlAlicloudEcsImage) sharedAccounts() ([]any, error) {
	accounts, _ := r.sharePermission()
	return accounts, nil
}

func (r *mqlAlicloudEcsImage) shareGroups() ([]any, error) {
	_, groups := r.sharePermission()
	return groups, nil
}

func (r *mqlAlicloudEcsImage) isShared() (bool, error) {
	accounts, groups := r.sharePermission()
	return ecsImageIsShared(accounts, groups), nil
}

// ---------------------------------------------------------------------------
// snapshots
// ---------------------------------------------------------------------------

// mqlAlicloudEcsSnapshotInternal caches the identifiers the snapshot's typed
// references resolve.
type mqlAlicloudEcsSnapshotInternal struct {
	cacheRegion string
	cacheDiskID string
	cacheKeyID  string
}

func (r *mqlAlicloudEcsSnapshot) id() (string, error) {
	return r.RegionId.Data + "/" + r.SnapshotId.Data, nil
}

// snapshots enumerates the account's disk snapshots across every scanned
// region. A region that is not activated, or that the credentials may not read,
// is skipped rather than failing the whole listing, matching the other ECS
// listings.
func (r *mqlAlicloudEcs) snapshots() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.EcsClient(region)
		if err != nil {
			return nil, err
		}

		req := &ecsclient.DescribeSnapshotsRequest{
			RegionId:   new(region),
			MaxResults: tea.Int32(ecsSnapshotPageSize),
		}
		for {
			resp, err := client.DescribeSnapshots(req)
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list ECS snapshots")
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.Snapshots == nil {
				break
			}
			for _, snap := range resp.Body.Snapshots.Snapshot {
				if snap == nil || snap.SnapshotId == nil {
					continue
				}
				kmsKeyID := tea.StringValue(snap.KMSKeyId)
				resource, err := CreateResource(r.MqlRuntime, "alicloud.ecs.snapshot", map[string]*llx.RawData{
					"__id":                     llx.StringData(region + "/" + tea.StringValue(snap.SnapshotId)),
					"regionId":                 llx.StringData(region),
					"snapshotId":               llx.StringDataPtr(snap.SnapshotId),
					"snapshotName":             llx.StringDataPtr(snap.SnapshotName),
					"description":              llx.StringDataPtr(snap.Description),
					"sourceDiskId":             llx.StringDataPtr(snap.SourceDiskId),
					"sourceDiskSize":           llx.StringDataPtr(snap.SourceDiskSize),
					"sourceDiskType":           llx.StringDataPtr(snap.SourceDiskType),
					"sourceRegionId":           llx.StringDataPtr(snap.SourceRegionId),
					"sourceSnapshotId":         llx.StringDataPtr(snap.SourceSnapshotId),
					"encrypted":                llx.BoolData(tea.BoolValue(snap.Encrypted)),
					"kmsKeyId":                 llx.StringData(kmsKeyID),
					"encryptedWithCustomerKey": llx.BoolData(kmsKeyID != ""),
					"status":                   llx.StringDataPtr(snap.Status),
					"progress":                 llx.StringDataPtr(snap.Progress),
					"available":                llx.BoolData(tea.BoolValue(snap.Available)),
					"category":                 llx.StringDataPtr(snap.Category),
					"retentionDays":            llx.IntData(int64(tea.Int32Value(snap.RetentionDays))),
					"snapshotType":             llx.StringDataPtr(snap.SnapshotType),
					"usage":                    llx.StringDataPtr(snap.Usage),
					"fullSnapshotSizeInBytes":  llx.IntData(tea.Int64Value(snap.FullSnapshotSizeInBytes)),
					"instantAccess":            llx.BoolData(tea.BoolValue(snap.InstantAccess)),
					"creationTime":             llx.TimeDataPtr(parseEcsTime(snap.CreationTime)),
					"lastModifiedTime":         llx.TimeDataPtr(parseEcsTime(snap.LastModifiedTime)),
					"resourceGroupId":          llx.StringDataPtr(snap.ResourceGroupId),
					"tags":                     llx.MapData(ecsSnapshotTagsToMap(snap.Tags), types.String),
				})
				if err != nil {
					return nil, err
				}
				mqlSnapshot := resource.(*mqlAlicloudEcsSnapshot)
				mqlSnapshot.cacheRegion = region
				mqlSnapshot.cacheDiskID = tea.StringValue(snap.SourceDiskId)
				mqlSnapshot.cacheKeyID = kmsKeyID
				res = append(res, mqlSnapshot)
			}
			if tea.StringValue(resp.Body.NextToken) == "" {
				break
			}
			req.NextToken = resp.Body.NextToken
		}
	}
	return res, nil
}

func (r *mqlAlicloudEcsSnapshot) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// kmsKey resolves the customer master key that encrypts the snapshot, or null
// when the snapshot is unencrypted or uses the service-managed key.
func (r *mqlAlicloudEcsSnapshot) kmsKey() (*mqlAlicloudKmsKey, error) {
	if r.cacheKeyID == "" {
		r.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	key, err := resolveKmsKey(r.MqlRuntime, r.cacheRegion, r.cacheKeyID)
	if err != nil || key == nil {
		r.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return key, nil
}

// disk resolves the source disk by scanning alicloud.ecs.disks, which is
// fetched once for the scan, rather than through a lookup per snapshot. Null
// when the disk has since been deleted.
func (r *mqlAlicloudEcsSnapshot) disk() (*mqlAlicloudEcsDisk, error) {
	if r.cacheDiskID == "" {
		r.Disk.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	disks, err := ecsDiskList(r.MqlRuntime)
	if err != nil {
		r.Disk.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, entry := range disks {
		disk, ok := entry.(*mqlAlicloudEcsDisk)
		if !ok {
			continue
		}
		if disk.DiskId.Data == r.cacheDiskID && disk.RegionId.Data == r.cacheRegion {
			return disk, nil
		}
	}
	r.Disk.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// snapshots lists the snapshots taken from this disk, resolved out of the
// account-wide snapshot listing so a query over every disk costs one walk
// rather than one call per disk.
func (r *mqlAlicloudEcsDisk) snapshots() ([]any, error) {
	ecs, err := CreateResource(r.MqlRuntime, "alicloud.ecs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	snapshots := ecs.(*mqlAlicloudEcs).GetSnapshots()
	if snapshots.Error != nil {
		return nil, snapshots.Error
	}

	res := []any{}
	for _, entry := range snapshots.Data {
		snapshot, ok := entry.(*mqlAlicloudEcsSnapshot)
		if !ok {
			continue
		}
		if snapshot.SourceDiskId.Data == r.DiskId.Data && snapshot.RegionId.Data == r.RegionId.Data {
			res = append(res, snapshot)
		}
	}
	return res, nil
}

// ecsDiskList returns the account-wide disk listing, which is cached by the
// runtime after the first read.
func ecsDiskList(runtime *plugin.Runtime) ([]any, error) {
	ecs, err := CreateResource(runtime, "alicloud.ecs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	disks := ecs.(*mqlAlicloudEcs).GetDisks()
	if disks.Error != nil {
		return nil, disks.Error
	}
	return disks.Data, nil
}
