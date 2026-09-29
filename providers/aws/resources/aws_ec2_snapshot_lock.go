// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
)

// lockedSnapshotCache holds the locks of every locked snapshot in a region,
// keyed by region and then by snapshot ID. DescribeLockedSnapshots answers for
// a whole region in one paginated walk, so reading it per snapshot would turn
// one call into one per snapshot.
type lockedSnapshotCache struct {
	lock    sync.Mutex
	regions map[string]*lockedSnapshotRegion
}

// lockedSnapshotRegion keeps a region's locks once they were read. A failed
// read is not kept, so a transient error (throttling, a timeout) is retried
// by the next snapshot instead of blanking every snapshot in the region.
type lockedSnapshotRegion struct {
	lock    sync.Mutex
	fetched bool
	locks   map[string]ec2types.LockedSnapshotsInfo
}

func (c *lockedSnapshotCache) region(region string) *lockedSnapshotRegion {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.regions == nil {
		c.regions = map[string]*lockedSnapshotRegion{}
	}
	r, ok := c.regions[region]
	if !ok {
		r = &lockedSnapshotRegion{}
		c.regions[region] = r
	}
	return r
}

// indexLockedSnapshots keys lock records by snapshot ID, skipping records
// without one.
func indexLockedSnapshots(infos []ec2types.LockedSnapshotsInfo, into map[string]ec2types.LockedSnapshotsInfo) {
	for _, info := range infos {
		if info.SnapshotId == nil || *info.SnapshotId == "" {
			continue
		}
		into[*info.SnapshotId] = info
	}
}

// locksForRegion returns the snapshot locks of a region, reading them once.
func (a *mqlAwsEc2) locksForRegion(region string) (map[string]ec2types.LockedSnapshotsInfo, error) {
	r := a.lockedSnapshots.region(region)
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched {
		return r.locks, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	ctx := context.Background()
	locks := map[string]ec2types.LockedSnapshotsInfo{}
	var nextToken *string
	for {
		out, err := svc.DescribeLockedSnapshots(ctx, &ec2.DescribeLockedSnapshotsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		indexLockedSnapshots(out.Snapshots, locks)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		if nextToken != nil && *nextToken == *out.NextToken {
			// A cursor that does not advance would loop forever.
			break
		}
		nextToken = out.NextToken
	}
	r.locks = locks
	r.fetched = true
	return r.locks, nil
}

type snapshotLockState struct {
	fetched bool
	lock    sync.Mutex
	info    *ec2types.LockedSnapshotsInfo
}

// fetchLock returns the snapshot's lock, or nil when it has none. A nil lock
// with a nil error is also returned when the account may not read locks and
// structured errors are off.
func (a *mqlAwsEc2Snapshot) fetchLock() (*ec2types.LockedSnapshotsInfo, error) {
	a.snapshotLock.lock.Lock()
	defer a.snapshotLock.lock.Unlock()
	if a.snapshotLock.fetched {
		return a.snapshotLock.info, nil
	}

	obj, err := CreateResource(a.MqlRuntime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	locks, err := obj.(*mqlAwsEc2).locksForRegion(a.Region.Data)
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.snapshotLock.fetched = true
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("ec2:DescribeLockedSnapshots"))
		}
		return nil, err
	}
	if info, ok := locks[a.Id.Data]; ok {
		a.snapshotLock.info = &info
	}
	a.snapshotLock.fetched = true
	return a.snapshotLock.info, nil
}

func (a *mqlAwsEc2Snapshot) lockState() (string, error) {
	info, err := a.fetchLock()
	if err != nil {
		return "", err
	}
	if info == nil || info.LockState == "" {
		a.LockState.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(info.LockState), nil
}

func (a *mqlAwsEc2Snapshot) lockDuration() (int64, error) {
	info, err := a.fetchLock()
	if err != nil {
		return 0, err
	}
	if info == nil || info.LockDuration == nil {
		a.LockDuration.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*info.LockDuration), nil
}

func (a *mqlAwsEc2Snapshot) coolOffPeriod() (int64, error) {
	info, err := a.fetchLock()
	if err != nil {
		return 0, err
	}
	if info == nil || info.CoolOffPeriod == nil {
		a.CoolOffPeriod.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*info.CoolOffPeriod), nil
}

// snapshotLockTime reads one timestamp off the snapshot's lock, reporting
// null when the snapshot has no lock or the lock does not carry it.
func (a *mqlAwsEc2Snapshot) snapshotLockTime(field *plugin.TValue[*time.Time], pick func(*ec2types.LockedSnapshotsInfo) *time.Time) (*time.Time, error) {
	info, err := a.fetchLock()
	if err != nil {
		return nil, err
	}
	if info == nil || pick(info) == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return pick(info), nil
}

func (a *mqlAwsEc2Snapshot) lockCreatedAt() (*time.Time, error) {
	return a.snapshotLockTime(&a.LockCreatedAt, func(i *ec2types.LockedSnapshotsInfo) *time.Time { return i.LockCreatedOn })
}

func (a *mqlAwsEc2Snapshot) lockDurationStartAt() (*time.Time, error) {
	return a.snapshotLockTime(&a.LockDurationStartAt, func(i *ec2types.LockedSnapshotsInfo) *time.Time { return i.LockDurationStartTime })
}

func (a *mqlAwsEc2Snapshot) lockExpiresAt() (*time.Time, error) {
	return a.snapshotLockTime(&a.LockExpiresAt, func(i *ec2types.LockedSnapshotsInfo) *time.Time { return i.LockExpiresOn })
}

func (a *mqlAwsEc2Snapshot) coolOffPeriodExpiresAt() (*time.Time, error) {
	return a.snapshotLockTime(&a.CoolOffPeriodExpiresAt, func(i *ec2types.LockedSnapshotsInfo) *time.Time { return i.CoolOffPeriodExpiresOn })
}
