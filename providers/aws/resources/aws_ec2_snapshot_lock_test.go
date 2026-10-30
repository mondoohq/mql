// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
)

// stubAwsConn returns a connection whose clients answer every operation from
// answer instead of the network. The middleware short-circuits at the
// Initialize step, before signing and transport, so no credentials are needed
// and answer sees the typed SDK input.
func stubAwsConn(t *testing.T, answer func(params any) (any, error)) *connection.AwsConnection {
	t.Helper()
	apiOption := func(s *middleware.Stack) error {
		return s.Initialize.Add(middleware.InitializeMiddlewareFunc("mqlTier1TestStub",
			func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
				middleware.InitializeOutput, middleware.Metadata, error,
			) {
				out, err := answer(in.Parameters)
				if err != nil {
					return middleware.InitializeOutput{}, middleware.Metadata{}, err
				}
				return middleware.InitializeOutput{Result: out}, middleware.Metadata{}, nil
			}), middleware.Before)
	}
	return connection.NewTestConnection(aws.Config{
		Region:     "us-east-1",
		APIOptions: []func(*middleware.Stack) error{apiOption},
	})
}

func lockedSnapshotsStub(t *testing.T, pages map[string]*ec2.DescribeLockedSnapshotsOutput, calls *int) *plugin.Runtime {
	t.Helper()
	rt := testRuntime()
	rt.Connection = stubAwsConn(t, func(params any) (any, error) {
		in, ok := params.(*ec2.DescribeLockedSnapshotsInput)
		if !ok {
			return nil, fmt.Errorf("unexpected operation %T", params)
		}
		*calls++
		if *calls > 5 {
			return nil, fmt.Errorf("DescribeLockedSnapshots called %d times", *calls)
		}
		return pages[aws.ToString(in.NextToken)], nil
	})
	return rt
}

func TestLocksForRegionFollowsPagesAndStopsOnStuckCursor(t *testing.T) {
	calls := 0
	rt := lockedSnapshotsStub(t, map[string]*ec2.DescribeLockedSnapshotsOutput{
		"": {
			Snapshots: []ec2types.LockedSnapshotsInfo{{SnapshotId: aws.String("snap-a"), LockState: ec2types.LockStateCompliance}},
			NextToken: aws.String("page2"),
		},
		// The second page hands back the cursor it was given.
		"page2": {
			Snapshots: []ec2types.LockedSnapshotsInfo{{SnapshotId: aws.String("snap-b"), LockState: ec2types.LockStateGovernance}},
			NextToken: aws.String("page2"),
		},
	}, &calls)
	ec2Res := &mqlAwsEc2{MqlRuntime: rt}

	locks, err := ec2Res.locksForRegion("us-east-1")
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Equal(t, ec2types.LockStateCompliance, locks["snap-a"].LockState)
	assert.Equal(t, ec2types.LockStateGovernance, locks["snap-b"].LockState)

	// A second snapshot in the same region reuses the walk.
	_, err = ec2Res.locksForRegion("us-east-1")
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
}

func TestIndexLockedSnapshotsSkipsRecordsWithoutID(t *testing.T) {
	into := map[string]ec2types.LockedSnapshotsInfo{}
	indexLockedSnapshots([]ec2types.LockedSnapshotsInfo{
		{SnapshotId: nil, LockState: ec2types.LockStateCompliance},
		{SnapshotId: aws.String(""), LockState: ec2types.LockStateCompliance},
		{SnapshotId: aws.String("snap-1"), LockState: ec2types.LockStateExpired},
	}, into)
	assert.Len(t, into, 1)
	assert.Equal(t, ec2types.LockStateExpired, into["snap-1"].LockState)
}

func TestSnapshotLockFieldsLockedAndUnlocked(t *testing.T) {
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	calls := 0
	rt := lockedSnapshotsStub(t, map[string]*ec2.DescribeLockedSnapshotsOutput{
		"": {Snapshots: []ec2types.LockedSnapshotsInfo{{
			SnapshotId:    aws.String("snap-locked"),
			LockState:     ec2types.LockStateComplianceCooloff,
			LockDuration:  aws.Int32(30),
			CoolOffPeriod: aws.Int32(24),
			LockExpiresOn: &expires,
		}}},
	}, &calls)

	locked := &mqlAwsEc2Snapshot{MqlRuntime: rt, Id: setString("snap-locked"), Region: setString("us-east-1")}
	state, err := locked.lockState()
	require.NoError(t, err)
	assert.Equal(t, "compliance-cooloff", state)
	duration, err := locked.lockDuration()
	require.NoError(t, err)
	assert.Equal(t, int64(30), duration)
	coolOff, err := locked.coolOffPeriod()
	require.NoError(t, err)
	assert.Equal(t, int64(24), coolOff)
	expiresAt, err := locked.lockExpiresAt()
	require.NoError(t, err)
	assert.Equal(t, expires, *expiresAt)
	_, err = locked.lockCreatedAt()
	require.NoError(t, err)
	assert.True(t, locked.LockCreatedAt.IsNull(), "a lock without a creation time reads null")

	unlocked := &mqlAwsEc2Snapshot{MqlRuntime: rt, Id: setString("snap-free"), Region: setString("us-east-1")}
	_, err = unlocked.lockState()
	require.NoError(t, err)
	assert.True(t, unlocked.LockState.IsNull(), "an unlocked snapshot has no lock state")
	_, err = unlocked.lockDuration()
	require.NoError(t, err)
	assert.True(t, unlocked.LockDuration.IsNull())

	assert.Equal(t, 1, calls, "both snapshots share one regional walk")
}

func TestLocksForRegionRetriesAfterTransientError(t *testing.T) {
	calls := 0
	rt := testRuntime()
	rt.Connection = stubAwsConn(t, func(params any) (any, error) {
		calls++
		if calls == 1 {
			return nil, awsAPIErr(503, "RequestLimitExceeded", "Request limit exceeded.")
		}
		return &ec2.DescribeLockedSnapshotsOutput{
			Snapshots: []ec2types.LockedSnapshotsInfo{{SnapshotId: aws.String("snap-a"), LockState: ec2types.LockStateGovernance}},
		}, nil
	})
	ec2Res := &mqlAwsEc2{MqlRuntime: rt}

	_, err := ec2Res.locksForRegion("us-east-1")
	require.Error(t, err)
	locks, err := ec2Res.locksForRegion("us-east-1")
	require.NoError(t, err, "a failed read is not cached")
	assert.Equal(t, ec2types.LockStateGovernance, locks["snap-a"].LockState)
	assert.Equal(t, 2, calls)
}
