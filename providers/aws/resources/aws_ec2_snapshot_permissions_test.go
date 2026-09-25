// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// deniedSnapshot builds a snapshot whose createVolumePermission read was
// refused, without touching the API: it consumes the sync.Once with the error
// the fetch records for a real EC2 denial.
func deniedSnapshot() *mqlAwsEc2Snapshot {
	a := &mqlAwsEc2Snapshot{}
	a.cvpOnce.Do(func() {
		a.cvpErr = classifyAwsError(awsAPIError(400, "UnauthorizedOperation",
			"You are not authorized to perform this operation."), "ec2:DescribeSnapshotAttribute")
	})
	return a
}

func readableSnapshot(perms ...ec2types.CreateVolumePermission) *mqlAwsEc2Snapshot {
	a := &mqlAwsEc2Snapshot{}
	a.cvpOnce.Do(func() { a.cvp = perms })
	return a
}

// An access-denied permission read must be a forbidden error, never false.
// Returning false asserts the snapshot is definitively not shared when its
// permissions were never read, and a policy looking for public snapshots
// would record that as a clean result.
func TestSnapshotIsPublicIsForbiddenWhenAccessDenied(t *testing.T) {
	a := deniedSnapshot()

	_, err := a.isPublic()
	require.ErrorIs(t, err, llx.ErrForbidden)
	assert.Equal(t, []string{"ec2:DescribeSnapshotAttribute"}, llx.ErrorDetailOf(err).GetPermissions())
}

func TestSnapshotIsPublicTrueOnPermissionGroupAll(t *testing.T) {
	a := readableSnapshot(ec2types.CreateVolumePermission{Group: ec2types.PermissionGroupAll})

	got, err := a.isPublic()
	require.NoError(t, err)
	assert.True(t, got)
	assert.Zero(t, a.IsPublic.State&plugin.StateIsNull, "a successful read is never null")
}

func TestSnapshotIsPublicFalseWhenSharedWithNamedAccountsOnly(t *testing.T) {
	acct := "123456789012"
	a := readableSnapshot(ec2types.CreateVolumePermission{UserId: &acct})

	got, err := a.isPublic()
	require.NoError(t, err)
	assert.False(t, got, "sharing with a named account is not public")
	assert.Zero(t, a.IsPublic.State&plugin.StateIsNull)
}

// The deprecated dict and the typed lists answer from the same fetch and must
// not report an empty permission list when the read was refused.
func TestSnapshotPermissionListsAreForbiddenWhenAccessDenied(t *testing.T) {
	a := deniedSnapshot()

	_, err := a.createVolumePermission()
	assert.ErrorIs(t, err, llx.ErrForbidden)
	_, err = a.createVolumePermissionUserIds()
	assert.ErrorIs(t, err, llx.ErrForbidden)
	_, err = a.createVolumePermissionGroups()
	assert.ErrorIs(t, err, llx.ErrForbidden)
}
