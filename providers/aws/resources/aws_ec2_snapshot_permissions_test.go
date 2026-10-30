// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// denied builds a snapshot whose createVolumePermission read was refused,
// without touching the API: it consumes the sync.Once so fetch returns the
// seeded state.
func deniedSnapshot() *mqlAwsEc2Snapshot {
	a := &mqlAwsEc2Snapshot{}
	a.cvpOnce.Do(func() { a.cvpDenied = true })
	return a
}

func readableSnapshot(perms ...ec2types.CreateVolumePermission) *mqlAwsEc2Snapshot {
	a := &mqlAwsEc2Snapshot{}
	a.cvpOnce.Do(func() { a.cvp = perms })
	return a
}

// An access-denied permission read must leave isPublic null, not false.
// Returning false asserts the snapshot is definitively not shared when its
// permissions were never read, and a policy looking for public snapshots
// would record that as a clean result.
func TestSnapshotIsPublicIsNullWhenAccessDenied(t *testing.T) {
	a := deniedSnapshot()

	got, err := a.isPublic()
	require.NoError(t, err)
	assert.False(t, got)
	assert.NotZero(t, a.IsPublic.State&plugin.StateIsNull,
		"a denied permission read must read null, never a confident false")
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

// The deprecated dict answers from the same fetch and must not report an
// empty permission list when the read was refused.
func TestSnapshotCreateVolumePermissionIsNullWhenAccessDenied(t *testing.T) {
	a := deniedSnapshot()

	got, err := a.createVolumePermission()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.NotZero(t, a.CreateVolumePermission.State&plugin.StateIsNull,
		"a denied read must not read as an empty permission list")
}
