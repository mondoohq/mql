// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestVolumeAttachmentArgs(t *testing.T) {
	iscsi := volumeAttachmentArgs(core.IScsiVolumeAttachment{
		Id:                             common.String("ocid1.volumeattachment..a"),
		IsPvEncryptionInTransitEnabled: common.Bool(false),
		EncryptionInTransitType:        core.EncryptionInTransitTypeBmEncryptionInTransit,
		ChapUsername:                   common.String("ocid1.volume..v"),
		ChapSecret:                     common.String("never-read"),
	})
	assert.Equal(t, "iscsi", iscsi["attachmentType"].Value)
	assert.Equal(t, "BM_ENCRYPTION_IN_TRANSIT", iscsi["encryptionInTransitType"].Value)
	assert.Equal(t, true, iscsi["chapEnabled"].Value)
	for k, v := range iscsi {
		assert.NotEqual(t, "never-read", v.Value, "the CHAP secret must not reach field %s", k)
	}

	noChap := volumeAttachmentArgs(core.IScsiVolumeAttachment{Id: common.String("a")})
	assert.Equal(t, false, noChap["chapEnabled"].Value)

	pv := volumeAttachmentArgs(core.ParavirtualizedVolumeAttachment{
		Id:                             common.String("b"),
		IsPvEncryptionInTransitEnabled: common.Bool(true),
	})
	assert.Equal(t, "paravirtualized", pv["attachmentType"].Value)
	assert.Equal(t, true, pv["isPvEncryptionInTransitEnabled"].Value)
	assert.Equal(t, "", pv["encryptionInTransitType"].Value, "only iSCSI attachments have an in-transit encryption type")
	assert.Equal(t, false, pv["chapEnabled"].Value)

	em := volumeAttachmentArgs(core.EmulatedVolumeAttachment{Id: common.String("c")})
	assert.Equal(t, "emulated", em["attachmentType"].Value)
	assert.Nil(t, em["isPvEncryptionInTransitEnabled"].Value, "absent is null, not false")
}

func TestVolumeBackupScheduleArgs(t *testing.T) {
	week := 7*86400 + 3600
	args := volumeBackupScheduleArgs(core.VolumeBackupSchedule{
		BackupType:             core.VolumeBackupScheduleBackupTypeIncremental,
		Period:                 core.VolumeBackupSchedulePeriodDay,
		RetentionSeconds:       &week,
		IsRetentionLockEnabled: common.Bool(true),
	})
	assert.Equal(t, int64(7), args["retentionDays"].Value, "retention is whole days, rounded down")
	assert.Equal(t, "ONE_DAY", args["period"].Value)
	assert.Equal(t, true, args["isRetentionLockEnabled"].Value)
	assert.Equal(t, false, args["isPreventDeletionEnabled"].Value)
	assert.Nil(t, args["hourOfDay"].Value)

	assert.Nil(t, volumeBackupScheduleArgs(core.VolumeBackupSchedule{})["retentionDays"].Value, "absent retention is null, not zero days")
}

func TestVolumeBackupPolicyArgs(t *testing.T) {
	assert.Equal(t, true, volumeBackupPolicyArgs(core.VolumeBackupPolicy{Id: common.String("gold")})["isOracleDefined"].Value,
		"Oracle's predefined policies have no compartment")
	assert.Equal(t, false, volumeBackupPolicyArgs(core.VolumeBackupPolicy{
		Id: common.String("custom"), CompartmentId: common.String("ocid1.compartment..c"),
	})["isOracleDefined"].Value)
}

func TestSplitVolumeIDs(t *testing.T) {
	block, boot := splitVolumeIDs([]string{"ocid1.volume.oc1..a", "ocid1.bootvolume.oc1..b", "ocid1.volume.oc1..c", "other"})
	assert.Equal(t, []string{"ocid1.volume.oc1..a", "ocid1.volume.oc1..c"}, block)
	assert.Equal(t, []string{"ocid1.bootvolume.oc1..b"}, boot)
}

func TestOciListedRef(t *testing.T) {
	vol := &mqlOciComputeBlockVolume{Id: plugin.TValue[string]{Data: "v1", State: plugin.StateIsSet}}
	list := &plugin.TValue[[]any]{Data: []any{vol}, State: plugin.StateIsSet}

	var field plugin.TValue[*mqlOciComputeBlockVolume]
	got, err := ociListedRef(list, "v1", &field)
	require.NoError(t, err)
	assert.Same(t, vol, got)

	field = plugin.TValue[*mqlOciComputeBlockVolume]{}
	got, err = ociListedRef(list, "gone", &field)
	require.NoError(t, err, "a reference to a deleted volume is null, not an error")
	assert.Nil(t, got)
	assert.True(t, field.IsNull())

	field = plugin.TValue[*mqlOciComputeBlockVolume]{}
	_, err = ociListedRef(list, "", &field)
	require.NoError(t, err)
	assert.True(t, field.IsNull())

	_, err = ociListedRef(&plugin.TValue[[]any]{Error: errors.New("refused")}, "v1", &field)
	assert.Error(t, err, "a refused listing is an error, not a missing reference")
}
