// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOciDatabaseArgs(t *testing.T) {
	t.Run("a database with no backup configuration is not backed up", func(t *testing.T) {
		args := ociDatabaseArgs(&database.DatabaseSummary{
			Id:     common.String("ocid1.database.oc1..a"),
			DbName: common.String("ORCL"),
		})
		// False rather than null: a null would pass an assertion that
		// automatic backups are enabled.
		assert.Equal(t, false, args["autoBackupEnabled"].Value)
		assert.Nil(t, args["backupRecoveryWindowInDays"].Value)
		assert.Empty(t, args["backupDestinations"].Value)
		assert.Nil(t, args["lastBackup"].Value)
	})

	t.Run("the backup configuration is reported", func(t *testing.T) {
		args := ociDatabaseArgs(&database.DatabaseSummary{
			Id:     common.String("ocid1.database.oc1..b"),
			DbName: common.String("PROD"),
			IsCdb:  common.Bool(true),
			DbBackupConfig: &database.DbBackupConfig{
				AutoBackupEnabled:    common.Bool(true),
				RecoveryWindowInDays: common.Int(30),
				AutoBackupWindow:     database.DbBackupConfigAutoBackupWindowTwo,
				BackupDeletionPolicy: database.DbBackupConfigBackupDeletionPolicyAfterRetentionPeriod,
				BackupDestinationDetails: []database.BackupDestinationDetails{
					{Type: database.BackupDestinationDetailsTypeObjectStore},
				},
			},
		})
		assert.Equal(t, true, args["autoBackupEnabled"].Value)
		assert.Equal(t, int64(30), args["backupRecoveryWindowInDays"].Value)
		assert.Equal(t, "SLOT_TWO", args["autoBackupWindow"].Value)
		assert.Equal(t, "DELETE_AFTER_RETENTION_PERIOD", args["backupDeletionPolicy"].Value)
		assert.Equal(t, true, args["isCdb"].Value)
		assert.Len(t, args["backupDestinations"].Value, 1)
	})
}

func TestOciBackupDestinations(t *testing.T) {
	got := ociBackupDestinations([]database.BackupDestinationDetails{
		{
			Type:                   database.BackupDestinationDetailsTypeRecoveryAppliance,
			Id:                     common.String("ocid1.backupdestination.oc1..zdlra"),
			VpcUser:                common.String("vpc_backup"),
			VpcPassword:            common.String("Recovery-Appliance-Pa55"),
			IsRetentionLockEnabled: common.Bool(true),
		},
		{
			Type:         database.BackupDestinationDetailsTypeObjectStore,
			IsRemote:     common.Bool(true),
			RemoteRegion: common.String("us-phoenix-1"),
		},
	})
	require.Len(t, got, 2)

	appliance := got[0].(map[string]any)
	assert.Equal(t, "RECOVERY_APPLIANCE", appliance["type"])
	assert.Equal(t, true, appliance["isRetentionLockEnabled"])
	assert.Nil(t, appliance["isRemote"], "an unset flag stays null")

	remote := got[1].(map[string]any)
	assert.Equal(t, true, remote["isRemote"])
	assert.Equal(t, "us-phoenix-1", remote["remoteRegion"])

	serialized, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(serialized), "Recovery-Appliance-Pa55")
}
