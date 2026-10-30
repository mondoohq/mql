// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLongTermBackupArgs(t *testing.T) {
	backupAt := time.Date(2026, 6, 1, 2, 0, 0, 0, time.UTC)
	nextAt := time.Date(2026, 7, 1, 2, 0, 0, 0, time.UTC)

	args := longTermBackupArgs(&database.LongTermBackUpScheduleDetails{
		RepeatCadence:         database.LongTermBackUpScheduleDetailsRepeatCadenceMonthly,
		TimeOfBackup:          &common.SDKTime{Time: backupAt},
		RetentionPeriodInDays: new(365),
		IsDisabled:            new(false),
	}, &common.SDKTime{Time: nextAt})

	assert.Equal(t, "MONTHLY", args["longTermBackupRepeatCadence"].Value)
	assert.Equal(t, backupAt, *args["longTermBackupTimeOfBackup"].Value.(*time.Time))
	assert.Equal(t, int64(365), args["longTermBackupRetentionPeriodInDays"].Value)
	assert.Equal(t, false, args["longTermBackupScheduleDisabled"].Value)
	assert.Equal(t, nextAt, *args["nextLongTermBackupTimestamp"].Value.(*time.Time))
}

// A database with no long-term backup schedule must read null across the board.
// A zero retention or an empty cadence would report a schedule the database
// does not have, and a zero time would date the next backup to year 1.
func TestLongTermBackupArgsAreNullWithoutASchedule(t *testing.T) {
	args := longTermBackupArgs(nil, nil)

	for _, k := range []string{
		"longTermBackupRepeatCadence",
		"longTermBackupTimeOfBackup",
		"longTermBackupRetentionPeriodInDays",
		"longTermBackupScheduleDisabled",
		"nextLongTermBackupTimestamp",
	} {
		require.NotNil(t, args[k], k)
		assert.Nil(t, args[k].Value, k)
	}
}

// "No schedule configured" and "a schedule exists but is switched off" are
// different findings. A disabled schedule reports true, not null, so a policy
// can tell an operator who turned long-term backups off from one who never
// set them up.
func TestLongTermBackupArgsDistinguishDisabledFromAbsent(t *testing.T) {
	disabled := longTermBackupArgs(&database.LongTermBackUpScheduleDetails{
		RepeatCadence: database.LongTermBackUpScheduleDetailsRepeatCadenceYearly,
		IsDisabled:    new(true),
	}, nil)
	assert.Equal(t, true, disabled["longTermBackupScheduleDisabled"].Value)

	absent := longTermBackupArgs(nil, nil)
	assert.Nil(t, absent["longTermBackupScheduleDisabled"].Value)
}

// The SDK leaves an unset enum as the empty string. Passing that straight
// through would give a cadence of "" that compares unequal to every real
// cadence while looking like a configured value.
func TestLongTermBackupArgsEmptyCadenceIsNull(t *testing.T) {
	args := longTermBackupArgs(&database.LongTermBackUpScheduleDetails{
		RetentionPeriodInDays: new(90),
	}, nil)

	assert.Nil(t, args["longTermBackupRepeatCadence"].Value)
	assert.Equal(t, int64(90), args["longTermBackupRetentionPeriodInDays"].Value)
}
