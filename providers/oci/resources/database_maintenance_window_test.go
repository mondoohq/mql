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

func TestScheduledMaintenanceWindowArgs(t *testing.T) {
	updateAt := time.Date(2026, 9, 14, 3, 30, 0, 0, time.UTC)

	args := scheduledMaintenanceWindowArgs(&database.AutonomousDatabaseMaintenanceWindowSummary{
		DayOfWeek:                          &database.DayOfWeek{Name: database.DayOfWeekNameTuesday},
		MaintenanceStartTime:               new("02:00"),
		MaintenanceEndTime:                 new("06:00"),
		AvailabilityDomain:                 new("Uocm:PHX-AD-1"),
		IsMaintenanceWindowChangeScheduled: new(true),
	}, &common.SDKTime{Time: updateAt})

	assert.Equal(t, "TUESDAY", args["maintenanceDayOfWeek"].Value)
	assert.Equal(t, "02:00", args["maintenanceStartTime"].Value)
	assert.Equal(t, "06:00", args["maintenanceEndTime"].Value)
	assert.Equal(t, "Uocm:PHX-AD-1", args["maintenanceAvailabilityDomain"].Value)
	assert.Equal(t, true, args["maintenanceWindowChangeScheduled"].Value)
	assert.Equal(t, updateAt, *args["timeScheduledMaintenanceWindowUpdate"].Value.(*time.Time))
}

// A database with no scheduled maintenance window must read null across the
// board. An empty day or start time would report a window the database does
// not have, and a zero time would date the pending change to year 1.
func TestScheduledMaintenanceWindowArgsAreNullWithoutAWindow(t *testing.T) {
	args := scheduledMaintenanceWindowArgs(nil, nil)

	for _, k := range []string{
		"maintenanceDayOfWeek",
		"maintenanceStartTime",
		"maintenanceEndTime",
		"maintenanceAvailabilityDomain",
		"maintenanceWindowChangeScheduled",
		"timeScheduledMaintenanceWindowUpdate",
	} {
		require.NotNil(t, args[k], k)
		assert.Nil(t, args[k].Value, k)
	}
}

// The window and the pending-change timestamp are separate fields on the API
// record. A database with a fixed window and no change queued must report the
// window and leave the update time null, rather than dating the change to the
// zero time.
func TestScheduledMaintenanceWindowArgsNullUpdateWithAWindow(t *testing.T) {
	args := scheduledMaintenanceWindowArgs(&database.AutonomousDatabaseMaintenanceWindowSummary{
		DayOfWeek:                          &database.DayOfWeek{Name: database.DayOfWeekNameSunday},
		MaintenanceStartTime:               new("22:00"),
		IsMaintenanceWindowChangeScheduled: new(false),
	}, nil)

	assert.Equal(t, "SUNDAY", args["maintenanceDayOfWeek"].Value)
	assert.Equal(t, "22:00", args["maintenanceStartTime"].Value)
	assert.Nil(t, args["timeScheduledMaintenanceWindowUpdate"].Value)

	// "No change queued" is a measured false, not an absence.
	assert.Equal(t, false, args["maintenanceWindowChangeScheduled"].Value)
}

// DayOfWeek is a pointer to a struct carrying an enum, so two absences are
// possible: no DayOfWeek at all, and a DayOfWeek whose enum the SDK left as
// the empty string. Passing either through would give a day of "" that
// compares unequal to every real day while looking like a configured value.
func TestScheduledMaintenanceWindowArgsDayOfWeekAbsence(t *testing.T) {
	nilDay := scheduledMaintenanceWindowArgs(&database.AutonomousDatabaseMaintenanceWindowSummary{
		MaintenanceStartTime: new("04:00"),
	}, nil)
	assert.Nil(t, nilDay["maintenanceDayOfWeek"].Value)
	assert.Equal(t, "04:00", nilDay["maintenanceStartTime"].Value)

	emptyEnum := scheduledMaintenanceWindowArgs(&database.AutonomousDatabaseMaintenanceWindowSummary{
		DayOfWeek:            &database.DayOfWeek{},
		MaintenanceStartTime: new("04:00"),
	}, nil)
	assert.Nil(t, emptyEnum["maintenanceDayOfWeek"].Value)
}

// Every day the API can return has to survive the enum-to-string conversion.
// A window pinned to a day this misses would read null, reporting a database
// as unscheduled when Oracle has a fixed patch day for it.
func TestScheduledMaintenanceWindowArgsCoversEveryDay(t *testing.T) {
	for _, tc := range []struct {
		day  database.DayOfWeekNameEnum
		want string
	}{
		{database.DayOfWeekNameMonday, "MONDAY"},
		{database.DayOfWeekNameTuesday, "TUESDAY"},
		{database.DayOfWeekNameWednesday, "WEDNESDAY"},
		{database.DayOfWeekNameThursday, "THURSDAY"},
		{database.DayOfWeekNameFriday, "FRIDAY"},
		{database.DayOfWeekNameSaturday, "SATURDAY"},
		{database.DayOfWeekNameSunday, "SUNDAY"},
	} {
		args := scheduledMaintenanceWindowArgs(&database.AutonomousDatabaseMaintenanceWindowSummary{
			DayOfWeek: &database.DayOfWeek{Name: tc.day},
		}, nil)
		assert.Equal(t, tc.want, args["maintenanceDayOfWeek"].Value)
	}

	// The set above is the whole set the SDK accepts. If Oracle adds an
	// eighth day this fails, which is the signal to widen the doc comment.
	assert.Len(t, database.GetDayOfWeekNameEnumStringValues(), 7)
}

// The maintenance window arrives on the list response, so the whole schedule
// is readable without a second API call. This pins the struct tags the decode
// depends on: a mistyped tag yields a zero value, which would report a
// database as having no patch window while Oracle patches it every Tuesday.
func TestAutonomousDatabaseSummaryDecodesMaintenanceWindow(t *testing.T) {
	payload := []byte(`{
		"id": "ocid1.autonomousdatabase.oc1.phx.exampleuniqueid",
		"displayName": "adb-1",
		"scheduledMaintenanceWindow": {
			"dayOfWeek": {"name": "WEDNESDAY"},
			"maintenanceStartTime": "01:00",
			"maintenanceEndTime": "05:00",
			"availabilityDomain": "Uocm:PHX-AD-2",
			"isMaintenanceWindowChangeScheduled": true
		},
		"timeScheduledMaintenanceWindowUpdate": "2026-10-01T00:00:00.000Z"
	}`)

	var summary database.AutonomousDatabaseSummary
	require.NoError(t, summary.UnmarshalJSON(payload))

	require.NotNil(t, summary.ScheduledMaintenanceWindow)
	args := scheduledMaintenanceWindowArgs(summary.ScheduledMaintenanceWindow, summary.TimeScheduledMaintenanceWindowUpdate)

	assert.Equal(t, "WEDNESDAY", args["maintenanceDayOfWeek"].Value)
	assert.Equal(t, "01:00", args["maintenanceStartTime"].Value)
	assert.Equal(t, "05:00", args["maintenanceEndTime"].Value)
	assert.Equal(t, "Uocm:PHX-AD-2", args["maintenanceAvailabilityDomain"].Value)
	assert.Equal(t, true, args["maintenanceWindowChangeScheduled"].Value)
	assert.Equal(t,
		time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		args["timeScheduledMaintenanceWindowUpdate"].Value.(*time.Time).UTC())
}

// An Autonomous Database whose response carries no maintenance window at all
// must not fabricate one from the surrounding record.
func TestAutonomousDatabaseSummaryWithoutMaintenanceWindow(t *testing.T) {
	payload := []byte(`{
		"id": "ocid1.autonomousdatabase.oc1.phx.exampleuniqueid",
		"displayName": "adb-2"
	}`)

	var summary database.AutonomousDatabaseSummary
	require.NoError(t, summary.UnmarshalJSON(payload))

	assert.Nil(t, summary.ScheduledMaintenanceWindow)
	assert.Nil(t, summary.TimeScheduledMaintenanceWindowUpdate)

	args := scheduledMaintenanceWindowArgs(summary.ScheduledMaintenanceWindow, summary.TimeScheduledMaintenanceWindowUpdate)
	assert.Nil(t, args["maintenanceDayOfWeek"].Value)
	assert.Nil(t, args["timeScheduledMaintenanceWindowUpdate"].Value)
}
