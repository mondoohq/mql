// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/compute/v1"
)

func TestEffectiveInstanceMetadataArgs(t *testing.T) {
	// Synthetic: an instance whose resource status carries no effective
	// metadata block; every field must be null, not false.
	for _, rs := range []*compute.ResourceStatus{nil, {}} {
		args := effectiveInstanceMetadataArgs(rs)
		require.Len(t, args, 8)
		for k, v := range args {
			assert.Nil(t, v.Value, k)
		}
	}

	// Measured: live e2-micro instance, 2026-11-23, with enable-oslogin,
	// serial-port-enable, serial-port-logging-enable, block-project-ssh-keys,
	// and enable-guest-attributes set to TRUE in instance metadata and no
	// osconfig or inventory keys; the live scan returned these values.
	measured := effectiveInstanceMetadataArgs(&compute.ResourceStatus{
		EffectiveInstanceMetadata: &compute.ResourceStatusEffectiveInstanceMetadata{
			EnableOsloginMetadataValue:           true,
			SerialPortEnableMetadataValue:        true,
			SerialPortLoggingEnableMetadataValue: true,
			BlockProjectSshKeysMetadataValue:     true,
			EnableGuestAttributesMetadataValue:   true,
			VmDnsSettingMetadataValue:            "ZonalOnly",
		},
	})
	assert.Equal(t, true, measured["effectiveSerialPortLoggingEnabled"].Value)
	assert.Equal(t, false, measured["effectiveOsConfigEnabled"].Value)
	assert.Equal(t, "ZonalOnly", measured["effectiveVmDnsSetting"].Value)

	// Synthetic: each flag set independently so a swapped mapping fails.
	args := effectiveInstanceMetadataArgs(&compute.ResourceStatus{
		EffectiveInstanceMetadata: &compute.ResourceStatusEffectiveInstanceMetadata{
			EnableOsloginMetadataValue:         true,
			SerialPortEnableMetadataValue:      false,
			BlockProjectSshKeysMetadataValue:   true,
			EnableGuestAttributesMetadataValue: true,
			VmDnsSettingMetadataValue:          "ZonalOnly",
		},
	})
	assert.Equal(t, true, args["effectiveOsLoginEnabled"].Value)
	assert.Equal(t, false, args["effectiveSerialPortEnabled"].Value)
	assert.Equal(t, false, args["effectiveSerialPortLoggingEnabled"].Value)
	assert.Equal(t, true, args["effectiveBlockProjectSshKeys"].Value)
	assert.Equal(t, false, args["effectiveOsConfigEnabled"].Value)
	assert.Equal(t, false, args["effectiveOsInventoryEnabled"].Value)
	assert.Equal(t, true, args["effectiveGuestAttributesEnabled"].Value)
	assert.Equal(t, "ZonalOnly", args["effectiveVmDnsSetting"].Value)
}

func TestUpcomingMaintenanceToDict(t *testing.T) {
	// Synthetic: no maintenance scheduled.
	assert.Nil(t, upcomingMaintenanceToDict(nil))
	assert.Nil(t, upcomingMaintenanceToDict(&compute.ResourceStatus{}))

	// Synthetic: a scheduled event with reasons.
	d := upcomingMaintenanceToDict(&compute.ResourceStatus{
		UpcomingMaintenance: &compute.UpcomingMaintenance{
			Type:               "SCHEDULED",
			MaintenanceStatus:  "PENDING",
			CanReschedule:      true,
			WindowStartTime:    "2026-12-01T10:00:00Z",
			WindowEndTime:      "2026-12-01T14:00:00Z",
			MaintenanceReasons: []string{"PLANNED_UPDATE"},
		},
	})
	require.NotNil(t, d)
	assert.Equal(t, "SCHEDULED", d["type"])
	assert.Equal(t, "PENDING", d["maintenanceStatus"])
	assert.Equal(t, true, d["canReschedule"])
	assert.Equal(t, "2026-12-01T10:00:00Z", d["windowStartTime"])
	assert.Equal(t, "2026-12-01T14:00:00Z", d["windowEndTime"])
	assert.Equal(t, []any{"PLANNED_UPDATE"}, d["maintenanceReasons"])
}

func TestGlobalComputeResourceRef(t *testing.T) {
	tests := []struct {
		ref, kind, project, name string
	}{
		// Synthetic: self-link shapes Compute Engine returns.
		{"https://www.googleapis.com/compute/v1/projects/p1/global/machineImages/mi-1", "machineImages", "p1", "mi-1"},
		{"https://compute.googleapis.com/compute/v1/projects/p1/global/images/img", "images", "p1", "img"},
		{"projects/p1/global/images/img", "images", "p1", "img"},
		// Synthetic: wrong collection, regional path, empty and truncated values.
		{"https://www.googleapis.com/compute/v1/projects/p1/global/images/img", "machineImages", "", ""},
		{"https://www.googleapis.com/compute/v1/projects/p1/regions/r/images/img", "images", "", ""},
		{"", "images", "", ""},
		{"projects/p1/global/images/", "images", "", ""},
	}
	for _, tt := range tests {
		p, n := globalComputeResourceRef(tt.ref, tt.kind)
		assert.Equal(t, tt.project, p, tt.ref)
		assert.Equal(t, tt.name, n, tt.ref)
	}
}

func TestImageDeprecation(t *testing.T) {
	// Synthetic: never deprecated.
	assert.Equal(t, imageDeprecationInfo{}, imageDeprecation(nil))

	d := imageDeprecation(&compute.DeprecationStatus{
		State:       "DEPRECATED",
		Deprecated:  "2026-11-01T00:00:00Z",
		Obsolete:    "2026-12-01T00:00:00Z",
		Deleted:     "2027-01-01T00:00:00Z",
		Replacement: "https://www.googleapis.com/compute/v1/projects/p1/global/images/new",
	})
	assert.Equal(t, "DEPRECATED", d.state)
	assert.Equal(t, "2026-11-01T00:00:00Z", d.deprecated)
	assert.Equal(t, "2026-12-01T00:00:00Z", d.obsolete)
	assert.Equal(t, "2027-01-01T00:00:00Z", d.deleted)
	assert.Equal(t, "https://www.googleapis.com/compute/v1/projects/p1/global/images/new", d.replacement)
}

func TestGuestOsFeatureTypes(t *testing.T) {
	// Synthetic: nil entries and empty types are dropped.
	got := guestOsFeatureTypes([]*compute.GuestOsFeature{
		{Type: "UEFI_COMPATIBLE"}, nil, {Type: ""}, {Type: "GVNIC"},
	})
	assert.Equal(t, []any{"UEFI_COMPATIBLE", "GVNIC"}, got)
	assert.Empty(t, guestOsFeatureTypes(nil))
}
