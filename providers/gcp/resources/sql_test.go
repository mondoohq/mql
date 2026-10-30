// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/sqladmin/v1"
)

func TestSQLIPMappingID(t *testing.T) {
	// A Cloud SQL instance can expose more than one IP of the same Type
	// (e.g., two PRIVATE IPs across distinct VPC networks). The address
	// itself disambiguates them.
	cases := []struct {
		name string
		want string
		got  string
	}{
		{
			name: "primary",
			want: "inst1/ipAddresses/PRIMARY/34.10.20.30",
			got:  sqlIPMappingID("inst1", "PRIMARY", "34.10.20.30"),
		},
		{
			name: "first private",
			want: "inst1/ipAddresses/PRIVATE/10.0.0.5",
			got:  sqlIPMappingID("inst1", "PRIVATE", "10.0.0.5"),
		},
		{
			name: "second private on different VPC",
			want: "inst1/ipAddresses/PRIVATE/10.1.0.5",
			got:  sqlIPMappingID("inst1", "PRIVATE", "10.1.0.5"),
		},
	}
	seen := make(map[string]string, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got)
			if prev, exists := seen[tc.got]; exists {
				t.Fatalf("id collision: %q produced by both %q and %q", tc.got, prev, tc.name)
			}
			seen[tc.got] = tc.name
		})
	}
}

func TestSQLDenyMaintenancePeriodID(t *testing.T) {
	// Two periods can begin on the same date (e.g., recurring annual
	// freezes) but end on different ones; both must participate in the id.
	cases := []struct {
		name string
		want string
		got  string
	}{
		{
			name: "single period",
			want: "inst1/settings/denyMaintenancePeriod/2026-01-01/2026-01-07",
			got:  sqlDenyMaintenancePeriodID("inst1", "2026-01-01", "2026-01-07"),
		},
		{
			name: "same start, different end",
			want: "inst1/settings/denyMaintenancePeriod/2026-01-01/2026-01-14",
			got:  sqlDenyMaintenancePeriodID("inst1", "2026-01-01", "2026-01-14"),
		},
		{
			name: "different start, same end",
			want: "inst1/settings/denyMaintenancePeriod/2026-02-01/2026-01-14",
			got:  sqlDenyMaintenancePeriodID("inst1", "2026-02-01", "2026-01-14"),
		},
	}
	seen := make(map[string]string, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got)
			if prev, exists := seen[tc.got]; exists {
				t.Fatalf("id collision: %q produced by both %q and %q", tc.got, prev, tc.name)
			}
			seen[tc.got] = tc.name
		})
	}
}

func TestSQLDiskConfidentialMode(t *testing.T) {
	// The whole DiskEncryptionConfiguration message is absent on an instance
	// using Google-managed encryption, which is the common case. Reading it
	// unguarded would panic on most of an estate.
	t.Run("absent encryption configuration reports not enabled", func(t *testing.T) {
		assert.False(t, sqlDiskConfidentialMode(nil))
	})

	// Confidential Mode is only supported on zonal C4A instances, so an
	// encryption configuration that exists for a customer-managed key but says
	// nothing about confidential disks must report false rather than inheriting
	// anything from the key being set.
	t.Run("customer-managed key alone does not imply confidential mode", func(t *testing.T) {
		assert.False(t, sqlDiskConfidentialMode(&sqladmin.DiskEncryptionConfiguration{
			KmsKeyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		}))
	})

	t.Run("enabled confidential mode is reported", func(t *testing.T) {
		assert.True(t, sqlDiskConfidentialMode(&sqladmin.DiskEncryptionConfiguration{
			ConfidentialMode: true,
		}))
	})
}

func TestSQLDiskEncryptionConfigDict(t *testing.T) {
	t.Run("absent configuration is nil", func(t *testing.T) {
		assert.Nil(t, sqlDiskEncryptionConfigDict(nil))
	})

	t.Run("carries the key and the source log encryption setting", func(t *testing.T) {
		assert.Equal(t, map[string]any{
			"kmsKeyName":                      "projects/p/locations/l/keyRings/r/cryptoKeys/k",
			"cmekSourceLogEncryptionEnforced": true,
		}, sqlDiskEncryptionConfigDict(&sqladmin.DiskEncryptionConfiguration{
			KmsKeyName:                      "projects/p/locations/l/keyRings/r/cryptoKeys/k",
			CmekSourceLogEncryptionEnforced: true,
		}))
	})
}

func TestSQLCmekSourceLogEncryptionEnforced(t *testing.T) {
	// Google-managed encryption has no configuration at all; the setting does
	// not apply and must not read as false.
	t.Run("absent configuration is null", func(t *testing.T) {
		assert.Nil(t, sqlCmekSourceLogEncryptionEnforced(nil))
	})

	t.Run("configuration without a customer-managed key is null", func(t *testing.T) {
		assert.Nil(t, sqlCmekSourceLogEncryptionEnforced(&sqladmin.DiskEncryptionConfiguration{
			ConfidentialMode: true,
		}))
	})

	t.Run("customer-managed key without enforcement is false", func(t *testing.T) {
		got := sqlCmekSourceLogEncryptionEnforced(&sqladmin.DiskEncryptionConfiguration{
			KmsKeyName: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		})
		if assert.NotNil(t, got) {
			assert.False(t, *got)
		}
	})

	t.Run("enforced is true", func(t *testing.T) {
		got := sqlCmekSourceLogEncryptionEnforced(&sqladmin.DiskEncryptionConfiguration{
			KmsKeyName:                      "projects/p/locations/l/keyRings/r/cryptoKeys/k",
			CmekSourceLogEncryptionEnforced: true,
		})
		if assert.NotNil(t, got) {
			assert.True(t, *got)
		}
	})
}
