// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
)

func TestExternalVolumeStorageLocations(t *testing.T) {
	t.Run("parses json locations and ignores other properties", func(t *testing.T) {
		props := []sdk.ExternalVolumeProperty{
			{Parent: "", Name: "ALLOW_WRITES", Type: "Boolean", Value: "true"},
			{
				Parent: "STORAGE_LOCATIONS",
				Name:   "STORAGE_LOCATION_1",
				Value:  `{"NAME":"my-s3-loc","STORAGE_PROVIDER":"S3","STORAGE_BASE_URL":"s3://bucket/path/","STORAGE_AWS_ROLE_ARN":"arn:aws:iam::role/snowflake"}`,
			},
			{
				Parent: "STORAGE_LOCATIONS",
				Name:   "STORAGE_LOCATION_2",
				Value:  `{"NAME":"my-gcs-loc","STORAGE_PROVIDER":"GCS","STORAGE_BASE_URL":"gcs://bucket/","STORAGE_GCP_SERVICE_ACCOUNT":"svc@project.iam.gserviceaccount.com"}`,
			},
		}

		got := externalVolumeStorageLocations(props)
		if len(got) != 2 {
			t.Fatalf("got %d locations, want 2: %#v", len(got), got)
		}

		first, ok := got[0].(map[string]any)
		if !ok {
			t.Fatalf("location 0 is %T, want map[string]any", got[0])
		}
		want := map[string]any{
			"NAME":                 "my-s3-loc",
			"STORAGE_PROVIDER":     "S3",
			"STORAGE_BASE_URL":     "s3://bucket/path/",
			"STORAGE_AWS_ROLE_ARN": "arn:aws:iam::role/snowflake",
		}
		if !reflect.DeepEqual(first, want) {
			t.Errorf("location 0 = %#v, want %#v", first, want)
		}
	})

	t.Run("no locations yields an empty slice, never nil", func(t *testing.T) {
		got := externalVolumeStorageLocations([]sdk.ExternalVolumeProperty{
			{Parent: "", Name: "ALLOW_WRITES", Value: "false"},
		})
		if got == nil {
			t.Fatal("got nil, want an empty slice")
		}
		if len(got) != 0 {
			t.Errorf("got %#v, want an empty slice", got)
		}
	})

	// An unexpected describe format must not read as "no storage locations" —
	// that would make an exposure check pass vacuously.
	t.Run("unparseable value is preserved, not dropped", func(t *testing.T) {
		got := externalVolumeStorageLocations([]sdk.ExternalVolumeProperty{
			{Parent: "STORAGE_LOCATIONS", Name: "STORAGE_LOCATION_1", Value: "not json at all"},
		})
		if len(got) != 1 {
			t.Fatalf("got %d locations, want 1: %#v", len(got), got)
		}
		want := map[string]any{
			"NAME":             "STORAGE_LOCATION_1",
			"STORAGE_LOCATION": "not json at all",
		}
		if !reflect.DeepEqual(got[0], want) {
			t.Errorf("got %#v, want %#v", got[0], want)
		}
	})

	t.Run("json null is preserved rather than treated as an object", func(t *testing.T) {
		got := externalVolumeStorageLocations([]sdk.ExternalVolumeProperty{
			{Parent: "STORAGE_LOCATIONS", Name: "STORAGE_LOCATION_1", Value: "null"},
		})
		if len(got) != 1 {
			t.Fatalf("got %d locations, want 1: %#v", len(got), got)
		}
		location, ok := got[0].(map[string]any)
		if !ok {
			t.Fatalf("location is %T, want map[string]any", got[0])
		}
		if location["STORAGE_LOCATION"] != "null" {
			t.Errorf("got %#v, want the raw value preserved", location)
		}
	})

	t.Run("parent match is case insensitive", func(t *testing.T) {
		got := externalVolumeStorageLocations([]sdk.ExternalVolumeProperty{
			{Parent: "storage_locations", Name: "STORAGE_LOCATION_1", Value: `{"NAME":"loc"}`},
		})
		if len(got) != 1 {
			t.Errorf("got %d locations, want 1", len(got))
		}
	})
}
