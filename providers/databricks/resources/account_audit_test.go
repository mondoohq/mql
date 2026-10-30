// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
	"time"

	"github.com/databricks/databricks-sdk-go/service/iam"
	"github.com/databricks/databricks-sdk-go/service/settings"
)

func TestRfc3339Time(t *testing.T) {
	t.Run("empty means unset", func(t *testing.T) {
		// A secret with no expiry reports an empty expire_time. Parsing that
		// into the zero time would date it to year 1 and read as expired.
		if got := rfc3339Time(""); got != nil {
			t.Fatalf("rfc3339Time(\"\") = %v, want nil", got)
		}
	})

	t.Run("parses an RFC 3339 timestamp", func(t *testing.T) {
		got := rfc3339Time("2026-08-09T10:38:32Z")
		if got == nil {
			t.Fatal("rfc3339Time() = nil, want a time")
		}
		want := time.Date(2026, 8, 9, 10, 38, 32, 0, time.UTC)
		if !got.Equal(want) {
			t.Fatalf("rfc3339Time() = %v, want %v", got, want)
		}
	})

	t.Run("an unrecognized format reads as unset, not as a date", func(t *testing.T) {
		if got := rfc3339Time("09/08/2026"); got != nil {
			t.Fatalf("rfc3339Time() = %v, want nil", got)
		}
	})
}

func TestAssignedPrincipal(t *testing.T) {
	cases := []struct {
		name      string
		principal iam.PrincipalOutput
		wantName  string
		wantKind  string
	}{
		{"user", iam.PrincipalOutput{UserName: "alice@example.com"}, "alice@example.com", principalKindUser},
		{"group", iam.PrincipalOutput{GroupName: "data-eng"}, "data-eng", principalKindGroup},
		{"service principal", iam.PrincipalOutput{ServicePrincipalName: "etl-sp"}, "etl-sp", principalKindServicePrincipal},
		// An assignment naming no principal is unattributable, and every such
		// entry would produce the same record. The caller drops these.
		{"nothing named", iam.PrincipalOutput{PrincipalId: 42}, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotKind := assignedPrincipal(tc.principal)
			if gotName != tc.wantName || gotKind != tc.wantKind {
				t.Fatalf("assignedPrincipal() = (%q, %q), want (%q, %q)", gotName, gotKind, tc.wantName, tc.wantKind)
			}
		})
	}
}

func TestInternetDestinationMap(t *testing.T) {
	got := internetDestinationMap([]settings.EgressNetworkPolicyNetworkAccessPolicyInternetDestination{
		{Destination: "pypi.org", InternetDestinationType: "FQDN"},
		{Destination: "files.pythonhosted.org", InternetDestinationType: "FQDN"},
	})
	want := map[string]any{"pypi.org": "FQDN", "files.pythonhosted.org": "FQDN"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("internetDestinationMap() = %v, want %v", got, want)
	}
}

func TestStorageDestinationDicts(t *testing.T) {
	t.Run("keeps only the fields the destination's cloud populates", func(t *testing.T) {
		got := storageDestinationDicts([]settings.EgressNetworkPolicyNetworkAccessPolicyStorageDestination{
			{StorageDestinationType: "AWS_S3", BucketName: "landing", Region: "us-east-1"},
			{StorageDestinationType: "AZURE_STORAGE", AzureStorageAccount: "acct", AzureStorageService: "blob"},
		})
		want := []any{
			map[string]any{"type": "AWS_S3", "bucketName": "landing", "region": "us-east-1"},
			map[string]any{"type": "AZURE_STORAGE", "azureStorageAccount": "acct", "azureStorageService": "blob"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("storageDestinationDicts() = %v, want %v", got, want)
		}
	})

	t.Run("no destinations yields an empty list", func(t *testing.T) {
		if got := storageDestinationDicts(nil); len(got) != 0 {
			t.Fatalf("storageDestinationDicts(nil) = %v, want empty", got)
		}
	})
}
