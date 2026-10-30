// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/databricks/databricks-sdk-go/service/catalog"
	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/iam"
)

func TestEpochMsTime(t *testing.T) {
	// A known epoch-ms: 2021-01-01T00:00:00Z = 1609459200000 ms.
	const knownMs int64 = 1609459200000

	tests := []struct {
		name string
		ms   int64
		// wantNil true means the function should return a nil *time.Time.
		wantNil bool
	}{
		{name: "zero is unset sentinel", ms: 0, wantNil: true},
		// NOTE: the guard is `ms <= 0`, so any negative value (not just -1)
		// maps to nil.
		{name: "negative sentinel -1", ms: -1, wantNil: true},
		{name: "large negative", ms: -1609459200000, wantNil: true},
		{name: "known positive epoch-ms", ms: knownMs, wantNil: false},
		{name: "one millisecond", ms: 1, wantNil: false},
		{name: "large positive", ms: 4102444800000, wantNil: false}, // 2100-01-01T00:00:00Z
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := epochMsTime(tc.ms)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("epochMsTime(%d) = %v, want nil", tc.ms, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("epochMsTime(%d) = nil, want non-nil", tc.ms)
			}
			// The result must equal time.UnixMilli of the same input.
			want := time.UnixMilli(tc.ms)
			if !got.Equal(want) {
				t.Fatalf("epochMsTime(%d) = %v, want %v", tc.ms, got, want)
			}
		})
	}

	// Spot-check the actual UTC calendar time for the known epoch-ms.
	got := epochMsTime(knownMs)
	if got == nil {
		t.Fatal("epochMsTime(knownMs) = nil, want non-nil")
	}
	wantUTC := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.UTC().Equal(wantUTC) {
		t.Fatalf("epochMsTime(%d).UTC() = %v, want %v", knownMs, got.UTC(), wantUTC)
	}
}

func TestEpochMsRFC3339(t *testing.T) {
	tests := []struct {
		name string
		ms   int64
		want string
	}{
		{name: "zero is unset sentinel", ms: 0, want: ""},
		// NOTE: the guard is `ms <= 0`, so negatives render as "" too.
		{name: "negative sentinel -1", ms: -1, want: ""},
		{name: "known positive epoch-ms", ms: 1609459200000, want: "2021-01-01T00:00:00Z"},
		{name: "one millisecond after epoch", ms: 1, want: "1970-01-01T00:00:00Z"},
		{name: "large positive", ms: 4102444800000, want: "2100-01-01T00:00:00Z"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := epochMsRFC3339(tc.ms)
			if got != tc.want {
				t.Fatalf("epochMsRFC3339(%d) = %q, want %q", tc.ms, got, tc.want)
			}
		})
	}
}

func TestComplexValueIds(t *testing.T) {
	tests := []struct {
		name string
		vals []iam.ComplexValue
		want []string
	}{
		{
			name: "nil slice yields empty non-nil slice",
			vals: nil,
			want: []string{},
		},
		{
			name: "empty slice yields empty non-nil slice",
			vals: []iam.ComplexValue{},
			want: []string{},
		},
		{
			name: "entries with values",
			vals: []iam.ComplexValue{{Value: "1"}, {Value: "2"}},
			want: []string{"1", "2"},
		},
		{
			name: "empty value is skipped",
			vals: []iam.ComplexValue{{Value: ""}},
			want: []string{},
		},
		{
			name: "mixed populated and empty values",
			vals: []iam.ComplexValue{
				{Value: "grp-1", Display: "Group 1"},
				{Value: ""},
				{Value: "grp-2"},
			},
			want: []string{"grp-1", "grp-2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := complexValueIds(tc.vals)
			// complexValueIds always returns a non-nil slice (make with cap).
			if got == nil {
				t.Fatalf("complexValueIds(%v) = nil, want non-nil", tc.vals)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("complexValueIds(%v) = %v, want %v", tc.vals, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("complexValueIds(%v)[%d] = %q, want %q", tc.vals, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSseEncryption(t *testing.T) {
	tests := []struct {
		name          string
		ed            *catalog.EncryptionDetails
		wantAlgorithm string
		wantKmsArn    string
	}{
		{
			name:          "nil pointer",
			ed:            nil,
			wantAlgorithm: "",
			wantKmsArn:    "",
		},
		{
			name:          "non-nil with nil SseEncryptionDetails",
			ed:            &catalog.EncryptionDetails{SseEncryptionDetails: nil},
			wantAlgorithm: "",
			wantKmsArn:    "",
		},
		{
			name: "fully populated SSE-KMS",
			ed: &catalog.EncryptionDetails{
				SseEncryptionDetails: &catalog.SseEncryptionDetails{
					Algorithm:    catalog.SseEncryptionDetailsAlgorithmAwsSseKms,
					AwsKmsKeyArn: "arn:aws:kms:us-east-1:123456789012:key/abc",
				},
			},
			wantAlgorithm: "AWS_SSE_KMS",
			wantKmsArn:    "arn:aws:kms:us-east-1:123456789012:key/abc",
		},
		{
			name: "SSE-S3 with no KMS ARN",
			ed: &catalog.EncryptionDetails{
				SseEncryptionDetails: &catalog.SseEncryptionDetails{
					Algorithm: catalog.SseEncryptionDetailsAlgorithmAwsSseS3,
				},
			},
			wantAlgorithm: "AWS_SSE_S3",
			wantKmsArn:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			algo, arn := sseEncryption(tc.ed)
			if algo != tc.wantAlgorithm {
				t.Fatalf("sseEncryption() algorithm = %q, want %q", algo, tc.wantAlgorithm)
			}
			if arn != tc.wantKmsArn {
				t.Fatalf("sseEncryption() kmsKeyArn = %q, want %q", arn, tc.wantKmsArn)
			}
		})
	}
}

func TestInitScriptsToDict(t *testing.T) {
	tests := []struct {
		name            string
		scripts         []compute.InitScriptInfo
		wantType        string
		wantDestination string
	}{
		{
			name:            "workspace script",
			scripts:         []compute.InitScriptInfo{{Workspace: &compute.WorkspaceStorageInfo{Destination: "/Shared/init.sh"}}},
			wantType:        "workspace",
			wantDestination: "/Shared/init.sh",
		},
		{
			name:            "volumes script",
			scripts:         []compute.InitScriptInfo{{Volumes: &compute.VolumesStorageInfo{Destination: "/Volumes/my-init.sh"}}},
			wantType:        "volumes",
			wantDestination: "/Volumes/my-init.sh",
		},
		{
			name:            "abfss script",
			scripts:         []compute.InitScriptInfo{{Abfss: &compute.Adlsgen2Info{Destination: "abfss://c@a.dfs.core.windows.net/i.sh"}}},
			wantType:        "abfss",
			wantDestination: "abfss://c@a.dfs.core.windows.net/i.sh",
		},
		{
			name:            "gcs script",
			scripts:         []compute.InitScriptInfo{{Gcs: &compute.GcsStorageInfo{Destination: "gs://bucket/i.sh"}}},
			wantType:        "gcs",
			wantDestination: "gs://bucket/i.sh",
		},
		{
			name:            "dbfs script",
			scripts:         []compute.InitScriptInfo{{Dbfs: &compute.DbfsStorageInfo{Destination: "dbfs:/i.sh"}}},
			wantType:        "dbfs",
			wantDestination: "dbfs:/i.sh",
		},
		{
			name:            "local file script",
			scripts:         []compute.InitScriptInfo{{File: &compute.LocalFileInfo{Destination: "file:/local/i.sh"}}},
			wantType:        "file",
			wantDestination: "file:/local/i.sh",
		},
		{
			// An entry with no storage field set must still be reported, so the
			// list never silently under-reports the number of init scripts.
			name:            "unknown storage type still reported",
			scripts:         []compute.InitScriptInfo{{}},
			wantType:        "",
			wantDestination: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := initScriptsToDict(tc.scripts)
			if len(got) != 1 {
				t.Fatalf("initScriptsToDict() returned %d entries, want 1", len(got))
			}
			entry, ok := got[0].(map[string]any)
			if !ok {
				t.Fatalf("entry is %T, want map[string]any", got[0])
			}
			if entry["type"] != tc.wantType {
				t.Fatalf("type = %v, want %q", entry["type"], tc.wantType)
			}
			if entry["destination"] != tc.wantDestination {
				t.Fatalf("destination = %v, want %q", entry["destination"], tc.wantDestination)
			}
		})
	}
}

func TestInitScriptsToDictS3CarriesExtras(t *testing.T) {
	got := initScriptsToDict([]compute.InitScriptInfo{{
		S3: &compute.S3StorageInfo{
			Destination:      "s3://bucket/i.sh",
			Region:           "us-west-2",
			Endpoint:         "https://s3.us-west-2.amazonaws.com",
			EnableEncryption: true,
		},
	}})
	if len(got) != 1 {
		t.Fatalf("returned %d entries, want 1", len(got))
	}
	entry := got[0].(map[string]any)
	for k, want := range map[string]any{
		"type":             "s3",
		"destination":      "s3://bucket/i.sh",
		"region":           "us-west-2",
		"endpoint":         "https://s3.us-west-2.amazonaws.com",
		"enableEncryption": true,
	} {
		if entry[k] != want {
			t.Fatalf("%s = %v, want %v", k, entry[k], want)
		}
	}
}

func TestInitScriptsToDictPreservesOrder(t *testing.T) {
	got := initScriptsToDict([]compute.InitScriptInfo{
		{Workspace: &compute.WorkspaceStorageInfo{Destination: "/first.sh"}},
		{Dbfs: &compute.DbfsStorageInfo{Destination: "dbfs:/second.sh"}},
		{Volumes: &compute.VolumesStorageInfo{Destination: "/Volumes/third.sh"}},
	})
	want := []string{"/first.sh", "dbfs:/second.sh", "/Volumes/third.sh"}
	if len(got) != len(want) {
		t.Fatalf("returned %d entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		if d := got[i].(map[string]any)["destination"]; d != w {
			t.Fatalf("entry %d destination = %v, want %q", i, d, w)
		}
	}
}

func TestInitScriptsToDictEmpty(t *testing.T) {
	got := initScriptsToDict(nil)
	if got == nil {
		t.Fatal("initScriptsToDict(nil) = nil, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Fatalf("initScriptsToDict(nil) returned %d entries, want 0", len(got))
	}
}

func TestDockerImageUrl(t *testing.T) {
	if got := dockerImageUrl(nil); got != "" {
		t.Fatalf("dockerImageUrl(nil) = %q, want empty", got)
	}
	// The basic-auth password must never leak into the exposed value.
	img := &compute.DockerImage{
		Url:       "example.io/repo/image:1.2.3",
		BasicAuth: &compute.DockerBasicAuth{Username: "u", Password: "hunter2"},
	}
	if got := dockerImageUrl(img); got != "example.io/repo/image:1.2.3" {
		t.Fatalf("dockerImageUrl() = %q", got)
	}
}

func TestGoogleServiceAccount(t *testing.T) {
	if got := googleServiceAccount(nil); got != "" {
		t.Fatalf("googleServiceAccount(nil) = %q, want empty", got)
	}
	attrs := &compute.GcpAttributes{GoogleServiceAccount: "sa@project.iam.gserviceaccount.com"}
	if got := googleServiceAccount(attrs); got != "sa@project.iam.gserviceaccount.com" {
		t.Fatalf("googleServiceAccount() = %q", got)
	}
}

func TestNonEmptyString(t *testing.T) {
	// Synthetic: the two cases the helper distinguishes.
	if got := nonEmptyString(""); got.Value != nil {
		t.Fatalf("nonEmptyString(\"\") = %v, want null", got.Value)
	}
	if got := nonEmptyString("24h"); got.Value != "24h" {
		t.Fatalf("nonEmptyString(\"24h\") = %v, want 24h", got.Value)
	}
}
