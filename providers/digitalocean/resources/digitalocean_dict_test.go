// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertDictSerializable enforces the same contract as llx's dict2primitive:
// a value stored in a `dict`/`[]dict` field must be one of bool, int64,
// float64, string, []any, map[string]any, or nil. Anything else (a raw SDK
// *int32, int32, []string, *time.Time, ...) trips the converter's default
// branch and surfaces to the user as
// "failed to convert dict to primitive, unsupported child type: ...".
// The recursion mirrors dict2primitive so nested values are checked too.
func assertDictSerializable(t *testing.T, path string, v any) {
	t.Helper()
	switch x := v.(type) {
	case nil, bool, int64, float64, string:
		// JSON-native scalars — fine.
	case []any:
		for i, e := range x {
			assertDictSerializable(t, path, e)
			_ = i
		}
	case map[string]any:
		for k, e := range x {
			assertDictSerializable(t, path+"."+k, e)
		}
	default:
		t.Fatalf("dict value %q is not JSON-native (%T); dict2primitive will reject it", path, v)
	}
}

func TestSecretVersionDict_Serializable(t *testing.T) {
	// Timestamps must be strings, not *time.Time.
	d := secretVersionDict(&godo.SecretVersion{
		Version:   3,
		CreatedAt: "2026-01-02T15:04:05Z",
		UpdatedAt: "2026-01-03T15:04:05Z",
	})
	for k, v := range d {
		assertDictSerializable(t, "secretVersion."+k, v)
	}
	assert.Equal(t, int64(3), d["version"])
	assert.Equal(t, "2026-01-02T15:04:05Z", d["createdAt"])
	assert.Equal(t, "2026-01-03T15:04:05Z", d["updatedAt"])
}

func TestSpacesCorsRuleDict_Serializable(t *testing.T) {
	tests := []struct {
		name string
		rule s3types.CORSRule
	}{
		{
			name: "fully populated",
			rule: s3types.CORSRule{
				ID:             aws.String("rule-1"),
				AllowedHeaders: []string{"*"},
				AllowedMethods: []string{"GET", "PUT"},
				AllowedOrigins: []string{"https://example.com"},
				ExposeHeaders:  []string{"ETag"},
				MaxAgeSeconds:  aws.Int32(3600),
			},
		},
		{
			// The common case: required members only, nil max-age. This is
			// what used to error (raw []string + nil *int32 in the dict).
			name: "required members only, nil maxAge",
			rule: s3types.CORSRule{
				AllowedMethods: []string{"GET"},
				AllowedOrigins: []string{"*"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := spacesCorsRuleDict(tt.rule)
			for k, v := range d {
				assertDictSerializable(t, "corsRule."+k, v)
			}
			// []string must be widened to []any.
			methods, ok := d["allowedMethods"].([]any)
			require.True(t, ok, "allowedMethods must be []any, got %T", d["allowedMethods"])
			assert.NotEmpty(t, methods)
			// nil max-age must be omitted, not stored as a typed nil.
			if tt.rule.MaxAgeSeconds == nil {
				_, present := d["maxAgeSeconds"]
				assert.False(t, present, "maxAgeSeconds must be omitted when nil")
			} else {
				assert.Equal(t, int64(3600), d["maxAgeSeconds"])
			}
		})
	}
}

func TestSpacesLifecycleRuleDict_Serializable(t *testing.T) {
	tests := []struct {
		name        string
		rule        s3types.LifecycleRule
		wantExpDays bool
	}{
		{
			name: "expiration + noncurrent + abort days set",
			rule: s3types.LifecycleRule{
				ID:                          aws.String("lc-1"),
				Status:                      s3types.ExpirationStatusEnabled,
				Filter:                      &s3types.LifecycleRuleFilter{Prefix: aws.String("logs/")},
				Expiration:                  &s3types.LifecycleExpiration{Days: aws.Int32(30)},
				NoncurrentVersionExpiration: &s3types.NoncurrentVersionExpiration{NoncurrentDays: aws.Int32(7)},
				AbortIncompleteMultipartUpload: &s3types.AbortIncompleteMultipartUpload{
					DaysAfterInitiation: aws.Int32(1),
				},
			},
			wantExpDays: true,
		},
		{
			// A status-only rule (no day counts) must not store typed-nil *int32.
			name:        "no day counts",
			rule:        s3types.LifecycleRule{Status: s3types.ExpirationStatusEnabled},
			wantExpDays: false,
		},
		{
			// Present sub-struct but nil Days pointer — must be omitted.
			name: "expiration present but nil Days",
			rule: s3types.LifecycleRule{
				Status:     s3types.ExpirationStatusEnabled,
				Expiration: &s3types.LifecycleExpiration{},
			},
			wantExpDays: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := spacesLifecycleRuleDict(tt.rule)
			for k, v := range d {
				assertDictSerializable(t, "lifecycleRule."+k, v)
			}
			_, present := d["expirationDays"]
			assert.Equal(t, tt.wantExpDays, present)
			if tt.wantExpDays {
				assert.Equal(t, int64(30), d["expirationDays"])
			}
		})
	}
}
