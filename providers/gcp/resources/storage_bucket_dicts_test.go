// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"google.golang.org/api/storage/v1"
)

// bucketFromJSON decodes an API response body the way the SDK does, so the
// tests below exercise the same decoded structs a live list produces.
func bucketFromJSON(t *testing.T, body string) *storage.Bucket {
	t.Helper()
	var b storage.Bucket
	require.NoError(t, json.Unmarshal([]byte(body), &b))
	return &b
}

// TestBucketDictsKeepFalse is the regression test for a uniform bucket-level
// access setting of false disappearing from the dict.
//
// GCS returns "enabled": false on a bucket without uniform bucket-level access.
// Re-marshaling the decoded struct dropped it, so the buckets an audit is
// hunting for read null instead of false and
// `buckets.where(uniformBucketLevelAccess["enabled"] == false)` matched nothing.
func TestBucketDictsKeepFalse(t *testing.T) {
	bucket := bucketFromJSON(t, `{
	  "name": "ubla-off",
	  "iamConfiguration": {
	    "publicAccessPrevention": "inherited",
	    "uniformBucketLevelAccess": {"enabled": false},
	    "bucketPolicyOnly": {"enabled": false}
	  },
	  "retentionPolicy": {"effectiveTime": "2026-01-01T00:00:00Z", "isLocked": false, "retentionPeriod": "3600"},
	  "autoclass": {"enabled": false, "toggleTime": "2026-01-01T00:00:00Z"},
	  "hierarchicalNamespace": {"enabled": false},
	  "billing": {"requesterPays": false},
	  "ipFilter": {"mode": "Disabled", "allowAllServiceAgentAccess": false, "allowCrossOrgVpcs": false}
	}`)

	ubla := bucketUniformBucketLevelAccessDict(bucket.IamConfiguration.UniformBucketLevelAccess)
	require.Contains(t, ubla, "enabled", "uniformBucketLevelAccess.enabled must be present, not null")
	assert.Equal(t, false, ubla["enabled"])

	iamConfig := bucketIamConfigurationDict(bucket.IamConfiguration)
	nested, ok := iamConfig["uniformBucketLevelAccess"].(map[string]any)
	require.True(t, ok, "iamConfiguration.uniformBucketLevelAccess must be a dict")
	require.Contains(t, nested, "enabled")
	assert.Equal(t, false, nested["enabled"])
	bpo, ok := iamConfig["bucketPolicyOnly"].(map[string]any)
	require.True(t, ok, "iamConfiguration.bucketPolicyOnly must be a dict")
	require.Contains(t, bpo, "enabled")
	assert.Equal(t, false, bpo["enabled"])

	retention := bucketRetentionPolicyDict(bucket.RetentionPolicy)
	require.Contains(t, retention, "isLocked")
	assert.Equal(t, false, retention["isLocked"])

	autoclass := bucketAutoclassDict(bucket.Autoclass)
	require.Contains(t, autoclass, "enabled")
	assert.Equal(t, false, autoclass["enabled"])

	hns := bucketHierarchicalNamespaceDict(bucket.HierarchicalNamespace)
	require.Contains(t, hns, "enabled")
	assert.Equal(t, false, hns["enabled"])

	billing := bucketBillingDict(bucket.Billing)
	require.Contains(t, billing, "requesterPays")
	assert.Equal(t, false, billing["requesterPays"])

	ipFilter := bucketIpFilterDict(bucket.IpFilter)
	require.Contains(t, ipFilter, "allowAllServiceAgentAccess")
	assert.Equal(t, false, ipFilter["allowAllServiceAgentAccess"])
	require.Contains(t, ipFilter, "allowCrossOrgVpcs")
	assert.Equal(t, false, ipFilter["allowCrossOrgVpcs"])
}

// TestBucketDictsKeepTrue pins that the true case is unchanged, alongside the
// non-bool fields that travel with it.
func TestBucketDictsKeepTrue(t *testing.T) {
	bucket := bucketFromJSON(t, `{
	  "name": "ubla-on",
	  "iamConfiguration": {
	    "publicAccessPrevention": "enforced",
	    "uniformBucketLevelAccess": {"enabled": true, "lockedTime": "2026-04-01T00:00:00Z"}
	  },
	  "retentionPolicy": {"effectiveTime": "2026-01-01T00:00:00Z", "isLocked": true, "retentionPeriod": "3600"},
	  "autoclass": {"enabled": true, "terminalStorageClass": "ARCHIVE", "toggleTime": "2026-01-01T00:00:00Z"},
	  "hierarchicalNamespace": {"enabled": true},
	  "billing": {"requesterPays": true},
	  "ipFilter": {
	    "mode": "Enabled",
	    "allowAllServiceAgentAccess": true,
	    "allowCrossOrgVpcs": true,
	    "publicNetworkSource": {"allowedIpCidrRanges": ["203.0.113.0/24"]},
	    "vpcNetworkSources": [{"network": "projects/p/global/networks/n", "allowedIpCidrRanges": ["10.0.0.0/8"]}]
	  }
	}`)

	ubla := bucketUniformBucketLevelAccessDict(bucket.IamConfiguration.UniformBucketLevelAccess)
	assert.Equal(t, map[string]any{
		"enabled":    true,
		"lockedTime": "2026-04-01T00:00:00Z",
	}, ubla)

	assert.Equal(t, "enforced", bucketIamConfigurationDict(bucket.IamConfiguration)["publicAccessPrevention"])

	// retentionPeriod keeps the API's string encoding, which is the form the
	// field has always reported and what existing content compares against.
	assert.Equal(t, map[string]any{
		"effectiveTime":   "2026-01-01T00:00:00Z",
		"isLocked":        true,
		"retentionPeriod": "3600",
	}, bucketRetentionPolicyDict(bucket.RetentionPolicy))

	assert.Equal(t, map[string]any{
		"enabled":              true,
		"terminalStorageClass": "ARCHIVE",
		"toggleTime":           "2026-01-01T00:00:00Z",
	}, bucketAutoclassDict(bucket.Autoclass))

	assert.Equal(t, map[string]any{"enabled": true}, bucketHierarchicalNamespaceDict(bucket.HierarchicalNamespace))
	assert.Equal(t, map[string]any{"requesterPays": true}, bucketBillingDict(bucket.Billing))

	assert.Equal(t, map[string]any{
		"mode":                       "Enabled",
		"allowAllServiceAgentAccess": true,
		"allowCrossOrgVpcs":          true,
		"publicNetworkSource":        map[string]any{"allowedIpCidrRanges": []any{"203.0.113.0/24"}},
		"vpcNetworkSources": []any{map[string]any{
			"network":             "projects/p/global/networks/n",
			"allowedIpCidrRanges": []any{"10.0.0.0/8"},
		}},
	}, bucketIpFilterDict(bucket.IpFilter))
}

// TestBucketDictsNilStaysNull pins that an absent message reports null rather
// than an empty object. "The bucket has no retention policy" and "the bucket has
// a retention policy that is unlocked" are different facts and must not collapse
// onto the same value.
func TestBucketDictsNilStaysNull(t *testing.T) {
	bucket := bucketFromJSON(t, `{"name": "bare"}`)

	assert.Nil(t, bucketIamConfigurationDict(bucket.IamConfiguration))
	assert.Nil(t, bucketUniformBucketLevelAccessDict(nil))
	assert.Nil(t, bucketRetentionPolicyDict(bucket.RetentionPolicy))
	assert.Nil(t, bucketAutoclassDict(bucket.Autoclass))
	assert.Nil(t, bucketHierarchicalNamespaceDict(bucket.HierarchicalNamespace))
	assert.Nil(t, bucketBillingDict(bucket.Billing))
	assert.Nil(t, bucketIpFilterDict(bucket.IpFilter))

	// An iamConfiguration that carries only publicAccessPrevention must not
	// invent a uniformBucketLevelAccess sub-dict.
	withoutUbla := bucketFromJSON(t, `{"iamConfiguration": {"publicAccessPrevention": "inherited"}}`)
	dict := bucketIamConfigurationDict(withoutUbla.IamConfiguration)
	assert.NotContains(t, dict, "uniformBucketLevelAccess")
	assert.NotContains(t, dict, "bucketPolicyOnly")
}

// TestBucketDictsOmitEmptyStrings pins that an absent string stays absent rather
// than becoming an empty string that would read as a measured value.
func TestBucketDictsOmitEmptyStrings(t *testing.T) {
	bucket := bucketFromJSON(t, `{
	  "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": false}},
	  "retentionPolicy": {"isLocked": false},
	  "autoclass": {"enabled": false},
	  "ipFilter": {"allowAllServiceAgentAccess": false, "allowCrossOrgVpcs": false}
	}`)

	assert.Equal(t, map[string]any{"enabled": false},
		bucketUniformBucketLevelAccessDict(bucket.IamConfiguration.UniformBucketLevelAccess))
	assert.Equal(t, map[string]any{"isLocked": false}, bucketRetentionPolicyDict(bucket.RetentionPolicy))
	assert.Equal(t, map[string]any{"enabled": false}, bucketAutoclassDict(bucket.Autoclass))
	assert.Equal(t, map[string]any{
		"allowAllServiceAgentAccess": false,
		"allowCrossOrgVpcs":          false,
	}, bucketIpFilterDict(bucket.IpFilter))
	assert.NotContains(t, bucketIamConfigurationDict(bucket.IamConfiguration), "publicAccessPrevention")
}

// TestBucketConfigRoundTripIsLossy pins the SDK behavior the explicit builders
// exist to work around: the generated MarshalJSON honors omitempty for every
// bool unless ForceSendFields names it, and a decoded response never populates
// ForceSendFields. If this ever stops being true, the builders can be revisited.
func TestBucketConfigRoundTripIsLossy(t *testing.T) {
	bucket := bucketFromJSON(t, `{"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": false}}}`)
	ubla := bucket.IamConfiguration.UniformBucketLevelAccess
	require.False(t, ubla.Enabled, "the decoded struct carries the false")

	roundTripped, err := convert.JsonToDict(ubla)
	require.NoError(t, err)
	assert.NotContains(t, roundTripped, "enabled", "re-marshaling still drops a false bool")

	assert.Contains(t, bucketUniformBucketLevelAccessDict(ubla), "enabled")
}

// TestUniformBucketLevelAccessEnabledAgreesWithDict pins that the hoisted scalar
// and the dict it reads from report the same answer. They disagreed before:
// the scalar read false from the absent key by accident while the dict reported
// the setting as unknown.
func TestUniformBucketLevelAccessEnabledAgreesWithDict(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"ubla off", `{"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": false}}}`, false},
		{"ubla on", `{"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": true}}}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bucket := bucketFromJSON(t, c.body)
			dict := bucketUniformBucketLevelAccessDict(bucket.IamConfiguration.UniformBucketLevelAccess)

			res := &mqlGcpProjectStorageServiceBucket{
				UniformBucketLevelAccess: plugin.TValue[any]{Data: dict, State: plugin.StateIsSet},
			}
			got, err := res.uniformBucketLevelAccessEnabled()
			require.NoError(t, err)

			assert.Equal(t, c.want, got, "hoisted scalar")
			assert.Equal(t, c.want, dict["enabled"], "dict value")
		})
	}
}

// TestBucketDictsEmptyMessageReadsAsFalse documents the one case the API does
// not let us distinguish. GCS omits "enabled" entirely on a bucket where the
// setting is off, so an empty message and an explicit false decode identically
// and both report false, which is the API's documented default.
func TestBucketDictsEmptyMessageReadsAsFalse(t *testing.T) {
	empty := bucketFromJSON(t, `{"iamConfiguration": {"uniformBucketLevelAccess": {}}}`)
	explicit := bucketFromJSON(t, `{"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": false}}}`)

	assert.Equal(t,
		bucketUniformBucketLevelAccessDict(empty.IamConfiguration.UniformBucketLevelAccess),
		bucketUniformBucketLevelAccessDict(explicit.IamConfiguration.UniformBucketLevelAccess),
	)
	assert.Equal(t, map[string]any{"enabled": false},
		bucketUniformBucketLevelAccessDict(empty.IamConfiguration.UniformBucketLevelAccess))
}
