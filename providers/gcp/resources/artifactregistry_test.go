// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

//go:fix inline
func int32Ptr(v int32) *int32 { return new(v) }

func TestCleanupPolicyType(t *testing.T) {
	t.Run("condition policy", func(t *testing.T) {
		p := &artifactregistrypb.CleanupPolicy{
			ConditionType: &artifactregistrypb.CleanupPolicy_Condition{
				Condition: &artifactregistrypb.CleanupPolicyCondition{},
			},
		}
		assert.Equal(t, "condition", cleanupPolicyType(p))
	})

	t.Run("mostRecentVersions policy", func(t *testing.T) {
		p := &artifactregistrypb.CleanupPolicy{
			ConditionType: &artifactregistrypb.CleanupPolicy_MostRecentVersions{
				MostRecentVersions: &artifactregistrypb.CleanupPolicyMostRecentVersions{
					KeepCount: int32Ptr(5),
				},
			},
		}
		assert.Equal(t, "mostRecentVersions", cleanupPolicyType(p))
	})

	t.Run("no condition type set", func(t *testing.T) {
		p := &artifactregistrypb.CleanupPolicy{}
		assert.Equal(t, "", cleanupPolicyType(p))
	})
}

func TestExtractFormatConfigFields(t *testing.T) {
	t.Run("docker config with immutable tags", func(t *testing.T) {
		r := &artifactregistrypb.Repository{
			Format: artifactregistrypb.Repository_DOCKER,
			FormatConfig: &artifactregistrypb.Repository_DockerConfig{
				DockerConfig: &artifactregistrypb.Repository_DockerRepositoryConfig{
					ImmutableTags: true,
				},
			},
		}
		f := extractFormatConfigFields(r)
		assert.True(t, f.immutableTags)
		assert.False(t, f.allowSnapshotOverwrites)
		assert.Empty(t, f.mavenVersionPolicy)
	})

	t.Run("docker config without immutable tags", func(t *testing.T) {
		r := &artifactregistrypb.Repository{
			Format: artifactregistrypb.Repository_DOCKER,
			FormatConfig: &artifactregistrypb.Repository_DockerConfig{
				DockerConfig: &artifactregistrypb.Repository_DockerRepositoryConfig{
					ImmutableTags: false,
				},
			},
		}
		f := extractFormatConfigFields(r)
		assert.False(t, f.immutableTags)
	})

	t.Run("maven config with snapshot overwrites", func(t *testing.T) {
		r := &artifactregistrypb.Repository{
			Format: artifactregistrypb.Repository_MAVEN,
			FormatConfig: &artifactregistrypb.Repository_MavenConfig{
				MavenConfig: &artifactregistrypb.Repository_MavenRepositoryConfig{
					AllowSnapshotOverwrites: true,
					VersionPolicy:           artifactregistrypb.Repository_MavenRepositoryConfig_RELEASE,
				},
			},
		}
		f := extractFormatConfigFields(r)
		assert.False(t, f.immutableTags)
		assert.True(t, f.allowSnapshotOverwrites)
		assert.Equal(t, "RELEASE", f.mavenVersionPolicy)
	})

	t.Run("maven config with snapshot policy", func(t *testing.T) {
		r := &artifactregistrypb.Repository{
			Format: artifactregistrypb.Repository_MAVEN,
			FormatConfig: &artifactregistrypb.Repository_MavenConfig{
				MavenConfig: &artifactregistrypb.Repository_MavenRepositoryConfig{
					VersionPolicy: artifactregistrypb.Repository_MavenRepositoryConfig_SNAPSHOT,
				},
			},
		}
		f := extractFormatConfigFields(r)
		assert.Equal(t, "SNAPSHOT", f.mavenVersionPolicy)
		assert.False(t, f.allowSnapshotOverwrites)
	})

	t.Run("no format config (e.g. NPM, Python, Go)", func(t *testing.T) {
		r := &artifactregistrypb.Repository{
			Format: artifactregistrypb.Repository_NPM,
		}
		f := extractFormatConfigFields(r)
		assert.False(t, f.immutableTags)
		assert.False(t, f.allowSnapshotOverwrites)
		assert.Empty(t, f.mavenVersionPolicy)
	})

	t.Run("nil docker config inner", func(t *testing.T) {
		r := &artifactregistrypb.Repository{
			Format: artifactregistrypb.Repository_DOCKER,
			FormatConfig: &artifactregistrypb.Repository_DockerConfig{
				DockerConfig: nil,
			},
		}
		f := extractFormatConfigFields(r)
		assert.False(t, f.immutableTags)
	})
}

func TestTimestampAsTimePtrFromVulnScanConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		assert.Nil(t, timestampAsTimePtrFromVulnScanConfig(nil))
	})

	t.Run("nil timestamp in config", func(t *testing.T) {
		cfg := &artifactregistrypb.Repository_VulnerabilityScanningConfig{}
		assert.Nil(t, timestampAsTimePtrFromVulnScanConfig(cfg))
	})

	t.Run("valid timestamp", func(t *testing.T) {
		ts := timestamppb.New(time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC))
		cfg := &artifactregistrypb.Repository_VulnerabilityScanningConfig{
			LastEnableTime: ts,
		}
		result := timestampAsTimePtrFromVulnScanConfig(cfg)
		assert.NotNil(t, result)
		assert.Equal(t, time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC), *result)
	})
}
