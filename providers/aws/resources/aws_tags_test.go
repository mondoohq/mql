// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"

	"github.com/aws/aws-sdk-go-v2/aws"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	cstypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	elasticache_types "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	secretstypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyValueTag mirrors the shape of the vast majority of AWS SDK tag structs
// (Key/Value, both *string).
type keyValueTag struct {
	Key   *string
	Value *string
}

// tagKeyValueTag mirrors the KMS-style shape (TagKey/TagValue) to prove the
// generic helper handles alternate field names via its accessors.
type tagKeyValueTag struct {
	TagKey   *string
	TagValue *string
}

func kvKey(t keyValueTag) *string   { return t.Key }
func kvValue(t keyValueTag) *string { return t.Value }

func TestTagsToMap(t *testing.T) {
	t.Run("nil slice returns non-nil empty map", func(t *testing.T) {
		got := tagsToMap(nil, kvKey, kvValue)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("empty slice returns non-nil empty map", func(t *testing.T) {
		got := tagsToMap([]keyValueTag{}, kvKey, kvValue)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("maps key/value pairs", func(t *testing.T) {
		got := tagsToMap([]keyValueTag{
			{Key: aws.String("Name"), Value: aws.String("web")},
			{Key: aws.String("env"), Value: aws.String("prod")},
		}, kvKey, kvValue)
		assert.Equal(t, map[string]any{"Name": "web", "env": "prod"}, got)
	})

	t.Run("skips entries with a nil key", func(t *testing.T) {
		got := tagsToMap([]keyValueTag{
			{Key: nil, Value: aws.String("orphan")},
			{Key: aws.String("ok"), Value: aws.String("yes")},
		}, kvKey, kvValue)
		assert.Equal(t, map[string]any{"ok": "yes"}, got)
	})

	t.Run("coerces a nil value to empty string, keeping the key", func(t *testing.T) {
		got := tagsToMap([]keyValueTag{
			{Key: aws.String("present-empty"), Value: nil},
		}, kvKey, kvValue)
		assert.Equal(t, map[string]any{"present-empty": ""}, got)
	})

	t.Run("values are stored as strings", func(t *testing.T) {
		got := tagsToMap([]keyValueTag{
			{Key: aws.String("k"), Value: aws.String("v")},
		}, kvKey, kvValue)
		v, ok := got["k"].(string)
		require.True(t, ok, "value must be a string, got %T", got["k"])
		assert.Equal(t, "v", v)
	})

	t.Run("works with alternate field names (TagKey/TagValue)", func(t *testing.T) {
		got := tagsToMap([]tagKeyValueTag{
			{TagKey: aws.String("k"), TagValue: aws.String("v")},
			{TagKey: nil, TagValue: aws.String("dropped")},
		},
			func(t tagKeyValueTag) *string { return t.TagKey },
			func(t tagKeyValueTag) *string { return t.TagValue },
		)
		assert.Equal(t, map[string]any{"k": "v"}, got)
	})
}

// Wrapper spot-checks: guard the mechanical rewrite of the per-service
// converters against a Key/Value accessor swap or wrong output type. The
// common Tag shape is already covered by TestEc2TagsToMap (Tag -> string) and
// TestCfnTagsToMap (Tag -> any); these cover the structurally different
// families.

func TestAutoscalingTagsToMap_TagDescriptionShape(t *testing.T) {
	// autoscaling / SSM use ec2types.TagDescription, not Tag.
	got := autoscalingTagsToMap([]astypes.TagDescription{
		{Key: aws.String("team"), Value: aws.String("infra")},
		{Key: aws.String("empty"), Value: nil},
		{Key: nil, Value: aws.String("dropped")},
	})
	assert.Equal(t, map[string]any{"team": "infra", "empty": ""}, got)
}

func TestEmrTagsToMap_StringMapShape(t *testing.T) {
	got := emrTagsToMap([]emrtypes.Tag{
		{Key: aws.String("k"), Value: aws.String("v")},
	})
	// must be a map[string]string, and key/value must not be swapped
	assert.Equal(t, map[string]string{"k": "v"}, got)
}

func TestElasticacheTagsToMap(t *testing.T) {
	got := elasticacheTagsToMap([]elasticache_types.Tag{
		{Key: aws.String("env"), Value: aws.String("prod")},
		{Key: aws.String("empty"), Value: nil},
		{Key: nil, Value: aws.String("dropped")},
	})
	assert.Equal(t, map[string]any{"env": "prod", "empty": ""}, got)
}

// secretTagsToStringMap feeds the discovery tag filter. A swapped Key/Value
// accessor here would not fail loudly - it would silently invert every
// `--filters tag:` match on Secrets Manager.
func TestSecretTagsToStringMap(t *testing.T) {
	got := secretTagsToStringMap([]secretstypes.Tag{
		{Key: aws.String("environment"), Value: aws.String("prod")},
		{Key: aws.String("empty"), Value: nil},
		{Key: nil, Value: aws.String("dropped")},
	})
	assert.Equal(t, map[string]string{"environment": "prod", "empty": ""}, got)
}

func TestConfigTagsToMap(t *testing.T) {
	got := configTagsToMap([]cstypes.Tag{
		{Key: aws.String("owner"), Value: aws.String("secops")},
		{Key: aws.String("empty"), Value: nil},
		{Key: nil, Value: aws.String("dropped")},
	})
	assert.Equal(t, map[string]any{"owner": "secops", "empty": ""}, got)
}

// TestBackupManagedArn pins the guard that decides whether Backup can read a
// resource's tags at all. Getting this wrong in the permissive direction turns
// every recovery point of a resource Backup does not fully manage into a
// confident "no tags", which an audit filtering on a tag would silently accept.
func TestBackupManagedArn(t *testing.T) {
	tests := []struct {
		name       string
		arn        string
		wantRegion string
		wantOK     bool
	}{
		{
			name:       "backup vault",
			arn:        "arn:aws:backup:us-east-1:123456789012:backup-vault:Default",
			wantRegion: "us-east-1",
			wantOK:     true,
		},
		{
			name:       "backup-managed recovery point",
			arn:        "arn:aws:backup:eu-west-1:123456789012:recovery-point:1a2b3c4d",
			wantRegion: "eu-west-1",
			wantOK:     true,
		},
		{
			name:   "dynamodb recovery point is not backup-managed",
			arn:    "arn:aws:dynamodb:us-east-1:123456789012:table/orders/backup/01234567890123-abcdefgh",
			wantOK: false,
		},
		{
			name:   "ec2 recovery point is not backup-managed",
			arn:    "arn:aws:ec2:us-east-1::image/ami-1234567890abcdef0",
			wantOK: false,
		},
		{
			name:   "unparseable arn",
			arn:    "not-an-arn",
			wantOK: false,
		},
		{
			name:   "empty arn",
			arn:    "",
			wantOK: false,
		},
		{
			name:   "service prefix must match exactly, not by prefix",
			arn:    "arn:aws:backupstorage:us-east-1:123456789012:something/x",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, ok := backupManagedArn(tt.arn)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantRegion, region)
		})
	}
}

func TestLazyTagsResolveTags(t *testing.T) {
	t.Run("fetches once and caches the result", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]
		calls := 0
		fetch := func() (map[string]any, error) {
			calls++
			return map[string]any{"env": "prod"}, nil
		}

		for i := 0; i < 3; i++ {
			got, err := h.resolveTags(&field, fetch)
			require.NoError(t, err)
			assert.Equal(t, map[string]any{"env": "prod"}, got)
		}
		assert.Equal(t, 1, calls, "fetch must run only on the first read")
	})

	t.Run("caches an empty tag set so an untagged resource costs one call", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]
		calls := 0
		fetch := func() (map[string]any, error) {
			calls++
			return map[string]any{}, nil
		}

		for i := 0; i < 3; i++ {
			got, err := h.resolveTags(&field, fetch)
			require.NoError(t, err)
			assert.Empty(t, got)
		}
		assert.Equal(t, 1, calls)
		assert.Zero(t, field.State, "an untagged resource is not null")
	})

	t.Run("normalizes a nil map to empty", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]
		got, err := h.resolveTags(&field, func() (map[string]any, error) { return nil, nil })
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	// An unreadable tag set must surface as null, never as an empty map. An
	// empty map asserts "this resource has no tags", so a scan role missing the
	// tag permission would otherwise make every tag-based audit pass vacuously.
	t.Run("errTagsUnreadable marks the field null instead of empty", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]
		got, err := h.resolveTags(&field, func() (map[string]any, error) {
			return nil, errTagsUnreadable
		})
		require.NoError(t, err, "an unreadable tag set is not a query error")
		assert.Nil(t, got)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
	})

	t.Run("a wrapped errTagsUnreadable is still recognized", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]
		_, err := h.resolveTags(&field, func() (map[string]any, error) {
			return nil, fmt.Errorf("listing tags: %w", errTagsUnreadable)
		})
		require.NoError(t, err)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
	})

	t.Run("caches the unreadable result rather than re-asking", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]
		calls := 0
		fetch := func() (map[string]any, error) {
			calls++
			return nil, errTagsUnreadable
		}

		for i := 0; i < 3; i++ {
			_, err := h.resolveTags(&field, fetch)
			require.NoError(t, err)
		}
		// A missing permission does not change mid-scan, so re-asking would
		// only spend a denied call per read.
		assert.Equal(t, 1, calls)
	})

	t.Run("does not cache an ordinary error", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]
		calls := 0
		fetch := func() (map[string]any, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("throttled")
			}
			return map[string]any{"env": "prod"}, nil
		}

		_, err := h.resolveTags(&field, fetch)
		require.Error(t, err)

		// A throttled call must be retried rather than remembered as an empty
		// tag set.
		got, err := h.resolveTags(&field, fetch)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"env": "prod"}, got)
		assert.Equal(t, 2, calls)
	})

	// The generated accessor reaches tags() through plugin.GetOrCompute, so the
	// null state resolveTags sets is only useful if GetOrCompute honors a state
	// the compute function set itself. This pins that interaction: without it
	// the field would surface as an empty map and the nullness would be lost
	// between resolveTags and the query result.
	t.Run("GetOrCompute surfaces the null rather than an empty map", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]

		got := plugin.GetOrCompute(&field, func() (map[string]any, error) {
			return h.resolveTags(&field, func() (map[string]any, error) {
				return nil, errTagsUnreadable
			})
		})

		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, got.State)
		assert.Nil(t, got.Data)
		assert.NoError(t, got.Error)
	})

	// The same path for a resource that really has no tags must NOT be null,
	// or "no tags" becomes indistinguishable from "tags unreadable".
	t.Run("GetOrCompute surfaces an untagged resource as an empty map", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]

		got := plugin.GetOrCompute(&field, func() (map[string]any, error) {
			return h.resolveTags(&field, func() (map[string]any, error) {
				return map[string]any{}, nil
			})
		})

		assert.Equal(t, plugin.StateIsSet, got.State)
		assert.NotNil(t, got.Data)
		assert.Empty(t, got.Data)
	})

	t.Run("concurrent readers fetch once", func(t *testing.T) {
		var h lazyTags
		var field plugin.TValue[map[string]any]
		var calls atomic.Int64
		fetch := func() (map[string]any, error) {
			calls.Add(1)
			time.Sleep(10 * time.Millisecond)
			return map[string]any{"env": "prod"}, nil
		}

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := h.resolveTags(&field, fetch)
				assert.NoError(t, err)
				assert.Equal(t, map[string]any{"env": "prod"}, got)
			}()
		}
		wg.Wait()
		assert.Equal(t, int64(1), calls.Load())
	})
}

func TestTagsToStringMap(t *testing.T) {
	t.Run("nil slice returns non-nil empty map", func(t *testing.T) {
		got := tagsToStringMap(nil, kvKey, kvValue)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("returns a map[string]string with the same nil policy", func(t *testing.T) {
		got := tagsToStringMap([]keyValueTag{
			{Key: aws.String("a"), Value: aws.String("1")},
			{Key: nil, Value: aws.String("drop")},
			{Key: aws.String("b"), Value: nil},
		}, kvKey, kvValue)
		assert.Equal(t, map[string]string{"a": "1", "b": ""}, got)
	})
}

// markTagsUnreadable is what an accessor that reads its tags directly, rather
// than caching them through lazyTags, uses to express "the tags could not be
// read". The assertions that matter are about nullness: an empty map claims
// the resource carries no tags, and a tag-based audit run by a role missing
// the tag permission would pass vacuously over every such resource.
func TestMarkTagsUnreadable(t *testing.T) {
	t.Run("marks the field null and reports no tags", func(t *testing.T) {
		var field plugin.TValue[map[string]any]

		got, err := markTagsUnreadable(&field)

		require.NoError(t, err, "an unreadable tag set is not a query error")
		assert.Nil(t, got)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
	})

	// The state has to survive GetOrCompute, not merely be set on the field:
	// GetOrCompute only honors a proactively set state, and would otherwise
	// store the returned nil map as the field's value.
	t.Run("surfaces as null through GetOrCompute, not as an empty map", func(t *testing.T) {
		var field plugin.TValue[map[string]any]

		res := plugin.GetOrCompute(&field, func() (map[string]any, error) {
			return markTagsUnreadable(&field)
		})

		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, res.State)
		assert.Nil(t, res.Data)
		assert.NotEqual(t, map[string]any{}, res.Data, "null must not degrade to an empty map")
	})

	// The contrast case: a resource that genuinely carries no tags is not null.
	t.Run("an untagged resource stays empty rather than null", func(t *testing.T) {
		var field plugin.TValue[map[string]any]

		res := plugin.GetOrCompute(&field, func() (map[string]any, error) {
			return map[string]any{}, nil
		})

		assert.NotEqual(t, plugin.StateIsSet|plugin.StateIsNull, res.State)
		assert.Empty(t, res.Data)
		assert.NotNil(t, res.Data)
	})
}

// tagsOrUnreadable adapts the shared per-service tag helpers, which report an
// unreadable tag set as errTagsUnreadable because they serve several resources
// and cannot know which field to mark.
func TestTagsOrUnreadable(t *testing.T) {
	t.Run("passes a real tag set through untouched", func(t *testing.T) {
		var field plugin.TValue[map[string]any]
		tags := map[string]any{"env": "prod"}

		got, err := tagsOrUnreadable(&field, tags, nil)

		require.NoError(t, err)
		assert.Equal(t, tags, got)
		assert.Zero(t, field.State, "a readable tag set is not null")
	})

	t.Run("turns errTagsUnreadable into a null field", func(t *testing.T) {
		var field plugin.TValue[map[string]any]

		got, err := tagsOrUnreadable(&field, nil, errTagsUnreadable)

		require.NoError(t, err)
		assert.Nil(t, got)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
	})

	t.Run("recognizes a wrapped errTagsUnreadable", func(t *testing.T) {
		var field plugin.TValue[map[string]any]

		_, err := tagsOrUnreadable(&field, nil, fmt.Errorf("listing tags: %w", errTagsUnreadable))

		require.NoError(t, err)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
	})

	// A throttle or a network failure is a real error. Reporting it as "no
	// tags readable" would hide a transient fault behind a permanent-looking
	// null, so it propagates instead.
	t.Run("propagates an ordinary error and leaves the field alone", func(t *testing.T) {
		var field plugin.TValue[map[string]any]
		boom := errors.New("throttled")

		_, err := tagsOrUnreadable(&field, nil, boom)

		assert.ErrorIs(t, err, boom)
		assert.Zero(t, field.State)
	})
}
