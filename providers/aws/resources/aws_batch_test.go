// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	batch_types "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchContainerNullState(t *testing.T) {
	t.Run("nil containerProperties sets null state", func(t *testing.T) {
		jd := &mqlAwsBatchJobDefinition{}
		// cacheContainerProperties is nil by default
		result, err := jd.container()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, jd.Container.IsNull())
		assert.True(t, jd.Container.IsSet())
	})
}

func TestBatchRetryNullState(t *testing.T) {
	t.Run("nil retryStrategy sets null state", func(t *testing.T) {
		jd := &mqlAwsBatchJobDefinition{}
		result, err := jd.retry()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, jd.Retry.IsNull())
		assert.True(t, jd.Retry.IsSet())
	})
}

func TestBatchJobTimeoutNullState(t *testing.T) {
	t.Run("nil timeout sets null state", func(t *testing.T) {
		jd := &mqlAwsBatchJobDefinition{}
		result, err := jd.jobTimeout()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, jd.JobTimeout.IsNull())
		assert.True(t, jd.JobTimeout.IsSet())
	})
}

func TestTimeFromBatchMillis(t *testing.T) {
	// Batch API returns *int64 milliseconds. nil and 0 must produce nil so
	// runtime applies StateIsNull (avoids surfacing fabricated 1970 timestamps).
	cases := []struct {
		name string
		in   *int64
		want *int64 // nil means expect nil *time.Time, non-nil is unix-milli
	}{
		{name: "nil", in: nil, want: nil},
		{name: "zero", in: ptrInt64(0), want: nil},
		{name: "positive", in: ptrInt64(1_700_000_000_000), want: ptrInt64(1_700_000_000_000)},
		{name: "small positive", in: ptrInt64(1), want: ptrInt64(1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := timeFromBatchMillis(tc.in)
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, *tc.want, got.UnixMilli())
		})
	}
}

func TestBatchChildID(t *testing.T) {
	// batchChildID is the shared __id builder for sibling children where the
	// natural key (Name, JobId, etc.) may be empty. Unnamed siblings must never
	// collide — that was the class of bug fixed in `buildBatchSecrets` and
	// `buildBatchEksContainers`.
	t.Run("uses name when present", func(t *testing.T) {
		assert.Equal(t, "arn:aws:batch:us-west-2::job/abc/dep/xyz",
			batchChildID("arn:aws:batch:us-west-2::job/abc/dep", "xyz", 0))
	})

	t.Run("uses indexed fallback when name is empty", func(t *testing.T) {
		assert.Equal(t, "arn:aws:batch:us-west-2::job/abc/dep/#7",
			batchChildID("arn:aws:batch:us-west-2::job/abc/dep", "", 7))
	})

	t.Run("large indices stay ASCII (regression for rune('0'+i) overflow)", func(t *testing.T) {
		// The previous implementation used string(rune('0'+i)), which wrapped to
		// ':' at i=10 and non-digit ASCII beyond that, colliding trivially.
		// Assert every index through 64 produces a distinct ASCII-safe id.
		const base = "parent/kind"
		seen := make(map[string]struct{}, 64)
		for i := range 64 {
			id := batchChildID(base, "", i)
			_, dup := seen[id]
			require.False(t, dup, "duplicate __id for index %d: %q", i, id)
			seen[id] = struct{}{}
		}
	})

	t.Run("many anonymous siblings are all distinct", func(t *testing.T) {
		// Direct regression for the eksContainer fix — multiple unnamed
		// containers in the same pod must get distinct __id values.
		const n = 50
		const base = "pod/container"
		ids := make(map[string]struct{}, n)
		for i := range n {
			ids[batchChildID(base, "", i)] = struct{}{}
		}
		assert.Len(t, ids, n)
	})
}

//go:fix inline
func ptrInt64(v int64) *int64 { return new(v) }

func TestParseImageReference(t *testing.T) {
	tests := []struct {
		ref        string
		registry   string
		repository string
		tag        string
		digest     string
	}{
		// Public AWS ECR.
		{"public.ecr.aws/foo/bar:1", "public.ecr.aws", "foo/bar", "1", ""},
		// Explicit Docker Hub hostnames are left as-is.
		{"docker.io/library/nginx", "docker.io", "library/nginx", "", ""},
		{"registry.hub.docker.com/library/nginx:1.21", "registry.hub.docker.com", "library/nginx", "1.21", ""},
		// Bare name and single-segment path normalize to docker.io.
		{"nginx", "docker.io", "nginx", "", ""},
		{"nginx:1.21", "docker.io", "nginx", "1.21", ""},
		{"library/nginx", "docker.io", "library/nginx", "", ""},
		// Private ECR with a fully-qualified host.
		{"123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest", "123456789012.dkr.ecr.us-east-1.amazonaws.com", "app", "latest", ""},
		// Host with an explicit port.
		{"myreg:5000/team/app:v2", "myreg:5000", "team/app", "v2", ""},
		// localhost is treated as a registry host.
		{"localhost/app", "localhost", "app", "", ""},
		// Digests, with and without a tag.
		{"nginx@sha256:abc123", "docker.io", "nginx", "", "sha256:abc123"},
		{"public.ecr.aws/x/y@sha256:deadbeef", "public.ecr.aws", "x/y", "", "sha256:deadbeef"},
		{"nginx:1.21@sha256:abc123", "docker.io", "nginx", "1.21", "sha256:abc123"},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			registry, repository, tag, digest := parseImageReference(tt.ref)
			assert.Equal(t, tt.registry, registry, "registry")
			assert.Equal(t, tt.repository, repository, "repository")
			assert.Equal(t, tt.tag, tag, "tag")
			assert.Equal(t, tt.digest, digest, "digest")
		})
	}
}

func TestBatchJobDefinitionImages(t *testing.T) {
	t.Run("no image sources returns empty", func(t *testing.T) {
		jd := &mqlAwsBatchJobDefinition{}
		result, err := jd.images()
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("flattens every location and dedupes", func(t *testing.T) {
		jd := &mqlAwsBatchJobDefinition{}
		// Single-node container.
		jd.cacheContainerProperties = &batch_types.ContainerProperties{
			Image: aws.String("public.ecr.aws/foo/bar:1"),
		}
		// EKS pod containers and init containers.
		jd.cacheEks = &batch_types.EksProperties{
			PodProperties: &batch_types.EksPodProperties{
				Containers:     []batch_types.EksContainer{{Image: aws.String("nginx")}},
				InitContainers: []batch_types.EksContainer{{Image: aws.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/init:latest")}},
			},
		}
		// ECS task containers.
		jd.cacheEcs = &batch_types.EcsProperties{
			TaskProperties: []batch_types.EcsTaskProperties{{
				Containers: []batch_types.TaskContainerProperties{{Image: aws.String("docker.io/library/redis:7")}},
			}},
		}
		// Multi-node node ranges, including a duplicate of the single-node image.
		jd.cacheNodeProperties = &batch_types.NodeProperties{
			NodeRangeProperties: []batch_types.NodeRangeProperty{
				{Container: &batch_types.ContainerProperties{Image: aws.String("public.ecr.aws/foo/bar:1")}},
				{Container: &batch_types.ContainerProperties{Image: aws.String("library/busybox")}},
			},
		}

		result, err := jd.images()
		require.NoError(t, err)

		byImage := map[string]map[string]any{}
		for _, r := range result {
			entry := r.(map[string]any)
			byImage[entry["image"].(string)] = entry
		}
		// Five distinct images (the duplicate public.ecr.aws ref collapses).
		require.Len(t, result, 5)

		assert.Equal(t, "public.ecr.aws", byImage["public.ecr.aws/foo/bar:1"]["registry"])
		assert.Equal(t, "docker.io", byImage["nginx"]["registry"])
		assert.Equal(t, "docker.io", byImage["library/busybox"]["registry"])
		assert.Equal(t, "docker.io", byImage["docker.io/library/redis:7"]["registry"])
		assert.Equal(t, "123456789012.dkr.ecr.us-east-1.amazonaws.com", byImage["123456789012.dkr.ecr.us-east-1.amazonaws.com/init:latest"]["registry"])
		assert.Equal(t, "7", byImage["docker.io/library/redis:7"]["tag"])
	})
}
