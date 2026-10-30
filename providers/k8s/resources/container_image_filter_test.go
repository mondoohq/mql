// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
)

func TestSkipContainerImage(t *testing.T) {
	tests := []struct {
		name     string
		include  []string
		exclude  []string
		image    string
		wantSkip bool
	}{
		{name: "no filters accepts everything", image: "docker.io/library/nginx:latest", wantSkip: false},

		// include
		{name: "include exact match is kept", include: []string{"docker.io/library/nginx:latest"}, image: "docker.io/library/nginx:latest", wantSkip: false},
		{name: "include non-match is skipped", include: []string{"docker.io/library/nginx:latest"}, image: "gcr.io/my-project/app:v1", wantSkip: true},
		{name: "include glob registry match", include: []string{"gcr.io/*"}, image: "gcr.io/my-project/app:v1", wantSkip: false},
		{name: "include glob registry non-match", include: []string{"gcr.io/*"}, image: "docker.io/library/nginx:latest", wantSkip: true},
		{name: "include multiple patterns", include: []string{"gcr.io/*", "docker.io/myorg/*"}, image: "docker.io/myorg/api:latest", wantSkip: false},
		{name: "include multiple patterns no match", include: []string{"gcr.io/*", "docker.io/myorg/*"}, image: "quay.io/some/image:v2", wantSkip: true},

		// exclude
		{name: "exclude exact match is skipped", exclude: []string{"docker.io/library/nginx:latest"}, image: "docker.io/library/nginx:latest", wantSkip: true},
		{name: "exclude non-match is kept", exclude: []string{"docker.io/library/nginx:latest"}, image: "gcr.io/my-project/app:v1", wantSkip: false},
		{name: "exclude glob registry match", exclude: []string{"gcr.io/*"}, image: "gcr.io/my-project/app:v1", wantSkip: true},
		{name: "exclude glob registry non-match", exclude: []string{"gcr.io/*"}, image: "docker.io/library/nginx:latest", wantSkip: false},
		{name: "exclude multiple patterns", exclude: []string{"gcr.io/*", "quay.io/*"}, image: "quay.io/some/image:v2", wantSkip: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &FilterOpts{include: tt.include, exclude: tt.exclude}
			assert.Equal(t, tt.wantSkip, f.skip(tt.image))
		})
	}
}

func TestSetImageFiltersMutualExclusion(t *testing.T) {
	cfg := &inventory.Config{
		Options: map[string]string{
			shared.OPTION_IMAGES:         "gcr.io/*",
			shared.OPTION_IMAGES_EXCLUDE: "quay.io/*",
		},
	}
	_, err := setImageFilters(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestSetImageFiltersIncludeOnly(t *testing.T) {
	cfg := &inventory.Config{
		Options: map[string]string{
			shared.OPTION_IMAGES: "gcr.io/*,docker.io/myorg/*",
		},
	}
	f, err := setImageFilters(cfg)
	require.NoError(t, err)
	assert.Equal(t, []string{"gcr.io/*", "docker.io/myorg/*"}, f.include)
	assert.Empty(t, f.exclude)
}

func TestSetImageFiltersExcludeOnly(t *testing.T) {
	cfg := &inventory.Config{
		Options: map[string]string{
			shared.OPTION_IMAGES_EXCLUDE: "quay.io/*",
		},
	}
	f, err := setImageFilters(cfg)
	require.NoError(t, err)
	assert.Empty(t, f.include)
	assert.Equal(t, []string{"quay.io/*"}, f.exclude)
}
