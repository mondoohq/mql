// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

func TestIsSubgroup(t *testing.T) {
	// GitLab group names are display names and never contain a "/", so the
	// nesting has to be read off FullPath. Testing Name instead meant the
	// "skip subgroup discovery for a subgroup" guard never fired.
	tests := []struct {
		name  string
		group *gitlab.Group
		want  bool
	}{
		{"top-level group", &gitlab.Group{Name: "acme", Path: "acme", FullPath: "acme"}, false},
		{"subgroup", &gitlab.Group{Name: "platform", Path: "platform", FullPath: "acme/platform"}, true},
		{"deeply nested", &gitlab.Group{Name: "api", Path: "api", FullPath: "acme/platform/api"}, true},
		{
			"display name differs from path",
			&gitlab.Group{Name: "Platform Team", Path: "platform", FullPath: "acme/platform"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isSubgroup(tt.group))
		})
	}
}

func TestIacDir(t *testing.T) {
	// Repository paths are POSIX. Using path/filepath here rewrote separators
	// on Windows, so the directory handed to the chained helm/kustomize
	// connections could not be found inside the clone.
	tests := []struct {
		path string
		want string
	}{
		{"Chart.yaml", ""},
		{"charts/frontend/Chart.yaml", "charts/frontend"},
		{"deploy/overlays/prod/kustomization.yaml", "deploy/overlays/prod"},
		{"a/b/c/d.yaml", "a/b/c"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := iacDir(tt.path)
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, `\`, "repo paths must stay POSIX-separated")
		})
	}
}

func TestIsHiddenPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"Chart.yaml", false},
		{"charts/frontend/Chart.yaml", false},
		{".gitlab-ci.yml", true},
		{".gitlab/CODEOWNERS", true},
		{"a/.hidden/b.yaml", true},
		{"a/b/.env", true},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, isHiddenPath(tt.path))
		})
	}
}

func TestIsDockerfile(t *testing.T) {
	for _, base := range []string{"Dockerfile", "Dockerfile.prod", "app.Dockerfile", "app.dockerfile"} {
		assert.True(t, isDockerfile(base), base)
	}
	for _, base := range []string{"Chart.yaml", "README.md", "docker-compose.yml", "Dockerfilex"} {
		assert.False(t, isDockerfile(base), base)
	}
}

func TestIsKustomization(t *testing.T) {
	for _, base := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		assert.True(t, isKustomization(base), base)
	}
	for _, base := range []string{"Chart.yaml", "values.yaml", "kustomize.yaml"} {
		assert.False(t, isKustomization(base), base)
	}
}
