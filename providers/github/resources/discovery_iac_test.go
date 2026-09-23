// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/assert"
)

func blob(path string) *github.TreeEntry {
	return &github.TreeEntry{Path: github.Ptr(path), Type: github.Ptr("blob")}
}

func TestIsDockerfile(t *testing.T) {
	for _, base := range []string{"Dockerfile", "Dockerfile.prod", "app.Dockerfile", "app.dockerfile"} {
		assert.True(t, isDockerfile(base), base)
	}
	for _, base := range []string{"DockerfileLint.md", "dockerfile-notes.txt", "Chart.yaml", "docker-compose.yml"} {
		assert.False(t, isDockerfile(base), base)
	}
}

func TestIsKustomization(t *testing.T) {
	for _, base := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		assert.True(t, isKustomization(base), base)
	}
	for _, base := range []string{"kustomization.json", "Kustomization.yaml", "kustomize.yaml"} {
		assert.False(t, isKustomization(base), base)
	}
}

func TestIacDir(t *testing.T) {
	assert.Equal(t, "", iacDir("Chart.yaml"))
	assert.Equal(t, "charts/app", iacDir("charts/app/Chart.yaml"))

	// Repository paths are slash-separated whatever the scanner runs on. This
	// fails on Windows if iacDir uses path/filepath, which treats the whole
	// path as one segment.
	assert.Equal(t, "a/b/c", iacDir("a/b/c/Chart.yaml"))
}

// Same concern one level up: the classifier takes a file's base name to match
// Dockerfile and kustomization.yaml, so it has to split on "/" everywhere.
func TestClassifyIacTreeSplitsOnSlash(t *testing.T) {
	got := classifyIacTree([]*github.TreeEntry{
		blob("services/api/Dockerfile"),
		blob("overlays/prod/kustomization.yaml"),
	})

	assert.Equal(t, []string{"services/api/Dockerfile"}, got.dockerfiles)
	assert.Equal(t, []string{"overlays/prod"}, got.kustomizeDirs)
}

func TestIsHiddenPath(t *testing.T) {
	assert.True(t, isHiddenPath(".github/workflows/ci.yml"))
	assert.True(t, isHiddenPath(".drone.yml"))
	assert.True(t, isHiddenPath("deploy/.hidden/app.yaml"))
	assert.False(t, isHiddenPath("deploy/app.yaml"))
}

func TestClassifyIacTree(t *testing.T) {
	t.Run("classifies each entry point", func(t *testing.T) {
		got := classifyIacTree([]*github.TreeEntry{
			blob("infra/main.bicep"),
			blob("charts/app/Chart.yaml"),
			blob("charts/app/templates/deployment.yaml"),
			blob("overlays/prod/kustomization.yaml"),
			blob("Dockerfile"),
			blob("services/api.Dockerfile"),
			blob("deploy/manifest.yaml"),
		})

		assert.True(t, got.hasBicep)
		assert.True(t, got.hasYaml)
		assert.Equal(t, []string{"charts/app"}, got.helmChartDirs)
		assert.Equal(t, []string{"overlays/prod"}, got.kustomizeDirs)
		assert.Equal(t, []string{"Dockerfile", "services/api.Dockerfile"}, got.dockerfiles)
	})

	t.Run("skips trees, hidden paths and mql bundles", func(t *testing.T) {
		got := classifyIacTree([]*github.TreeEntry{
			{Path: github.Ptr("charts"), Type: github.Ptr("tree")},
			blob(".github/workflows/ci.yml"),
			blob("mql.yaml"),
			blob("policies/mql.yml"),
		})

		assert.False(t, got.hasYaml)
		assert.False(t, got.hasBicep)
		assert.Empty(t, got.helmChartDirs)
		assert.Empty(t, got.dockerfiles)
	})

	t.Run("deduplicates chart and kustomize directories", func(t *testing.T) {
		got := classifyIacTree([]*github.TreeEntry{
			blob("charts/app/Chart.yaml"),
			blob("charts/app/Chart.yaml"),
			blob("overlays/prod/kustomization.yaml"),
			blob("overlays/prod/kustomization.yml"),
		})

		assert.Equal(t, []string{"charts/app"}, got.helmChartDirs)
		assert.Equal(t, []string{"overlays/prod"}, got.kustomizeDirs)
	})

	// Chart.yaml and kustomization.yaml match their own cases and must not also
	// register the repository as carrying k8s manifests.
	t.Run("chart and kustomize files are not k8s manifests", func(t *testing.T) {
		got := classifyIacTree([]*github.TreeEntry{
			blob("charts/app/Chart.yaml"),
			blob("overlays/prod/kustomization.yaml"),
		})

		assert.False(t, got.hasYaml)
	})
}
