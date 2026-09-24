// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testLock = `provider "registry.terraform.io/hashicorp/aws" {
  version = "5.31.0"
}
`

func writeLock(t *testing.T, afs *afero.Afero, path string) {
	t.Helper()
	require.NoError(t, afs.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, afero.WriteFile(afs, path, []byte(testLock), 0o644))
}

func names(files []string) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, filepath.ToSlash(f))
	}
	return out
}

func TestCollectTerraformPackagesWalksTree(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	// A repository with one workspace per environment. Only a lock file
	// sitting exactly at the search root was ever found before.
	writeLock(t, afs, "/repo/.terraform.lock.hcl")
	writeLock(t, afs, "/repo/envs/prod/.terraform.lock.hcl")
	writeLock(t, afs, "/repo/envs/staging/.terraform.lock.hcl")

	deps, files := collectTerraformPackages(afs, "/repo")

	assert.ElementsMatch(t, []string{
		"/repo/.terraform.lock.hcl",
		"/repo/envs/prod/.terraform.lock.hcl",
		"/repo/envs/staging/.terraform.lock.hcl",
	}, names(files))
	assert.Equal(t, 3, len(deps))
}

func TestCollectTerraformPackagesSkipsDownloadedModules(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	writeLock(t, afs, "/repo/.terraform.lock.hcl")
	// A module Terraform downloaded, carrying its own lock file. Reporting it
	// would attribute a dependency's providers to this project.
	writeLock(t, afs, "/repo/.terraform/modules/vpc/.terraform.lock.hcl")
	// Same for a vendored tree.
	writeLock(t, afs, "/repo/vendor/other/.terraform.lock.hcl")

	_, files := collectTerraformPackages(afs, "/repo")

	assert.Equal(t, []string{"/repo/.terraform.lock.hcl"}, names(files))
}

func TestCollectTerraformPackagesBoundsDepth(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	deep := "/repo"
	for i := 0; i < maxLockSearchDepth+2; i++ {
		deep = filepath.Join(deep, "d"+strconv.Itoa(i))
	}
	writeLock(t, afs, filepath.Join(deep, ".terraform.lock.hcl"))
	writeLock(t, afs, "/repo/.terraform.lock.hcl")

	_, files := collectTerraformPackages(afs, "/repo")

	// The shallow one is found; the one past the cap is not, so a walk against
	// an OS connection cannot descend without bound.
	assert.Equal(t, []string{"/repo/.terraform.lock.hcl"}, names(files))
}

func TestCollectTerraformPackagesAcceptsFilePath(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	writeLock(t, afs, "/repo/.terraform.lock.hcl")

	deps, files := collectTerraformPackages(afs, "/repo/.terraform.lock.hcl")
	require.Equal(t, 1, len(files))
	require.Equal(t, 1, len(deps))
	assert.True(t, strings.HasSuffix(deps[0].Purl, "hashicorp/aws@5.31.0"))

	// A file that is not a lock file yields nothing.
	require.NoError(t, afero.WriteFile(afs, "/repo/main.tf", []byte("# tf"), 0o644))
	deps, files = collectTerraformPackages(afs, "/repo/main.tf")
	assert.Empty(t, deps)
	assert.Empty(t, files)
}
