// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
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
	// Three workspaces pinning the same provider is one component with three
	// pieces of evidence, not three components.
	require.Equal(t, 1, len(deps))
	assert.Equal(t, 3, len(deps[0].EvidenceList))
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

const testConfig = `terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    docker = { source = "kreuzwerker/docker" }
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"
}

module "local" {
  source = "./modules/networking"
}
`

const testManifest = `{"Modules":[
  {"Key":"","Source":"","Dir":"."},
  {"Key":"vpc","Source":"terraform-aws-modules/vpc/aws","Version":"5.1.2","Dir":".terraform/modules/vpc"},
  {"Key":"vpc.sg","Source":"terraform-aws-modules/security-group/aws","Version":"5.1.0","Dir":".terraform/modules/vpc.sg"}
]}`

func purls(pkgs []*languages.Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Purl)
	}
	sort.Strings(out)
	return out
}

func TestCollectTerraformWorkspace(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	writeLock(t, afs, "/repo/.terraform.lock.hcl")
	require.NoError(t, afero.WriteFile(afs, "/repo/main.tf", []byte(testConfig), 0o644))
	require.NoError(t, afero.WriteFile(afs, "/repo/.terraform/modules/modules.json", []byte(testManifest), 0o644))
	// Module source Terraform downloaded. Its own .tf must never be read as
	// this project's configuration.
	require.NoError(t, afero.WriteFile(afs,
		"/repo/.terraform/modules/vpc/main.tf",
		[]byte(`module "someone_elses" {
  source  = "evil/dependency/aws"
  version = "1.0.0"
}
`), 0o644))

	deps, _ := collectTerraformPackages(afs, "/repo")

	assert.Equal(t, []string{
		// The module the manifest says a dependency installed.
		"pkg:terraform-module/terraform-aws-modules/security-group@5.1.0?target_system=aws",
		// The module this configuration calls, declared and installed — one
		// component, not two.
		"pkg:terraform-module/terraform-aws-modules/vpc@5.1.2?target_system=aws",
		// Declared with a constraint and locked at 5.31.0: only the resolved
		// record survives.
		"pkg:terraform/hashicorp/aws@5.31.0",
		// Declared in required_providers and never locked: the version-less
		// record survives because it is the only statement of it.
		"pkg:terraform/kreuzwerker/docker",
	}, purls(deps))

	// The dependency's own module call is not ours.
	for _, p := range deps {
		assert.NotContains(t, p.Purl, "evil", "a downloaded module's configuration must not be read")
	}
}
