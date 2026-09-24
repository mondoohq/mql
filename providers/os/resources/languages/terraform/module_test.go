// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package terraform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyModuleSource(t *testing.T) {
	tests := []struct {
		source  string
		kind    ModuleSourceKind
		name    string
		purl    string
		version string
	}{
		// Registry modules. The target system is part of the identity.
		{
			source: "terraform-aws-modules/vpc/aws", kind: ModuleSourceRegistry,
			name: "terraform-aws-modules/vpc/aws", version: "5.1.2",
			purl: "pkg:terraform-module/terraform-aws-modules/vpc@5.1.2?target_system=aws",
		},
		// A private module registry keeps the type and records the host.
		{
			source: "app.terraform.io/acme/vpc/aws", kind: ModuleSourceRegistry,
			name: "acme/vpc/aws", version: "1.0.0",
			purl: "pkg:terraform-module/acme/vpc@1.0.0?repository_url=app.terraform.io&target_system=aws",
		},
		// Git sources. Note the type is generic, not github: pkg:github is
		// already read as a GitHub Action by the SBOM pipeline.
		{
			source: "git::https://github.com/acme/terraform-modules.git?ref=v1.2.0",
			kind:   ModuleSourceVCS, name: "github.com/acme/terraform-modules",
			purl: "pkg:generic/github.com/acme/terraform-modules@v1.2.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Facme%2Fterraform-modules.git",
		},
		// The GitHub shorthand, unpinned: still a real dependency, just with
		// no version to report.
		{
			source: "github.com/acme/terraform-aws-vpc", kind: ModuleSourceVCS,
			name: "github.com/acme/terraform-aws-vpc",
			purl: "pkg:generic/github.com/acme/terraform-aws-vpc?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Facme%2Fterraform-aws-vpc.git",
		},
		// The SCP-like address names the same repository as the https one, so
		// it must land on the same coordinate rather than a second component.
		{
			source: "git::git@github.com:acme/terraform-modules.git?ref=abc123",
			kind:   ModuleSourceVCS, name: "github.com/acme/terraform-modules",
			purl: "pkg:generic/github.com/acme/terraform-modules@abc123?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Facme%2Fterraform-modules.git",
		},
		// Local paths are not third-party dependencies and get no purl.
		{source: "./modules/vpc", kind: ModuleSourceLocal},
		{source: "../shared/logging", kind: ModuleSourceLocal},
		// Fetchers with no stable public coordinate are left alone rather than
		// guessed at.
		{source: "s3::https://bucket.s3.amazonaws.com/vpc.zip", kind: ModuleSourceUnknown},
		{source: "gcs::https://www.googleapis.com/storage/v1/b/m/o/vpc.zip", kind: ModuleSourceUnknown},
		// A two-segment address is not a valid registry address.
		{source: "acme/vpc", kind: ModuleSourceUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			m := ClassifyModuleSource(tt.source)
			assert.Equal(t, tt.kind, m.Kind, "kind")
			if tt.name != "" {
				assert.Equal(t, tt.name, ModuleName(m), "name")
			}
			assert.Equal(t, tt.purl, NewModulePackageUrl(m, tt.version), "purl")
		})
	}
}

func TestClassifyModuleSourceSubdir(t *testing.T) {
	m := ClassifyModuleSource("git::https://github.com/acme/terraform-modules.git//eks?ref=v2.4.0")
	assert.Equal(t, ModuleSourceVCS, m.Kind)
	assert.Equal(t, "eks", m.Subdir)
	assert.Equal(t, "v2.4.0", m.Ref)
	assert.Equal(t, "github.com/acme/terraform-modules", ModuleName(m))

	// The "//" of the scheme must not be read as a subdirectory separator.
	h := ClassifyModuleSource("https://artifacts.example.com/modules/vpc-1.2.0.zip")
	assert.Equal(t, ModuleSourceHTTP, h.Kind)
	assert.Empty(t, h.Subdir)
	assert.Equal(t, "artifacts.example.com/modules/vpc-1.2.0.zip", ModuleName(h))
}
