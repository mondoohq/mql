// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package terraform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseProviderSource(t *testing.T) {
	tests := []struct {
		source            string
		expectedHost      string
		expectedNamespace string
		expectedType      string
	}{
		// Default registry, named explicitly — how a lock file writes it.
		{"registry.terraform.io/hashicorp/aws", "registry.terraform.io", "hashicorp", "aws"},
		{"registry.terraform.io/integrations/github", "registry.terraform.io", "integrations", "github"},
		// OpenTofu's registry.
		{"registry.opentofu.org/hashicorp/aws", "registry.opentofu.org", "hashicorp", "aws"},
		// Host omitted, as required_providers usually writes it.
		{"hashicorp/aws", "", "hashicorp", "aws"},
		// A private registry.
		{"custom.registry.io/myorg/myprovider", "custom.registry.io", "myorg", "myprovider"},
		// A private registry that nests the namespace. Splitting on segment
		// count read "tf" as the namespace and "acme/docker" as the type.
		{"artifactory.acme.com/tf/acme/docker", "artifactory.acme.com", "tf/acme", "docker"},
		// A bare type.
		{"aws", "", "", "aws"},
		// A host with a port still reads as a host.
		{"registry.acme.com:8443/acme/docker", "registry.acme.com:8443", "acme", "docker"},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			host, ns, pt := ParseProviderSource(tt.source)
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedNamespace, ns)
			assert.Equal(t, tt.expectedType, pt)
		})
	}
}

func TestNewPackageUrl(t *testing.T) {
	// The default registry keeps the coordinate it has always had; nothing
	// downstream that already matched pkg:terraform/... moves.
	assert.Equal(t, "pkg:terraform/hashicorp/aws@5.31.0",
		NewPackageUrl("registry.terraform.io", "hashicorp", "aws", "5.31.0"))
	assert.Equal(t, "pkg:terraform/hashicorp/aws@5.31.0",
		NewPackageUrl("", "hashicorp", "aws", "5.31.0"))
	assert.Equal(t, "pkg:terraform/integrations/github@5.42.0",
		NewPackageUrl("registry.terraform.io", "integrations", "github", "5.42.0"))

	// OpenTofu providers are their own artifacts and get their own type; they
	// used to collapse onto the HashiCorp coordinate.
	assert.Equal(t, "pkg:opentofu/hashicorp/aws@5.31.0",
		NewPackageUrl("registry.opentofu.org", "hashicorp", "aws", "5.31.0"))
}

func TestPurlTypeForHost(t *testing.T) {
	assert.Equal(t, PurlTypeProvider, PurlTypeForHost(""))
	assert.Equal(t, PurlTypeProvider, PurlTypeForHost(DefaultRegistry))
	assert.Equal(t, PurlTypeOpenTofuProvider, PurlTypeForHost(OpenTofuRegistry))
	// A private registry serves the Terraform protocol and keeps the type.
	assert.Equal(t, PurlTypeProvider, PurlTypeForHost("artifactory.acme.com"))
}
