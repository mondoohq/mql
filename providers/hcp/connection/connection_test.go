// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestNewPlatformID(t *testing.T) {
	tests := []struct {
		scope    string
		segments []string
		want     string
	}{
		{ScopeOrg, []string{"org-123"}, "//platformid.api.mondoo.app/runtime/hcp/org/org-123"},
		{ScopeProject, []string{"proj-9"}, "//platformid.api.mondoo.app/runtime/hcp/project/proj-9"},
		{ScopeVaultCluster, []string{"proj-9", "vault-1"}, "//platformid.api.mondoo.app/runtime/hcp/vault-cluster/proj-9/vault-1"},
		{ScopePackerRegistry, []string{"proj-9"}, "//platformid.api.mondoo.app/runtime/hcp/packer-registry/proj-9"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, NewPlatformID(tt.scope, tt.segments...), "scope %q", tt.scope)
	}
}

func TestNewPlatformAppliesCatalog(t *testing.T) {
	// Every discoverable scope must map to a catalog entry so the emitted
	// platform carries the right name, title, and technology URL segments.
	for scope, name := range scopePlatform {
		pf := NewPlatform(scope, "proj", "res")
		assert.Equal(t, name, pf.Name, "scope %q platform name", scope)
		assert.NotEmpty(t, pf.Title, "scope %q title", scope)
		assert.Equal(t, []string{"hcp"}, pf.Family, "scope %q family", scope)
		assert.Equal(t, "hcp", pf.TechnologyUrlSegments[1], "scope %q tech url", scope)
		assert.Equal(t, scope, pf.TechnologyUrlSegments[2], "scope %q tech url scope segment", scope)
	}
}

func TestClientSecretFromConf(t *testing.T) {
	// The client secret is tagged by credential user; an untagged or wrong-type
	// credential must be ignored.
	conf := &inventory.Config{
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("other", "nope"),
			vault.NewPasswordCredential(CredentialClientSecret, "s3cret"),
		},
	}
	assert.Equal(t, "s3cret", clientSecretFromConf(conf))

	empty := &inventory.Config{}
	assert.Equal(t, "", clientSecretFromConf(empty))
}
