// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestNewJamfConnection_MissingCredentials(t *testing.T) {
	_, err := NewJamfConnection(0, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required Jamf credentials")
	// Error should enumerate every missing piece so the user knows what to
	// provide, not just that "something" is missing.
	assert.Contains(t, err.Error(), "instance_domain")
	assert.Contains(t, err.Error(), "client_id")
	assert.Contains(t, err.Error(), "client_secret")
}

func TestNewJamfConnection_MissingOnlyDomainNamesOnlyDomain(t *testing.T) {
	cred := &vault.Credential{
		Type:   vault.CredentialType_password,
		User:   "client-id",
		Secret: []byte("client-secret"),
	}
	_, err := NewJamfConnection(0, &inventory.Asset{}, &inventory.Config{
		Options:     map[string]string{},
		Credentials: []*vault.Credential{cred},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "instance_domain")
	assert.NotContains(t, err.Error(), "client_id")
	assert.NotContains(t, err.Error(), "client_secret")
}

func TestNewJamfConnection_MissingDomain(t *testing.T) {
	cred := &vault.Credential{
		Type:   vault.CredentialType_password,
		User:   "client-id",
		Secret: []byte("client-secret"),
	}
	_, err := NewJamfConnection(0, &inventory.Asset{}, &inventory.Config{
		Options:     map[string]string{},
		Credentials: []*vault.Credential{cred},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required Jamf credentials")
}

func TestNewJamfConnection_MissingClientID(t *testing.T) {
	_, err := NewJamfConnection(0, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			"instance_domain": "https://example.jamfcloud.com",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required Jamf credentials")
}

func TestJamfConnection_PlatformInfo(t *testing.T) {
	conn := &JamfConnection{}
	platform, err := conn.PlatformInfo()
	require.NoError(t, err)
	assert.Equal(t, "jamf", platform.Name)
	assert.Equal(t, "Jamf Pro", platform.Title)
	assert.Equal(t, "api", platform.Kind)
	assert.Equal(t, "jamf", platform.Runtime)
	assert.Equal(t, []string{"jamf"}, platform.Family)
}

func TestJamfConnection_Identifier(t *testing.T) {
	conn := &JamfConnection{
		Conf: &inventory.Config{
			Options: map[string]string{
				"instance_domain": "https://MyCompany.jamfcloud.com",
			},
		},
	}
	id := conn.Identifier()
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/jamf/mycompany.jamfcloud.com", id)
}

func TestJamfConnection_IdentifierBareHostname(t *testing.T) {
	conn := &JamfConnection{
		Conf: &inventory.Config{
			Options: map[string]string{
				"instance_domain": "MyCompany.jamfcloud.com",
			},
		},
	}
	id := conn.Identifier()
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/jamf/mycompany.jamfcloud.com", id)
}

func TestJamfConnection_IdentifierStripsPath(t *testing.T) {
	conn := &JamfConnection{
		Conf: &inventory.Config{
			Options: map[string]string{
				"instance_domain": "https://mycompany.jamfcloud.com/extra/path",
			},
		},
	}
	id := conn.Identifier()
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/jamf/mycompany.jamfcloud.com", id)
}

func TestJamfConnection_Name(t *testing.T) {
	conn := &JamfConnection{}
	assert.Equal(t, "jamf", conn.Name())
}

func TestJamfConnection_LocalUserAccountsCache(t *testing.T) {
	conn := &JamfConnection{
		localUserAccounts: make(map[string][]jamfpro.ComputerInventorySubsetLocalUserAccount),
	}

	// Cache should be empty initially
	_, ok := conn.GetCachedLocalUserAccounts("123")
	assert.False(t, ok)

	// After caching, should return data
	testAccounts := []jamfpro.ComputerInventorySubsetLocalUserAccount{
		{UID: "501", Username: "admin", Admin: true},
		{UID: "502", Username: "user1", Admin: false},
	}
	conn.CacheLocalUserAccounts("123", testAccounts)

	cached, ok := conn.GetCachedLocalUserAccounts("123")
	assert.True(t, ok)
	require.Len(t, cached, 2)
	assert.Equal(t, "admin", cached[0].Username)
	assert.True(t, cached[0].Admin)
	assert.Equal(t, "user1", cached[1].Username)
	assert.False(t, cached[1].Admin)

	// Different ID should miss cache
	_, ok = conn.GetCachedLocalUserAccounts("456")
	assert.False(t, ok)
}
