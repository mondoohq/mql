// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestGetCredentialsPrecedence(t *testing.T) {
	t.Setenv(EXOSCALE_LEGACY_KEY_VAR, "EXOlegacy")
	t.Setenv(EXOSCALE_LEGACY_SECRET_VAR, "from-legacy-env")
	t.Setenv(EXOSCALE_API_KEY_VAR, "")
	t.Setenv(EXOSCALE_API_SECRET_VAR, "")

	key, secret := GetCredentials(&inventory.Config{})
	assert.Equal(t, "EXOlegacy", key)
	assert.Equal(t, "from-legacy-env", secret)

	t.Setenv(EXOSCALE_API_KEY_VAR, "EXOenv")
	t.Setenv(EXOSCALE_API_SECRET_VAR, "from-env")
	key, secret = GetCredentials(&inventory.Config{})
	assert.Equal(t, "EXOenv", key)
	assert.Equal(t, "from-env", secret)

	conf := credentialConf("EXOflag", "from-flag")
	key, secret = GetCredentials(conf)
	assert.Equal(t, "EXOflag", key)
	assert.Equal(t, "from-flag", secret)
}

func TestGetCredentialsPartialFlagKeepsEnvSecret(t *testing.T) {
	t.Setenv(EXOSCALE_API_KEY_VAR, "EXOenv")
	t.Setenv(EXOSCALE_API_SECRET_VAR, "from-env")
	conf := credentialConf("EXOflag", "")
	key, secret := GetCredentials(conf)
	assert.Equal(t, "EXOflag", key)
	assert.Equal(t, "from-env", secret)
}

func TestGetZones(t *testing.T) {
	t.Setenv(EXOSCALE_ZONES_VAR, "de-fra-1")
	assert.Equal(t, []string{"de-fra-1"}, GetZones(&inventory.Config{}))
	conf := &inventory.Config{Options: map[string]string{OPTION_ZONES: " ch-gva-2, ,at-vie-1 "}}
	assert.Equal(t, []string{"ch-gva-2", "at-vie-1"}, GetZones(conf))
	t.Setenv(EXOSCALE_ZONES_VAR, "")
	assert.Nil(t, GetZones(&inventory.Config{}))
}

// credentialConf builds a config carrying the key and secret the way
// ParseCLI stores the --api-key and --api-secret flags.
func credentialConf(key, secret string) *inventory.Config {
	return &inventory.Config{Credentials: []*vault.Credential{vault.NewPasswordCredential(key, secret)}}
}
