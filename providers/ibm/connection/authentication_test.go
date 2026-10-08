// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestGetAPIKeyPrecedence(t *testing.T) {
	t.Setenv(LegacyAPIKeyEnvVar, "from-legacy-env")
	t.Setenv(APIKeyEnvVar, "")
	k, err := GetAPIKey(&inventory.Config{})
	require.NoError(t, err)
	assert.Equal(t, "from-legacy-env", k)

	t.Setenv(APIKeyEnvVar, "from-env")
	k, _ = GetAPIKey(&inventory.Config{})
	assert.Equal(t, "from-env", k)

	file := filepath.Join(t.TempDir(), "apikey.json")
	require.NoError(t, os.WriteFile(file, []byte(`{"name":"ci","apikey":"from-file"}`), 0o600))
	k, _ = GetAPIKey(&inventory.Config{Options: map[string]string{OptionAPIKeyFile: file}})
	assert.Equal(t, "from-file", k)

	conf := &inventory.Config{
		Options:     map[string]string{OptionAPIKeyFile: file},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "from-flag")},
	}
	k, _ = GetAPIKey(conf)
	assert.Equal(t, "from-flag", k)
}

func TestReadAPIKeyFileErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := readAPIKeyFile(filepath.Join(dir, "missing.json"))
	assert.Error(t, err)

	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`not json`), 0o600))
	_, err = readAPIKeyFile(bad)
	assert.ErrorContains(t, err, "is not an IBM Cloud API key JSON document")

	empty := filepath.Join(dir, "empty.json")
	require.NoError(t, os.WriteFile(empty, []byte(`{"name":"x"}`), 0o600))
	_, err = readAPIKeyFile(empty)
	assert.ErrorContains(t, err, "has no apikey field")
}

func TestGetRegions(t *testing.T) {
	t.Setenv(RegionsEnvVar, "eu-de")
	assert.Equal(t, []string{"eu-de"}, GetRegions(&inventory.Config{}))
	assert.Equal(t, []string{"us-south", "eu-gb"}, GetRegions(&inventory.Config{Options: map[string]string{OptionRegions: " us-south, ,eu-gb"}}))
	t.Setenv(RegionsEnvVar, "")
	assert.Nil(t, GetRegions(&inventory.Config{}))
}
