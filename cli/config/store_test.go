// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	subject "go.mondoo.com/mql/cli/config"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestStoreConfig(t *testing.T) {
	fs := afero.NewMemMapFs()
	viper.SetFs(fs)
	tempDir := "/tmp/config_test"
	configPath := filepath.Join(tempDir, "config.yaml")
	viper.SetConfigFile(configPath)

	t.Run("creates new config file when missing", func(t *testing.T) {
		err := subject.StoreConfig()
		require.NoError(t, err)

		exists, err := afero.Exists(fs, configPath)
		require.NoError(t, err)
		assert.True(t, exists, "config file should be created")
	})

	t.Run("writes to existing config file", func(t *testing.T) {
		// Pre-create the config file
		assert.NoError(t, afero.WriteFile(fs, configPath, []byte("initial data"), 0o644))

		viper.Set("key", "value")
		err := subject.StoreConfig()
		require.NoError(t, err)

		// Validate YAML format of the stored file
		content, err := afero.ReadFile(fs, configPath)
		assert.NoError(t, err, "Should be able to read the config file")

		var yamlData map[string]any
		err = yaml.Unmarshal(content, &yamlData)
		assert.NoError(t, err, "Config file should be valid YAML")

		// Verify the saved key-value pair in YAML format
		assert.Equal(t, "value", yamlData["key"], "Config should retain stored values")
	})

	t.Run("correctly omits writing fields that we don't want to store", func(t *testing.T) {
		// valid
		viper.Set("key", "value")
		// omit field
		viper.Set("force", false)

		// store config
		err := subject.StoreConfig()
		require.NoError(t, err)

		// Validate no force field is written to disk
		content, err := afero.ReadFile(fs, configPath)
		assert.NoError(t, err)

		var yamlData map[string]any
		err = yaml.Unmarshal(content, &yamlData)
		assert.NoError(t, err, "Config file should be valid YAML")

		// Verify valid field
		assert.Equal(t, "value", yamlData["key"], "should store valid field")
		// Verify invalid field
		_, exist := yamlData["force"]
		assert.False(t, exist, "should not store omitted field")
	})

	t.Run("handles error when failing to write config file", func(t *testing.T) {
		readOnlyFs := afero.NewReadOnlyFs(fs)
		viper.SetFs(readOnlyFs)

		err := subject.StoreConfig()
		assert.Error(t, err)
	})
}

func TestMarshalConfig(t *testing.T) {
	newConfig := func() *subject.Config {
		cfg := &subject.Config{}
		cfg.AgentMrn = "//agents.api.mondoo.app/spaces/space-1/agents/agent-1"
		cfg.ServiceAccountMrn = "//agents.api.mondoo.app/spaces/space-1/serviceaccounts/sa-1"
		cfg.PrivateKey = "private-key"
		cfg.APIEndpoint = "https://api.example.com"
		return cfg
	}

	t.Run("a .json path is written as JSON", func(t *testing.T) {
		data, err := subject.MarshalConfig("/etc/opt/mondoo/credentials.json", newConfig())
		require.NoError(t, err)

		// The output must parse as JSON. YAML output (e.g. `mrn: ...`) would not.
		var parsed map[string]any
		require.NoError(t, json.Unmarshal(data, &parsed), "output should be valid JSON")

		assert.Equal(t, "//agents.api.mondoo.app/spaces/space-1/serviceaccounts/sa-1", parsed["mrn"])
		assert.Equal(t, "https://api.example.com", parsed["api_endpoint"])
	})

	t.Run("a .yaml path is written as YAML", func(t *testing.T) {
		data, err := subject.MarshalConfig("/etc/opt/mondoo/mondoo.yaml", newConfig())
		require.NoError(t, err)

		// sigs.k8s.io/yaml honors json tags, so keys stay snake_case in YAML too.
		var parsed map[string]any
		require.NoError(t, sigsyaml.Unmarshal(data, &parsed), "output should be valid YAML")

		assert.Equal(t, "//agents.api.mondoo.app/spaces/space-1/serviceaccounts/sa-1", parsed["mrn"])
		assert.Equal(t, "https://api.example.com", parsed["api_endpoint"])
	})

	t.Run("an extensionless path defaults to YAML", func(t *testing.T) {
		data, err := subject.MarshalConfig("/etc/opt/mondoo/mondoo", newConfig())
		require.NoError(t, err)

		// JSON would begin with '{'; the YAML default must not.
		assert.NotEqual(t, byte('{'), data[0], "extensionless path should default to YAML, not JSON")

		var parsed map[string]any
		require.NoError(t, sigsyaml.Unmarshal(data, &parsed))
		assert.Equal(t, "https://api.example.com", parsed["api_endpoint"])
	})

	t.Run("cleared agent_mrn is omitted, unrelated keys retained", func(t *testing.T) {
		cfg := newConfig()
		cfg.AgentMrn = "" // logout clears this before writing

		for _, path := range []string{"credentials.json", "mondoo.yaml"} {
			data, err := subject.MarshalConfig(path, cfg)
			require.NoError(t, err)

			var parsed map[string]any
			require.NoError(t, sigsyaml.Unmarshal(data, &parsed))

			_, hasAgentMrn := parsed["agent_mrn"]
			assert.False(t, hasAgentMrn, "%s: cleared agent_mrn should be omitted", path)
			assert.Equal(t, "private-key", parsed["private_key"], "%s: unrelated keys should be retained", path)
			assert.Equal(t, "//agents.api.mondoo.app/spaces/space-1/serviceaccounts/sa-1", parsed["mrn"], "%s: unrelated keys should be retained", path)
		}
	})
}
