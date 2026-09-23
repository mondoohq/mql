// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"sigs.k8s.io/yaml"
)

// defaultAiderConfigFile is Aider's configuration file in the user's home.
// Unlike most agents Aider keeps its settings in a single file, not a
// directory, so configPath names the file.
const defaultAiderConfigFile = ".aider.conf.yml"

func initAider(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "aider", defaultAiderConfigFile)
}

func (r *mqlAider) id() (string, error) {
	return "aider/" + r.ConfigPath.Data, nil
}

// aiderConfig holds the keys of .aider.conf.yml this resource reports. The
// API keys are read only to tell whether one is set; they are never returned.
type aiderConfig struct {
	Model           string `json:"model"`
	OpenAIAPIKey    string `json:"openai-api-key"`
	AnthropicAPIKey string `json:"anthropic-api-key"`
	// APIKey is `api-key`: one "provider=key" string or a list of them.
	APIKey interface{} `json:"api-key"`
}

// mqlAiderInternal caches the parsed config, so model() and hasApiKeys() read
// and parse the file once between them.
type mqlAiderInternal struct {
	configOnce      sync.Once
	cachedConfig    *aiderConfig
	cachedConfigErr error
}

func (r *mqlAider) loadConfig() (*aiderConfig, error) {
	r.configOnce.Do(func() {
		r.cachedConfig, r.cachedConfigErr = r.readConfig()
	})
	return r.cachedConfig, r.cachedConfigErr
}

func (r *mqlAider) readConfig() (*aiderConfig, error) {
	data, err := connectionAfs(r.MqlRuntime).ReadFile(r.ConfigPath.Data)
	if err != nil {
		if os.IsNotExist(err) {
			return &aiderConfig{}, nil
		}
		return nil, err
	}
	return parseAiderConfig(data, filepath.Base(r.ConfigPath.Data))
}

func parseAiderConfig(data []byte, name string) (*aiderConfig, error) {
	var cfg aiderConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse aider %s: %w", name, err)
	}
	return &cfg, nil
}

// hasAPIKeys reports whether the configuration stores any provider API key.
// An `api-key` entry counts only when it carries a value after "provider=".
func (c *aiderConfig) hasAPIKeys() bool {
	if strings.TrimSpace(c.OpenAIAPIKey) != "" || strings.TrimSpace(c.AnthropicAPIKey) != "" {
		return true
	}
	var entries []string
	switch v := c.APIKey.(type) {
	case string:
		entries = []string{v}
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok {
				entries = append(entries, s)
			}
		}
	}
	for _, e := range entries {
		_, key, found := strings.Cut(e, "=")
		if !found {
			key = e
		}
		if strings.TrimSpace(key) != "" {
			return true
		}
	}
	return false
}

func (r *mqlAider) model() (string, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return "", err
	}
	return cfg.Model, nil
}

func (r *mqlAider) hasApiKeys() (bool, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return false, err
	}
	return cfg.hasAPIKeys(), nil
}
