// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path/filepath"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"sigs.k8s.io/yaml"
)

const defaultGooseConfigDir = ".config/goose"

func initGoose(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "goose", defaultGooseConfigDir)
}

func (r *mqlGoose) id() (string, error) {
	return "goose/" + r.ConfigPath.Data, nil
}

func (r *mqlGoose) loadConfig() (*gooseConfig, error) {
	afs := connectionAfs(r.MqlRuntime)
	data, err := afs.ReadFile(filepath.Join(r.ConfigPath.Data, "config.yaml"))
	if err != nil {
		return nil, err
	}

	var config gooseConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse goose config.yaml: %w", err)
	}
	return &config, nil
}

func (r *mqlGoose) provider() (string, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return config.Provider, nil
}

func (r *mqlGoose) model() (string, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return config.Model, nil
}

func (r *mqlGoose) telemetryEnabled() (bool, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return config.TelemetryEnabled, nil
}

func (r *mqlGoose) extensions() ([]interface{}, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []interface{}
	for name, ext := range config.Extensions {
		res, err := NewResource(r.MqlRuntime, "goose.extension", map[string]*llx.RawData{
			"__id":        llx.StringData(aiChildID("goose.extension", r.ConfigPath.Data, name)),
			"name":        llx.StringData(name),
			"enabled":     llx.BoolData(ext.Enabled),
			"type":        llx.StringData(ext.Type),
			"description": llx.StringData(ext.Description),
			"bundled":     llx.BoolData(ext.Bundled),
			"timeout":     llx.IntData(int64(ext.Timeout)),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlGoose) skills() ([]interface{}, error) {
	return agentSkills(r.MqlRuntime, "goose.skill", r.ConfigPath.Data, defaultGooseConfigDir,
		filepath.Join(defaultGooseConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

// Child resource ID methods

func (r *mqlGooseExtension) id() (string, error) {
	return "goose.extension/" + r.Name.Data, nil
}

func (r *mqlGooseSkill) id() (string, error) {
	return "goose.skill/" + r.Source.Data, nil
}

func (r *mqlGooseSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlGooseSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// Helper types

type gooseConfig struct {
	Extensions       map[string]gooseExtension `json:"extensions"`
	Provider         string                    `json:"GOOSE_PROVIDER"`
	Model            string                    `json:"GOOSE_MODEL"`
	TelemetryEnabled bool                      `json:"GOOSE_TELEMETRY_ENABLED"`
}

type gooseExtension struct {
	Enabled     bool   `json:"enabled"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Bundled     bool   `json:"bundled"`
	Timeout     int    `json:"timeout"`
}
