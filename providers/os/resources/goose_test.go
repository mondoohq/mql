// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"sigs.k8s.io/yaml"
)

func createTestGooseConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeTestFile(t, dir, "config.yaml", `extensions:
  developer:
    enabled: true
    type: builtin
    name: developer
    description: General development tools useful for software engineering.
    timeout: 300
    bundled: true
  memory:
    enabled: false
    type: builtin
    name: memory
    description: Teach goose your preferences as you go.
    timeout: 300
    bundled: true
  skills:
    enabled: true
    type: platform
    name: skills
    description: Load and use skills from relevant directories
    bundled: true
GOOSE_TELEMETRY_ENABLED: false
GOOSE_PROVIDER: custom_ollama
GOOSE_MODEL: qwen3:8b
`)

	return dir
}

func TestGooseConfigParsing(t *testing.T) {
	afs := testAfero()
	dir := createTestGooseConfig(t)

	data, err := afs.ReadFile(dir + "/config.yaml")
	require.NoError(t, err)

	var config gooseConfig
	err = yaml.Unmarshal(data, &config)
	require.NoError(t, err)

	assert.Equal(t, "custom_ollama", config.Provider)
	assert.Equal(t, "qwen3:8b", config.Model)
	assert.False(t, config.TelemetryEnabled)
	assert.Len(t, config.Extensions, 3)

	dev := config.Extensions["developer"]
	assert.True(t, dev.Enabled)
	assert.Equal(t, "builtin", dev.Type)
	assert.Equal(t, "developer", dev.Name)
	assert.Equal(t, 300, dev.Timeout)
	assert.True(t, dev.Bundled)

	mem := config.Extensions["memory"]
	assert.False(t, mem.Enabled)

	skills := config.Extensions["skills"]
	assert.True(t, skills.Enabled)
	assert.Equal(t, "platform", skills.Type)
}

func TestGooseConfigMissing(t *testing.T) {
	afs := testAfero()
	dir := t.TempDir()

	_, err := afs.ReadFile(dir + "/config.yaml")
	assert.Error(t, err)
}

func TestGooseChildrenPerUser(t *testing.T) {
	rt := newAIToolsTestRuntime(t, perUserFiles(map[string]string{
		"/home/{u}/.config/goose/config.yaml": "extensions:\n  developer:\n    enabled: true\n    description: {u} ext\n",
	}))
	assertPerUser(t, childValues(t, rt, "goose", ".config/goose", func(p plugin.Resource) (string, string, error) {
		l := p.(*mqlGoose).GetExtensions()
		s, err := only[*mqlGooseExtension](t, l.Data, l.Error)
		if err != nil {
			return "", "", err
		}
		return s.MqlID(), s.Description.Data, nil
	}), "%s ext")
}
