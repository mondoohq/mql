// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// parseWorkflow parses workflow YAML the same way the resource does, so the
// tests exercise the shapes the runtime actually sees.
func parseWorkflow(t *testing.T, source string) map[string]any {
	t.Helper()
	config := map[string]any{}
	require.NoError(t, yaml.Unmarshal([]byte(source), &config))
	return config
}

func TestWorkflowTriggers(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected []string
	}{
		{
			name:     "single event as a string",
			source:   "on: push",
			expected: []string{"push"},
		},
		{
			name:     "list of events",
			source:   "on: [push, pull_request]",
			expected: []string{"pull_request", "push"},
		},
		{
			name: "map keyed by event",
			source: `
on:
  push:
    branches: [main]
  pull_request_target:
  workflow_dispatch:
`,
			expected: []string{"pull_request_target", "push", "workflow_dispatch"},
		},
		{
			name:     "no trigger block",
			source:   "name: build",
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, workflowTriggers(parseWorkflow(t, test.source)))
		})
	}
}

// Workflow YAML is parsed as YAML 1.1, where the bare word `on` is the boolean
// true. Every real workflow's trigger block therefore lands under the key
// "true", and a lookup of "on" alone finds nothing at all.
func TestWorkflowTriggersUnderFoldedOnKey(t *testing.T) {
	config := parseWorkflow(t, "on:\n  push:\n    branches: [main]\n")

	require.NotContains(t, config, "on", "YAML 1.1 folds the bare key `on` to true")
	require.Contains(t, config, "true")

	assert.Equal(t, []string{"push"}, workflowTriggers(config))
}

// A workflow that quotes the key keeps it as the string "on", which must work
// the same way.
func TestWorkflowTriggersUnderQuotedOnKey(t *testing.T) {
	config := parseWorkflow(t, `"on":`+"\n  push:\n")

	require.Contains(t, config, "on")
	assert.Equal(t, []string{"push"}, workflowTriggers(config))
}

// A trigger block of an unexpected type reports no triggers rather than
// panicking. `on: true` is not a workflow anyone writes, but the block is
// reached through a folded key, so the value is worth pinning.
func TestWorkflowTriggersOfAnUnexpectedType(t *testing.T) {
	assert.Equal(t, []string{}, workflowTriggers(parseWorkflow(t, "on: true")))
	assert.Equal(t, []string{}, workflowTriggers(parseWorkflow(t, "on: 42")))
	assert.Equal(t, []string{}, workflowTriggers(parseWorkflow(t, "on:")))
}

func TestWorkflowTokenPermissions(t *testing.T) {
	t.Run("scope map", func(t *testing.T) {
		config := parseWorkflow(t, "permissions:\n  contents: read\n  id-token: write\n")

		assert.Equal(t, map[string]any{"contents": "read", "id-token": "write"},
			workflowTokenPermissions(config))
	})

	t.Run("shorthand string is reported under all", func(t *testing.T) {
		config := parseWorkflow(t, "permissions: write-all")

		assert.Equal(t, map[string]any{"all": "write-all"}, workflowTokenPermissions(config))
	})

	t.Run("absent block is unknown, not empty", func(t *testing.T) {
		// An empty map would read as "no permissions granted". In fact the
		// repository or organization default applies, which may well be
		// write-all.
		assert.Nil(t, workflowTokenPermissions(parseWorkflow(t, "name: build")))
	})
}

func TestWorkflowRunsOnLabels(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected []string
	}{
		{
			name: "string and list forms",
			source: `
jobs:
  a:
    runs-on: ubuntu-latest
  b:
    runs-on: [self-hosted, linux, x64]
`,
			expected: []string{"linux", "self-hosted", "ubuntu-latest", "x64"},
		},
		{
			name: "runner group with labels",
			source: `
jobs:
  a:
    runs-on:
      group: production-runners
      labels: [gpu]
`,
			expected: []string{"gpu", "production-runners"},
		},
		{
			name: "group with a single label as a string",
			source: `
jobs:
  a:
    runs-on:
      group: production-runners
      labels: gpu
`,
			expected: []string{"gpu", "production-runners"},
		},
		{
			name: "expressions are reported verbatim",
			source: `
jobs:
  a:
    runs-on: ${{ matrix.os }}
`,
			expected: []string{"${{ matrix.os }}"},
		},
		{
			name: "duplicates across jobs collapse",
			source: `
jobs:
  a:
    runs-on: ubuntu-latest
  b:
    runs-on: ubuntu-latest
`,
			expected: []string{"ubuntu-latest"},
		},
		{
			name:     "no jobs",
			source:   "name: build",
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, workflowRunsOnLabels(parseWorkflow(t, test.source)))
		})
	}
}

func TestWorkflowActionRefs(t *testing.T) {
	source := `
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: a step that runs a command
        run: make build
      - uses: ./.github/actions/local
  call:
    uses: octo-org/shared/.github/workflows/release.yml@v1
`
	assert.Equal(t, []string{
		"./.github/actions/local",
		"actions/checkout@v4",
		"octo-org/shared/.github/workflows/release.yml@v1",
	}, workflowActionRefs(parseWorkflow(t, source)))
}

func TestWorkflowActionRefsToleratesMalformedYaml(t *testing.T) {
	// A workflow file is arbitrary user content and may not match the schema.
	// Parsing must not panic on entries of an unexpected shape.
	source := `
jobs:
  a: "not an object"
  b:
    steps: "not a list"
  c:
    steps:
      - "not an object"
      - uses: 42
      - uses: actions/checkout@v4
`
	assert.Equal(t, []string{"actions/checkout@v4"}, workflowActionRefs(parseWorkflow(t, source)))
	assert.Equal(t, []string{}, workflowRunsOnLabels(parseWorkflow(t, source)))
}

func TestIsPinnedActionRef(t *testing.T) {
	const sha = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"

	tests := []struct {
		ref    string
		pinned bool
	}{
		{ref: "actions/checkout@" + sha, pinned: true},
		{ref: "actions/checkout@v4", pinned: false},
		{ref: "actions/checkout@main", pinned: false},
		// A short SHA resolves, but names more than one possible commit.
		{ref: "actions/checkout@8f4b7f8", pinned: false},
		{ref: "actions/checkout", pinned: false},
		// Local actions are part of the commit being built.
		{ref: "./.github/actions/local", pinned: true},
		{ref: ".\\.github\\actions\\local", pinned: true},
		// Container actions pin by digest rather than by commit.
		{ref: "docker://alpine@sha256:" + "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", pinned: true},
		{ref: "docker://alpine:3.20", pinned: false},
		{ref: "docker://alpine@sha256:tooshort", pinned: false},
		// A reusable workflow pinned to a SHA is pinned like any other ref.
		{ref: "octo-org/shared/.github/workflows/release.yml@" + sha, pinned: true},
		{ref: "octo-org/shared/.github/workflows/release.yml@v1", pinned: false},
	}

	for _, test := range tests {
		t.Run(test.ref, func(t *testing.T) {
			assert.Equal(t, test.pinned, isPinnedActionRef(test.ref))
		})
	}
}
