// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package workflows

// workflow represents the minimal structure of a GitHub Actions workflow YAML.
type workflow struct {
	Jobs map[string]job `yaml:"jobs"`

	// evidence is a list of file paths where the workflow was found.
	evidence []string `yaml:"-"`
}

// job represents a single job in a workflow. A job either runs steps or calls
// a reusable workflow with a job-level `uses`
// (owner/repo/.github/workflows/build.yml@ref).
type job struct {
	Uses  string `yaml:"uses"`
	Steps []step `yaml:"steps"`
}

// step represents a single step in a job.
type step struct {
	Uses string `yaml:"uses"`
}
