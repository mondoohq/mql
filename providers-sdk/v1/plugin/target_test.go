// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatcherMatch(t *testing.T) {
	tests := []struct {
		name     string
		glob     string
		path     string
		wantSite string
		wantOk   bool
	}{
		// A base-name glob is tested against the base name, not the whole
		// path, and sites at the file's own directory.
		{"base name, nested", "*.tf", "envs/prod/main.tf", "envs/prod", true},
		{"base name, at the root", "*.tf", "main.tf", "", true},
		{"base name, wrong extension", "*.tf", "main.tofu", "", false},
		// A base-name glob matching against the full path would make this
		// miss, since `*` does not cross a separator in path.Match.
		{"base name, deep path still matches", "Chart.yaml", "charts/api/Chart.yaml", "charts/api", true},

		// A slashed glob is tested against the tail of the path and sites at
		// the directory its segments hang below.
		{"slashed glob", "roles/*/tasks/main.yml", "ansible/roles/web/tasks/main.yml", "ansible", true},
		{"slashed glob at the root", "roles/*/tasks/main.yml", "roles/web/tasks/main.yml", "", true},
		{"slashed glob, * must not cross a separator", "roles/*/tasks/main.yml", "roles/a/b/tasks/main.yml", "", false},
		{"slashed glob, path too short", "roles/*/tasks/main.yml", "tasks/main.yml", "", false},
		{"slashed glob, wrong leaf", "roles/*/tasks/main.yml", "ansible/roles/web/tasks/other.yml", "", false},

		// The Dockerfile set, which is where the forge classifier and the
		// ADR's opt-in table disagreed.
		{"Dockerfile exact", "Dockerfile", "services/api/Dockerfile", "services/api", true},
		{"Dockerfile suffixed", "Dockerfile.*", "Dockerfile.dev", "", true},
		{"Dockerfile prefix is not enough", "Dockerfile.*", "DockerfileLint.md", "", false},
		{"prefixed Dockerfile", "*.Dockerfile", "api.Dockerfile", "", true},
		// path.Match is case-sensitive, which is why the lowercase arm of the
		// forges' isDockerfile needs a glob of its own.
		{"prefixed dockerfile is a different glob", "*.Dockerfile", "api.dockerfile", "", false},
		{"lowercase arm", "*.dockerfile", "api.dockerfile", "", true},

		// Windows paths must not match: the walk works in slash paths, and
		// filepath.Match would treat these as a single segment.
		{"backslash path does not match", "roles/*/tasks/main.yml", `ansible\roles\web\tasks\main.yml`, "", false},

		// Degenerate inputs answer false rather than panicking or matching
		// everything.
		{"malformed glob", "[", "main.tf", "", false},
		{"empty glob matches nothing", "", "main.tf", "", false},
		{"empty path matches nothing", "*.tf", "", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			site, ok := Matcher{Glob: test.glob}.Match(test.path)
			assert.Equal(t, test.wantOk, ok)
			assert.Equal(t, test.wantSite, site)
		})
	}
}

func TestTargetOptInMatches(t *testing.T) {
	// The ansible opt-in, which is the one mixing base-name and slashed globs.
	optIn := TargetOptIn{
		Match: []Matcher{
			{Glob: "ansible.cfg"},
			{Glob: "roles/*/tasks/main.yml"},
			{Glob: "*.yml"},
		},
	}

	site, ok := optIn.Matches("infra/ansible/ansible.cfg")
	require.True(t, ok)
	assert.Equal(t, "infra/ansible", site)

	// The slashed glob wins over the trailing *.yml one, so the site is the
	// project directory rather than the tasks directory.
	site, ok = optIn.Matches("infra/ansible/roles/web/tasks/main.yml")
	require.True(t, ok)
	assert.Equal(t, "infra/ansible", site)

	// A playbook only the *.yml matcher catches sites at its own directory.
	site, ok = optIn.Matches("infra/ansible/site.yml")
	require.True(t, ok)
	assert.Equal(t, "infra/ansible", site)

	_, ok = optIn.Matches("infra/terraform/main.tf")
	assert.False(t, ok)
}

func TestProviderTargetOptIns(t *testing.T) {
	p := &Provider{
		Targets: []TargetOptIn{
			{Target: "iac", Discovery: "terraform"},
			{Target: "iac", Discovery: "opentofu"},
			{Target: "other", Discovery: "terraform"},
		},
	}

	iac := p.TargetOptIns("iac")
	require.Len(t, iac, 2)
	assert.Equal(t, "terraform", iac[0].Discovery)
	assert.Equal(t, "opentofu", iac[1].Discovery)

	assert.True(t, p.DeclaresTarget("iac"))
	assert.True(t, p.DeclaresTarget("other"))
	assert.False(t, p.DeclaresTarget("nope"))
	assert.False(t, p.DeclaresTarget(""))

	// A provider with no opt-ins is the common case and must answer cleanly.
	assert.Nil(t, (&Provider{}).TargetOptIns("iac"))
	assert.False(t, (&Provider{}).DeclaresTarget("iac"))
	assert.False(t, (*Provider)(nil).DeclaresTarget("iac"))
}
