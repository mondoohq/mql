// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package execruntime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnDefaultBranch(t *testing.T) {
	setenv := func(t *testing.T, kv map[string]string) {
		environmentProvider = newMockEnvProvider()
		t.Cleanup(func() { environmentProvider = &osEnvProvider{} })
		for k, v := range kv {
			require.NoError(t, environmentProvider.Setenv(k, v))
		}
	}

	event := filepath.Join(t.TempDir(), "event.json")
	require.NoError(t, os.WriteFile(event, []byte(`{"repository":{"default_branch":"main"}}`), 0o644))

	github := func(eventName, refType, ref string) map[string]string {
		return map[string]string{
			"GITHUB_ACTION":     "run",
			"GITHUB_EVENT_NAME": eventName,
			"GITHUB_EVENT_PATH": event,
			"GITHUB_REF_TYPE":   refType,
			"GITHUB_REF_NAME":   ref,
		}
	}

	with := func(env map[string]string, kv ...string) map[string]string {
		for i := 0; i < len(kv); i += 2 {
			env[kv[i]] = kv[i+1]
		}
		return env
	}
	jenkins := func(kv ...string) map[string]string {
		return with(map[string]string{"JENKINS_URL": "https://jenkins.example.com/"}, kv...)
	}
	circle := func(kv ...string) map[string]string {
		return with(map[string]string{"CIRCLECI": "true"}, kv...)
	}
	azure := func(reason, ref, defaultBranch string) map[string]string {
		env := map[string]string{"TF_BUILD": "True", "BUILD_REASON": reason, "BUILD_SOURCEBRANCH": ref}
		if defaultBranch != "" {
			env[DefaultBranchEnv] = defaultBranch
		}
		return env
	}

	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"github push to default", github("push", "branch", "main"), true},
		{"github push to feature", github("push", "branch", "feature"), false},
		{"github tag", github("push", "tag", "main"), false},
		{"github pull request", github("pull_request", "branch", "main"), false},
		{"gitlab default", map[string]string{"GITLAB_CI": "true", "CI_COMMIT_BRANCH": "main", "CI_DEFAULT_BRANCH": "main"}, true},
		{"gitlab feature", map[string]string{"GITLAB_CI": "true", "CI_COMMIT_BRANCH": "x", "CI_DEFAULT_BRANCH": "main"}, false},
		{"gitlab merge request", map[string]string{"GITLAB_CI": "true", "CI_DEFAULT_BRANCH": "main"}, false},
		{"gitlab ignores configured default", map[string]string{"GITLAB_CI": "true", "CI_COMMIT_BRANCH": "x", "CI_DEFAULT_BRANCH": "main", DefaultBranchEnv: "x"}, false},
		{"github ignores configured default", with(github("push", "branch", "feature"), DefaultBranchEnv, "feature"), false},

		{"jenkins primary branch", jenkins("BRANCH_NAME", "main", "BRANCH_IS_PRIMARY", "true"), true},
		{"jenkins non-primary branch", jenkins("BRANCH_NAME", "feature"), false},
		{"jenkins change request on primary target", jenkins("BRANCH_NAME", "PR-24", "CHANGE_ID", "24", "BRANCH_IS_PRIMARY", "true"), false},
		{"jenkins tag", jenkins("BRANCH_NAME", "v1.0", "TAG_NAME", "v1.0", "BRANCH_IS_PRIMARY", "true"), false},
		{"jenkins configured default", jenkins("BRANCH_NAME", "main", DefaultBranchEnv, "main"), true},
		{"jenkins freestyle configured default", jenkins("GIT_BRANCH", "origin/main", DefaultBranchEnv, "main"), true},
		{"jenkins freestyle other branch", jenkins("GIT_BRANCH", "origin/feature", DefaultBranchEnv, "main"), false},
		{"jenkins freestyle unconfigured", jenkins("GIT_BRANCH", "origin/main"), false},

		{"azure configured default", azure("IndividualCI", "refs/heads/main", "main"), true},
		{"azure configured default as ref", azure("IndividualCI", "refs/heads/main", "refs/heads/main"), true},
		{"azure feature", azure("IndividualCI", "refs/heads/feature", "main"), false},
		{"azure pull request", azure("PullRequest", "refs/heads/main", "main"), false},
		{"azure pull request ref", azure("IndividualCI", "refs/pull/7/merge", "main"), false},
		{"azure tag", azure("IndividualCI", "refs/tags/main", "main"), false},
		{"azure unconfigured", azure("IndividualCI", "refs/heads/main", ""), false},

		{"circleci configured default", circle("CIRCLE_BRANCH", "main", DefaultBranchEnv, "main"), true},
		{"circleci feature", circle("CIRCLE_BRANCH", "feature", DefaultBranchEnv, "main"), false},
		{"circleci fork pull request", circle("CIRCLE_BRANCH", "pull/12", DefaultBranchEnv, "main"), false},
		{"circleci tag", circle("CIRCLE_BRANCH", "main", "CIRCLE_TAG", "v1.0", DefaultBranchEnv, "main"), false},
		{"circleci unconfigured", circle("CIRCLE_BRANCH", "main"), false},

		{"local", map[string]string{}, false},
		{"local ignores configured default", map[string]string{DefaultBranchEnv: "main"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setenv(t, tc.env)
			assert.Equal(t, tc.want, Detect().OnDefaultBranch())
		})
	}
}
