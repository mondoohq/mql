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
		{"local", map[string]string{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setenv(t, tc.env)
			assert.Equal(t, tc.want, Detect().OnDefaultBranch())
		})
	}
}
