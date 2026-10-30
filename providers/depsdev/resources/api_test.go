// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
)

func TestGithubOwnerRepo(t *testing.T) {
	tests := []struct {
		name      string
		projectID string
		want      string
		wantErr   bool // errNotGitHubProject expected
	}{
		{name: "plain repo", projectID: "github.com/rs/zerolog", want: "rs/zerolog"},
		{name: "repo with subpath", projectID: "github.com/aws/aws-sdk-go-v2/config", want: "aws/aws-sdk-go-v2"},
		{name: "gitlab is not github", projectID: "gitlab.com/foo/bar", wantErr: true},
		{name: "bitbucket is not github", projectID: "bitbucket.org/foo/bar", wantErr: true},
		{name: "too few segments", projectID: "github.com/onlyowner", wantErr: true},
		{name: "empty", projectID: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := githubOwnerRepo(tt.projectID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tt.projectID, got)
				}
				if !errors.Is(err, errNotGitHubProject) {
					t.Fatalf("expected errNotGitHubProject for %q, got %v", tt.projectID, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.projectID, err)
			}
			if got != tt.want {
				t.Fatalf("githubOwnerRepo(%q) = %q, want %q", tt.projectID, got, tt.want)
			}
		})
	}
}
