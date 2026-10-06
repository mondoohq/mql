// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package execruntime

import (
	"encoding/json"
	"os"
)

// OnDefaultBranch reports whether this run builds the repository's default
// branch, as opposed to a feature branch, a tag or a pull request. It is false
// wherever that cannot be told, which includes every environment but GitHub
// Actions and GitLab CI.
func (c *RuntimeEnv) OnDefaultBranch() bool {
	switch c.Id {
	case GITLAB:
		// CI_COMMIT_BRANCH is unset in merge request pipelines and for tags.
		branch := environmentProvider.Getenv("CI_COMMIT_BRANCH")
		return branch != "" && branch == environmentProvider.Getenv("CI_DEFAULT_BRANCH")

	case GITHUB:
		// GitHub Actions has no variable for the default branch; the event
		// payload carries it. Pull request events build a merge ref and never
		// count, whichever branch they target.
		switch environmentProvider.Getenv("GITHUB_EVENT_NAME") {
		case "pull_request", "pull_request_target", "merge_group":
			return false
		}
		if environmentProvider.Getenv("GITHUB_REF_TYPE") != "branch" {
			return false
		}
		branch := environmentProvider.Getenv("GITHUB_REF_NAME")
		return branch != "" && branch == githubDefaultBranch(environmentProvider.Getenv("GITHUB_EVENT_PATH"))
	}
	return false
}

func githubDefaultBranch(eventPath string) string {
	if eventPath == "" {
		return ""
	}
	data, err := os.ReadFile(eventPath)
	if err != nil {
		return ""
	}
	var event struct {
		Repository struct {
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return ""
	}
	return event.Repository.DefaultBranch
}
