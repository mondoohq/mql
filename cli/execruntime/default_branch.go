// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package execruntime

import (
	"encoding/json"
	"os"
	"strings"
)

// DefaultBranchEnv names the repository's default branch on CI platforms that
// don't expose it themselves: Azure Pipelines, CircleCI and Jenkins outside a
// multibranch project. It has no effect on GitHub Actions and GitLab CI, which
// report the default branch, or outside a detected CI platform.
const DefaultBranchEnv = "MONDOO_DEFAULT_BRANCH"

// OnDefaultBranch reports whether this run builds the repository's default
// branch, as opposed to a feature branch, a tag or a pull request. It is false
// wherever that cannot be told: outside GitHub Actions, GitLab CI, Jenkins,
// Azure Pipelines and CircleCI, and on the last three when neither the
// platform nor DefaultBranchEnv names the default branch.
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

	case JENKINS:
		// Multibranch projects set CHANGE_ID for change requests and TAG_NAME
		// for tags; neither counts. BRANCH_IS_PRIMARY comes from the SCM source
		// (branch-api 2.6.4+). A freestyle job's GIT_BRANCH is remote-qualified,
		// e.g. origin/main.
		if environmentProvider.Getenv("CHANGE_ID") != "" || environmentProvider.Getenv("TAG_NAME") != "" {
			return false
		}
		if environmentProvider.Getenv("BRANCH_IS_PRIMARY") == "true" {
			return true
		}
		branch := environmentProvider.Getenv("BRANCH_NAME")
		if branch == "" {
			branch = strings.TrimPrefix(environmentProvider.Getenv("GIT_BRANCH"), "origin/")
		}
		return isConfiguredDefaultBranch(branch)

	case AZUREPIPELINE:
		// Azure Pipelines has no variable for the default branch. Pull request
		// builds check out refs/pull/..., tags refs/tags/...; only refs/heads/
		// can be a branch push.
		if environmentProvider.Getenv("BUILD_REASON") == "PullRequest" {
			return false
		}
		ref := environmentProvider.Getenv("BUILD_SOURCEBRANCH")
		if !strings.HasPrefix(ref, "refs/heads/") {
			return false
		}
		return isConfiguredDefaultBranch(strings.TrimPrefix(ref, "refs/heads/"))

	case CIRCLE:
		// The default branch is only a pipeline value
		// (pipeline.git.branch.is_default), not an environment variable. Pull
		// requests from forks build as pull/<n> and never match.
		if environmentProvider.Getenv("CIRCLE_TAG") != "" {
			return false
		}
		return isConfiguredDefaultBranch(environmentProvider.Getenv("CIRCLE_BRANCH"))
	}
	return false
}

// isConfiguredDefaultBranch reports whether branch is the one DefaultBranchEnv
// names, written either as a name or as refs/heads/<name>.
func isConfiguredDefaultBranch(branch string) bool {
	want := strings.TrimPrefix(strings.TrimSpace(environmentProvider.Getenv(DefaultBranchEnv)), "refs/heads/")
	return want != "" && branch == want
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
