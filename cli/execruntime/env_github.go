// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package execruntime

const GITHUB = "github"

// https://docs.github.com/en/actions/reference/workflows-and-actions/variables#default-environment-variables
var githubEnv = &RuntimeEnv{
	Id:        GITHUB,
	Name:      "GitHub Actions",
	Namespace: "actions.github.com",
	Prefix:    "GITHUB",
	Identify: []Variable{
		{
			Name: "GITHUB_ACTION",
			Desc: "The name of the action or the id of a step",
		},
		{
			Name: "GITHUB_ACTIONS",
			Desc: "Always set to true when GitHub Actions is running the workflow",
		},
	},
	Variables: []Variable{
		{
			Name: "GITHUB_ACTION",
			Desc: "The name of the action",
		},
		{
			Name: "GITHUB_ACTION_PATH",
			Desc: "The path where an action is located.",
		},
		{
			Name: "GITHUB_WORKFLOW",
			Desc: "The name of the workflow",
		},
		{
			Name: "GITHUB_ACTOR",
			Desc: "The name of the person or app that initiated the workflow",
		},
		{
			Name: "GITHUB_RUN_ID",
			Desc: "A unique number for each workflow run within a repository",
		},
		{
			Name: "GITHUB_RUN_ATTEMPT",
			Desc: "A unique number for each attempt of a particular workflow run in a repository",
		},
		{
			Name: "GITHUB_RUN_NUMBER",
			Desc: "A unique number for each run of a particular workflow in a repository",
		},
		{
			Name: "GITHUB_REPOSITORY",
			Desc: "The owner and repository name",
		},
		{
			Name: "GITHUB_REPOSITORY_OWNER",
			Desc: "The repository owner's name",
		},
		{
			Name: "GITHUB_EVENT_NAME",
			Desc: "The name of the webhook event that triggered the workflow",
		},
		{
			Name: "GITHUB_EVENT_PATH",
			Desc: "The path of the file with the complete webhook event payload",
		},
		{
			Name: "GITHUB_WORKSPACE",
			Desc: "The GitHub workspace directory path",
		},
		{
			Name: "GITHUB_SHA",
			Desc: "The commit SHA that triggered the workflow",
		},
		{
			Name: "GITHUB_REF",
			Desc: "The branch or tag ref that triggered the workflow",
			// for example, refs/heads/feature-branch-1
		},
		{
			Name: "GITHUB_REF_NAME",
			Desc: "The branch or tag name that triggered the workflow run",
			// for example, feature-branch-1
		},
		{
			Name: "GITHUB_HEAD_REF",
			Desc: "The branch of the head repository",
		},
		{
			Name: "GITHUB_BASE_REF",
			Desc: "The branch of the base repository",
		},
		{
			Name: "GITHUB_REF_TYPE",
			Desc: "The type of ref that triggered the workflow run: `branch` or `tag`",
		},
		{
			Name: "GITHUB_JOB",
			Desc: "The job_id of the current job",
		},
		{
			Name: "GITHUB_SERVER_URL",
			Desc: "The URL of the GitHub server",
		},
		{
			Name: "GITHUB_WORKFLOW",
			Desc: "The name of the workflow",
		},
		{
			Name: "GITHUB_REF_PROTECTED",
			Desc: "true if branch protections are configured for the ref",
		},
		{
			Name: "RUNNER_ARCH",
			Desc: "The architecture of the runner executing the job",
		},
		{
			Name: "RUNNER_NAME",
			Desc: "The name of the runner executing the job",
		},
		{
			Name: "RUNNER_OS",
			Desc: "The operating system of the runner executing the job",
		},
	},
}
