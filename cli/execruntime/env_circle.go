// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package execruntime

const CIRCLE = "circle"

// see https://circleci.com/docs/guides/security/env-vars/
var circleciEnv = &RuntimeEnv{
	Id:        CIRCLE,
	Name:      "CircleCI",
	Namespace: "circleci.com",
	Prefix:    "CIRCLE",
	Identify: []Variable{
		{
			Name: "CIRCLECI",
			Desc: "represents whether the current environment is a CircleCI environment",
		},
	},
	Variables: []Variable{
		{
			Name: "CIRCLE_PULL_REQUEST",
			Desc: "The URL of the associated pull request.",
		},
		{
			Name: "CIRCLE_JOB",
			Desc: "The name of the current job.",
		},
		{
			Name: "CIRCLE_BUILD_NUM",
			Desc: "The number of the current job. Job numbers are unique for each job.",
		},
		{
			Name: "CIRCLE_BUILD_URL",
			Desc: "The URL for the current build.",
		},
		{
			Name: "CIRCLE_USERNAME",
			Desc: "The GitHub or Bitbucket username of the user who triggered the build.",
		},
		{
			Name: "CIRCLE_SHA1",
			Desc: "The SHA1 hash of the last commit of the current build.",
		},
		{
			Name: "CIRCLE_TAG",
			Desc: "The name of the git tag, if the current build is tagged",
		},
		{
			Name: "CIRCLE_REPOSITORY_URL",
			Desc: "The URL of your GitHub or Bitbucket repository.",
		},
		{
			Name: "CIRCLE_BRANCH",
			Desc: "The name of the Git branch currently being built.",
		},
		{
			Name: "CIRCLE_PROJECT_REPONAME",
			Desc: "The repo name associated with this circle project.",
		},
		{
			Name: "CIRCLE_PULL_REQUESTS",
			Desc: "Comma-separated list of URLs of the current build’s associated pull requests.",
		},
		{
			Name: "CIRCLE_WORKFLOW_ID",
			Desc: "A unique identifier for the workflow instance of the current job. This identifier is the same for every job in a given workflow instance.",
		},
		{
			Name: "CIRCLE_WORKFLOW_JOB_ID",
			Desc: "A unique identifier for the current job.",
		},
		{
			Name: "CIRCLE_WORKFLOW_WORKSPACE_ID",
			Desc: "An identifier for the workspace of the current job. This identifier is the same for every job in a given workflow.",
		},
	},
}
