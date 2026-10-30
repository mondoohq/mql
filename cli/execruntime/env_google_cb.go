// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package execruntime

const GOOGLE_CLOUD_BUILD = "google-cb"

// seems like google does not set default environment variables,
// therefore users need to set them themselves, see
// https://docs.cloud.google.com/build/docs/configuring-builds/substitute-variable-values#using_default_substitutions
//
// steps:
// # Uses the ubuntu build step:
// # to run a shell script; and
// # set env variables for its execution
// - name: 'ubuntu'
//   args: ['bash', './myscript.sh']
//   env:
//   - 'CLOUDBUILD=true'
//   - 'BUILD=$BUILD_ID'
//   - 'PROJECT=$PROJECT_ID'
//   - 'COMMIT_SHA=$COMMIT_SHA'
//   - 'SHORT_SHA=$SHORT_SHA'
//   - 'REPO_NAME=$REPO_NAME'
//   - 'BRANCH_NAME=$BRANCH_NAME'
//   - 'TAG_NAME=$TAG_NAME'
//   - 'REVISION_ID=$REVISION_ID'

var googleCloudBuildEnv = &RuntimeEnv{ //nolint:unused
	Id:        GOOGLE_CLOUD_BUILD,
	Name:      "Google Cloud Build",
	Namespace: "build.cloud.google.com",
	Identify: []Variable{
		{
			Name: "CLOUDBUILD",
		},
	},
	Variables: []Variable{
		{
			Name: "PROJECT_ID",
			Desc: "build.ProjectId",
		},
		{
			Name: "BUILD_ID",
			Desc: "build.BuildId",
		},
		{
			Name: "COMMIT_SHA",
			Desc: "build.SourceProvenance.ResolvedRepoSource.Revision.CommitSha",
		},
		{
			Name: "SHORT_SHA",
			Desc: "The first seven characters of COMMIT_SHA",
		},
		{
			Name: "REPO_NAME",
			Desc: "build.Source.RepoSource.RepoName",
		},
		{
			Name: "BRANCH_NAME",
			Desc: "build.Source.RepoSource.Revision.BranchName",
		},
		{
			Name: "TAG_NAME",
			Desc: "build.Source.RepoSource.Revision.TagName",
		},
		{
			Name: "REVISION_ID",
			Desc: "build.SourceProvenance.ResolvedRepoSource.Revision.CommitSha",
		},
	},
}
