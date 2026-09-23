// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"sigs.k8s.io/yaml"
)

func (g *mqlGithubWorkflow) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "github.workflow/" + strconv.FormatInt(id, 10), nil
}

func (g *mqlGithubWorkflow) configuration() (any, error) {
	// Use GetFile() to ensure the field is computed
	fileTValue := g.GetFile()
	if fileTValue.Error != nil {
		return nil, fileTValue.Error
	}
	file := fileTValue.Data
	if file == nil {
		// The workflow file is not on the default branch; there is no
		// configuration to parse.
		return nil, nil
	}

	contentTValue := file.GetContent()
	if contentTValue.Error != nil {
		return nil, contentTValue.Error
	}
	content := contentTValue.Data

	data := map[string]any{}
	err := yaml.Unmarshal([]byte(content), &data)
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(data)
}

func (g *mqlGithubWorkflow) file() (*mqlGithubFile, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Path.Error != nil {
		return nil, g.Path.Error
	}
	filePath := g.Path.Data

	if g.repositoryFullName == "" {
		return nil, errors.New("repositoryFullName is not set")
	}
	fullName := g.repositoryFullName
	fullNameSplit := strings.Split(fullName, "/")
	ownerLogin := fullNameSplit[0]
	repoName := fullNameSplit[1]

	// Prefer the default branch already known to the parent repository to
	// avoid an extra Repositories.Get on every workflow access.
	defaultBranch := g.defaultBranchName
	if defaultBranch == "" {
		repo, _, err := conn.Client().Repositories.Get(conn.Context(), ownerLogin, repoName)
		if err != nil {
			return nil, err
		}
		defaultBranch = repo.GetDefaultBranch()
	}
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	log.Debug().
		Str("owner", ownerLogin).
		Str("repo", repoName).
		Str("path", filePath).
		Str("branch", defaultBranch).
		Msg("fetching workflow file")

	fileContent, _, _, err := conn.Client().Repositories.GetContents(conn.Context(), ownerLogin, repoName, filePath, &github.RepositoryContentGetOptions{
		Ref: defaultBranch,
	})
	if err != nil {
		log.Debug().
			Err(err).
			Str("owner", ownerLogin).
			Str("repo", repoName).
			Str("path", filePath).
			Str("branch", defaultBranch).
			Msg("failed to get workflow file contents")

		// A workflow can be registered from a branch other than the default
		// one, in which case the file is not there to read. Report that as a
		// null file rather than failing the query.
		if strings.Contains(err.Error(), "404") {
			g.File.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return newMqlGithubFile(g.MqlRuntime, ownerLogin, repoName, fileContent)
}
