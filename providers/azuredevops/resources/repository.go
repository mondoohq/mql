// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

// repositoryArgs is every field of a repository resource that is not computed.
func repositoryArgs(project string, r connection.Repository) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":            llx.StringData(r.ID),
		"name":          llx.StringData(r.Name),
		"projectName":   llx.StringData(project),
		"fullName":      llx.StringData(project + "/" + r.Name),
		"defaultBranch": llx.StringData(r.DefaultBranch),
		"size":          llx.IntData(r.Size),
		"isDisabled":    llx.BoolData(r.IsDisabled),
		"isEmpty":       llx.BoolData(r.IsEmpty()),
		"isFork":        llx.BoolData(r.IsFork),
		"status":        llx.StringData(string(r.Status())),
		"webUrl":        llx.StringData(r.WebURL),
		"sshUrl":        llx.StringData(r.SSHURL),
		"cloneUrl":      llx.StringData(r.HTTPURL()),
	}
}

// newRepository builds the resource of a repository that was listed.
func newRepository(runtime *plugin.Runtime, project string, r connection.Repository) (*mqlAzuredevopsRepository, error) {
	res, err := CreateResource(runtime, "azuredevops.repository", repositoryArgs(project, r))
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzuredevopsRepository), nil
}

func stringArg(args map[string]*llx.RawData, key string) string {
	if x, ok := args[key]; ok && x != nil {
		if s, ok := x.Value.(string); ok {
			return s
		}
	}
	return ""
}

// initAzuredevopsRepository resolves the repository a connection stands for,
// or the one named by projectName and name.
func initAzuredevopsRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := connectionOf(runtime)
	project := stringArg(args, "projectName")
	name := stringArg(args, "name")
	if project == "" {
		project = conn.Project()
	}
	if name == "" {
		name = conn.Repository()
	}
	if project == "" || name == "" {
		return nil, nil, errors.New("azuredevops.repository needs a project and a name, " +
			`for example azuredevops.repository(projectName: "<project>", name: "<repository>"), or a repository connection`)
	}

	repo, err := conn.Client().Repository(apiContext(), project, name)
	if err != nil {
		return nil, nil, err
	}
	if repo.Project.Name != "" {
		project = repo.Project.Name
	}
	return repositoryArgs(project, *repo), nil, nil
}

func (r *mqlAzuredevopsRepository) id() (string, error) {
	return "azuredevops.repository/" + r.Id.Data, nil
}

func (r *mqlAzuredevopsRepository) project() (*mqlAzuredevopsProject, error) {
	p, err := connectionOf(r.MqlRuntime).Client().Project(apiContext(), r.ProjectName.Data)
	if err != nil {
		return nil, err
	}
	return newProject(r.MqlRuntime, *p)
}
