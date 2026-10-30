// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// projectAdminRoles are the roles that administer a project. A member holding
// one decides who else reaches the project's repositories, as far as the
// project's own administrative privileges allow.
var projectAdminRoles = map[string]bool{
	"project admin": true,
	"project_admin": true,
	"admin":         true,
}

// projectRecord is a project as the Access API reports it.
type projectRecord struct {
	ProjectKey      string `json:"project_key"`
	DisplayName     string `json:"display_name"`
	Description     string `json:"description"`
	AdminPrivileges struct {
		ManageMembers   *bool `json:"manage_members"`
		ManageResources *bool `json:"manage_resources"`
		IndexResources  *bool `json:"index_resources"`
	} `json:"admin_privileges"`
	StorageQuotaBytes *int64 `json:"storage_quota_bytes"`
	SoftLimit         *bool  `json:"soft_limit"`
}

// projectMembersResponse is the roster of a project.
type projectMembersResponse struct {
	Members []projectMemberRecord `json:"members"`
}

type projectMemberRecord struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

type mqlArtifactoryProjectInternal struct {
	projectKey string
}

// projects lists the projects the instance defines. A project delegates part of
// the instance to its own administrators, which is a second path to access
// alongside the permission targets.
func (a *mqlArtifactory) projects() ([]any, error) {
	conn := artifactoryConn(a.MqlRuntime)

	var records []projectRecord
	if err := conn.GetJSON(context.Background(), conn.AccessURL("/api/v1/projects"), &records); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		project, err := newArtifactoryProject(a.MqlRuntime, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, project)
	}
	return res, nil
}

func newArtifactoryProject(runtime *plugin.Runtime, rec *projectRecord) (*mqlArtifactoryProject, error) {
	privileges := rec.AdminPrivileges

	created, err := CreateResource(runtime, "artifactory.project", map[string]*llx.RawData{
		"key":               llx.StringData(rec.ProjectKey),
		"displayName":       llx.StringData(rec.DisplayName),
		"description":       optionalString(rec.Description),
		"manageMembers":     llx.BoolData(boolValue(privileges.ManageMembers)),
		"manageResources":   llx.BoolData(boolValue(privileges.ManageResources)),
		"indexResources":    llx.BoolData(boolValue(privileges.IndexResources)),
		"storageQuotaBytes": optionalInt(rec.StorageQuotaBytes),
		"softLimit":         llx.BoolData(boolValue(rec.SoftLimit)),
	})
	if err != nil {
		return nil, err
	}

	project := created.(*mqlArtifactoryProject)
	project.projectKey = rec.ProjectKey
	return project, nil
}

func (p *mqlArtifactoryProject) id() (string, error) {
	return "artifactory.project/" + p.Key.Data, p.Key.Error
}

// members reads the roster of the project. The instance serves it per project,
// so this is one call for each project it is asked about.
func (p *mqlArtifactoryProject) members() ([]any, error) {
	conn := artifactoryConn(p.MqlRuntime)
	requestURL := conn.AccessURL("/api/v1/projects/" + url.PathEscape(p.projectKey) + "/users")

	var response projectMembersResponse
	if err := conn.GetJSON(context.Background(), requestURL, &response); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(response.Members))
	for i := range response.Members {
		rec := response.Members[i]

		created, err := CreateResource(p.MqlRuntime, "artifactory.project.member", map[string]*llx.RawData{
			"name":    llx.StringData(rec.Name),
			"roles":   llx.ArrayData(strSliceToAny(rec.Roles), types.String),
			"isAdmin": llx.BoolData(rolesAdministerProject(rec.Roles)),
		})
		if err != nil {
			return nil, err
		}

		member := created.(*mqlArtifactoryProjectMember)
		member.projectKey = p.projectKey
		res = append(res, member)
	}
	return res, nil
}

// rolesAdministerProject reports whether any role administers the project.
// Every role is read before the answer is no, because the roles are
// alternatives and any one of them can be the administrative one.
func rolesAdministerProject(roles []string) bool {
	for _, role := range roles {
		if projectAdminRoles[strings.ToLower(strings.TrimSpace(role))] {
			return true
		}
	}
	return false
}

// repositories reports the repositories attached to the project, resolved from
// the repositories that name it. A repository a project administrator attached
// is reached through the project's roles as well as through the instance's
// permission targets.
func (p *mqlArtifactoryProject) repositories() ([]any, error) {
	root, err := getArtifactory(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	repositories := root.GetRepositories()
	if repositories.Error != nil {
		return nil, repositories.Error
	}

	wanted := p.projectKey
	res := []any{}
	for _, it := range repositories.Data {
		repo, ok := it.(*mqlArtifactoryRepository)
		if !ok {
			continue
		}
		attached := repo.GetProjectKey()
		if attached.Error != nil {
			return nil, attached.Error
		}
		// Both sides are project names the administrator chose, so a plain
		// comparison is what is wanted here.
		if named := attached.Data; named == wanted {
			res = append(res, repo)
		}
	}
	return res, nil
}

type mqlArtifactoryProjectMemberInternal struct {
	projectKey string
}

func (m *mqlArtifactoryProjectMember) id() (string, error) {
	return "artifactory.project/" + m.projectKey + "/member/" + m.Name.Data, m.Name.Error
}

// user resolves the member against the instance's user list. A member the list
// does not hold reports null rather than an error, since the membership is
// still real.
func (m *mqlArtifactoryProjectMember) user() (*mqlArtifactoryUser, error) {
	user, err := findUser(m.MqlRuntime, m.Name.Data)
	if err != nil {
		return nil, err
	}
	if user == nil {
		m.User.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return user, nil
}
