// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	authorization "github.com/stackitcloud/stackit-sdk-go/services/authorization/v2api"
	resourcemanager "github.com/stackitcloud/stackit-sdk-go/services/resourcemanager/v0api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestIamRoleArgs pins the role mapping: the shipped permissions list keeps
// only names, the descriptions land in permissionDescriptions keyed by name,
// and the optional id and etag read empty rather than failing when the
// response omits them.
func TestIamRoleArgs(t *testing.T) {
	var role authorization.Role
	if err := json.Unmarshal([]byte(`{
		"name": "project.auditor",
		"description": "Read-only access",
		"id": "role-1",
		"etag": "W/\"7\"",
		"permissions": [
			{"name": "project.read", "description": "Read project metadata"},
			{"name": "iam.read", "description": "Read IAM bindings"},
			{"name": "", "description": "orphan"}
		]
	}`), &role); err != nil {
		t.Fatalf("decoding role: %v", err)
	}
	args := iamRoleArgs(&role)
	if got := args["id"].Value; got != "role-1" {
		t.Fatalf("id = %v", got)
	}
	if got := args["etag"].Value; got != `W/"7"` {
		t.Fatalf("etag = %v", got)
	}
	perms, _ := args["permissions"].Value.([]any)
	if !reflect.DeepEqual(perms, []any{"project.read", "iam.read", ""}) {
		t.Fatalf("permissions = %v", perms)
	}
	descs, _ := args["permissionDescriptions"].Value.(map[string]any)
	want := map[string]any{"project.read": "Read project metadata", "iam.read": "Read IAM bindings"}
	if !reflect.DeepEqual(descs, want) {
		t.Fatalf("permissionDescriptions = %v, want %v (unnamed entry dropped)", descs, want)
	}

	var bare authorization.Role
	if err := json.Unmarshal([]byte(`{"name": "custom", "description": "", "permissions": []}`), &bare); err != nil {
		t.Fatalf("decoding bare role: %v", err)
	}
	bareArgs := iamRoleArgs(&bare)
	if bareArgs["id"].Value != "" || bareArgs["etag"].Value != "" {
		t.Fatalf("absent id/etag = %v/%v, want empty", bareArgs["id"].Value, bareArgs["etag"].Value)
	}
	if d, _ := bareArgs["permissionDescriptions"].Value.(map[string]any); len(d) != 0 {
		t.Fatalf("empty permissions gave descriptions %v", d)
	}
}

// TestFilterIamMembers pins the reverse edges: role.members and
// serviceAccount.roleBindings are both filters over the one member list, and
// anything in that list that is not a member resource is dropped rather than
// crashing the filter.
func TestFilterIamMembers(t *testing.T) {
	mk := func(subject, role string) *mqlStackitIamMember {
		m := &mqlStackitIamMember{}
		m.Subject.Data = subject
		m.Role.Data = role
		return m
	}
	items := []any{
		mk("sa-a@sa.stackit.cloud", "owner"),
		mk("alice@example.test", "owner"),
		mk("sa-a@sa.stackit.cloud", "reader"),
		"not a member",
		nil,
	}

	owners := filterIamMembers(items, func(m *mqlStackitIamMember) bool { return m.Role.Data == "owner" })
	if len(owners) != 2 {
		t.Fatalf("owners = %d, want 2", len(owners))
	}
	saBindings := filterIamMembers(items, func(m *mqlStackitIamMember) bool { return m.Subject.Data == "sa-a@sa.stackit.cloud" })
	if len(saBindings) != 2 {
		t.Fatalf("service account bindings = %d, want 2", len(saBindings))
	}
	if none := filterIamMembers(items, func(m *mqlStackitIamMember) bool { return m.Role.Data == "editor" }); len(none) != 0 {
		t.Fatalf("editor bindings = %v, want empty", none)
	}
	if got := filterIamMembers(nil, func(*mqlStackitIamMember) bool { return true }); len(got) != 0 {
		t.Fatalf("nil list = %v, want empty", got)
	}
}

// decodeProjectParents decodes a GetProject response shaped like the API's
// and returns its ancestry chain, so the lookups are tested against the same
// JSON path the provider takes.
func decodeProjectParents(t *testing.T, payload string) []resourcemanager.ParentListInner {
	t.Helper()
	var resp resourcemanager.GetProjectResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		t.Fatalf("decoding project: %v", err)
	}
	return resp.GetParents()
}

const projectInNestedFolders = `{
	"projectId": "11111111-1111-1111-1111-111111111111",
	"containerId": "my-project-abc123",
	"name": "my-project",
	"lifecycleState": "ACTIVE",
	"creationTime": "2026-01-02T03:04:05Z",
	"updateTime": "2026-02-03T04:05:06Z",
	"parent": {"id": "22222222-2222-2222-2222-222222222222", "containerId": "team-folder-def456", "type": "FOLDER"},
	"parents": [
		{"id": "33333333-3333-3333-3333-333333333333", "containerId": "acme-org-ghi789", "name": "acme", "type": "ORGANIZATION"},
		{"id": "44444444-4444-4444-4444-444444444444", "containerId": "dept-folder-jkl012", "name": "dept", "type": "FOLDER", "containerParentId": "acme-org-ghi789"},
		{"id": "22222222-2222-2222-2222-222222222222", "containerId": "team-folder-def456", "name": "team", "type": "FOLDER", "containerParentId": "dept-folder-jkl012"}
	]
}`

// TestProjectOrganization pins the organization lookup: found by type, not
// by position (the fixture lists it first), and a chain without one reads
// nil rather than picking any entry.
func TestProjectOrganization(t *testing.T) {
	parents := decodeProjectParents(t, projectInNestedFolders)
	org := projectOrganization(parents)
	if org == nil || org.GetContainerId() != "acme-org-ghi789" || org.GetId() != "33333333-3333-3333-3333-333333333333" || org.GetName() != "acme" {
		t.Fatalf("organization = %+v, want acme-org-ghi789", org)
	}
	if got := projectOrganization(parents[1:]); got != nil {
		t.Fatalf("folder-only chain organization = %+v, want nil", got)
	}
	if got := projectOrganization(nil); got != nil {
		t.Fatalf("empty chain organization = %+v, want nil", got)
	}
}

// TestOrderedFolders pins the nearest-first ordering: the walk starts at the
// project's direct parent and follows containerParentId upward, regardless of
// the order the API returned the entries in, and the organization is never a
// folder.
func TestOrderedFolders(t *testing.T) {
	parents := decodeProjectParents(t, projectInNestedFolders)
	got := orderedFolders(parents, "team-folder-def456")
	names := make([]string, 0, len(got))
	for i := range got {
		names = append(names, got[i].GetContainerId())
	}
	if !reflect.DeepEqual(names, []string{"team-folder-def456", "dept-folder-jkl012"}) {
		t.Fatalf("folders = %v, want nearest first [team-folder-def456 dept-folder-jkl012]", names)
	}

	t.Run("project directly under the organization has no folders", func(t *testing.T) {
		if got := orderedFolders(parents[:1], "acme-org-ghi789"); len(got) != 0 {
			t.Fatalf("folders = %d, want 0", len(got))
		}
	})
	t.Run("a folder the walk cannot reach is still listed", func(t *testing.T) {
		// Parent points at a folder missing from the chain; the remaining
		// folders come out in API order rather than being dropped.
		got := orderedFolders(parents, "missing-folder")
		if len(got) != 2 || got[0].GetContainerId() != "dept-folder-jkl012" || got[1].GetContainerId() != "team-folder-def456" {
			t.Fatalf("unreachable walk = %v", got)
		}
	})
	t.Run("a cycle terminates", func(t *testing.T) {
		cyclic := decodeProjectParents(t, `{"projectId":"p","containerId":"p","name":"p","lifecycleState":"ACTIVE","creationTime":"2026-01-02T03:04:05Z","updateTime":"2026-01-02T03:04:05Z","parent":{"id":"a","containerId":"a","type":"FOLDER"},"parents":[
			{"id":"a","containerId":"a","name":"a","type":"FOLDER","containerParentId":"b"},
			{"id":"b","containerId":"b","name":"b","type":"FOLDER","containerParentId":"a"}
		]}`)
		if got := orderedFolders(cyclic, "a"); len(got) != 2 {
			t.Fatalf("cyclic chain = %d folders, want 2 (each once)", len(got))
		}
	})
}

const (
	fakeOrgID    = "7c6b5a49-3827-4165-9483-a2b1c0d9e8f7"
	fakeFolderID = "1e2d3c4b-5a69-4788-97a6-b5c4d3e2f1a0"
	fakeOwner    = "owner@example.com"
)

func membersBody(resourceType, resourceID string, members ...string) string {
	body := `{"resourceType":"` + resourceType + `","resourceId":"` + resourceID + `","members":[`
	for i := 0; i+1 < len(members); i += 2 {
		if i > 0 {
			body += ","
		}
		body += `{"subject":"` + members[i] + `","role":"` + members[i+1] + `"}`
	}
	return body + "]}"
}

func newOrganization(t *testing.T, runtime *plugin.Runtime) *mqlStackitOrganization {
	t.Helper()
	res, err := CreateResource(runtime, "stackit.organization", map[string]*llx.RawData{
		"id":          llx.StringData(fakeOrgID),
		"containerId": llx.StringData("organization-example"),
		"name":        llx.StringData("Example"),
	})
	require.NoError(t, err)
	return res.(*mqlStackitOrganization)
}

func TestIamMemberID(t *testing.T) {
	// Synthetic: one subject and role bound at two levels of the hierarchy.
	org := iamMemberID(authResourceTypeOrganization, fakeOrgID, fakeOwner, "owner")
	project := iamMemberID(authResourceTypeProject, fakeProjectID, fakeOwner, "owner")
	assert.NotEqual(t, org, project, "the container must be part of the member cache key")
	assert.NotEqual(t,
		iamMemberID(authResourceTypeOrganization, fakeOrgID, fakeOwner, "owner"),
		iamMemberID(authResourceTypeFolder, fakeOrgID, fakeOwner, "owner"),
		"the container type must be part of the key, not only its id")
}

func TestOrganizationAndFolderMembers(t *testing.T) {
	orgPath := "GET /v2/organization/" + fakeOrgID + "/members"
	folderPath := "GET /v2/folder/" + fakeFolderID + "/members"
	projectPath := "GET /v2/project/" + fakeProjectID + "/members"

	// Synthetic: the same owner bound on the organization and on the project,
	// shaped after the SDK's ListMembersResponse; no target showed this.
	t.Run("organization and project bindings of one subject stay distinct", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{
			orgPath: json200(membersBody("organization", fakeOrgID,
				fakeOwner, "owner", "auditor@example.com", "reader")),
			projectPath: json200(membersBody("project", fakeProjectID, fakeOwner, "owner")),
		})

		orgMembers := newOrganization(t, runtime).GetMembers()
		require.NoError(t, orgMembers.Error)
		require.Len(t, orgMembers.Data, 2)
		first := orgMembers.Data[0].(*mqlStackitIamMember)
		assert.Equal(t, fakeOwner, first.Subject.Data)
		assert.Equal(t, "owner", first.Role.Data)
		assert.Equal(t, "organization", first.ResourceType.Data)
		assert.Equal(t, fakeOrgID, first.ResourceId.Data)

		i, err := iamResource(runtime)
		require.NoError(t, err)
		projectMembers := i.GetMembers()
		require.NoError(t, projectMembers.Error)
		require.Len(t, projectMembers.Data, 1)
		pm := projectMembers.Data[0].(*mqlStackitIamMember)
		assert.NotSame(t, first, pm, "a project binding must not come back as the cached organization binding")
		assert.Equal(t, "project", pm.ResourceType.Data)
		assert.Equal(t, fakeProjectID, pm.ResourceId.Data)
	})

	// Synthetic: roleDetails reads the project catalog, which says nothing
	// about a role granted on the organization.
	t.Run("organization binding has null roleDetails", func(t *testing.T) {
		runtime, api := fakeRuntime(t, map[string]fakeAnswer{
			orgPath: json200(membersBody("organization", fakeOrgID, fakeOwner, "owner")),
		})
		members := newOrganization(t, runtime).GetMembers()
		require.NoError(t, members.Error)
		require.Len(t, members.Data, 1)
		rd := members.Data[0].(*mqlStackitIamMember).GetRoleDetails()
		require.NoError(t, rd.Error)
		assert.True(t, rd.IsNull())
		assert.Equal(t, 0, api.count("GET /v2/project/"+fakeProjectID+"/roles"), "no project catalog read for an organization binding")
	})

	// Synthetic: a folder built from the project's ancestry chain.
	t.Run("folder members are read by folder id", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{
			folderPath: json200(membersBody("folder", fakeFolderID, "dev@example.com", "editor")),
		})
		res, err := CreateResource(runtime, "stackit.folder", map[string]*llx.RawData{
			"id":          llx.StringData(fakeFolderID),
			"containerId": llx.StringData("folder-example"),
			"name":        llx.StringData("Dev"),
		})
		require.NoError(t, err)
		members := res.(*mqlStackitFolder).GetMembers()
		require.NoError(t, members.Error)
		require.Len(t, members.Data, 1)
		m := members.Data[0].(*mqlStackitIamMember)
		assert.Equal(t, "editor", m.Role.Data)
		assert.Equal(t, "folder", m.ResourceType.Data)
	})

	// Synthetic: a project-scoped credential without organization read access.
	t.Run("a refusal is a Forbidden error, not an empty list", func(t *testing.T) {
		runtime, _ := fakeRuntime(t, map[string]fakeAnswer{orgPath: jsonStatus(http.StatusForbidden)})
		members := newOrganization(t, runtime).GetMembers()
		require.Error(t, members.Error)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(members.Error))
	})
}
