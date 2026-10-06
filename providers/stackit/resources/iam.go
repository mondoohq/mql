// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	authorization "github.com/stackitcloud/stackit-sdk-go/services/authorization/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// Authorization API works against any STACKIT resource by type/id. For
// the stackit provider we scope it to the configured project.
const authResourceTypeProject = "project"

// mqlStackitIamInternal memoizes the project role catalog indexed by name.
// stackit.iam.role has no init and no by-name lookup: roles exist only as the
// result of ListRoles. One such call covers the whole project, so it is made
// once and every member binding resolves its role against the shared index
// rather than issuing a lookup of its own.
type mqlStackitIamInternal struct {
	roleIndexLock  sync.Mutex
	roleIndexBuilt bool
	roleIndex      map[string]*mqlStackitIamRole
	roleIndexErr   error
}

// iamResource returns the stackit.iam singleton for this project. Its id is
// constant per project, so CreateResource hands back the one cached instance
// and with it the shared role index.
func iamResource(runtime *plugin.Runtime) (*mqlStackitIam, error) {
	res, err := CreateResource(runtime, "stackit.iam", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	i, ok := res.(*mqlStackitIam)
	if !ok {
		return nil, errors.New("stackit: unexpected type for the stackit.iam resource")
	}
	return i, nil
}

// roleIndexByName builds (once) and returns the project's roles indexed by
// name. The failure is memoized alongside the value so a broken catalog read is
// not retried once per member binding.
func (r *mqlStackitIam) roleIndexByName() (map[string]*mqlStackitIamRole, error) {
	r.roleIndexLock.Lock()
	defer r.roleIndexLock.Unlock()
	if r.roleIndexBuilt {
		return r.roleIndex, r.roleIndexErr
	}
	r.roleIndexBuilt = true

	roles := r.GetRoles()
	if roles.Error != nil {
		r.roleIndexErr = roles.Error
		return nil, r.roleIndexErr
	}
	r.roleIndex = indexIamRolesByName(roles.Data)
	return r.roleIndex, nil
}

// indexIamRolesByName indexes role resources by their name, which is unique
// within a project. Entries that are not roles, and roles without a name, are
// skipped; the first role wins on a duplicate name.
func indexIamRolesByName(items []any) map[string]*mqlStackitIamRole {
	idx := make(map[string]*mqlStackitIamRole, len(items))
	for _, item := range items {
		role, ok := item.(*mqlStackitIamRole)
		if !ok || role == nil {
			continue
		}
		name := role.Name.Data
		if name == "" {
			continue
		}
		if _, seen := idx[name]; seen {
			continue
		}
		idx[name] = role
	}
	return idx
}

func (r *mqlStackitIam) members() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Authorization()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListMembers(bgctx(), authResourceTypeProject, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	members, _ := resp.GetMembersOk()
	out := make([]any, 0, len(members))
	for i := range members {
		m := members[i]
		args := map[string]*llx.RawData{
			"subject": llx.StringData(m.GetSubject()),
			"role":    llx.StringData(m.GetRole()),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.iam.member", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// roleDetails resolves the binding's role name against the project role
// catalog, turning a member binding into the permissions it actually grants.
func (r *mqlStackitIamMember) roleDetails() (*mqlStackitIamRole, error) {
	return iamRoleRef(r.MqlRuntime, r.Role.Data, &r.RoleDetails)
}

func (r *mqlStackitIamMember) id() (string, error) {
	return "stackit.iam.member/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Subject.Data + "/" + r.Role.Data, nil
}

func (r *mqlStackitIam) roles() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Authorization()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListRoles(bgctx(), authResourceTypeProject, c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	roles, _ := resp.GetRolesOk()
	out := make([]any, 0, len(roles))
	for i := range roles {
		res, err := CreateResource(r.MqlRuntime, "stackit.iam.role", iamRoleArgs(&roles[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// iamRoleArgs maps a role onto stackit.iam.role. The permission names stay a
// plain list for the shipped `permissions` field; the descriptions the API
// attaches to each permission land in `permissionDescriptions`, keyed by
// name, so a reviewer can read what a permission string allows.
func iamRoleArgs(role *authorization.Role) map[string]*llx.RawData {
	perms := make([]string, 0, len(role.GetPermissions()))
	for _, p := range role.GetPermissions() {
		perms = append(perms, p.GetName())
	}
	return map[string]*llx.RawData{
		"name":                   llx.StringData(role.GetName()),
		"id":                     llx.StringData(role.GetId()),
		"etag":                   llx.StringData(role.GetEtag()),
		"description":            llx.StringData(role.GetDescription()),
		"permissions":            strSliceData(perms),
		"permissionDescriptions": llx.MapData(permissionDescriptions(role.GetPermissions()), types.String),
	}
}

// permissionDescriptions indexes a role's permissions by name onto the
// description the API supplies for each, dropping unnamed entries.
func permissionDescriptions(perms []authorization.Permission) map[string]any {
	out := make(map[string]any, len(perms))
	for i := range perms {
		if name := perms[i].GetName(); name != "" {
			out[name] = perms[i].GetDescription()
		}
	}
	return out
}

func (r *mqlStackitIamRole) id() (string, error) {
	return "stackit.iam.role/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Name.Data, nil
}

// members lists the bindings that grant this role on the project, read off
// the member list the stackit.iam singleton already holds. Direct project
// bindings only; grants inherited from the folder or organization are not
// part of the project's member list.
func (r *mqlStackitIamRole) members() ([]any, error) {
	i, err := iamResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	members := i.GetMembers()
	if members.Error != nil {
		return nil, members.Error
	}
	return filterIamMembers(members.Data, func(m *mqlStackitIamMember) bool {
		return m.Role.Data == r.Name.Data
	}), nil
}

// serviceAccount resolves the binding's subject when it is one of the
// project's service accounts. Null for a human user or a group, which the
// API does not distinguish by shape, so the service-account list is the
// test.
func (r *mqlStackitIamMember) serviceAccount() (*mqlStackitServiceAccount, error) {
	return serviceAccountRef(r.MqlRuntime, r.Subject.Data, &r.ServiceAccount)
}

// resourceType names the kind of resource whose bindings and roles this
// resource lists. The provider is project-scoped, so it is always "project";
// the field makes that scope explicit rather than implied.
func (r *mqlStackitIam) resourceType() (string, error) {
	return authResourceTypeProject, nil
}

// resourceId is the project the bindings and roles belong to.
func (r *mqlStackitIam) resourceId() (string, error) {
	return conn(r.MqlRuntime).ProjectID(), nil
}

// iamMembershipArgs maps one resolved membership onto stackit.iam.membership.
// `inherited` is true when the binding lives on a container other than the
// scanned project, which is how a folder or organization grant reaches the
// project without appearing in its own member list.
func iamMembershipArgs(m *authorization.UserMembership, projectID string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"subject":      llx.StringData(m.GetSubject()),
		"role":         llx.StringData(m.GetRole()),
		"resourceType": llx.StringData(m.GetResourceType()),
		"resourceId":   llx.StringData(m.GetResourceId()),
		"inherited":    llx.BoolData(membershipInherited(m.GetResourceType(), m.GetResourceId(), projectID)),
	}
}

// membershipInherited reports whether a binding on resourceType/resourceId is
// held somewhere other than the scanned project.
func membershipInherited(resourceType, resourceID, projectID string) bool {
	return !(resourceType == authResourceTypeProject && resourceID == projectID)
}

func (r *mqlStackitIamMembership) id() (string, error) {
	return "stackit.iam.membership/" + r.ResourceType.Data + "/" + r.ResourceId.Data + "/" + r.Subject.Data + "/" + r.Role.Data, nil
}

// filterIamMembers keeps the member bindings a predicate accepts. Entries
// that are not member resources are dropped.
func filterIamMembers(items []any, keep func(*mqlStackitIamMember) bool) []any {
	out := []any{}
	for _, item := range items {
		m, ok := item.(*mqlStackitIamMember)
		if !ok || m == nil {
			continue
		}
		if keep(m) {
			out = append(out, m)
		}
	}
	return out
}

// stackit.kms and stackit.iam namespaces need stable __id values too.
func (r *mqlStackitKms) id() (string, error) {
	return "stackit.kms/" + conn(r.MqlRuntime).ProjectID(), nil
}

func (r *mqlStackitIam) id() (string, error) {
	return "stackit.iam/" + conn(r.MqlRuntime).ProjectID(), nil
}
