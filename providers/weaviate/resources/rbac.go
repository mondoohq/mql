// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/weaviate/weaviate-go-client/v5/weaviate/rbac"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlWeaviateInstance) roles() ([]any, error) {
	conn := weaviateConnection(r.MqlRuntime)
	roles, err := conn.Roles()
	if err != nil {
		// RBAC disabled or the credential cannot read roles: no visible roles.
		if isForbidden(err) {
			return []any{}, nil
		}
		return nil, err
	}

	serverID := conn.ServerID()
	list := make([]any, 0, len(roles))
	for i := range roles {
		// &roles[i], not the address of a loop copy: a Role carries twelve
		// permission slices, and every one of them becomes a retained resource
		// anyway, so copying each before taking its address buys nothing.
		mqlRole, err := newWeaviateRole(r.MqlRuntime, serverID, &roles[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlRole)
	}
	return list, nil
}

// Permission domains, one per typed permission slice a role carries. Reported
// as the permission's domain so a policy can select a whole class of grants
// without matching on action names.
const (
	domainAlias       = "alias"
	domainBackups     = "backups"
	domainCluster     = "cluster"
	domainCollections = "collections"
	domainData        = "data"
	domainGroups      = "groups"
	domainMCP         = "mcp"
	domainNodes       = "nodes"
	domainReplicate   = "replicate"
	domainRoles       = "roles"
	domainTenants     = "tenants"
	domainUsers       = "users"
)

// permEntry is one flattened grant of a role: a single action, the domain it
// belongs to, and the qualifiers that domain carries. A qualifier belonging to
// another domain stays nil and is reported as null, which keeps "this grant
// says nothing about scope" distinct from "this grant is scoped to the empty
// string".
type permEntry struct {
	action     string
	domain     string
	collection string
	scope      *string
	targetRole *string
	group      *string
	groupType  *string
	alias      *string
	shard      *string
	verbosity  *string
}

func strPtr(s string) *string { return &s }

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// flattenPermissions expands a role's per-domain permission slices into one
// entry per action, carrying every qualifier the domain defines. Dropping a
// qualifier makes two different grants look identical: a create_roles grant
// scoped "all" can hand out permissions the role does not itself hold, and one
// scoped "match" cannot.
func flattenPermissions(role *rbac.Role) []permEntry {
	if role == nil {
		return nil
	}
	var out []permEntry
	add := func(actions []string, base permEntry) {
		for _, a := range actions {
			e := base
			e.action = a
			out = append(out, e)
		}
	}
	for _, p := range role.Alias {
		add(p.Actions, permEntry{domain: domainAlias, collection: p.Collection, alias: strPtr(p.Alias)})
	}
	for _, p := range role.Backups {
		add(p.Actions, permEntry{domain: domainBackups, collection: p.Collection})
	}
	for _, p := range role.Cluster {
		add(p.Actions, permEntry{domain: domainCluster})
	}
	for _, p := range role.Collections {
		add(p.Actions, permEntry{domain: domainCollections, collection: p.Collection})
	}
	for _, p := range role.Data {
		add(p.Actions, permEntry{domain: domainData, collection: p.Collection})
	}
	for _, p := range role.Groups {
		add(p.Actions, permEntry{domain: domainGroups, group: strPtr(p.Group), groupType: strPtr(p.GroupType)})
	}
	for _, p := range role.MCP {
		add(p.Actions, permEntry{domain: domainMCP})
	}
	for _, p := range role.Nodes {
		add(p.Actions, permEntry{domain: domainNodes, collection: p.Collection, verbosity: strPtr(p.Verbosity)})
	}
	for _, p := range role.Replicate {
		add(p.Actions, permEntry{domain: domainReplicate, collection: p.Collection, shard: strPtr(p.Shard)})
	}
	for _, p := range role.Roles {
		add(p.Actions, permEntry{domain: domainRoles, targetRole: strPtr(p.Role), scope: strPtr(p.Scope)})
	}
	for _, p := range role.Tenants {
		add(p.Actions, permEntry{domain: domainTenants})
	}
	for _, p := range role.Users {
		add(p.Actions, permEntry{domain: domainUsers})
	}
	return out
}

// permEntryKey builds a permission's identity from every dimension along which
// it can repeat. The action alone is not enough: one role can hold create_roles
// twice, once scoped "all" over one target role and once scoped "match" over
// another, and a key carrying only the action reports the first grant twice.
func permEntryKey(p permEntry) string {
	return strings.Join([]string{
		p.domain, p.action, p.collection, derefStr(p.scope), derefStr(p.targetRole),
		derefStr(p.group), derefStr(p.groupType), derefStr(p.alias),
		derefStr(p.shard), derefStr(p.verbosity),
	}, "/")
}

func (r *mqlWeaviateRole) permissions() ([]any, error) {
	if r.cacheRole == nil {
		return []any{}, nil
	}
	// A repeated key still gets a counter suffix, so two entries the server
	// reports identically land on distinct resources instead of collapsing
	// into one through the resource cache.
	seen := map[string]int{}
	list := []any{}
	for _, p := range flattenPermissions(r.cacheRole) {
		key := permEntryKey(p)
		suffix := key
		if n := seen[key]; n > 0 {
			suffix = key + "#" + intToStr(int64(n))
		}
		seen[key]++
		res, err := CreateResource(r.MqlRuntime, "weaviate.role.permission", map[string]*llx.RawData{
			"__id":       llx.StringData(r.__id + "/perm/" + suffix),
			"action":     llx.StringData(p.action),
			"domain":     llx.StringData(p.domain),
			"collection": llx.StringData(p.collection),
			"scope":      llx.StringDataPtr(p.scope),
			"targetRole": llx.StringDataPtr(p.targetRole),
			"group":      llx.StringDataPtr(p.group),
			"groupType":  llx.StringDataPtr(p.groupType),
			"alias":      llx.StringDataPtr(p.alias),
			"shard":      llx.StringDataPtr(p.shard),
			"verbosity":  llx.StringDataPtr(p.verbosity),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlWeaviateRole) assignedUsers() ([]any, error) {
	conn := weaviateConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	assignments, err := client.Roles().UserAssignmentGetter().WithRole(r.Name.Data).Do(weaviateContext())
	if err != nil {
		if isForbidden(err) {
			return []any{}, nil
		}
		return nil, err
	}
	// A user can be assigned under more than one user type (db, oidc), which
	// returns it once per type; report each distinct user id once.
	seen := map[string]struct{}{}
	list := []any{}
	for _, a := range assignments {
		if _, dup := seen[a.UserID]; dup {
			continue
		}
		seen[a.UserID] = struct{}{}
		list = append(list, a.UserID)
	}
	return list, nil
}

// assignedGroups reports the groups holding this role. A role granted to a
// group is held by every member of it, and none of those members appears in
// assignedUsers, so a role can look unused while an entire directory group
// holds it.
func (r *mqlWeaviateRole) assignedGroups() ([]any, error) {
	conn := weaviateConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	assignments, err := client.Roles().GroupAssignmentGetter().WithRole(r.Name.Data).Do(weaviateContext())
	if err != nil {
		if isForbidden(err) || isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	serverID := conn.ServerID()
	// One group belongs in the list once. A repeated assignment resolves to the
	// same resource, which would otherwise appear twice under one identity.
	seen := map[string]struct{}{}
	list := []any{}
	for _, a := range assignments {
		key := string(a.GroupType) + "/" + a.Group
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		mqlGroup, err := newWeaviateGroup(r.MqlRuntime, serverID, a.Group, string(a.GroupType))
		if err != nil {
			return nil, err
		}
		list = append(list, mqlGroup)
	}
	return list, nil
}

func (r *mqlWeaviateInstance) groups() ([]any, error) {
	conn := weaviateConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	names, err := client.Groups().OIDC().GetKnownGroups().Do(weaviateContext())
	if err != nil {
		// No OpenID Connect configuration, or the credential cannot read group
		// assignments: no group holds a role here as far as this query can see.
		if isForbidden(err) || isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	serverID := conn.ServerID()
	list := []any{}
	for _, name := range names {
		mqlGroup, err := newWeaviateGroup(r.MqlRuntime, serverID, name, groupTypeOIDC)
		if err != nil {
			return nil, err
		}
		list = append(list, mqlGroup)
	}
	return list, nil
}

func (r *mqlWeaviateGroup) roles() ([]any, error) {
	// Roles are read through an endpoint per kind of group, and OpenID Connect
	// is the only kind the client can ask about.
	if r.GroupType.Data != groupTypeOIDC {
		return []any{}, nil
	}
	conn := weaviateConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	// WithIncludeFullRoles carries each role's permissions back with it, so the
	// permissions of a role held only by a group resolve without another call.
	roles, err := client.Groups().OIDC().RolesGetter().
		WithGroupID(r.GroupId.Data).
		WithIncludeFullRoles(true).
		Do(weaviateContext())
	if err != nil {
		if isForbidden(err) || isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	serverID := conn.ServerID()
	list := []any{}
	for _, role := range roles {
		if role == nil {
			continue
		}
		mqlRole, err := newWeaviateRole(r.MqlRuntime, serverID, role)
		if err != nil {
			return nil, err
		}
		list = append(list, mqlRole)
	}
	return list, nil
}

func (r *mqlWeaviateInstance) users() ([]any, error) {
	conn := weaviateConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	// WithLastUsedTime asks for ?includeLastUsedTime=true; without it the
	// server omits the field and every key looks as though it has never been
	// used.
	infos, err := client.Users().DB().Lister().WithLastUsedTime().Do(weaviateContext())
	if err != nil {
		// User management disabled or the credential cannot read users.
		if isForbidden(err) {
			return []any{}, nil
		}
		return nil, err
	}

	serverID := conn.ServerID()
	list := []any{}
	for i := range infos {
		info := infos[i]
		res, err := CreateResource(r.MqlRuntime, "weaviate.user", map[string]*llx.RawData{
			"__id":       llx.StringData(userResourceID(serverID, info.UserID)),
			"userId":     llx.StringData(info.UserID),
			"userType":   llx.StringData(string(info.UserType)),
			"active":     llx.BoolData(info.Active),
			"createdAt":  llx.TimeDataPtr(nonZeroTime(info.CreatedAt)),
			"lastUsedAt": llx.TimeDataPtr(nonZeroTime(info.LastUsedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlUser := res.(*mqlWeaviateUser)
		mqlUser.cacheRoles = info.Roles
		list = append(list, mqlUser)
	}
	return list, nil
}

// resolveRole returns the server's own definition of a role named by something
// else. The user listing names a user's roles and nothing more, leaving every
// permission slice empty, so a role reached through a user would otherwise
// report no permissions at all. The server's role list is read once per
// connection and indexed by name, so this costs neither a request nor a scan.
// When the list cannot be read the reference is returned unchanged, which keeps
// the role's name available to a credential that may query users but not roles.
func resolveRole(runtime *plugin.Runtime, ref *rbac.Role) *rbac.Role {
	if hasPermissions(ref) {
		return ref
	}
	if full, ok := weaviateConnection(runtime).RoleByName(ref.Name); ok {
		return full
	}
	return ref
}

func (r *mqlWeaviateUser) roles() ([]any, error) {
	serverID := weaviateConnection(r.MqlRuntime).ServerID()
	list := []any{}
	for _, role := range r.cacheRoles {
		if role == nil {
			continue
		}
		mqlRole, err := newWeaviateRole(r.MqlRuntime, serverID, resolveRole(r.MqlRuntime, role))
		if err != nil {
			return nil, err
		}
		list = append(list, mqlRole)
	}
	return list, nil
}

var _ = types.String
