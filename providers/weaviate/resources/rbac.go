// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/weaviate/connection"
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
	for _, role := range roles {
		mqlRole, err := newWeaviateRole(r.MqlRuntime, serverID, role)
		if err != nil {
			return nil, err
		}
		list = append(list, mqlRole)
	}
	return list, nil
}

// Permission domains the server defines. Reported as the permission's domain
// so a policy can select a whole class of grants without matching on action
// names.
const (
	domainAlias       = "alias"
	domainBackups     = "backups"
	domainCluster     = "cluster"
	domainCollections = "collections"
	domainData        = "data"
	domainGroups      = "groups"
	domainMCP         = "mcp"
	domainNamespaces  = "namespaces"
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
	tenant     *string
	object     *string
	targetUser *string
	namespace  *string
}

//go:fix inline
func strPtr(s string) *string { return new(s) }

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// permissionDomain names the domain a grant belongs to. The server puts a
// grant's qualifiers under a key naming its domain, so that key decides first.
// A key this build has no model for still names the domain, so a grant in a
// domain added to the server later is reported rather than dropped. The cluster
// and mcp domains carry no qualifiers at all, and an older server may omit the
// tenants and users qualifiers, so a grant without any falls back to the last
// word of its action ("read_cluster", "assign_and_revoke_users").
func permissionDomain(p *connection.Permission) string {
	switch {
	case p.Aliases != nil:
		return domainAlias
	case p.Backups != nil:
		return domainBackups
	case p.Collections != nil:
		return domainCollections
	case p.Data != nil:
		return domainData
	case p.Groups != nil:
		return domainGroups
	case p.Namespaces != nil:
		return domainNamespaces
	case p.Nodes != nil:
		return domainNodes
	case p.Replicate != nil:
		return domainReplicate
	case p.Roles != nil:
		return domainRoles
	case p.Tenants != nil:
		return domainTenants
	case p.Users != nil:
		return domainUsers
	}
	if len(p.QualifierKeys) > 0 {
		return p.QualifierKeys[0]
	}
	action := p.ActionName()
	domain := action[strings.LastIndex(action, "_")+1:]
	if domain == "aliases" {
		return domainAlias
	}
	return domain
}

// flattenPermissions turns a role's grants into one entry per action, carrying
// every qualifier the domain defines. Dropping a qualifier makes two different
// grants look identical: a create_roles grant scoped "all" can hand out
// permissions the role does not itself hold, and one scoped "match" cannot; a
// read_data grant on one tenant reaches far less than one on every tenant.
//
// A qualifier is reported, possibly as an empty string, exactly when the server
// sent the object holding it, and is null otherwise.
func flattenPermissions(role *connection.Role) []permEntry {
	if role == nil {
		return nil
	}
	var out []permEntry
	for _, p := range role.Permissions {
		if p == nil {
			continue
		}
		e := permEntry{action: p.ActionName(), domain: permissionDomain(p)}
		switch e.domain {
		case domainAlias:
			if p.Aliases != nil {
				e.collection = derefStr(p.Aliases.Collection)
				e.alias = new(derefStr(p.Aliases.Alias))
			}
		case domainBackups:
			if p.Backups != nil {
				e.collection = derefStr(p.Backups.Collection)
			}
		case domainCollections:
			if p.Collections != nil {
				e.collection = derefStr(p.Collections.Collection)
			}
		case domainData:
			if p.Data != nil {
				e.collection = derefStr(p.Data.Collection)
				e.tenant = new(derefStr(p.Data.Tenant))
				e.object = new(derefStr(p.Data.Object))
			}
		case domainGroups:
			if p.Groups != nil {
				e.group = new(derefStr(p.Groups.Group))
				e.groupType = new(string(p.Groups.GroupType))
			}
		case domainNamespaces:
			if p.Namespaces != nil {
				e.namespace = new(derefStr(p.Namespaces.Namespace))
			}
		case domainNodes:
			if p.Nodes != nil {
				e.collection = derefStr(p.Nodes.Collection)
				e.verbosity = new(derefStr(p.Nodes.Verbosity))
			}
		case domainReplicate:
			if p.Replicate != nil {
				e.collection = derefStr(p.Replicate.Collection)
				e.shard = new(derefStr(p.Replicate.Shard))
			}
		case domainRoles:
			if p.Roles != nil {
				e.targetRole = new(derefStr(p.Roles.Role))
				e.scope = new(derefStr(p.Roles.Scope))
			}
		case domainTenants:
			if p.Tenants != nil {
				e.collection = derefStr(p.Tenants.Collection)
				e.tenant = new(derefStr(p.Tenants.Tenant))
			}
		case domainUsers:
			if p.Users != nil {
				e.targetUser = new(derefStr(p.Users.Users))
			}
		}
		out = append(out, e)
	}
	return out
}

// permEntryKey builds a permission's identity from every dimension along which
// it can repeat. The action alone is not enough: one role can hold create_roles
// twice, once scoped "all" over one target role and once scoped "match" over
// another, and a key carrying only the action reports the first grant twice.
// Likewise read_data on two tenants of one collection is two grants.
func permEntryKey(p permEntry) string {
	return strings.Join([]string{
		p.domain, p.action, p.collection, derefStr(p.scope), derefStr(p.targetRole),
		derefStr(p.group), derefStr(p.groupType), derefStr(p.alias),
		derefStr(p.shard), derefStr(p.verbosity), derefStr(p.tenant),
		derefStr(p.object), derefStr(p.targetUser), derefStr(p.namespace),
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
			"tenant":     llx.StringDataPtr(p.tenant),
			"object":     llx.StringDataPtr(p.object),
			"targetUser": llx.StringDataPtr(p.targetUser),
			"namespace":  llx.StringDataPtr(p.namespace),
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
	// The roles come back with their permissions, so the permissions of a role
	// held only by a group resolve without another call. They are read from the
	// server's own response for the same reason as the instance's role list.
	roles, err := conn.GroupRoles(weaviateContext(), r.GroupType.Data, r.GroupId.Data)
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
		names := make([]string, 0, len(info.Roles))
		for _, role := range info.Roles {
			if role != nil {
				names = append(names, role.Name)
			}
		}
		mqlUser.cacheRoleNames = names
		list = append(list, mqlUser)
	}
	return list, nil
}

// resolveRole returns the server's own definition of a role named by something
// else. The user listing names a user's roles and nothing more, so a role
// reached through a user would otherwise report no permissions at all. The
// server's role list is read once per connection and indexed by name, so this
// costs neither a request nor a scan. When the list cannot be read a bare
// reference carrying only the name comes back, which keeps the role's name
// available to a credential that may query users but not roles.
func resolveRole(runtime *plugin.Runtime, name string) *connection.Role {
	if full, ok := weaviateConnection(runtime).RoleByName(name); ok {
		return full
	}
	return &connection.Role{Name: name}
}

func (r *mqlWeaviateUser) roles() ([]any, error) {
	serverID := weaviateConnection(r.MqlRuntime).ServerID()
	list := []any{}
	for _, name := range r.cacheRoleNames {
		mqlRole, err := newWeaviateRole(r.MqlRuntime, serverID, resolveRole(r.MqlRuntime, name))
		if err != nil {
			return nil, err
		}
		list = append(list, mqlRole)
	}
	return list, nil
}

var _ = types.String
