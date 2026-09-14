// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/weaviate/weaviate-go-client/v5/weaviate/fault"
	"github.com/weaviate/weaviate-go-client/v5/weaviate/rbac"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/weaviate/connection"
	"go.mondoo.com/mql/types"
)

func weaviateConnection(runtime *plugin.Runtime) *connection.WeaviateConnection {
	return runtime.Connection.(*connection.WeaviateConnection)
}

func weaviateContext() context.Context {
	return context.Background()
}

func intToStr(i int64) string {
	return strconv.FormatInt(i, 10)
}

// isForbidden reports whether an error is a Weaviate authentication or
// authorization failure (HTTP 401 or 403). Only these should be treated as
// "not visible"; every other error must propagate.
func isForbidden(err error) bool {
	var ce *fault.WeaviateClientError
	if errors.As(err, &ce) {
		return ce.StatusCode == 401 || ce.StatusCode == 403
	}
	return false
}

// isNotFound reports whether an error is a Weaviate HTTP 404. The group
// endpoints answer 404 on a server with no OpenID Connect configuration, where
// the honest answer is that no group holds a role rather than an error.
func isNotFound(err error) bool {
	var ce *fault.WeaviateClientError
	if errors.As(err, &ce) {
		return ce.StatusCode == 404
	}
	return false
}

// nonZeroTime returns a pointer to t, or nil when the server reported no time
// at all. The API sends an absent timestamp as the zero time, so without this
// a key that has never been used reports January of year 1 instead of null.
func nonZeroTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// builtinRoles is the set of Weaviate-provided, predefined role names. These
// ship with the server and are not created by an administrator.
var builtinRoles = map[string]struct{}{
	"root":      {},
	"admin":     {},
	"viewer":    {},
	"read-only": {},
}

// moduleNames returns the sorted keys of a Weaviate module-config object, which
// the client decodes as a JSON object (map[string]any). Non-object values yield
// an empty list.
func moduleNames(v any) []any {
	m, ok := v.(map[string]any)
	if !ok {
		return []any{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, k)
	}
	return out
}

// --- id builders ------------------------------------------------------------

func collectionResourceID(serverID, name string) string {
	return serverID + "/collection/" + name
}

func roleResourceID(serverID, name string) string {
	return serverID + "/role/" + name
}

func userResourceID(serverID, userID string) string {
	return serverID + "/user/" + userID
}

func nodeResourceID(serverID, name string) string {
	return serverID + "/node/" + name
}

// groupResourceID keys a group by both dimensions it can repeat along. One
// name can belong to two kinds of group, and a key built from the name alone
// would report the second as the first.
func groupResourceID(serverID, groupType, groupID string) string {
	return serverID + "/group/" + groupType + "/" + groupID
}

// --- shared role builder ----------------------------------------------------

// hasPermissions reports whether a role carries any permission at all. The user
// listing builds its roles from names alone, leaving every permission slice
// empty, so this separates a role read in full from a bare reference to one.
func hasPermissions(role *rbac.Role) bool {
	if role == nil {
		return false
	}
	return len(role.Alias) > 0 || len(role.Backups) > 0 || len(role.Cluster) > 0 ||
		len(role.Collections) > 0 || len(role.Data) > 0 || len(role.Groups) > 0 ||
		len(role.MCP) > 0 || len(role.Nodes) > 0 || len(role.Replicate) > 0 ||
		len(role.Roles) > 0 || len(role.Tenants) > 0 || len(role.Users) > 0
}

// newWeaviateRole creates a role resource, caching the source role so its
// permissions resolve without a second fetch. Assigned users are still fetched
// lazily by the role's own accessor.
//
// A role name identifies the role, so every reference to it resolves to one
// resource and CreateResource hands back the instance built the first time.
// That makes the cached source role shared state: a bare reference reaching it
// second must not erase the permissions a full read put there, and a full read
// reaching it second must replace the bare reference.
func newWeaviateRole(runtime *plugin.Runtime, serverID string, role *rbac.Role) (*mqlWeaviateRole, error) {
	_, isBuiltin := builtinRoles[role.Name]
	res, err := CreateResource(runtime, "weaviate.role", map[string]*llx.RawData{
		"__id":      llx.StringData(roleResourceID(serverID, role.Name)),
		"name":      llx.StringData(role.Name),
		"isBuiltin": llx.BoolData(isBuiltin),
	})
	if err != nil {
		return nil, err
	}
	r := res.(*mqlWeaviateRole)
	if hasPermissions(r.cacheRole) && !hasPermissions(role) {
		return r, nil
	}
	r.cacheRole = role
	return r, nil
}

// --- shared group builder ---------------------------------------------------

// groupTypeOIDC is the only kind of group Weaviate assigns roles to today. The
// roles of a group are read through a per-kind endpoint, so the kind has to
// travel with the group.
const groupTypeOIDC = "oidc"

func newWeaviateGroup(runtime *plugin.Runtime, serverID, groupID, groupType string) (*mqlWeaviateGroup, error) {
	res, err := CreateResource(runtime, "weaviate.group", map[string]*llx.RawData{
		"__id":      llx.StringData(groupResourceID(serverID, groupType, groupID)),
		"groupId":   llx.StringData(groupID),
		"groupType": llx.StringData(groupType),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlWeaviateGroup), nil
}

var _ = types.String
