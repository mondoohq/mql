// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/url"
	"strings"
)

// GitRepositoriesNamespace is the id of the security namespace that holds the
// Git repository permissions. Azure DevOps uses the same id in every
// organization.
const GitRepositoriesNamespace = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

// Permission bits of the Git repositories namespace that the provider reads.
const (
	GitPermissionForcePush               int64 = 8
	GitPermissionCreateBranch            int64 = 16
	GitPermissionPolicyExempt            int64 = 128
	GitPermissionPullRequestBypassPolicy int64 = 32768
)

// serviceIdentityPrefix starts the descriptor of a build or release service
// identity.
const serviceIdentityPrefix = "microsoft.teamfoundation.serviceidentity;"

// AccessControlList is one entry of GET /_apis/accesscontrollists/{namespace}.
type AccessControlList struct {
	// InheritPermissions is false when the token ignores the lists of the
	// tokens above it.
	InheritPermissions bool `json:"inheritPermissions"`
	// Token is the secured object, for example repoV2/{projectId}/{repoId}.
	Token string `json:"token"`
	// Aces holds one entry per identity, keyed by its descriptor.
	Aces map[string]AccessControlEntry `json:"acesDictionary"`
}

// AccessControlEntry is the permissions one identity is allowed and denied on
// a token, as bit masks.
type AccessControlEntry struct {
	Descriptor string `json:"descriptor"`
	Allow      int64  `json:"allow"`
	Deny       int64  `json:"deny"`
}

// Identity is one entry of GET vssps /_apis/identities.
type Identity struct {
	ID string `json:"id"`
	// Descriptor is the identity descriptor that access control entries use.
	Descriptor string `json:"descriptor"`
	// ProviderDisplayName is [project]\group for a project group.
	ProviderDisplayName string `json:"providerDisplayName"`
}

// ProjectSecurityToken is the Git repositories token of every repository of a
// project.
func ProjectSecurityToken(projectID string) string {
	return "repoV2/" + strings.ToLower(projectID)
}

// RepositorySecurityToken is the Git repositories token of one repository.
func RepositorySecurityToken(projectID, repoID string) string {
	return ProjectSecurityToken(projectID) + "/" + strings.ToLower(repoID)
}

// IsServiceIdentity reports a build or release service identity.
func IsServiceIdentity(descriptor string) bool {
	return strings.HasPrefix(strings.ToLower(descriptor), serviceIdentityPrefix)
}

// AccessControlList reads the list of one token of the Git repositories
// namespace, without the tokens below it. A token with no list of its own
// gives nil and no error. Each token is read once per client.
func (c *Client) AccessControlList(ctx context.Context, token string) (*AccessControlList, error) {
	return c.acls.get(token, func() (*AccessControlList, error) {
		lists, err := listAll[AccessControlList](ctx, c, request{
			segments: []string{"_apis", "accesscontrollists", GitRepositoriesNamespace},
			query:    url.Values{"token": {token}, "recurse": {"false"}},
		}, 0)
		if err != nil {
			return nil, err
		}
		for i := range lists {
			if strings.EqualFold(lists[i].Token, token) {
				return &lists[i], nil
			}
		}
		return nil, nil
	})
}

// EffectiveAllow folds the lists of a chain of tokens, outermost first, into
// the permission bits each identity is allowed on the innermost token. The
// keys are lower-cased descriptors. A closer list decides a bit before a
// farther one, a deny beats an allow within one list, a nil list inherits
// everything, and a list that does not inherit ends the walk.
//
// It folds only the entries of the identities themselves. Permissions an
// identity gets through membership of a group stay with the group.
func EffectiveAllow(chain []*AccessControlList) map[string]int64 {
	allow := map[string]int64{}
	decided := map[string]int64{}
	for i := len(chain) - 1; i >= 0; i-- {
		acl := chain[i]
		if acl == nil {
			continue
		}
		for key, ace := range acl.Aces {
			d := ace.Descriptor
			if d == "" {
				d = key
			}
			d = strings.ToLower(d)
			open := ^decided[d]
			allow[d] |= (ace.Allow &^ ace.Deny) & open
			decided[d] |= (ace.Allow | ace.Deny) & open
		}
		if !acl.InheritPermissions {
			break
		}
	}
	return allow
}

// ProjectGroup finds a group of a project by its name, such as Contributors.
// A group the search does not find gives nil and no error. Each group is read
// once per client.
func (c *Client) ProjectGroup(ctx context.Context, project, name string) (*Identity, error) {
	want := "[" + project + "]\\" + name
	return c.groups.get(strings.ToLower(want), func() (*Identity, error) {
		var out struct {
			Value []Identity `json:"value"`
		}
		_, err := c.getJSON(ctx, request{
			host:     hostVSSPS,
			segments: []string{"_apis", "identities"},
			query: url.Values{
				"searchFilter":    {"General"},
				"filterValue":     {want},
				"queryMembership": {"None"},
			},
		}, &out)
		if err != nil {
			return nil, err
		}
		for i := range out.Value {
			if strings.EqualFold(out.Value[i].ProviderDisplayName, want) {
				return &out.Value[i], nil
			}
		}
		return nil, nil
	})
}
