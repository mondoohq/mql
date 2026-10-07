// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

// mqlAzuredevopsBranchProtectionInternal ties a branch protection to its
// repository, whose permissions decide the permission fields.
type mqlAzuredevopsBranchProtectionInternal struct {
	repo *mqlAzuredevopsRepository
}

// permissionsKnown reports whether the lists name every grant that reaches the
// repository. A repository list that stops inheriting stands on its own. In
// every other case the project list is part of the answer, so a missing one
// leaves the grants unknown: folding nothing would read as no identity holding
// any permission.
func permissionsKnown(project, repo *connection.AccessControlList) bool {
	if project != nil {
		return true
	}
	return repo != nil && !repo.InheritPermissions
}

// gitPermissions is the permission bits each identity is allowed on the
// repository, folded from the project and repository lists of the Git
// repositories namespace. The organization-wide list is not read. known is
// false when the lists do not settle the answer, with no error: nothing was
// refused, the permissions are just not known.
func (r *mqlAzuredevopsRepository) gitPermissions() (perms map[string]int64, known bool, err error) {
	if r.ProjectId.Data == "" {
		return nil, false, nil
	}
	client := connectionOf(r.MqlRuntime).Client()
	project, err := client.AccessControlList(apiContext(), connection.ProjectSecurityToken(r.ProjectId.Data))
	if err != nil {
		return nil, false, err
	}
	repo, err := client.AccessControlList(apiContext(), connection.RepositorySecurityToken(r.ProjectId.Data, r.Id.Data))
	if err != nil {
		return nil, false, err
	}
	if !permissionsKnown(project, repo) {
		return nil, false, nil
	}
	return connection.EffectiveAllow([]*connection.AccessControlList{project, repo}), true, nil
}

// unknownPermissions marks a permission field as unknown: set and null, with
// no error.
func (r *mqlAzuredevopsRepository) unknownPermissions(field *plugin.TValue[bool]) (bool, error) {
	log.Warn().Msg("azure devops: the permissions of " + r.FullName.Data + " are not known, reporting them as unknown")
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

// heldByAPerson reports whether an identity other than a service identity is
// allowed any of the bits.
func heldByAPerson(perms map[string]int64, bits int64) bool {
	for descriptor, allow := range perms {
		if allow&bits != 0 && !connection.IsServiceIdentity(descriptor) {
			return true
		}
	}
	return false
}

func (b *mqlAzuredevopsBranchProtection) allowForcePushesEnabled() (bool, error) {
	perms, known, err := b.repo.gitPermissions()
	if err != nil {
		return false, classifyForbidden(err)
	}
	if !known {
		return b.repo.unknownPermissions(&b.AllowForcePushesEnabled)
	}
	return heldByAPerson(perms, connection.GitPermissionForcePush), nil
}

func (b *mqlAzuredevopsBranchProtection) enforceAdminsEnabled() (bool, error) {
	perms, known, err := b.repo.gitPermissions()
	if err != nil {
		return false, classifyForbidden(err)
	}
	if !known {
		return b.repo.unknownPermissions(&b.EnforceAdminsEnabled)
	}
	return !heldByAPerson(perms, connection.GitPermissionPolicyExempt|connection.GitPermissionPullRequestBypassPolicy), nil
}

func (b *mqlAzuredevopsBranchProtection) blockCreations() (bool, error) {
	perms, known, err := b.repo.gitPermissions()
	if err != nil {
		return false, classifyForbidden(err)
	}
	if !known {
		return b.repo.unknownPermissions(&b.BlockCreations)
	}
	group, err := connectionOf(b.MqlRuntime).Client().ProjectGroup(apiContext(), b.repo.ProjectName.Data, "Contributors")
	if err != nil {
		return false, classifyForbidden(err)
	}
	if group == nil {
		log.Warn().Msg("azure devops: no Contributors group found in project " + b.repo.ProjectName.Data + ", reporting branch creation as unknown")
		b.BlockCreations.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return perms[strings.ToLower(group.Descriptor)]&connection.GitPermissionCreateBranch == 0, nil
}
