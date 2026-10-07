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

// gitPermissions is the permission bits each identity is allowed on the
// repository, folded from the project and repository lists of the Git
// repositories namespace. The organization-wide list is not read.
func (r *mqlAzuredevopsRepository) gitPermissions() (map[string]int64, error) {
	client := connectionOf(r.MqlRuntime).Client()
	project, err := client.AccessControlList(apiContext(), connection.ProjectSecurityToken(r.ProjectId.Data))
	if err != nil {
		return nil, err
	}
	repo, err := client.AccessControlList(apiContext(), connection.RepositorySecurityToken(r.ProjectId.Data, r.Id.Data))
	if err != nil {
		return nil, err
	}
	return connection.EffectiveAllow([]*connection.AccessControlList{project, repo}), nil
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
	perms, err := b.repo.gitPermissions()
	if err != nil {
		return false, classifyForbidden(err)
	}
	return heldByAPerson(perms, connection.GitPermissionForcePush), nil
}

func (b *mqlAzuredevopsBranchProtection) enforceAdminsEnabled() (bool, error) {
	perms, err := b.repo.gitPermissions()
	if err != nil {
		return false, classifyForbidden(err)
	}
	return !heldByAPerson(perms, connection.GitPermissionPolicyExempt|connection.GitPermissionPullRequestBypassPolicy), nil
}

func (b *mqlAzuredevopsBranchProtection) blockCreations() (bool, error) {
	perms, err := b.repo.gitPermissions()
	if err != nil {
		return false, classifyForbidden(err)
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
