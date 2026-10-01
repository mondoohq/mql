// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// resolveDirectoryRefs turns a Conditional Access scope list into typed
// resource references. Conditional Access mixes object IDs with special
// tokens (`All`, `None`, `GuestsOrExternalUsers`, `ServicePrincipalsInMyTenant`,
// …) in the same list, so anything that isn't a directory object ID (a GUID)
// is skipped. A reference to an object that has since been deleted from the
// directory is logged and skipped. Any other failure (a missing permission,
// throttling, a transport error) fails the list: skipping those entries would
// turn "could not read the exclusions" into "there are no exclusions".
func resolveDirectoryRefs(runtime *plugin.Runtime, resource string, ids []any) ([]any, error) {
	return resolveDirectoryRefsWith(resource, ids, func(id string) (plugin.Resource, error) {
		return runtime.NewResource(runtime, resource, map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
	})
}

// resolveDirectoryRefsWith is resolveDirectoryRefs with the lookup injected.
func resolveDirectoryRefsWith(resource string, ids []any, lookup func(id string) (plugin.Resource, error)) ([]any, error) {
	res := []any{}
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok || uuid.Validate(id) != nil {
			continue
		}
		r, err := lookup(id)
		if err != nil {
			if isDeletedDirectoryObject(err) {
				log.Warn().Err(err).Str("resource", resource).Str("id", id).
					Msg("ms365: skipping conditional access reference to a deleted directory object")
				continue
			}
			return nil, fmt.Errorf("unable to resolve %s %s: %w", resource, id, err)
		}
		res = append(res, r)
	}
	return res, nil
}

// isDeletedDirectoryObject reports whether a reference lookup failed because
// the object no longer exists, as opposed to the lookup itself failing. The
// user, group and role definition inits answer a missing object with Graph's
// Request_ResourceNotFound; the service principal init searches the tenant's
// full list and answers errServicePrincipalNotFound.
func isDeletedDirectoryObject(err error) bool {
	return isResourceNotFound(err) || errors.Is(err, errServicePrincipalNotFound)
}

// mqlMicrosoftConditionalAccessPolicyConditionsUsersInternal keeps the raw
// group and role scope lists that back the typed reference accessors. They are
// no longer part of the schema, so the reference accessors read them from here.
type mqlMicrosoftConditionalAccessPolicyConditionsUsersInternal struct {
	cacheIncludeGroups []string
	cacheExcludeGroups []string
	cacheIncludeRoles  []string
	cacheExcludeRoles  []string
}

func (c *mqlMicrosoftConditionalAccessPolicyConditionsUsers) includeUsersRefs() ([]any, error) {
	return resolveDirectoryRefs(c.MqlRuntime, "microsoft.user", c.IncludeUsers.Data)
}

func (c *mqlMicrosoftConditionalAccessPolicyConditionsUsers) excludeUsersRefs() ([]any, error) {
	return resolveDirectoryRefs(c.MqlRuntime, "microsoft.user", c.ExcludeUsers.Data)
}

func (c *mqlMicrosoftConditionalAccessPolicyConditionsUsers) includeGroupsRefs() ([]any, error) {
	return resolveDirectoryRefs(c.MqlRuntime, "microsoft.group", convert.SliceAnyToInterface(c.cacheIncludeGroups))
}

func (c *mqlMicrosoftConditionalAccessPolicyConditionsUsers) excludeGroupsRefs() ([]any, error) {
	return resolveDirectoryRefs(c.MqlRuntime, "microsoft.group", convert.SliceAnyToInterface(c.cacheExcludeGroups))
}

func (c *mqlMicrosoftConditionalAccessPolicyConditionsUsers) includeRolesRefs() ([]any, error) {
	return resolveDirectoryRefs(c.MqlRuntime, "microsoft.rolemanagement.roledefinition", convert.SliceAnyToInterface(c.cacheIncludeRoles))
}

func (c *mqlMicrosoftConditionalAccessPolicyConditionsUsers) excludeRolesRefs() ([]any, error) {
	return resolveDirectoryRefs(c.MqlRuntime, "microsoft.rolemanagement.roledefinition", convert.SliceAnyToInterface(c.cacheExcludeRoles))
}

func (c *mqlMicrosoftConditionalAccessPolicyConditionsClientApplications) includeServicePrincipalsRefs() ([]any, error) {
	return resolveDirectoryRefs(c.MqlRuntime, "microsoft.serviceprincipal", c.IncludeServicePrincipals.Data)
}

func (c *mqlMicrosoftConditionalAccessPolicyConditionsClientApplications) excludeServicePrincipalsRefs() ([]any, error) {
	return resolveDirectoryRefs(c.MqlRuntime, "microsoft.serviceprincipal", c.ExcludeServicePrincipals.Data)
}
