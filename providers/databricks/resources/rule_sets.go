// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/databricks/databricks-sdk-go/service/iam"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/databricks/connection"
	"go.mondoo.com/mql/types"
)

// ruleSetName builds the name the access-control API addresses a rule set by.
// The name is a path under the account, so every rule set carries the account
// id: accounts/<account-id>/ruleSets/default for the account itself, and
// accounts/<account-id>/<collection>/<resource-id>/ruleSets/default for a
// service principal or a group. An empty account id or resource id yields an
// empty name, which the caller reports as unreadable rather than sending a
// malformed name to the API.
func ruleSetName(accountID, collection, resourceID string) string {
	if accountID == "" {
		return ""
	}
	if collection == "" {
		return "accounts/" + accountID + "/ruleSets/default"
	}
	if resourceID == "" {
		return ""
	}
	return "accounts/" + accountID + "/" + collection + "/" + resourceID + "/ruleSets/default"
}

// principalParts splits a qualified rule-set principal into its kind and its
// bare name. The access-control API qualifies every principal with the
// collection it belongs to: users/<user-name>, groups/<group-name>, and
// servicePrincipals/<application-id>. An unrecognized prefix yields an empty
// kind, which the resource reports as null rather than guessing.
func principalParts(principal string) (kind string, name string) {
	prefix, rest, found := strings.Cut(principal, "/")
	if !found || rest == "" {
		return "", ""
	}
	switch prefix {
	case "users":
		return "user", rest
	case "groups":
		return "group", rest
	case "servicePrincipals":
		return "servicePrincipal", rest
	}
	return "", ""
}

// accountRuleSet exposes the grant rules on the account resource itself, which
// name the principals holding account-level roles.
func (r *mqlDatabricks) accountRuleSet() (*mqlDatabricksRuleSet, error) {
	return resolveRuleSet(r.MqlRuntime, "", "", &r.AccountRuleSet.State)
}

// ruleSet exposes the grant rules on this service principal. A principal
// holding roles/servicePrincipal.user here can authenticate as the service
// principal, so this is what answers who can act as it.
func (r *mqlDatabricksServicePrincipal) ruleSet() (*mqlDatabricksRuleSet, error) {
	// The rule-set path keys a service principal on its OAuth application id,
	// not on its SCIM id.
	return resolveRuleSet(r.MqlRuntime, "servicePrincipals", r.ApplicationId.Data, &r.RuleSet.State)
}

// ruleSet exposes the grant rules on this group. A principal holding
// roles/group.manager here can change the group's membership.
func (r *mqlDatabricksGroup) ruleSet() (*mqlDatabricksRuleSet, error) {
	return resolveRuleSet(r.MqlRuntime, "groups", r.Id.Data, &r.RuleSet.State)
}

// resolveRuleSet fetches one rule set and maps it. Rule sets are read from the
// account console, which is also where the account id in the rule set name
// comes from, so a workspace connection reports the account-plane error rather
// than an answer scoped to something else.
//
// There is no list endpoint for rule sets: each is fetched by the name of the
// resource it hangs off. Reading them across every service principal therefore
// costs one call per principal, which is why this is a computed field and not
// part of the service principal listing.
func resolveRuleSet(runtime *plugin.Runtime, collection, resourceID string, state *plugin.State) (*mqlDatabricksRuleSet, error) {
	acc, err := accountClient(runtime)
	if err != nil {
		return nil, err
	}
	conn := runtime.Connection.(*connection.DatabricksConnection)

	name := ruleSetName(conn.AccountID(), collection, resourceID)
	if name == "" {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	resp, err := acc.AccessControl.GetRuleSet(context.Background(), iam.GetRuleSetRequest{Name: name})
	if err != nil {
		// A resource that has never had a rule attached answers 404. That is a
		// rule set with no grants, not an unreadable one, so it is reported as
		// an empty rule set. A permission failure is left to propagate: "I may
		// not read the rules" must not look like "there are no rules".
		if isDatabricksFeatureUnavailable(err) {
			return newMqlDatabricksRuleSet(runtime, name, nil)
		}
		return nil, err
	}
	if resp == nil {
		*state = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDatabricksRuleSet(runtime, name, resp.GrantRules)
}

// newMqlDatabricksRuleSet maps a rule set and its grant rules. The rules are
// flattened to one resource per role and principal so a query can select the
// principals holding a single role, and so each row carries a cache key that
// covers every dimension along which a rule repeats.
func newMqlDatabricksRuleSet(runtime *plugin.Runtime, name string, rules []iam.GrantRule) (*mqlDatabricksRuleSet, error) {
	grants := []any{}
	for i := range rules {
		rule := rules[i]
		for _, principal := range rule.Principals {
			kind, bare := principalParts(principal)
			fields := map[string]*llx.RawData{
				"__id":          llx.StringData("databricks.ruleSet.grant/" + name + "/" + rule.Role + "/" + principal),
				"ruleSetName":   llx.StringData(name),
				"role":          llx.StringData(rule.Role),
				"principal":     llx.StringData(principal),
				"principalName": llx.StringData(bare),
			}
			if kind == "" {
				fields["principalType"] = llx.StringDataPtr(nil)
				fields["principalName"] = llx.StringDataPtr(nil)
			} else {
				fields["principalType"] = llx.StringData(kind)
			}
			res, err := CreateResource(runtime, "databricks.ruleSet.grant", fields)
			if err != nil {
				return nil, err
			}
			grants = append(grants, res)
		}
	}

	res, err := CreateResource(runtime, "databricks.ruleSet", map[string]*llx.RawData{
		"__id":   llx.StringData("databricks.ruleSet/" + name),
		"name":   llx.StringData(name),
		"grants": llx.ArrayData(grants, types.Resource("databricks.ruleSet.grant")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksRuleSet), nil
}
