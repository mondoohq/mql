// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/oracle/oci-go-sdk/v65/common"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// Cloud Guard's responder side answers a different question from its detector
// side. Detector recipes decide what gets noticed; responder recipes decide
// what, if anything, is done about it. A tenancy can be fully instrumented for
// detection and remediate nothing, and until these resources existed that
// state was indistinguishable from a remediated one.
//
// The listings live in the reporting region alongside problems and targets,
// and use the tenancy root with compartmentIdInSubtree, which is the scope
// Cloud Guard's own API offers - see ociScope. AccessLevel is not optional
// with that flag: Cloud Guard rejects the request outright without it.

// ociCloudGuardResponderRuleID keys a responder rule by the recipe it belongs
// to as well as by its own identifier.
//
// The rule identifier is a name like SIMPLE_QUARANTINE, not an OCID, and the
// same rule appears in every recipe that includes it - the Oracle-managed
// recipe and each customer clone of it. Keying on the rule alone would make
// those collide, and CreateResource answers a repeated id with the cached
// first instance, so every clone would report the original's enabled state and
// execution mode. A recipe with the responder switched off would read as
// switched on.
func ociCloudGuardResponderRuleID(recipeID, ruleID string) string {
	return recipeID + "/" + ruleID
}

// ociCloudGuardResponderSettingID keys one setting inside one rule inside one
// recipe. Setting keys repeat across rules for the same reason rule ids repeat
// across recipes.
func ociCloudGuardResponderSettingID(recipeID, ruleID, configKey string) string {
	return recipeID + "/" + ruleID + "/" + configKey
}

// ociCloudGuardResponderActivityID keys a responder activity by the problem it
// was recorded against.
//
// Activity ids are unique on their own today. The problem is included anyway
// because the activity is only ever reached through one, so a collision
// between two problems' histories would silently merge two remediation
// timelines, and nothing about the merged result would look wrong.
func ociCloudGuardResponderActivityID(problemID, activityID string) string {
	return problemID + "/" + activityID
}

// ociCloudGuardResponderRuleExecution reads whether a responder rule runs and
// how, from the optional detail block that carries both.
//
// Everything deciding whether the responder ever acts lives in Details, which
// the summary may omit. An absent block reports the failing reading - not
// enabled, no execution mode - rather than nothing at all, because a null
// would leave `rules.all(isEnabled)` with nothing to fail on and an
// unreadable rule would pass a check it should not.
func ociCloudGuardResponderRuleExecution(details *cloudguard.ResponderRuleDetails) (bool, string) {
	if details == nil {
		return false, ""
	}
	return boolValue(details.IsEnabled), string(details.Mode)
}

type mqlOciCloudGuardResponderRecipeInternal struct {
	ociCompartmentRef
	cacheSourceRecipeID string
}

func (o *mqlOciCloudGuardResponderRecipe) id() (string, error) {
	return "oci.cloudGuard.responderRecipe/" + o.Id.Data, nil
}

func (o *mqlOciCloudGuardResponderRecipe) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// responderRecipes is one subtree call for the whole tenancy, narrowed to the
// compartments the filters admit.
func (o *mqlOciCloudGuard) responderRecipes() ([]any, error) {
	items, err := o.listResponderRecipes()
	return ociKeepAdmitted(o.MqlRuntime, items, err)
}

// listResponderRecipes lists the remediation recipes defined in the tenancy.
//
// An empty result is a real and important answer: it means Cloud Guard can
// detect problems but has nothing configured to act on them.
func (o *mqlOciCloudGuard) listResponderRecipes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	serviceRegion, err := o.getServiceRegion()
	if err != nil {
		return nil, err
	}

	client, err := conn.CloudGuardClient(serviceRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	recipes, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.ResponderRecipeSummary, *string, error) {
		response, err := client.ListResponderRecipes(ctx, cloudguard.ListResponderRecipesRequest{
			CompartmentId: common.String(conn.TenantID()),
			// Responder recipes are created in whichever compartment owns the
			// Cloud Guard configuration, which is routinely a child of the
			// root. Without the subtree flag the root reports almost none.
			CompartmentIdInSubtree: common.Bool(true),
			// Required with the subtree flag rather than optional: Cloud Guard
			// answers 400 when one is sent without the other. ACCESSIBLE
			// degrades to the compartments the caller can read.
			AccessLevel: cloudguard.ListResponderRecipesAccessLevelAccessible,
			Page:        page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		if ociCloudGuardNotSubscribed(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(recipes))
	for i := range recipes {
		recipe := recipes[i]

		mqlRecipe, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.responderRecipe", stringValue(recipe.CompartmentId), map[string]*llx.RawData{
			"id":               llx.StringDataPtr(recipe.Id),
			"name":             llx.StringDataPtr(recipe.DisplayName),
			"description":      llx.StringDataPtr(recipe.Description),
			"owner":            llx.StringData(string(recipe.Owner)),
			"state":            llx.StringData(string(recipe.LifecycleState)),
			"lifecycleDetails": llx.StringDataPtr(recipe.LifecycleDetails),
			"created":          sdkTimeData(recipe.TimeCreated),
			"updated":          sdkTimeData(recipe.TimeUpdated),
			"freeformTags":     llx.MapData(strMapToAny(recipe.FreeformTags), types.String),
			"definedTags":      llx.MapData(definedTagsToAny(recipe.DefinedTags), types.Any),
			"systemTags":       llx.MapData(definedTagsToAny(recipe.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		mqlRecipe.(*mqlOciCloudGuardResponderRecipe).cacheSourceRecipeID = stringValue(recipe.SourceResponderRecipeId)
		res = append(res, mqlRecipe)
	}

	return res, nil
}

// sourceRecipe resolves the recipe a clone was made from.
//
// Resolved by scanning the already-fetched recipe listing rather than through
// NewResource: an init runs before the runtime cache is consulted, so a
// per-recipe lookup would cost one API call per clone to answer with a record
// already in hand.
func (o *mqlOciCloudGuardResponderRecipe) sourceRecipe() (*mqlOciCloudGuardResponderRecipe, error) {
	if o.cacheSourceRecipeID == "" {
		o.SourceRecipe.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	obj, err := CreateResource(o.MqlRuntime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	recipes := obj.(*mqlOciCloudGuard).GetResponderRecipes()
	if recipes.Error != nil {
		return nil, recipes.Error
	}

	for _, raw := range recipes.Data {
		r, ok := raw.(*mqlOciCloudGuardResponderRecipe)
		if ok && r.Id.Data == o.cacheSourceRecipeID {
			return r, nil
		}
	}

	// An Oracle-managed source recipe in a compartment the caller cannot read
	// lands here. Null says "not resolvable", which is the honest answer.
	o.SourceRecipe.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// rules lists the responder rules inside one recipe.
func (o *mqlOciCloudGuardResponderRecipe) rules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	obj, err := CreateResource(o.MqlRuntime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	serviceRegion, err := obj.(*mqlOciCloudGuard).getServiceRegion()
	if err != nil {
		return nil, err
	}

	client, err := conn.CloudGuardClient(serviceRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	rules, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.ResponderRecipeResponderRuleSummary, *string, error) {
		response, err := client.ListResponderRecipeResponderRules(ctx, cloudguard.ListResponderRecipeResponderRulesRequest{
			ResponderRecipeId: common.String(o.Id.Data),
			// The endpoint has no subtree flag and requires a compartment, so
			// it gets the one the recipe was listed from. The compartment OCID
			// is not a schema field, so it comes from the internal struct; an
			// empty value here would scope the listing to nothing.
			CompartmentId: common.String(o.cacheCompartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		// Recipes list without a Cloud Guard subscription (Oracle-managed
		// defaults come back either way), but this per-recipe endpoint does
		// not. Without the guard every recipe resolves and then fails on its
		// rules.
		if ociCloudGuardNotSubscribed(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(rules))
	for i := range rules {
		rule := rules[i]

		isEnabled, mode := ociCloudGuardResponderRuleExecution(rule.Details)

		var condition any
		// Empty rather than nil so the field renders as an empty list, matching
		// every other list in this provider, on a rule the service reported
		// without a detail block.
		settings := []any{}
		if rule.Details != nil {
			condition, err = convert.JsonToDict(rule.Details.Condition)
			if err != nil {
				return nil, err
			}

			settings, err = o.newResponderConfigurations(stringValue(rule.Id), rule.Details.Configurations)
			if err != nil {
				return nil, err
			}
		}

		supportedModes := make([]string, 0, len(rule.SupportedModes))
		for _, m := range rule.SupportedModes {
			supportedModes = append(supportedModes, string(m))
		}

		mqlRule, err := CreateResource(o.MqlRuntime, "oci.cloudGuard.responderRule", map[string]*llx.RawData{
			"__id":             llx.StringData(ociCloudGuardResponderRuleID(o.Id.Data, stringValue(rule.Id))),
			"id":               llx.StringDataPtr(rule.Id),
			"name":             llx.StringDataPtr(rule.DisplayName),
			"description":      llx.StringDataPtr(rule.Description),
			"isEnabled":        llx.BoolData(isEnabled),
			"mode":             llx.StringData(mode),
			"supportedModes":   llx.ArrayData(stringsToAny(supportedModes), types.String),
			"type":             llx.StringData(string(rule.Type)),
			"policies":         llx.ArrayData(stringsToAny(rule.Policies), types.String),
			"condition":        llx.DictData(condition),
			"settings":         llx.ArrayData(settings, types.Resource("oci.cloudGuard.responderRule.configuration")),
			"state":            llx.StringData(string(rule.LifecycleState)),
			"lifecycleDetails": llx.StringDataPtr(rule.LifecycleDetails),
			"created":          sdkTimeData(rule.TimeCreated),
			"updated":          sdkTimeData(rule.TimeUpdated),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}

	return res, nil
}

// newResponderConfigurations builds the settings rows for one responder rule.
func (o *mqlOciCloudGuardResponderRecipe) newResponderConfigurations(ruleID string, configs []cloudguard.ResponderConfiguration) ([]any, error) {
	res := make([]any, 0, len(configs))
	for i := range configs {
		cfg := configs[i]

		mqlCfg, err := CreateResource(o.MqlRuntime, "oci.cloudGuard.responderRule.configuration", map[string]*llx.RawData{
			"__id":      llx.StringData(ociCloudGuardResponderSettingID(o.Id.Data, ruleID, stringValue(cfg.ConfigKey))),
			"configKey": llx.StringDataPtr(cfg.ConfigKey),
			"name":      llx.StringDataPtr(cfg.Name),
			"value":     llx.StringDataPtr(cfg.Value),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCfg)
	}
	return res, nil
}

// responderActivities lists what a responder actually did about this problem.
//
// This is the field that separates a configured responder from an effective
// one. A problem with no activities was never acted on, and one whose only
// activity is AWAITING_CONFIRMATION is waiting on a human.
//
// The responder rule is reported by id and name rather than as a reference to
// oci.cloudGuard.responderRule, because the id names a rule within an
// unspecified recipe: the same rule id appears in the Oracle recipe and in
// every clone of it, so there is no single rule resource it resolves to.
func (o *mqlOciCloudGuardProblem) responderActivities() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	obj, err := CreateResource(o.MqlRuntime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	serviceRegion, err := obj.(*mqlOciCloudGuard).getServiceRegion()
	if err != nil {
		return nil, err
	}

	client, err := conn.CloudGuardClient(serviceRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	activities, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.ResponderActivitySummary, *string, error) {
		response, err := client.ListResponderActivities(ctx, cloudguard.ListResponderActivitiesRequest{
			ProblemId: common.String(o.Id.Data),
			Page:      page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		if ociCloudGuardNotSubscribed(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(activities))
	for i := range activities {
		activity := activities[i]

		mqlActivity, err := CreateResource(o.MqlRuntime, "oci.cloudGuard.responderActivity", map[string]*llx.RawData{
			"__id":              llx.StringData(ociCloudGuardResponderActivityID(o.Id.Data, stringValue(activity.Id))),
			"id":                llx.StringDataPtr(activity.Id),
			"responderRuleId":   llx.StringDataPtr(activity.ResponderRuleId),
			"responderRuleName": llx.StringDataPtr(activity.ResponderRuleName),
			"responderType":     llx.StringData(string(activity.ResponderType)),
			"activityType":      llx.StringData(string(activity.ResponderActivityType)),
			"executionStatus":   llx.StringData(string(activity.ResponderExecutionStatus)),
			"message":           llx.StringDataPtr(activity.Message),
			"created":           sdkTimeData(activity.TimeCreated),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlActivity)
	}

	return res, nil
}
