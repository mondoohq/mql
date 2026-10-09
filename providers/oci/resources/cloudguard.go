// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/oracle/oci-go-sdk/v65/common"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// CloudGuard is a tenancy-level service that only operates in the home region,
// unlike other OCI services that require per-region iteration.
//
// The home region and the configuration are two separate lazies rather than
// one: the configuration fetch needs the home region to build its client, and
// resolving it from inside the configuration's own fetch would deadlock.
type mqlOciCloudGuardInternal struct {
	config     ociRetryLazy[*cloudguard.Configuration]
	homeRegion ociRetryLazy[string]
}

// ociCloudGuardProblemWindow is how far back the problem listing reaches.
//
// The service defaults this to 30 days when the caller leaves it unset, which
// is short enough to hide the remediation history the resource exists to
// expose: a finding resolved six weeks ago simply vanishes, and "was this ever
// raised?" answers no. 90 days matches the shortest Audit retention period, so
// the two detection-side resources cover a comparable span.
const ociCloudGuardProblemWindow = 90 * 24 * time.Hour

// ociCloudGuardProblemStates are the lifecycle states a problem listing has to
// ask for. The filter takes one value at a time and defaults to ACTIVE, so
// every state has to be requested explicitly or the resolved ones never
// appear.
var ociCloudGuardProblemStates = []cloudguard.ListProblemsLifecycleStateEnum{
	cloudguard.ListProblemsLifecycleStateActive,
	cloudguard.ListProblemsLifecycleStateInactive,
}

// ociCloudGuardNotSubscribed reports whether the error means the tenancy never
// onboarded Cloud Guard, which the service answers with a 404 carrying
// "Cloudguard subscription is not available".
//
// A tenancy that has not enabled Cloud Guard is the single most likely state to
// query, and it is exactly the state the resource exists to report. Surfacing
// the 404 as a query error means status - the field whose whole job is to say
// whether Cloud Guard is on - fails precisely when the answer is "it is not",
// and takes the rest of the tenancy scan down with it.
//
// Only a 404 counts. A 401 is a credential problem and a 403 is the usual IAM
// policy gap; reporting either as "Cloud Guard is off" would turn an
// under-scoped token into a clean bill of health, which is worse than an error.
//
// The status alone is deliberately the whole test, without also matching the
// message text or the error code. The code is NotAuthorizedOrNotFound, which
// Cloud Guard returns for a missing resource and an IAM gap alike, so it does
// not discriminate; the message is prose and free to change. That leaves one
// caller where a 404 could mean something else - rules, which names a specific
// recipe and so can 404 because that recipe was deleted between listing it and
// reading its rules. Empty rules is the right answer to that too.
func ociCloudGuardNotSubscribed(err error) bool {
	svcErr, ok := common.IsServiceError(err)
	return ok && svcErr.GetHTTPStatusCode() == 404
}

func (o *mqlOciCloudGuard) id() (string, error) {
	return "oci.cloudGuard", nil
}

func (o *mqlOciCloudGuard) getHomeRegion() (string, error) {
	return o.homeRegion.get(func() (string, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		tenancy, err := conn.Tenant(context.Background())
		if err != nil {
			return "", err
		}

		if tenancy.HomeRegionKey == nil {
			return "", errors.New("no home region set")
		}

		// HomeRegionKey returns the short region key (e.g., "IAD"), not the region name (e.g., "us-ashburn-1").
		// The OCI SDK's SetRegion() accepts both formats.
		return *tenancy.HomeRegionKey, nil
	})
}

// getConfig returns the tenancy's Cloud Guard configuration, or (nil, nil) when
// the tenancy never onboarded Cloud Guard.
//
// The nil-without-error case is what every caller has to handle, and it is
// deliberately absorbed here rather than at each accessor. o.config remembers
// only successes, so reporting not-subscribed as an error meant re-issuing
// GetConfiguration for every field that read it - three identical 404s to
// answer status, reportingRegion and selfManageResources. Answering nil makes
// it a cached success, so the tenancy is asked once.
func (o *mqlOciCloudGuard) getConfig() (*cloudguard.Configuration, error) {
	// Resolve the home region before entering config's own critical section:
	// getHomeRegion takes a lock of its own, and nesting it inside this one
	// would deadlock. It caches, so this costs an atomic load once resolved.
	//
	// This is the one caller that must not use getServiceRegion. The reporting
	// region is read *from* this configuration, so asking for it here would
	// recurse back into getConfig and never terminate.
	homeRegion, err := o.getHomeRegion()
	if err != nil {
		return nil, err
	}

	return o.config.get(func() (*cloudguard.Configuration, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)

		client, err := conn.CloudGuardClient(homeRegion)
		if err != nil {
			return nil, err
		}

		response, err := client.GetConfiguration(context.Background(), cloudguard.GetConfigurationRequest{
			CompartmentId: common.String(conn.TenantID()),
		})
		if err != nil {
			if ociCloudGuardNotSubscribed(err) {
				return nil, nil
			}
			return nil, err
		}
		return &response.Configuration, nil
	})
}

// getServiceRegion returns the region Cloud Guard actually serves data from.
//
// Cloud Guard aggregates findings from every monitored region into a single
// reporting region, chosen when the service is enabled. That is usually the
// tenancy's home region but is not required to be, and querying the wrong one
// returns nothing - a Cloud Guard posture check that reports no problems at
// all while the console shows hundreds. The home region is the fallback,
// because it is also what getConfig has to use to discover the reporting
// region in the first place.
func (o *mqlOciCloudGuard) getServiceRegion() (string, error) {
	cfg, err := o.getConfig()
	if err == nil && cfg != nil && stringValue(cfg.ReportingRegion) != "" {
		return *cfg.ReportingRegion, nil
	}
	return o.getHomeRegion()
}

// A nil configuration below means the tenancy is not subscribed, which is a
// real answer rather than a failure: Cloud Guard is off. See getConfig.

func (o *mqlOciCloudGuard) status() (bool, error) {
	cfg, err := o.getConfig()
	if err != nil || cfg == nil {
		return false, err
	}
	return cfg.Status == cloudguard.CloudGuardStatusEnabled, nil
}

func (o *mqlOciCloudGuard) reportingRegion() (string, error) {
	cfg, err := o.getConfig()
	if err != nil || cfg == nil {
		return "", err
	}
	return stringValue(cfg.ReportingRegion), nil
}

func (o *mqlOciCloudGuard) selfManageResources() (bool, error) {
	cfg, err := o.getConfig()
	if err != nil || cfg == nil {
		return false, err
	}
	return boolValue(cfg.SelfManageResources), nil
}

// targets is one subtree call for the whole tenancy, narrowed to the
// compartments the filters admit.
func (o *mqlOciCloudGuard) targets() ([]any, error) {
	items, err := o.listTargets()
	return ociKeepAdmitted(o.MqlRuntime, items, err)
}

func (o *mqlOciCloudGuard) listTargets() ([]any, error) {
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
	targets, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.TargetSummary, *string, error) {
		response, err := client.ListTargets(ctx, cloudguard.ListTargetsRequest{
			CompartmentId: common.String(conn.TenantID()),
			// Cloud Guard targets are attached to sub-compartments far more
			// often than to the tenancy root.
			CompartmentIdInSubtree: common.Bool(true),
			// Cloud Guard rejects the subtree flag outright unless an access
			// level comes with it, so this is required rather than an
			// optimization. ACCESSIBLE degrades to the compartments the caller
			// can read instead of failing on the first one it cannot.
			AccessLevel: cloudguard.ListTargetsAccessLevelAccessible,
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

	res := make([]any, 0, len(targets))
	for i := range targets {
		target := targets[i]

		var created *time.Time
		if target.TimeCreated != nil {
			created = &target.TimeCreated.Time
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.target", stringValue(target.CompartmentId), map[string]*llx.RawData{
			"id":                 llx.StringDataPtr(target.Id),
			"name":               llx.StringDataPtr(target.DisplayName),
			"targetResourceId":   llx.StringDataPtr(target.TargetResourceId),
			"targetResourceType": llx.StringData(string(target.TargetResourceType)),
			"state":              llx.StringData(string(target.LifecycleState)),
			"recipeCount":        llx.IntDataPtr(target.RecipeCount),
			"created":            llx.TimeDataPtr(created),
			"freeformTags":       llx.MapData(strMapToAny(target.FreeformTags), types.String),
			"definedTags":        llx.MapData(definedTagsToAny(target.DefinedTags), types.Any),
			"systemTags":         llx.MapData(definedTagsToAny(target.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

// problems is one subtree call for the whole tenancy, narrowed to the
// compartments the filters admit.
func (o *mqlOciCloudGuard) problems() ([]any, error) {
	items, err := o.listProblems()
	return ociKeepAdmitted(o.MqlRuntime, items, err)
}

// listProblems lists the findings Cloud Guard has raised.
//
// Leaving the request's filters unset does not mean "everything": the service
// applies its own defaults, narrowing the result to problems whose lifecycle
// state is ACTIVE and that were last detected within the past 30 days. Both
// bounds are set explicitly here instead, so the scope is what this code says
// it is rather than whatever the service currently defaults to.
//
// The window is deliberately wider than the default. `lifecycleDetail` is
// exposed as a field so callers decide whether they care about OPEN findings
// only or also want the RESOLVED and DISMISSED history, and that history is
// the point - a dismissed-but-unfixed finding should be distinguishable from
// one that never existed, which a 30-day cutoff quietly prevents.
func (o *mqlOciCloudGuard) listProblems() ([]any, error) {
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
	since := common.SDKTime{Time: time.Now().UTC().Add(-ociCloudGuardProblemWindow)}
	problems := []cloudguard.ProblemSummary{}
	// One pass per lifecycle state: the filter accepts a single value, and
	// leaving it unset is not the union - the service falls back to ACTIVE.
	for _, state := range ociCloudGuardProblemStates {
		perState, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.ProblemSummary, *string, error) {
			response, err := client.ListProblems(ctx, cloudguard.ListProblemsRequest{
				CompartmentId: common.String(conn.TenantID()),
				// Problems are raised against resources in sub-compartments, so
				// without the subtree flag the tenancy root reports almost none.
				CompartmentIdInSubtree: common.Bool(true),
				// ACCESSIBLE degrades to the compartments the caller can read
				// instead of failing the whole listing on the first one it cannot.
				AccessLevel:                          cloudguard.ListProblemsAccessLevelAccessible,
				LifecycleState:                       state,
				TimeLastDetectedGreaterThanOrEqualTo: &since,
				Page:                                 page,
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
		problems = append(problems, perState...)
	}

	res := make([]any, 0, len(problems))
	for i := range problems {
		problem := problems[i]

		var riskScore float64
		if problem.RiskScore != nil {
			riskScore = *problem.RiskScore
		}

		mqlProblem, err := CreateResource(o.MqlRuntime, "oci.cloudGuard.problem", map[string]*llx.RawData{
			"id":              llx.StringDataPtr(problem.Id),
			"riskLevel":       llx.StringData(string(problem.RiskLevel)),
			"riskScore":       llx.FloatData(riskScore),
			"detectorRuleId":  llx.StringDataPtr(problem.DetectorRuleId),
			"detector":        llx.StringData(string(problem.DetectorId)),
			"resourceId":      llx.StringDataPtr(problem.ResourceId),
			"resourceName":    llx.StringDataPtr(problem.ResourceName),
			"resourceType":    llx.StringDataPtr(problem.ResourceType),
			"labels":          llx.ArrayData(stringsToAny(problem.Labels), types.String),
			"state":           llx.StringData(string(problem.LifecycleState)),
			"lifecycleDetail": llx.StringData(string(problem.LifecycleDetail)),
			"region":          llx.StringDataPtr(problem.Region),
			"regions":         llx.ArrayData(stringsToAny(problem.Regions), types.String),
			"firstDetected":   sdkTimeData(problem.TimeFirstDetected),
			"lastDetected":    sdkTimeData(problem.TimeLastDetected),
		})
		if err != nil {
			return nil, err
		}
		mqlProblemTyped := mqlProblem.(*mqlOciCloudGuardProblem)
		mqlProblemTyped.cacheCompartmentID = stringValue(problem.CompartmentId)
		mqlProblemTyped.cacheTargetID = stringValue(problem.TargetId)
		res = append(res, mqlProblemTyped)
	}

	return res, nil
}

type mqlOciCloudGuardProblemInternal struct {
	cacheCompartmentID string
	cacheTargetID      string
}

func (o *mqlOciCloudGuardProblem) id() (string, error) {
	return "oci.cloudGuard.problem/" + o.Id.Data, nil
}

func (o *mqlOciCloudGuardProblem) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCloudGuardProblem) target() (*mqlOciCloudGuardTarget, error) {
	if o.cacheTargetID == "" {
		o.Target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Targets are not individually addressable by OCID through an init, so
	// match against the already-cached target listing rather than issuing a
	// per-problem lookup.
	obj, err := CreateResource(o.MqlRuntime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	rawTargets := obj.(*mqlOciCloudGuard).GetTargets()
	if rawTargets.Error != nil {
		return nil, rawTargets.Error
	}

	for _, raw := range rawTargets.Data {
		t, ok := raw.(*mqlOciCloudGuardTarget)
		if ok && t.Id.Data == o.cacheTargetID {
			return t, nil
		}
	}

	o.Target.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (o *mqlOciCloudGuardDetectorRecipe) rules() ([]any, error) {
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
	rules, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.DetectorRecipeDetectorRuleSummary, *string, error) {
		response, err := client.ListDetectorRecipeDetectorRules(ctx, cloudguard.ListDetectorRecipeDetectorRulesRequest{
			DetectorRecipeId: common.String(o.Id.Data),
			// The compartment OCID is no longer a schema field, so it comes
			// from the value recorded when the recipe was listed. An empty
			// value here would quietly scope this listing to nothing.
			CompartmentId: common.String(o.cacheCompartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		// The recipe listing itself is answerable without a Cloud Guard
		// subscription - Oracle-managed recipes come back either way - but the
		// per-recipe rules endpoint is not. Without this the recipes resolve
		// and then every one of them fails on its rules.
		if ociCloudGuardNotSubscribed(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(rules))
	for i := range rules {
		rule := rules[i]

		// Every field that decides whether the rule actually fires lives in
		// DetectorDetails, which is optional on the summary. When it is absent
		// these fall back to their zero values and isEnabled is emitted as an
		// explicit false rather than left null, so an assertion over the rule
		// fails instead of passing on a rule nobody could read. MQL evaluates
		// null && null as true, so a null here would be the more dangerous
		// answer.
		var (
			isEnabled              bool
			riskLevel              string
			problemThreshold       int64
			labels                 []string
			isConfigurationAllowed bool
			configurations         []any
			settings               []any
		)
		if rule.DetectorDetails != nil {
			isEnabled = boolValue(rule.DetectorDetails.IsEnabled)
			riskLevel = string(rule.DetectorDetails.RiskLevel)
			if rule.DetectorDetails.ProblemThreshold != nil {
				problemThreshold = int64(*rule.DetectorDetails.ProblemThreshold)
			}
			labels = rule.DetectorDetails.Labels
			isConfigurationAllowed = boolValue(rule.DetectorDetails.IsConfigurationAllowed)

			configurations, err = convert.JsonToDictSlice(rule.DetectorDetails.Configurations)
			if err != nil {
				return nil, err
			}

			settings, err = o.newDetectorConfigurations(stringValue(rule.Id), rule.DetectorDetails.Configurations)
			if err != nil {
				return nil, err
			}
		}

		managedListTypes := make([]string, 0, len(rule.ManagedListTypes))
		for _, t := range rule.ManagedListTypes {
			managedListTypes = append(managedListTypes, string(t))
		}

		mqlRule, err := CreateResource(o.MqlRuntime, "oci.cloudGuard.detectorRule", map[string]*llx.RawData{
			"__id":                   llx.StringData(o.Id.Data + "/" + stringValue(rule.Id)),
			"id":                     llx.StringDataPtr(rule.Id),
			"detector":               llx.StringData(string(rule.Detector)),
			"name":                   llx.StringDataPtr(rule.DisplayName),
			"description":            llx.StringDataPtr(rule.Description),
			"recommendation":         llx.StringDataPtr(rule.Recommendation),
			"serviceType":            llx.StringDataPtr(rule.ServiceType),
			"resourceType":           llx.StringDataPtr(rule.ResourceType),
			"isEnabled":              llx.BoolData(isEnabled),
			"riskLevel":              llx.StringData(riskLevel),
			"problemThreshold":       llx.IntData(problemThreshold),
			"labels":                 llx.ArrayData(stringsToAny(labels), types.String),
			"configurations":         llx.ArrayData(configurations, types.Dict),
			"settings":               llx.ArrayData(settings, types.Resource("oci.cloudGuard.detectorRule.configuration")),
			"isConfigurationAllowed": llx.BoolData(isConfigurationAllowed),
			"isCloneable":            llx.BoolData(boolValue(rule.IsCloneable)),
			"managedListTypes":       llx.ArrayData(stringsToAny(managedListTypes), types.String),
			"state":                  llx.StringData(string(rule.LifecycleState)),
			"created":                sdkTimeData(rule.TimeCreated),
			"updated":                sdkTimeData(rule.TimeUpdated),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}

	return res, nil
}

// detectorRecipes is one subtree call for the whole tenancy, narrowed to the
// compartments the filters admit.
func (o *mqlOciCloudGuard) detectorRecipes() ([]any, error) {
	items, err := o.listDetectorRecipes()
	return ociKeepAdmitted(o.MqlRuntime, items, err)
}

func (o *mqlOciCloudGuard) listDetectorRecipes() ([]any, error) {
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
	recipes, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.DetectorRecipeSummary, *string, error) {
		response, err := client.ListDetectorRecipes(ctx, cloudguard.ListDetectorRecipesRequest{
			CompartmentId:          common.String(conn.TenantID()),
			CompartmentIdInSubtree: common.Bool(true),
			// Required whenever the subtree flag is set: Cloud Guard rejects
			// the combination without it. See targets for the full reasoning.
			AccessLevel: cloudguard.ListDetectorRecipesAccessLevelAccessible,
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

		var created *time.Time
		if recipe.TimeCreated != nil {
			created = &recipe.TimeCreated.Time
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.detectorRecipe", stringValue(recipe.CompartmentId), map[string]*llx.RawData{
			"id":           llx.StringDataPtr(recipe.Id),
			"name":         llx.StringDataPtr(recipe.DisplayName),
			"description":  llx.StringDataPtr(recipe.Description),
			"owner":        llx.StringData(string(recipe.Owner)),
			"detectorType": llx.StringData(string(recipe.Detector)),
			"state":        llx.StringData(string(recipe.LifecycleState)),
			"created":      llx.TimeDataPtr(created),
			"freeformTags": llx.MapData(strMapToAny(recipe.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(recipe.DefinedTags), types.Any),
			"systemTags":   llx.MapData(definedTagsToAny(recipe.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

type mqlOciCloudGuardDetectorRecipeInternal struct {
	ociCompartmentRef
}

// securityZones is one subtree call for the whole tenancy, narrowed to the
// compartments the filters admit.
func (o *mqlOciCloudGuard) securityZones() ([]any, error) {
	items, err := o.listSecurityZones()
	return ociKeepAdmitted(o.MqlRuntime, items, err)
}

func (o *mqlOciCloudGuard) listSecurityZones() ([]any, error) {
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
	zones, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.SecurityZoneSummary, *string, error) {
		// Security zones are attached to compartments and practically never to
		// the tenancy root, so without the subtree flag a correctly zoned
		// tenancy reported none at all.
		response, err := client.ListSecurityZones(ctx, cloudguard.ListSecurityZonesRequest{
			CompartmentId:                    common.String(conn.TenantID()),
			IsRequiredSecurityZonesInSubtree: common.Bool(true),
			Page:                             page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(zones))
	for i := range zones {
		zone := zones[i]

		var created *time.Time
		if zone.TimeCreated != nil {
			created = &zone.TimeCreated.Time
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.securityZone", stringValue(zone.CompartmentId), map[string]*llx.RawData{
			"id":                              llx.StringDataPtr(zone.Id),
			"name":                            llx.StringDataPtr(zone.DisplayName),
			"description":                     llx.StringDataPtr(zone.Description),
			"isInheritanceAfterDeleteEnabled": llx.BoolDataPtr(zone.IsInheritanceAfterDeleteEnabled),
			"state":                           llx.StringData(string(zone.LifecycleState)),
			"created":                         llx.TimeDataPtr(created),
			"freeformTags":                    llx.MapData(strMapToAny(zone.FreeformTags), types.String),
			"definedTags":                     llx.MapData(definedTagsToAny(zone.DefinedTags), types.Any),
			"systemTags":                      llx.MapData(definedTagsToAny(zone.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		mqlZone := mqlInstance.(*mqlOciCloudGuardSecurityZone)
		mqlZone.cacheRecipeID = stringValue(zone.SecurityZoneRecipeId)
		res = append(res, mqlZone)
	}

	return res, nil
}

func (o *mqlOciCloudGuard) securityZoneRecipes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	serviceRegion, err := o.getServiceRegion()
	if err != nil {
		return nil, err
	}

	client, err := conn.CloudGuardClient(serviceRegion)
	if err != nil {
		return nil, err
	}

	// Security recipes have no subtree flag, and a custom recipe can sit in
	// any compartment, so every compartment is asked, in Cloud Guard's
	// reporting region only.
	items, err := ociCollectGlobal(o.MqlRuntime, func(ctx context.Context, compartmentID string) ([]any, error) {
		recipes, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.SecurityRecipeSummary, *string, error) {
			response, err := client.ListSecurityRecipes(ctx, cloudguard.ListSecurityRecipesRequest{
				CompartmentId: common.String(compartmentID),
				Page:          page,
			})
			if err != nil {
				return nil, nil, err
			}
			return response.Items, response.OpcNextPage, nil
		})
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(recipes))
		for i := range recipes {
			out = append(out, recipes[i])
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	seen := map[string]bool{}
	for i := range items {
		recipe := items[i].(cloudguard.SecurityRecipeSummary)
		// Oracle-managed recipes may be answered from more than one compartment.
		id := stringValue(recipe.Id)
		if seen[id] {
			continue
		}
		seen[id] = true

		var created *time.Time
		if recipe.TimeCreated != nil {
			created = &recipe.TimeCreated.Time
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.securityZoneRecipe", stringValue(recipe.CompartmentId), map[string]*llx.RawData{
			"id":           llx.StringDataPtr(recipe.Id),
			"name":         llx.StringDataPtr(recipe.DisplayName),
			"description":  llx.StringDataPtr(recipe.Description),
			"owner":        llx.StringData(string(recipe.Owner)),
			"state":        llx.StringData(string(recipe.LifecycleState)),
			"created":      llx.TimeDataPtr(created),
			"freeformTags": llx.MapData(strMapToAny(recipe.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(recipe.DefinedTags), types.Any),
			"systemTags":   llx.MapData(definedTagsToAny(recipe.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		mqlRecipe := mqlInstance.(*mqlOciCloudGuardSecurityZoneRecipe)
		mqlRecipe.cachePolicyIDs = recipe.SecurityPolicies
		res = append(res, mqlRecipe)
	}

	return res, nil
}

func (o *mqlOciCloudGuard) securityPolicies() ([]any, error) {
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
	policies, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.SecurityPolicySummary, *string, error) {
		response, err := client.ListSecurityPolicies(ctx, cloudguard.ListSecurityPoliciesRequest{
			CompartmentId: common.String(conn.TenantID()),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(policies))
	for i := range policies {
		policy := policies[i]

		var created *time.Time
		if policy.TimeCreated != nil {
			created = &policy.TimeCreated.Time
		}

		services := make([]any, 0, len(policy.Services))
		for _, s := range policy.Services {
			services = append(services, s)
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.securityPolicy", stringValue(policy.CompartmentId), map[string]*llx.RawData{
			"id":           llx.StringDataPtr(policy.Id),
			"name":         llx.StringDataPtr(policy.DisplayName),
			"friendlyName": llx.StringDataPtr(policy.FriendlyName),
			"description":  llx.StringDataPtr(policy.Description),
			"owner":        llx.StringData(string(policy.Owner)),
			"category":     llx.StringDataPtr(policy.Category),
			"services":     llx.ArrayData(services, types.String),
			"state":        llx.StringData(string(policy.LifecycleState)),
			"created":      llx.TimeDataPtr(created),
			"freeformTags": llx.MapData(strMapToAny(policy.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(policy.DefinedTags), types.Any),
			"systemTags":   llx.MapData(definedTagsToAny(policy.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

type mqlOciCloudGuardSecurityZoneInternal struct {
	ociCompartmentRef
	cacheRecipeID string
}

type mqlOciCloudGuardSecurityZoneRecipeInternal struct {
	ociCompartmentRef
	cachePolicyIDs []string
}

func (o *mqlOciCloudGuardTarget) id() (string, error) {
	return "oci.cloudGuard.target/" + o.Id.Data, nil
}

func (o *mqlOciCloudGuardDetectorRecipe) id() (string, error) {
	return "oci.cloudGuard.detectorRecipe/" + o.Id.Data, nil
}

func (o *mqlOciCloudGuardSecurityZone) id() (string, error) {
	return "oci.cloudGuard.securityZone/" + o.Id.Data, nil
}

func (o *mqlOciCloudGuardSecurityZone) securityZoneRecipe() (*mqlOciCloudGuardSecurityZoneRecipe, error) {
	if o.cacheRecipeID == "" {
		o.SecurityZoneRecipe.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	cgRes, err := CreateResource(o.MqlRuntime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	cg := cgRes.(*mqlOciCloudGuard)

	rawRecipes := cg.GetSecurityZoneRecipes()
	if rawRecipes.Error != nil {
		return nil, rawRecipes.Error
	}

	for _, raw := range rawRecipes.Data {
		r := raw.(*mqlOciCloudGuardSecurityZoneRecipe)
		if r.Id.Data == o.cacheRecipeID {
			return r, nil
		}
	}

	o.SecurityZoneRecipe.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (o *mqlOciCloudGuardSecurityZoneRecipe) id() (string, error) {
	return "oci.cloudGuard.securityZoneRecipe/" + o.Id.Data, nil
}

func (o *mqlOciCloudGuardSecurityZoneRecipe) securityPolicies() ([]any, error) {
	if len(o.cachePolicyIDs) == 0 {
		return []any{}, nil
	}

	cgRes, err := CreateResource(o.MqlRuntime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	cg := cgRes.(*mqlOciCloudGuard)

	rawPolicies := cg.GetSecurityPolicies()
	if rawPolicies.Error != nil {
		return nil, rawPolicies.Error
	}

	byId := make(map[string]*mqlOciCloudGuardSecurityPolicy, len(rawPolicies.Data))
	for _, raw := range rawPolicies.Data {
		p := raw.(*mqlOciCloudGuardSecurityPolicy)
		byId[p.Id.Data] = p
	}

	res := make([]any, 0, len(o.cachePolicyIDs))
	for _, id := range o.cachePolicyIDs {
		if p, ok := byId[id]; ok {
			res = append(res, p)
		}
	}
	return res, nil
}

func (o *mqlOciCloudGuardSecurityPolicy) id() (string, error) {
	return "oci.cloudGuard.securityPolicy/" + o.Id.Data, nil
}

type mqlOciCloudGuardSecurityPolicyInternal struct {
	ociCompartmentRef
}

type mqlOciCloudGuardTargetInternal struct {
	ociCompartmentRef
}

// newDetectorConfigurations builds the setting resources for one detector rule.
//
// The nested value, allowed-value and additional-property lists stay dicts:
// each is a small name/value pair with no identity of its own, so a resource
// per row would add a cache key and a schema entry without adding query power.
func (o *mqlOciCloudGuardDetectorRecipe) newDetectorConfigurations(ruleID string, configurations []cloudguard.DetectorConfiguration) ([]any, error) {
	res := make([]any, 0, len(configurations))
	for i := range configurations {
		c := configurations[i]

		values, err := convert.JsonToDictSlice(c.Values)
		if err != nil {
			return nil, err
		}
		allowedValues, err := convert.JsonToDictSlice(c.AllowedValues)
		if err != nil {
			return nil, err
		}
		additionalProperties, err := convert.JsonToDictSlice(c.AdditionalProperties)
		if err != nil {
			return nil, err
		}

		mqlConfig, err := CreateResource(o.MqlRuntime, "oci.cloudGuard.detectorRule.configuration", map[string]*llx.RawData{
			"__id":                  llx.StringData(o.Id.Data + "/" + ruleID + "/configuration/" + stringValue(c.ConfigKey)),
			"configKey":             llx.StringDataPtr(c.ConfigKey),
			"name":                  llx.StringDataPtr(c.Name),
			"value":                 llx.StringDataPtr(c.Value),
			"dataType":              llx.StringDataPtr(c.DataType),
			"values":                llx.ArrayData(values, types.Dict),
			"allowedValuesDataType": llx.StringDataPtr(c.AllowedValuesDataType),
			"allowedValues":         llx.ArrayData(allowedValues, types.Dict),
			"additionalProperties":  llx.ArrayData(additionalProperties, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfig)
	}
	return res, nil
}
