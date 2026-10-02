// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// Reading the token lifetime, claims mapping, token issuance, and home realm
// discovery policies, and the objects they are assigned to, needs this
// permission.
const stsPolicyPermission = "Policy.Read.All"

// parseStsPolicyDefinition merges the JSON documents of a policy definition
// into one object. Empty strings are skipped; a definition with no documents
// yields nil. A string that is not a JSON object is malformed data, since a
// partial result would read as a policy with fewer rules than it has.
func parseStsPolicyDefinition(definition []any) (map[string]any, error) {
	var res map[string]any
	for i, raw := range definition {
		s, ok := raw.(string)
		if !ok {
			return nil, llx.MalformedData(fmt.Errorf("policy definition entry %d is not a string", i))
		}
		if strings.TrimSpace(s) == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			return nil, llx.MalformedData(fmt.Errorf("policy definition entry %d is not a JSON object: %w", i, err))
		}
		if doc == nil {
			// the literal `null`
			return nil, llx.MalformedData(fmt.Errorf("policy definition entry %d is not a JSON object", i))
		}
		if res == nil {
			res = make(map[string]any, len(doc))
		}
		for k, v := range doc {
			res[k] = v
		}
	}
	return res, nil
}

// stsPolicyAssignments holds the objects a policy is assigned to, fetched
// once and shared by the policy's own fields and the reverse fields on
// service principals.
type stsPolicyAssignments struct {
	once   sync.Once
	spIDs  []string
	appIDs []string
	err    error
}

type appliesToFetcher func(ctx context.Context, client *msgraphsdk.GraphServiceClient, policyID string) (models.DirectoryObjectCollectionResponseable, error)

func (s *stsPolicyAssignments) load(runtime *plugin.Runtime, policyID string, fetch appliesToFetcher) ([]string, []string, error) {
	s.once.Do(func() {
		conn := runtime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			s.err = err
			return
		}
		ctx := context.Background()
		resp, err := fetch(ctx, graphClient, policyID)
		if err != nil {
			s.err = classifyGraphError(err, stsPolicyPermission)
			return
		}
		objs, err := iterate[models.DirectoryObjectable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
		if err != nil {
			s.err = classifyGraphError(err, stsPolicyPermission)
			return
		}
		s.appIDs, s.spIDs = splitAppliesTo(objs)
	})
	return s.spIDs, s.appIDs, s.err
}

func (s *stsPolicyAssignments) servicePrincipals(runtime *plugin.Runtime, policyID string, fetch appliesToFetcher) ([]any, error) {
	spIDs, _, err := s.load(runtime, policyID, fetch)
	if err != nil {
		return nil, err
	}
	return resolveServicePrincipalsByID(runtime, spIDs)
}

func (s *stsPolicyAssignments) applications(runtime *plugin.Runtime, policyID string, fetch appliesToFetcher) ([]any, error) {
	_, appIDs, err := s.load(runtime, policyID, fetch)
	if err != nil {
		return nil, err
	}
	return resolveApplicationsByID(runtime, appIDs)
}

// resolveServicePrincipalsByID looks the ids up in the tenant's service
// principal list, which is fetched once per scan. An id missing from the list
// belongs to a deleted object and is skipped.
func resolveServicePrincipalsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	res := []any{}
	if len(ids) == 0 {
		return res, nil
	}
	mqlResource, err := CreateResource(runtime, ResourceMicrosoft, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := mqlResource.(*mqlMicrosoft).GetServiceprincipals()
	if list.Error != nil {
		return nil, list.Error
	}
	byID := make(map[string]any, len(list.Data))
	for _, r := range list.Data {
		sp := r.(*mqlMicrosoftServiceprincipal)
		byID[sp.Id.Data] = sp
	}
	for _, id := range ids {
		if sp, ok := byID[id]; ok {
			res = append(res, sp)
		} else {
			log.Debug().Str("id", id).Msg("ms365> policy is assigned to a service principal that is not in the tenant list")
		}
	}
	return res, nil
}

// resolveApplicationsByID looks the object ids up in the tenant's application
// list, which is fetched once per scan.
func resolveApplicationsByID(runtime *plugin.Runtime, ids []string) ([]any, error) {
	res := []any{}
	if len(ids) == 0 {
		return res, nil
	}
	mqlResource, err := CreateResource(runtime, ResourceMicrosoftApplications, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := mqlResource.(*mqlMicrosoftApplications).GetList()
	if list.Error != nil {
		return nil, list.Error
	}
	byID := make(map[string]any, len(list.Data))
	for _, r := range list.Data {
		app := r.(*mqlMicrosoftApplication)
		byID[app.Id.Data] = app
	}
	for _, id := range ids {
		if app, ok := byID[id]; ok {
			res = append(res, app)
		} else {
			log.Debug().Str("id", id).Msg("ms365> policy is assigned to an application that is not in the tenant list")
		}
	}
	return res, nil
}

func stsPolicyArgs(p models.StsPolicyable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                  llx.StringDataPtr(p.GetId()),
		"id":                    llx.StringDataPtr(p.GetId()),
		"displayName":           llx.StringDataPtr(p.GetDisplayName()),
		"description":           llx.StringDataPtr(p.GetDescription()),
		"isOrganizationDefault": llx.BoolDataPtr(p.GetIsOrganizationDefault()),
		"definition":            llx.ArrayData(convert.SliceAnyToInterface(p.GetDefinition()), types.String),
	}
}

func createStsPolicies[T models.StsPolicyable](runtime *plugin.Runtime, resource string, policies []T) ([]any, error) {
	res := make([]any, 0, len(policies))
	for _, p := range policies {
		if p.GetId() == nil {
			continue
		}
		mqlPolicy, err := CreateResource(runtime, resource, stsPolicyArgs(p))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

func stsPolicyGraphClient(runtime *plugin.Runtime) (*msgraphsdk.GraphServiceClient, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	return conn.GraphClient()
}

// policiesResource returns the tenant's microsoft.policies resource, which
// caches the policy lists the reverse fields scan.
func policiesResource(runtime *plugin.Runtime) (*mqlMicrosoftPolicies, error) {
	r, err := CreateResource(runtime, ResourceMicrosoftPolicies, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return r.(*mqlMicrosoftPolicies), nil
}

// ---- token lifetime policies ----

type mqlMicrosoftPoliciesTokenLifetimePolicyInternal struct {
	assignments stsPolicyAssignments
}

func fetchTokenLifetimePolicyAppliesTo(ctx context.Context, client *msgraphsdk.GraphServiceClient, id string) (models.DirectoryObjectCollectionResponseable, error) {
	return client.Policies().TokenLifetimePolicies().ByTokenLifetimePolicyId(id).AppliesTo().Get(ctx, nil)
}

func (a *mqlMicrosoftPolicies) tokenLifetimePolicies() ([]any, error) {
	graphClient, err := stsPolicyGraphClient(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Policies().TokenLifetimePolicies().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, stsPolicyPermission)
	}
	policies, err := iterate[models.TokenLifetimePolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateTokenLifetimePolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, stsPolicyPermission)
	}
	return createStsPolicies(a.MqlRuntime, ResourceMicrosoftPoliciesTokenLifetimePolicy, policies)
}

func (a *mqlMicrosoftPoliciesTokenLifetimePolicy) settings() (any, error) {
	return stsPolicySettings(a.Definition.Data)
}

func (a *mqlMicrosoftPoliciesTokenLifetimePolicy) appliesToServicePrincipals() ([]any, error) {
	return a.assignments.servicePrincipals(a.MqlRuntime, a.Id.Data, fetchTokenLifetimePolicyAppliesTo)
}

func (a *mqlMicrosoftPoliciesTokenLifetimePolicy) appliesToApplications() ([]any, error) {
	return a.assignments.applications(a.MqlRuntime, a.Id.Data, fetchTokenLifetimePolicyAppliesTo)
}

// ---- claims mapping policies ----

type mqlMicrosoftPoliciesClaimsMappingPolicyInternal struct {
	assignments stsPolicyAssignments
}

func fetchClaimsMappingPolicyAppliesTo(ctx context.Context, client *msgraphsdk.GraphServiceClient, id string) (models.DirectoryObjectCollectionResponseable, error) {
	return client.Policies().ClaimsMappingPolicies().ByClaimsMappingPolicyId(id).AppliesTo().Get(ctx, nil)
}

func (a *mqlMicrosoftPolicies) claimsMappingPolicies() ([]any, error) {
	graphClient, err := stsPolicyGraphClient(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Policies().ClaimsMappingPolicies().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, stsPolicyPermission)
	}
	policies, err := iterate[models.ClaimsMappingPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateClaimsMappingPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, stsPolicyPermission)
	}
	return createStsPolicies(a.MqlRuntime, ResourceMicrosoftPoliciesClaimsMappingPolicy, policies)
}

func (a *mqlMicrosoftPoliciesClaimsMappingPolicy) settings() (any, error) {
	return stsPolicySettings(a.Definition.Data)
}

func (a *mqlMicrosoftPoliciesClaimsMappingPolicy) appliesToServicePrincipals() ([]any, error) {
	return a.assignments.servicePrincipals(a.MqlRuntime, a.Id.Data, fetchClaimsMappingPolicyAppliesTo)
}

func (a *mqlMicrosoftPoliciesClaimsMappingPolicy) appliesToApplications() ([]any, error) {
	return a.assignments.applications(a.MqlRuntime, a.Id.Data, fetchClaimsMappingPolicyAppliesTo)
}

// ---- token issuance policies ----

type mqlMicrosoftPoliciesTokenIssuancePolicyInternal struct {
	assignments stsPolicyAssignments
}

func fetchTokenIssuancePolicyAppliesTo(ctx context.Context, client *msgraphsdk.GraphServiceClient, id string) (models.DirectoryObjectCollectionResponseable, error) {
	return client.Policies().TokenIssuancePolicies().ByTokenIssuancePolicyId(id).AppliesTo().Get(ctx, nil)
}

func (a *mqlMicrosoftPolicies) tokenIssuancePolicies() ([]any, error) {
	graphClient, err := stsPolicyGraphClient(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Policies().TokenIssuancePolicies().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, stsPolicyPermission)
	}
	policies, err := iterate[models.TokenIssuancePolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateTokenIssuancePolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, stsPolicyPermission)
	}
	return createStsPolicies(a.MqlRuntime, ResourceMicrosoftPoliciesTokenIssuancePolicy, policies)
}

func (a *mqlMicrosoftPoliciesTokenIssuancePolicy) settings() (any, error) {
	return stsPolicySettings(a.Definition.Data)
}

func (a *mqlMicrosoftPoliciesTokenIssuancePolicy) appliesToServicePrincipals() ([]any, error) {
	return a.assignments.servicePrincipals(a.MqlRuntime, a.Id.Data, fetchTokenIssuancePolicyAppliesTo)
}

func (a *mqlMicrosoftPoliciesTokenIssuancePolicy) appliesToApplications() ([]any, error) {
	return a.assignments.applications(a.MqlRuntime, a.Id.Data, fetchTokenIssuancePolicyAppliesTo)
}

// ---- home realm discovery policies ----

type mqlMicrosoftPoliciesHomeRealmDiscoveryPolicyInternal struct {
	assignments stsPolicyAssignments
}

func fetchHomeRealmDiscoveryPolicyAppliesTo(ctx context.Context, client *msgraphsdk.GraphServiceClient, id string) (models.DirectoryObjectCollectionResponseable, error) {
	return client.Policies().HomeRealmDiscoveryPolicies().ByHomeRealmDiscoveryPolicyId(id).AppliesTo().Get(ctx, nil)
}

func (a *mqlMicrosoftPolicies) homeRealmDiscoveryPolicies() ([]any, error) {
	graphClient, err := stsPolicyGraphClient(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Policies().HomeRealmDiscoveryPolicies().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, stsPolicyPermission)
	}
	policies, err := iterate[models.HomeRealmDiscoveryPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateHomeRealmDiscoveryPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, stsPolicyPermission)
	}
	return createStsPolicies(a.MqlRuntime, ResourceMicrosoftPoliciesHomeRealmDiscoveryPolicy, policies)
}

func (a *mqlMicrosoftPoliciesHomeRealmDiscoveryPolicy) settings() (any, error) {
	return stsPolicySettings(a.Definition.Data)
}

func (a *mqlMicrosoftPoliciesHomeRealmDiscoveryPolicy) appliesToServicePrincipals() ([]any, error) {
	return a.assignments.servicePrincipals(a.MqlRuntime, a.Id.Data, fetchHomeRealmDiscoveryPolicyAppliesTo)
}

func (a *mqlMicrosoftPoliciesHomeRealmDiscoveryPolicy) appliesToApplications() ([]any, error) {
	return a.assignments.applications(a.MqlRuntime, a.Id.Data, fetchHomeRealmDiscoveryPolicyAppliesTo)
}

func stsPolicySettings(definition []any) (any, error) {
	parsed, err := parseStsPolicyDefinition(definition)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, nil
	}
	return parsed, nil
}

// ---- reverse fields on service principals ----
//
// Each is answered from the tenant's policy lists and their assignments,
// which are fetched once per scan, so the cost is one call per policy rather
// than one call per service principal.

func (a *mqlMicrosoftServiceprincipal) tokenLifetimePolicies() ([]any, error) {
	p, err := policiesResource(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := p.GetTokenLifetimePolicies()
	if list.Error != nil {
		return nil, list.Error
	}
	res := []any{}
	for _, r := range list.Data {
		policy := r.(*mqlMicrosoftPoliciesTokenLifetimePolicy)
		spIDs, _, err := policy.assignments.load(a.MqlRuntime, policy.Id.Data, fetchTokenLifetimePolicyAppliesTo)
		if err != nil {
			return nil, err
		}
		if slices.Contains(spIDs, a.Id.Data) {
			res = append(res, policy)
		}
	}
	return res, nil
}

func (a *mqlMicrosoftServiceprincipal) claimsMappingPolicies() ([]any, error) {
	p, err := policiesResource(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := p.GetClaimsMappingPolicies()
	if list.Error != nil {
		return nil, list.Error
	}
	res := []any{}
	for _, r := range list.Data {
		policy := r.(*mqlMicrosoftPoliciesClaimsMappingPolicy)
		spIDs, _, err := policy.assignments.load(a.MqlRuntime, policy.Id.Data, fetchClaimsMappingPolicyAppliesTo)
		if err != nil {
			return nil, err
		}
		if slices.Contains(spIDs, a.Id.Data) {
			res = append(res, policy)
		}
	}
	return res, nil
}

func (a *mqlMicrosoftServiceprincipal) homeRealmDiscoveryPolicies() ([]any, error) {
	p, err := policiesResource(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := p.GetHomeRealmDiscoveryPolicies()
	if list.Error != nil {
		return nil, list.Error
	}
	res := []any{}
	for _, r := range list.Data {
		policy := r.(*mqlMicrosoftPoliciesHomeRealmDiscoveryPolicy)
		spIDs, _, err := policy.assignments.load(a.MqlRuntime, policy.Id.Data, fetchHomeRealmDiscoveryPolicyAppliesTo)
		if err != nil {
			return nil, err
		}
		if slices.Contains(spIDs, a.Id.Data) {
			res = append(res, policy)
		}
	}
	return res, nil
}
