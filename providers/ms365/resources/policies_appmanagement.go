// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/policies"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

type mqlMicrosoftPoliciesAppManagementPolicyInternal struct {
	// guards the appliesTo fetch, which feeds both applications and
	// servicePrincipals
	appliesToLock   sync.Mutex
	appliesToLoaded bool
	appliesToErr    error
	appliesToAppIds []string
	appliesToSpIds  []string
}

// https://learn.microsoft.com/en-us/graph/api/appmanagementpolicy-list?view=graph-rest-1.0
func (a *mqlMicrosoftPolicies) appManagementPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().AppManagementPolicies().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, "Policy.Read.All")
	}
	list, err := iterate[models.AppManagementPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateAppManagementPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, "Policy.Read.All")
	}
	return newMqlAppManagementPolicies(a.MqlRuntime, list)
}

func newMqlAppManagementPolicies(runtime *plugin.Runtime, list []models.AppManagementPolicyable) ([]any, error) {
	res := []any{}
	for _, policy := range list {
		if policy == nil || policy.GetId() == nil {
			continue
		}
		mqlPolicy, err := newMqlAppManagementPolicy(runtime, policy)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

func newMqlAppManagementPolicy(runtime *plugin.Runtime, policy models.AppManagementPolicyable) (*mqlMicrosoftPoliciesAppManagementPolicy, error) {
	policyId := *policy.GetId()

	// a policy that sets no restrictions still gets an (empty) restriction set,
	// so that keyCredentials and passwordCredentials read as empty lists
	mqlRestrictions, err := newAppManagementConfiguration(runtime, policy.GetRestrictions(), "appManagementPolicy/"+policyId+"/restrictions")
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, "microsoft.policies.appManagementPolicy", map[string]*llx.RawData{
		"__id":         llx.StringData("appManagementPolicy/" + policyId),
		"id":           llx.StringData(policyId),
		"displayName":  llx.StringDataPtr(policy.GetDisplayName()),
		"description":  llx.StringDataPtr(policy.GetDescription()),
		"isEnabled":    llx.BoolDataPtr(policy.GetIsEnabled()),
		"restrictions": llx.ResourceData(mqlRestrictions, "microsoft.defaultAppManagementPolicy.appManagementConfiguration"),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftPoliciesAppManagementPolicy), nil
}

// loadAppliesTo reads the objects the policy is assigned to, once for both
// applications and servicePrincipals. Only ids are selected: the objects are
// resolved from the tenant's application and service principal lists.
// https://learn.microsoft.com/en-us/graph/api/appmanagementpolicy-list-appliesto?view=graph-rest-1.0
func (a *mqlMicrosoftPoliciesAppManagementPolicy) loadAppliesTo() error {
	a.appliesToLock.Lock()
	defer a.appliesToLock.Unlock()
	if a.appliesToLoaded {
		return a.appliesToErr
	}
	a.appliesToLoaded = true

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		a.appliesToErr = err
		return err
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().AppManagementPolicies().ByAppManagementPolicyId(a.Id.Data).AppliesTo().Get(ctx, &policies.AppManagementPoliciesItemAppliesToRequestBuilderGetRequestConfiguration{
		QueryParameters: &policies.AppManagementPoliciesItemAppliesToRequestBuilderGetQueryParameters{
			Select: []string{"id"},
		},
	})
	if err != nil {
		a.appliesToErr = classifyGraphError(err, "Policy.Read.All", "Application.Read.All")
		return a.appliesToErr
	}
	objects, err := iterate[models.DirectoryObjectable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	if err != nil {
		a.appliesToErr = classifyGraphError(err, "Policy.Read.All", "Application.Read.All")
		return a.appliesToErr
	}
	a.appliesToAppIds, a.appliesToSpIds = splitAppliesTo(objects)
	return nil
}

// splitAppliesTo sorts the objects an app management policy is assigned to
// into application and service principal ids. Graph only assigns these
// policies to those two types; anything else is skipped.
func splitAppliesTo(objects []models.DirectoryObjectable) (appIds []string, spIds []string) {
	appIds = []string{}
	spIds = []string{}
	for _, obj := range objects {
		if obj == nil || obj.GetId() == nil {
			continue
		}
		switch obj.(type) {
		case models.Applicationable:
			appIds = append(appIds, *obj.GetId())
		case models.ServicePrincipalable:
			spIds = append(spIds, *obj.GetId())
		default:
			odataType := ""
			if t := obj.GetOdataType(); t != nil {
				odataType = *t
			}
			log.Debug().Str("object", *obj.GetId()).Str("type", odataType).Msg("skipping app management policy target that is neither an application nor a service principal")
		}
	}
	return appIds, spIds
}

func (a *mqlMicrosoftPoliciesAppManagementPolicy) applications() ([]any, error) {
	if err := a.loadAppliesTo(); err != nil {
		return nil, err
	}
	if len(a.appliesToAppIds) == 0 {
		return []any{}, nil
	}

	appsResource, err := CreateResource(a.MqlRuntime, "microsoft.applications", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := appsResource.(*mqlMicrosoftApplications).GetList()
	if list.Error != nil {
		return nil, list.Error
	}
	byId := make(map[string]any, len(list.Data))
	for _, item := range list.Data {
		if app, ok := item.(*mqlMicrosoftApplication); ok {
			byId[app.Id.Data] = app
		}
	}
	return pickByIds(byId, a.appliesToAppIds, "application"), nil
}

func (a *mqlMicrosoftPoliciesAppManagementPolicy) servicePrincipals() ([]any, error) {
	if err := a.loadAppliesTo(); err != nil {
		return nil, err
	}
	if len(a.appliesToSpIds) == 0 {
		return []any{}, nil
	}

	msResource, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := msResource.(*mqlMicrosoft).GetServiceprincipals()
	if list.Error != nil {
		return nil, list.Error
	}
	byId := make(map[string]any, len(list.Data))
	for _, item := range list.Data {
		if sp, ok := item.(*mqlMicrosoftServiceprincipal); ok {
			byId[sp.Id.Data] = sp
		}
	}
	return pickByIds(byId, a.appliesToSpIds, "service principal"), nil
}

// pickByIds returns the resources for ids in order, skipping an id the tenant
// list does not hold (an object deleted between the two reads).
func pickByIds(byId map[string]any, ids []string, kind string) []any {
	res := make([]any, 0, len(ids))
	for _, id := range ids {
		r, ok := byId[id]
		if !ok {
			log.Debug().Str("id", id).Str("kind", kind).Msg("app management policy target not found in tenant list")
			continue
		}
		res = append(res, r)
	}
	return res
}
