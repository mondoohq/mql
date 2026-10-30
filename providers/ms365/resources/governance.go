// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/identitygovernance"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	igmodels "github.com/microsoftgraph/msgraph-sdk-go/models/identitygovernance"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// Graph application permissions the governance inventories read with. They
// are named on a refused read so the error says what the scan app is missing.
const (
	permAgreementReadAll                    = "Agreement.Read.All"
	permLifecycleWorkflowsReadAll           = "LifecycleWorkflows.Read.All"
	permCustomSecAttributeDefinitionReadAll = "CustomSecAttributeDefinition.Read.All"
)

// isGraphLicenseRefusal reports whether Graph refused a request because the
// tenant lacks the license the feature needs, rather than because the caller
// lacks a permission. Graph answers both with 403, so the message decides:
// lifecycle workflows answer "Insufficient license to complete this
// operation. User workflows require an Entra ID Governance license."
func isGraphLicenseRefusal(err error) bool {
	if graphStatusCode(err) != http.StatusForbidden {
		return false
	}
	m := strings.ToLower(graphErrorMessage(err))
	return strings.Contains(m, "license") || strings.Contains(m, "licence")
}

// classifyLifecycleWorkflowsError classifies a failed lifecycle workflows
// read. A tenant without an Entra ID Governance license is NotApplicable;
// anything else goes through classifyGraphError.
func classifyLifecycleWorkflowsError(err error) error {
	if isGraphLicenseRefusal(err) {
		return llx.NotApplicable(transformError(err))
	}
	return classifyGraphError(err, permLifecycleWorkflowsReadAll)
}

// keyValuePairsToMap turns a list of name/value pairs into a map. A pair
// without a name is dropped, since it cannot be looked up; a pair without a
// value maps to the empty string.
func keyValuePairsToMap(pairs []models.KeyValuePairable) map[string]any {
	res := make(map[string]any, len(pairs))
	for _, pair := range pairs {
		if pair == nil || pair.GetName() == nil {
			continue
		}
		res[*pair.GetName()] = convert.ToValue(pair.GetValue())
	}
	return res
}

// ---- terms of use ----

func (a *mqlMicrosoftIdentityAndAccess) termsOfUseAgreements() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.IdentityGovernance().TermsOfUse().Agreements().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permAgreementReadAll)
	}
	if resp == nil {
		return []any{}, nil
	}
	agreements, err := iterate[models.Agreementable](ctx, resp, graphClient.GetAdapter(), models.CreateAgreementCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permAgreementReadAll)
	}

	res := []any{}
	for _, agreement := range agreements {
		if agreement == nil || agreement.GetId() == nil {
			continue
		}
		mqlAgreement, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessTermsOfUseAgreement, newTermsOfUseAgreementArgs(agreement))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAgreement)
	}
	return res, nil
}

// newTermsOfUseAgreementArgs maps one agreement onto the arguments of the
// terms of use agreement resource.
func newTermsOfUseAgreementArgs(agreement models.Agreementable) map[string]*llx.RawData {
	expirationStart := llx.NilData
	expirationFrequency := llx.NilData
	if expiration := agreement.GetTermsExpiration(); expiration != nil {
		expirationStart = graphTimeData(expiration.GetStartDateTime())
		expirationFrequency = llx.StringDataPtr(isoDurationPtr(expiration.GetFrequency()))
	}
	return map[string]*llx.RawData{
		"__id":                              llx.StringDataPtr(agreement.GetId()),
		"id":                                llx.StringDataPtr(agreement.GetId()),
		"displayName":                       llx.StringDataPtr(agreement.GetDisplayName()),
		"isPerDeviceAcceptanceRequired":     llx.BoolDataPtr(agreement.GetIsPerDeviceAcceptanceRequired()),
		"isViewingBeforeAcceptanceRequired": llx.BoolDataPtr(agreement.GetIsViewingBeforeAcceptanceRequired()),
		"termsExpirationStartDateTime":      expirationStart,
		"termsExpirationFrequency":          expirationFrequency,
		"userReacceptRequiredFrequency":     llx.StringDataPtr(isoDurationPtr(agreement.GetUserReacceptRequiredFrequency())),
	}
}

// conditionalAccessPolicies lists the Conditional Access policies whose grant
// controls require this agreement, read from the tenant's policy list.
func (a *mqlMicrosoftIdentityAndAccessTermsOfUseAgreement) conditionalAccessPolicies() ([]any, error) {
	ca, err := CreateResource(a.MqlRuntime, ResourceMicrosoftConditionalAccess, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	policies := ca.(*mqlMicrosoftConditionalAccess).GetPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}

	res := []any{}
	for _, p := range policies.Data {
		policy, ok := p.(*mqlMicrosoftConditionalAccessPolicy)
		if !ok {
			continue
		}
		grant := policy.GetGrantControls()
		if grant.Error != nil {
			return nil, grant.Error
		}
		if grant.Data == nil {
			continue
		}
		if slices.Contains(grant.Data.TermsOfUse.Data, any(a.Id.Data)) {
			res = append(res, policy)
		}
	}
	return res, nil
}

// termsOfUseAgreements resolves the agreement ids a policy requires against
// the tenant's agreement list. An id with no matching agreement (one deleted
// after the policy was saved) is dropped; the raw id stays in termsOfUse.
func (g *mqlMicrosoftConditionalAccessPolicyGrantControls) termsOfUseAgreements() ([]any, error) {
	if len(g.TermsOfUse.Data) == 0 {
		return []any{}, nil
	}
	iam, err := CreateResource(g.MqlRuntime, ResourceMicrosoftIdentityAndAccess, nil)
	if err != nil {
		return nil, err
	}
	agreements := iam.(*mqlMicrosoftIdentityAndAccess).GetTermsOfUseAgreements()
	if agreements.Error != nil {
		return nil, agreements.Error
	}
	return selectByID(agreements.Data, g.TermsOfUse.Data, func(r any) string {
		if agreement, ok := r.(*mqlMicrosoftIdentityAndAccessTermsOfUseAgreement); ok {
			return agreement.Id.Data
		}
		return ""
	}), nil
}

// selectByID returns the resources from all whose id is in ids, in the order
// ids lists them. Ids that match nothing are skipped.
func selectByID(all []any, ids []any, idOf func(any) string) []any {
	byID := make(map[string]any, len(all))
	for _, r := range all {
		if id := idOf(r); id != "" {
			byID[id] = r
		}
	}
	res := []any{}
	for _, raw := range ids {
		id, ok := raw.(string)
		if !ok {
			continue
		}
		if r, ok := byID[id]; ok {
			res = append(res, r)
		}
	}
	return res
}

// ---- lifecycle workflows ----

func (a *mqlMicrosoftIdentityAndAccess) lifecycleWorkflows() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.IdentityGovernance().LifecycleWorkflows().Workflows().Get(ctx, nil)
	if err != nil {
		return nil, classifyLifecycleWorkflowsError(err)
	}
	if resp == nil {
		return []any{}, nil
	}
	workflows, err := iterate[igmodels.Workflowable](ctx, resp, graphClient.GetAdapter(), igmodels.CreateWorkflowCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyLifecycleWorkflowsError(err)
	}

	res := []any{}
	for _, workflow := range workflows {
		if workflow == nil || workflow.GetId() == nil {
			continue
		}
		args, err := newLifecycleWorkflowArgs(workflow)
		if err != nil {
			return nil, err
		}
		mqlWorkflow, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessLifecycleWorkflow, args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlWorkflow)
	}
	return res, nil
}

// newLifecycleWorkflowArgs maps one workflow onto the arguments of the
// lifecycle workflow resource.
func newLifecycleWorkflowArgs(workflow igmodels.Workflowable) (map[string]*llx.RawData, error) {
	conditions, err := kiotaToDict(workflow.GetExecutionConditions())
	if err != nil {
		return nil, err
	}
	executionConditions := llx.NilData
	if conditions != nil {
		executionConditions = llx.DictData(conditions)
	}

	var version *int64
	if v := workflow.GetVersion(); v != nil {
		vv := int64(*v)
		version = &vv
	}

	return map[string]*llx.RawData{
		"__id":                    llx.StringDataPtr(workflow.GetId()),
		"id":                      llx.StringDataPtr(workflow.GetId()),
		"displayName":             llx.StringDataPtr(workflow.GetDisplayName()),
		"description":             llx.StringDataPtr(workflow.GetDescription()),
		"category":                llx.StringDataPtr(enumPtrString(workflow.GetCategory())),
		"isEnabled":               llx.BoolDataPtr(workflow.GetIsEnabled()),
		"isSchedulingEnabled":     llx.BoolDataPtr(workflow.GetIsSchedulingEnabled()),
		"executionConditions":     executionConditions,
		"version":                 llx.IntDataPtr(version),
		"createdDateTime":         graphTimeData(workflow.GetCreatedDateTime()),
		"lastModifiedDateTime":    graphTimeData(workflow.GetLastModifiedDateTime()),
		"nextScheduleRunDateTime": graphTimeData(workflow.GetNextScheduleRunDateTime()),
	}, nil
}

func (w *mqlMicrosoftIdentityAndAccessLifecycleWorkflow) tasks() ([]any, error) {
	conn := w.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.IdentityGovernance().LifecycleWorkflows().Workflows().ByWorkflowId(w.Id.Data).Tasks().Get(ctx, nil)
	if err != nil {
		return nil, classifyLifecycleWorkflowsError(err)
	}
	if resp == nil {
		return []any{}, nil
	}
	tasks, err := iterate[igmodels.Taskable](ctx, resp, graphClient.GetAdapter(), igmodels.CreateTaskCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyLifecycleWorkflowsError(err)
	}

	sortTasksByExecutionSequence(tasks)

	res := []any{}
	for _, task := range tasks {
		if task == nil || task.GetId() == nil {
			continue
		}
		mqlTask, err := CreateResource(w.MqlRuntime, ResourceMicrosoftIdentityAndAccessLifecycleWorkflowTask, newLifecycleWorkflowTaskArgs(w.Id.Data, task))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTask)
	}
	return res, nil
}

// sortTasksByExecutionSequence orders tasks the way the workflow runs them.
// A task without a sequence sorts last; ties keep the order Graph returned.
func sortTasksByExecutionSequence(tasks []igmodels.Taskable) {
	seq := func(t igmodels.Taskable) int64 {
		if t == nil || t.GetExecutionSequence() == nil {
			return int64(^uint32(0))
		}
		return int64(*t.GetExecutionSequence())
	}
	slices.SortStableFunc(tasks, func(a, b igmodels.Taskable) int {
		return cmp.Compare(seq(a), seq(b))
	})
}

// newLifecycleWorkflowTaskArgs maps one workflow task onto the arguments of
// the task resource. Task ids are only unique within a workflow version, so
// the workflow id is part of the cache key.
func newLifecycleWorkflowTaskArgs(workflowID string, task igmodels.Taskable) map[string]*llx.RawData {
	var sequence *int64
	if s := task.GetExecutionSequence(); s != nil {
		ss := int64(*s)
		sequence = &ss
	}
	return map[string]*llx.RawData{
		"__id":              llx.StringData(workflowID + "/tasks/" + convert.ToValue(task.GetId())),
		"id":                llx.StringDataPtr(task.GetId()),
		"displayName":       llx.StringDataPtr(task.GetDisplayName()),
		"description":       llx.StringDataPtr(task.GetDescription()),
		"category":          llx.StringDataPtr(enumPtrString(task.GetCategory())),
		"taskDefinitionId":  llx.StringDataPtr(task.GetTaskDefinitionId()),
		"isEnabled":         llx.BoolDataPtr(task.GetIsEnabled()),
		"continueOnError":   llx.BoolDataPtr(task.GetContinueOnError()),
		"executionSequence": llx.IntDataPtr(sequence),
		"arguments":         llx.MapData(keyValuePairsToMap(task.GetArguments()), types.String),
	}
}

func (w *mqlMicrosoftIdentityAndAccessLifecycleWorkflow) createdBy() (*mqlMicrosoftUser, error) {
	conn := w.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	user, err := graphClient.IdentityGovernance().LifecycleWorkflows().Workflows().ByWorkflowId(w.Id.Data).CreatedBy().
		Get(context.Background(), &identitygovernance.LifecycleWorkflowsWorkflowsItemCreatedByRequestBuilderGetRequestConfiguration{
			QueryParameters: &identitygovernance.LifecycleWorkflowsWorkflowsItemCreatedByRequestBuilderGetQueryParameters{
				Select: []string{"id"},
			},
		})
	if err != nil && !isResourceNotFound(err) {
		return nil, classifyLifecycleWorkflowsError(err)
	}
	return w.resolveUser(&w.CreatedBy, user)
}

func (w *mqlMicrosoftIdentityAndAccessLifecycleWorkflow) lastModifiedBy() (*mqlMicrosoftUser, error) {
	conn := w.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	user, err := graphClient.IdentityGovernance().LifecycleWorkflows().Workflows().ByWorkflowId(w.Id.Data).LastModifiedBy().
		Get(context.Background(), &identitygovernance.LifecycleWorkflowsWorkflowsItemLastModifiedByRequestBuilderGetRequestConfiguration{
			QueryParameters: &identitygovernance.LifecycleWorkflowsWorkflowsItemLastModifiedByRequestBuilderGetQueryParameters{
				Select: []string{"id"},
			},
		})
	if err != nil && !isResourceNotFound(err) {
		return nil, classifyLifecycleWorkflowsError(err)
	}
	return w.resolveUser(&w.LastModifiedBy, user)
}

// resolveUser turns the user Graph names on a workflow into a microsoft.user.
// No user, or one that has since been deleted from the directory, reads null.
func (w *mqlMicrosoftIdentityAndAccessLifecycleWorkflow) resolveUser(field *plugin.TValue[*mqlMicrosoftUser], user models.Userable) (*mqlMicrosoftUser, error) {
	if user == nil || user.GetId() == nil || *user.GetId() == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(w.MqlRuntime, ResourceMicrosoftUser, map[string]*llx.RawData{
		"id": llx.StringDataPtr(user.GetId()),
	})
	if err != nil {
		if isResourceNotFound(err) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlMicrosoftUser), nil
}

// ---- custom security attributes ----

type mqlMicrosoftIdentityAndAccessCustomSecurityAttributeDefinitionInternal struct {
	cacheAttributeSet string
}

func (a *mqlMicrosoftIdentityAndAccess) customSecurityAttributeDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Directory().CustomSecurityAttributeDefinitions().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permCustomSecAttributeDefinitionReadAll)
	}
	if resp == nil {
		return []any{}, nil
	}
	definitions, err := iterate[models.CustomSecurityAttributeDefinitionable](ctx, resp, graphClient.GetAdapter(), models.CreateCustomSecurityAttributeDefinitionCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permCustomSecAttributeDefinitionReadAll)
	}

	res := []any{}
	for _, definition := range definitions {
		if definition == nil || definition.GetId() == nil {
			continue
		}
		r, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessCustomSecurityAttributeDefinition, newCustomSecurityAttributeDefinitionArgs(definition))
		if err != nil {
			return nil, err
		}
		mqlDefinition := r.(*mqlMicrosoftIdentityAndAccessCustomSecurityAttributeDefinition)
		mqlDefinition.cacheAttributeSet = convert.ToValue(definition.GetAttributeSet())
		res = append(res, mqlDefinition)
	}
	return res, nil
}

// newCustomSecurityAttributeDefinitionArgs maps one definition onto the
// arguments of the custom security attribute definition resource.
func newCustomSecurityAttributeDefinitionArgs(definition models.CustomSecurityAttributeDefinitionable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                    llx.StringDataPtr(definition.GetId()),
		"id":                      llx.StringDataPtr(definition.GetId()),
		"name":                    llx.StringDataPtr(definition.GetName()),
		"description":             llx.StringDataPtr(definition.GetDescription()),
		"type":                    llx.StringDataPtr(definition.GetTypeEscaped()),
		"status":                  llx.StringDataPtr(definition.GetStatus()),
		"isCollection":            llx.BoolDataPtr(definition.GetIsCollection()),
		"isSearchable":            llx.BoolDataPtr(definition.GetIsSearchable()),
		"usePreDefinedValuesOnly": llx.BoolDataPtr(definition.GetUsePreDefinedValuesOnly()),
	}
}

// attributeSet resolves the definition's attribute set against the tenant's
// attribute set list.
func (d *mqlMicrosoftIdentityAndAccessCustomSecurityAttributeDefinition) attributeSet() (*mqlMicrosoftIdentityAndAccessAttributeSet, error) {
	if d.cacheAttributeSet == "" {
		d.AttributeSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	iam, err := CreateResource(d.MqlRuntime, ResourceMicrosoftIdentityAndAccess, nil)
	if err != nil {
		return nil, err
	}
	sets := iam.(*mqlMicrosoftIdentityAndAccess).GetAttributeSets()
	if sets.Error != nil {
		return nil, sets.Error
	}
	for _, s := range sets.Data {
		if set, ok := s.(*mqlMicrosoftIdentityAndAccessAttributeSet); ok && set.Id.Data == d.cacheAttributeSet {
			return set, nil
		}
	}
	d.AttributeSet.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (d *mqlMicrosoftIdentityAndAccessCustomSecurityAttributeDefinition) allowedValues() ([]any, error) {
	conn := d.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Directory().CustomSecurityAttributeDefinitions().ByCustomSecurityAttributeDefinitionId(d.Id.Data).AllowedValues().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permCustomSecAttributeDefinitionReadAll)
	}
	if resp == nil {
		return []any{}, nil
	}
	values, err := iterate[models.AllowedValueable](ctx, resp, graphClient.GetAdapter(), models.CreateAllowedValueCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permCustomSecAttributeDefinitionReadAll)
	}

	res := []any{}
	for _, value := range values {
		if value == nil || value.GetId() == nil {
			continue
		}
		mqlValue, err := CreateResource(d.MqlRuntime, ResourceMicrosoftIdentityAndAccessCustomSecurityAttributeDefinitionAllowedValue, map[string]*llx.RawData{
			"__id":     llx.StringData(d.Id.Data + "/allowedValues/" + *value.GetId()),
			"id":       llx.StringDataPtr(value.GetId()),
			"isActive": llx.BoolDataPtr(value.GetIsActive()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlValue)
	}
	return res, nil
}

func (a *mqlMicrosoftIdentityAndAccess) attributeSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Directory().AttributeSets().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, permCustomSecAttributeDefinitionReadAll)
	}
	if resp == nil {
		return []any{}, nil
	}
	sets, err := iterate[models.AttributeSetable](ctx, resp, graphClient.GetAdapter(), models.CreateAttributeSetCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, permCustomSecAttributeDefinitionReadAll)
	}

	res := []any{}
	for _, set := range sets {
		if set == nil || set.GetId() == nil {
			continue
		}
		var maxAttributes *int64
		if m := set.GetMaxAttributesPerSet(); m != nil {
			mm := int64(*m)
			maxAttributes = &mm
		}
		mqlSet, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessAttributeSet, map[string]*llx.RawData{
			"__id":                llx.StringDataPtr(set.GetId()),
			"id":                  llx.StringDataPtr(set.GetId()),
			"description":         llx.StringDataPtr(set.GetDescription()),
			"maxAttributesPerSet": llx.IntDataPtr(maxAttributes),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSet)
	}
	return res, nil
}

// definitions lists the custom security attribute definitions in this set,
// read from the tenant's definition list.
func (s *mqlMicrosoftIdentityAndAccessAttributeSet) definitions() ([]any, error) {
	iam, err := CreateResource(s.MqlRuntime, ResourceMicrosoftIdentityAndAccess, nil)
	if err != nil {
		return nil, err
	}
	definitions := iam.(*mqlMicrosoftIdentityAndAccess).GetCustomSecurityAttributeDefinitions()
	if definitions.Error != nil {
		return nil, definitions.Error
	}
	res := []any{}
	for _, d := range definitions.Data {
		if definition, ok := d.(*mqlMicrosoftIdentityAndAccessCustomSecurityAttributeDefinition); ok && definition.cacheAttributeSet == s.Id.Data {
			res = append(res, definition)
		}
	}
	return res, nil
}
