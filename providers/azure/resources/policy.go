// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/policyinsights/armpolicyinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionPolicy) id() (string, error) {
	return "azure.subscription.policy/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func (a *mqlAzureSubscriptionPolicyAssignment) id() (string, error) {
	return "azure.subscription.policy.assignment/" + a.AssignmentId.Data, nil
}

// initAzureSubscriptionPolicyAssignment resolves a single policy assignment by
// its resource ID. The assignments() list path passes every field, so this
// only fetches when the resource is created from just an assignmentId (e.g.
// via the typed reference on a policy exemption).
func initAzureSubscriptionPolicyAssignment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["assignmentId"]
	if !ok {
		return args, nil, nil
	}
	assignmentID, ok := idRaw.Value.(string)
	if !ok || assignmentID == "" {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	clientFactory, err := policyClientFactory(conn, conn.SubId())
	if err != nil {
		return nil, nil, err
	}

	resp, err := clientFactory.NewAssignmentsClient().GetByID(context.Background(), assignmentID, nil)
	if err != nil {
		return nil, nil, err
	}

	props := resp.Properties
	if props == nil {
		props = &armpolicy.AssignmentProperties{}
	}
	parameters, err := convert.JsonToDict(props.Parameters)
	if err != nil {
		return nil, nil, err
	}

	metadata, err := convert.JsonToDict(props.Metadata)
	if err != nil {
		return nil, nil, err
	}
	nonComplianceMessages, err := jsonToDictSlice(anySlice(props.NonComplianceMessages))
	if err != nil {
		return nil, nil, err
	}
	overrides, err := jsonToDictSlice(anySlice(props.Overrides))
	if err != nil {
		return nil, nil, err
	}
	resourceSelectors, err := jsonToDictSlice(anySlice(props.ResourceSelectors))
	if err != nil {
		return nil, nil, err
	}

	args["id"] = llx.StringDataPtr(props.PolicyDefinitionID)
	args["assignmentId"] = llx.StringDataPtr(resp.ID)
	args["name"] = llx.StringDataPtr(props.DisplayName)
	args["displayName"] = llx.StringDataPtr(props.DisplayName)
	args["scope"] = llx.StringDataPtr(props.Scope)
	args["description"] = llx.StringDataPtr(props.Description)
	args["enforcementMode"] = llx.StringData(string(convert.ToValue(props.EnforcementMode)))
	args["parameters"] = llx.DictData(parameters)

	// Every field the list path sets must also be set here. An init that leaves
	// one out degrades that field to null for the whole list in the same scan.
	args["notScopes"] = llx.ArrayData(strPtrsToAny(props.NotScopes), types.String)
	args["assignmentType"] = llx.StringData(string(convert.ToValue(props.AssignmentType)))
	args["definitionVersion"] = llx.StringDataPtr(props.DefinitionVersion)
	args["effectiveDefinitionVersion"] = llx.StringDataPtr(props.EffectiveDefinitionVersion)
	args["latestDefinitionVersion"] = llx.StringDataPtr(props.LatestDefinitionVersion)
	args["metadata"] = llx.DictData(metadata)
	args["nonComplianceMessages"] = llx.ArrayData(nonComplianceMessages, types.Dict)
	args["overrides"] = llx.ArrayData(overrides, types.Dict)
	args["resourceSelectors"] = llx.ArrayData(resourceSelectors, types.Dict)
	args["location"] = llx.StringDataPtr(resp.Location)
	args["selfServeExemptionEnabled"], args["selfServeExemptionPolicyDefinitionReferenceIds"] = selfServeExemptionFields(selfServeFromSDK(props.SelfServeExemptionSettings))
	if resp.Identity != nil {
		args["identityType"] = llx.StringData(string(convert.ToValue(resp.Identity.Type)))
		args["principalId"] = llx.StringDataPtr(resp.Identity.PrincipalID)
		args["tenantId"] = llx.StringDataPtr(resp.Identity.TenantID)
	} else {
		args["identityType"] = llx.StringData("")
		args["principalId"] = llx.StringData("")
		args["tenantId"] = llx.StringData("")
	}

	return args, nil, nil
}

// anySlice widens a typed pointer slice so it can be serialized element by
// element without naming each SDK type.
func anySlice[T any](in []*T) []any {
	out := make([]any, 0, len(in))
	for _, item := range in {
		if item != nil {
			out = append(out, item)
		}
	}
	return out
}

func (a *mqlAzureSubscriptionPolicy) assignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	armConn, err := getArmSecurityConnection(ctx, conn, subId)
	if err != nil {
		return nil, err
	}

	// The unfiltered subscription list also returns assignments inherited from the
	// management groups that contain the subscription; their scope is a
	// managementGroups path rather than the subscription. Every returned assignment
	// is mapped, inherited ones included.
	pas, err := getPolicyAssignments(ctx, armConn)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, assignment := range pas.PolicyAssignments {
		assignmentData, err := policyAssignmentArgs(assignment)
		if err != nil {
			return nil, err
		}

		mqlAssignment, err := CreateResource(a.MqlRuntime, "azure.subscription.policy.assignment", assignmentData)
		if err != nil {
			return nil, err
		}

		sysData, err := convert.JsonToDict(assignment.SystemData)
		if err != nil {
			return nil, err
		}
		mqlAssignment.(*mqlAzureSubscriptionPolicyAssignment).cacheSystemData = sysData

		res = append(res, mqlAssignment)
	}
	return res, nil
}

type mqlAzureSubscriptionPolicyAssignmentInternal struct {
	cacheSystemData any
}

// Keyed on the assignment's own ID, not on Id (which holds the assigned
// definition's ID). Two assignments of the same built-in definition at
// different scopes would otherwise share a synthetic system-data ID and the
// first one cached would be reported for both.
func (a *mqlAzureSubscriptionPolicyAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.AssignmentId.Data, a.cacheSystemData, &a.SystemMetadata)
}

// policyDefinition resolves the definition the assignment applies. Null when it
// cannot be read, which happens for an initiative (a policy set, a different
// resource type) and for a definition held at a management group the credential
// cannot see.
func (a *mqlAzureSubscriptionPolicyAssignment) policyDefinition() (*mqlAzureSubscriptionPolicyDefinition, error) {
	id := a.Id.Data
	if id == "" {
		a.PolicyDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.policy.definition",
		map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		log.Debug().Err(err).Str("id", id).Msg("could not resolve policy definition")
		a.PolicyDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAzureSubscriptionPolicyDefinition), nil
}

// initAzureSubscriptionPolicyDefinition resolves a policy definition by its
// resource ID, so a reference to one from an assignment does not require
// listing every definition visible to the subscription. Built-in definitions
// live under /providers/Microsoft.Authorization and are fetched with the
// built-in client; custom ones are scoped to a subscription or management
// group.
func initAzureSubscriptionPolicyDefinition(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	// Already fetched by an earlier reference: NewResource consults the cache
	// only after this init returns, so without this a definition assigned many
	// times is fetched once per assignment.
	if cached := cachedResource(runtime, "azure.subscription.policy.definition", id); cached != nil {
		return args, cached, nil
	}

	clientFactory, err := policyClientFactory(conn, conn.SubId())
	if err != nil {
		return nil, nil, err
	}

	name := policyDefinitionNameFromID(id)
	if name == "" {
		return nil, nil, fmt.Errorf("policy definition id %q names no definition", id)
	}
	client := clientFactory.NewDefinitionsClient()

	var def *armpolicy.Definition
	if strings.Contains(strings.ToLower(id), "/providers/microsoft.management/managementgroups/") {
		mgID, mgErr := managementGroupFromScope(id)
		if mgErr != nil {
			return nil, nil, mgErr
		}
		resp, getErr := client.GetAtManagementGroup(context.Background(), name, mgID, nil)
		if getErr != nil {
			return nil, nil, getErr
		}
		def = &resp.Definition
	} else if strings.Contains(strings.ToLower(id), "/subscriptions/") {
		resp, getErr := client.Get(context.Background(), name, nil)
		if getErr != nil {
			return nil, nil, getErr
		}
		def = &resp.Definition
	} else {
		resp, getErr := client.GetBuiltIn(context.Background(), name, nil)
		if getErr != nil {
			return nil, nil, getErr
		}
		def = &resp.Definition
	}

	res, err := newMqlPolicyDefinition(runtime, def)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// policyDefinitionNameFromID returns the last segment of a policy definition
// resource ID, which is the name the definitions client takes.
//
// ParseResourceID is deliberately not used here. It requires a subscription in
// the ID and errors without one, which rejects both of the shapes that matter
// most: a built-in definition (/providers/Microsoft.Authorization/policyDefinitions/{name})
// and a management-group-scoped one. Built-ins back the majority of
// assignments, so routing through ParseResourceID would fail the common case.
func policyDefinitionNameFromID(id string) string {
	id = strings.TrimSuffix(id, "/")
	i := strings.LastIndex(id, "/")
	if i < 0 {
		return id
	}
	return id[i+1:]
}

// managementGroupFromScope pulls the management group name out of a definition
// ID scoped to one.
func managementGroupFromScope(id string) (string, error) {
	const marker = "/providers/Microsoft.Management/managementGroups/"
	lower := strings.ToLower(id)
	idx := strings.Index(lower, strings.ToLower(marker))
	if idx < 0 {
		return "", fmt.Errorf("policy definition id %q is not management-group scoped", id)
	}
	rest := id[idx+len(marker):]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		rest = rest[:slash]
	}
	if rest == "" {
		return "", fmt.Errorf("policy definition id %q has an empty management group", id)
	}
	return rest, nil
}

// policyAssignmentArgs maps a single policy assignment to the resource fields.
// The assignment's scope is preserved verbatim, so subscription-scoped and
// management-group-inherited assignments are surfaced identically.
func policyAssignmentArgs(assignment PolicyAssignment) (map[string]*llx.RawData, error) {
	parameters, err := convert.JsonToDict(assignment.Properties.Parameters)
	if err != nil {
		return nil, err
	}

	metadata, err := convert.JsonToDict(assignment.Properties.Metadata)
	if err != nil {
		return nil, err
	}
	nonComplianceMessages, err := jsonToDictSlice(assignment.Properties.NonComplianceMessages)
	if err != nil {
		return nil, err
	}
	overrides, err := jsonToDictSlice(assignment.Properties.Overrides)
	if err != nil {
		return nil, err
	}
	resourceSelectors, err := jsonToDictSlice(assignment.Properties.ResourceSelectors)
	if err != nil {
		return nil, err
	}
	notScopes := []any{}
	for _, s := range assignment.Properties.NotScopes {
		if str, ok := s.(string); ok {
			notScopes = append(notScopes, str)
		}
	}

	selfServeEnabled, selfServeRefIds := selfServeExemptionFields(assignment.Properties.SelfServeExemptionSettings)

	return map[string]*llx.RawData{
		"selfServeExemptionEnabled":                      selfServeEnabled,
		"selfServeExemptionPolicyDefinitionReferenceIds": selfServeRefIds,

		"id":              llx.StringData(assignment.Properties.PolicyDefinitionID),
		"assignmentId":    llx.StringData(assignment.ID),
		"name":            llx.StringData(assignment.Properties.DisplayName),
		"displayName":     llx.StringData(assignment.Properties.DisplayName),
		"scope":           llx.StringData(assignment.Properties.Scope),
		"description":     llx.StringData(assignment.Properties.Description),
		"enforcementMode": llx.StringData(assignment.Properties.EnforcementMode),
		"parameters":      llx.DictData(parameters),

		"notScopes":                  llx.ArrayData(notScopes, types.String),
		"assignmentType":             llx.StringData(assignment.Properties.AssignmentType),
		"definitionVersion":          llx.StringData(assignment.Properties.DefinitionVersion),
		"effectiveDefinitionVersion": llx.StringData(assignment.Properties.EffectiveDefinitionVersion),
		"latestDefinitionVersion":    llx.StringData(assignment.Properties.LatestDefinitionVersion),
		"metadata":                   llx.DictData(metadata),
		"nonComplianceMessages":      llx.ArrayData(nonComplianceMessages, types.Dict),
		"overrides":                  llx.ArrayData(overrides, types.Dict),
		"resourceSelectors":          llx.ArrayData(resourceSelectors, types.Dict),
		"location":                   llx.StringData(assignment.Location),
		"identityType":               llx.StringData(assignment.Identity.Type),
		"principalId":                llx.StringData(assignment.Identity.PrincipalID),
		"tenantId":                   llx.StringData(assignment.Identity.TenantID),
	}, nil
}

// selfServeExemptionFields maps an assignment's self-serve exemption settings
// to the enabled flag and the covered definition reference IDs. Both are null
// when the assignment carries no settings; the ID list is also null when the
// settings omit it, since an empty list would claim no definition is covered.
func selfServeExemptionFields(settings *policySelfServeExemptionSettings) (enabled, refIds *llx.RawData) {
	if settings == nil {
		return llx.NilData, llx.NilData
	}
	refIds = llx.NilData
	if settings.PolicyDefinitionReferenceIDs != nil {
		refIds = llx.ArrayData(convert.SliceAnyToInterface(settings.PolicyDefinitionReferenceIDs), types.String)
	}
	return llx.BoolDataPtr(settings.Enabled), refIds
}

// selfServeFromSDK converts the SDK's settings to the shape the list path
// decodes, so both paths share selfServeExemptionFields. A nil ID list stays
// nil (absent), an empty one stays empty, and nil elements are dropped.
func selfServeFromSDK(in *armpolicy.SelfServeExemptionSettings) *policySelfServeExemptionSettings {
	if in == nil {
		return nil
	}
	out := &policySelfServeExemptionSettings{Enabled: in.Enabled}
	if in.PolicyDefinitionReferenceIDs != nil {
		out.PolicyDefinitionReferenceIDs = make([]string, 0, len(in.PolicyDefinitionReferenceIDs))
		for _, id := range in.PolicyDefinitionReferenceIDs {
			if id != nil {
				out.PolicyDefinitionReferenceIDs = append(out.PolicyDefinitionReferenceIDs, *id)
			}
		}
	}
	return out
}

// jsonToDictSlice converts a slice of open-ended API objects into the []dict
// shape MQL expects, one dict per element.
func jsonToDictSlice(in []any) ([]any, error) {
	out := []any{}
	for _, item := range in {
		d, err := convert.JsonToDict(item)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func policyClientFactory(conn *connection.AzureConnection, subId string) (*armpolicy.ClientFactory, error) {
	return armpolicy.NewClientFactory(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
}

func (a *mqlAzureSubscriptionPolicy) definitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	clientFactory, err := policyClientFactory(conn, a.SubscriptionId.Data)
	if err != nil {
		return nil, err
	}

	pager := clientFactory.NewDefinitionsClient().NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, def := range page.Value {
			if def == nil {
				continue
			}
			mqlDef, err := newMqlPolicyDefinition(a.MqlRuntime, def)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDef)
		}
	}
	return res, nil
}

func newMqlPolicyDefinition(runtime *plugin.Runtime, def *armpolicy.Definition) (plugin.Resource, error) {
	props := def.Properties
	if props == nil {
		props = &armpolicy.DefinitionProperties{}
	}

	metadata, err := convert.JsonToDict(props.Metadata)
	if err != nil {
		return nil, err
	}
	parameters, err := convert.JsonToDict(props.Parameters)
	if err != nil {
		return nil, err
	}
	policyRule, err := convert.JsonToDict(props.PolicyRule)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.policy.definition", map[string]*llx.RawData{
		"__id":        llx.StringDataPtr(def.ID),
		"id":          llx.StringDataPtr(def.ID),
		"name":        llx.StringDataPtr(def.Name),
		"displayName": llx.StringDataPtr(props.DisplayName),
		"description": llx.StringDataPtr(props.Description),
		"policyType":  llx.StringData(string(convert.ToValue(props.PolicyType))),
		"mode":        llx.StringDataPtr(props.Mode),
		"policyRule":  llx.DictData(policyRule),
		"parameters":  llx.DictData(parameters),
		"metadata":    llx.DictData(metadata),
		"version":     llx.StringDataPtr(props.Version),
	})
	if err != nil {
		return nil, err
	}

	sysData, err := convert.JsonToDict(def.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionPolicyDefinition).cacheSystemData = sysData

	return res, nil
}

type mqlAzureSubscriptionPolicyDefinitionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionPolicyDefinition) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionPolicy) setDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	clientFactory, err := policyClientFactory(conn, a.SubscriptionId.Data)
	if err != nil {
		return nil, err
	}

	pager := clientFactory.NewSetDefinitionsClient().NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, setDef := range page.Value {
			if setDef == nil {
				continue
			}
			props := setDef.Properties
			if props == nil {
				props = &armpolicy.SetDefinitionProperties{}
			}

			metadata, err := convert.JsonToDict(props.Metadata)
			if err != nil {
				return nil, err
			}
			parameters, err := convert.JsonToDict(props.Parameters)
			if err != nil {
				return nil, err
			}
			policyDefinitions, err := convert.JsonToDictSlice(props.PolicyDefinitions)
			if err != nil {
				return nil, err
			}

			mqlSetDef, err := CreateResource(a.MqlRuntime, "azure.subscription.policy.setDefinition", map[string]*llx.RawData{
				"__id":              llx.StringDataPtr(setDef.ID),
				"id":                llx.StringDataPtr(setDef.ID),
				"name":              llx.StringDataPtr(setDef.Name),
				"displayName":       llx.StringDataPtr(props.DisplayName),
				"description":       llx.StringDataPtr(props.Description),
				"policyType":        llx.StringData(string(convert.ToValue(props.PolicyType))),
				"policyDefinitions": llx.ArrayData(policyDefinitions, types.Dict),
				"parameters":        llx.DictData(parameters),
				"metadata":          llx.DictData(metadata),
				"version":           llx.StringDataPtr(props.Version),
			})
			if err != nil {
				return nil, err
			}

			sysData, err := convert.JsonToDict(setDef.SystemData)
			if err != nil {
				return nil, err
			}
			mqlSetDef.(*mqlAzureSubscriptionPolicySetDefinition).cacheSystemData = sysData

			res = append(res, mqlSetDef)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionPolicySetDefinitionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionPolicySetDefinition) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// azurePolicyExemption mirrors the Microsoft.Authorization/policyExemptions REST
// resource. Exemptions are not exposed by the armpolicy SDK, so they are fetched
// directly, like policy assignments above.
type azurePolicyExemption struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SystemData struct {
		CreatedAt      *time.Time `json:"createdAt"`
		LastModifiedAt *time.Time `json:"lastModifiedAt"`
	} `json:"systemData"`
	Properties struct {
		PolicyAssignmentID           string     `json:"policyAssignmentId"`
		PolicyDefinitionReferenceIDs []string   `json:"policyDefinitionReferenceIds"`
		ExemptionCategory            string     `json:"exemptionCategory"`
		ExemptionManagementMode      *string    `json:"exemptionManagementMode"`
		DisplayName                  string     `json:"displayName"`
		Description                  string     `json:"description"`
		ExpiresOn                    *time.Time `json:"expiresOn"`
		Metadata                     any        `json:"metadata"`
	} `json:"properties"`
}

// policyExemptionsAPIVersion is the first api-version that reports
// exemptionManagementMode. Exemptions only ship preview api-versions, and no
// Go SDK models them.
const policyExemptionsAPIVersion = "2025-12-01-preview"

type azurePolicyExemptionList struct {
	Value    []azurePolicyExemption `json:"value"`
	NextLink string                 `json:"nextLink"`
}

func (a *mqlAzureSubscriptionPolicy) exemptions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	armConn, err := getArmSecurityConnection(ctx, conn, subId)
	if err != nil {
		return nil, err
	}
	firstURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/policyExemptions?api-version=%s",
		armConn.host, subId, policyExemptionsAPIVersion)

	res := []any{}
	err = fetchArmPages(ctx, armConn.GetToken, firstURL, "policy exemptions", func(raw []byte) (string, error) {
		list := azurePolicyExemptionList{}
		if err := json.Unmarshal(raw, &list); err != nil {
			return "", err
		}
		for i := range list.Value {
			mqlExemption, err := newMqlPolicyExemption(a.MqlRuntime, &list.Value[i])
			if err != nil {
				return "", err
			}
			res = append(res, mqlExemption)
		}
		return list.NextLink, nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func newMqlPolicyExemption(runtime *plugin.Runtime, exemption *azurePolicyExemption) (plugin.Resource, error) {
	metadata, err := convert.JsonToDict(exemption.Properties.Metadata)
	if err != nil {
		return nil, err
	}

	// the exemption scope is the resource ID without the policyExemptions suffix
	scope := exemption.ID
	const marker = "/providers/microsoft.authorization/policyexemptions/"
	if idx := strings.Index(strings.ToLower(scope), marker); idx >= 0 {
		scope = scope[:idx]
	}

	res, err := CreateResource(runtime, "azure.subscription.policy.exemption", map[string]*llx.RawData{
		"__id":                         llx.StringData(exemption.ID),
		"id":                           llx.StringData(exemption.ID),
		"name":                         llx.StringData(exemption.Name),
		"displayName":                  llx.StringData(exemption.Properties.DisplayName),
		"description":                  llx.StringData(exemption.Properties.Description),
		"exemptionCategory":            llx.StringData(exemption.Properties.ExemptionCategory),
		"managementMode":               llx.StringDataPtr(exemption.Properties.ExemptionManagementMode),
		"scope":                        llx.StringData(scope),
		"policyDefinitionReferenceIds": llx.ArrayData(convert.SliceAnyToInterface(exemption.Properties.PolicyDefinitionReferenceIDs), types.String),
		"expiresOn":                    llx.TimeDataPtr(exemption.Properties.ExpiresOn),
		"metadata":                     llx.DictData(metadata),
		"createdAt":                    llx.TimeDataPtr(exemption.SystemData.CreatedAt),
		"updatedAt":                    llx.TimeDataPtr(exemption.SystemData.LastModifiedAt),
	})
	if err != nil {
		return nil, err
	}
	mqlExemption := res.(*mqlAzureSubscriptionPolicyExemption)
	mqlExemption.cachePolicyAssignmentID = exemption.Properties.PolicyAssignmentID
	return mqlExemption, nil
}

// mqlAzureSubscriptionPolicyExemptionInternal caches the raw policy assignment
// ID so the typed policyAssignment() reference can resolve it lazily.
type mqlAzureSubscriptionPolicyExemptionInternal struct {
	cachePolicyAssignmentID string
}

func (a *mqlAzureSubscriptionPolicyExemption) policyAssignment() (*mqlAzureSubscriptionPolicyAssignment, error) {
	if a.cachePolicyAssignmentID == "" {
		a.PolicyAssignment.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(a.MqlRuntime, "azure.subscription.policy.assignment", map[string]*llx.RawData{
		"assignmentId": llx.StringData(a.cachePolicyAssignmentID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionPolicyAssignment), nil
}

func initAzureSubscriptionPolicyComplianceSummary(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func (a *mqlAzureSubscriptionPolicyComplianceSummary) id() (string, error) {
	return "azure.subscription.policy.complianceSummary/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionPolicy) states() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := armpolicyinsights.NewPolicyStatesClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListQueryResultsForSubscriptionPager(armpolicyinsights.PolicyStatesResourceLatest, a.SubscriptionId.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ps := range page.Value {
			if ps == nil {
				continue
			}
			resourceId := convert.ToValue(ps.ResourceID)
			policyAssignmentId := convert.ToValue(ps.PolicyAssignmentID)
			policyDefinitionId := convert.ToValue(ps.PolicyDefinitionID)
			policySetDefinitionId := convert.ToValue(ps.PolicySetDefinitionID)
			policyDefinitionReferenceId := convert.ToValue(ps.PolicyDefinitionReferenceID)
			// A compliance state is unique per (resource, assignment, definition
			// reference); there is no single stable ID the API returns, so key on
			// the composite.
			stateId := resourceId + "/" + policyAssignmentId + "/" + policyDefinitionReferenceId
			mqlState, err := CreateResource(a.MqlRuntime, "azure.subscription.policy.state", map[string]*llx.RawData{
				"__id":                        llx.StringData(stateId),
				"complianceState":             llx.StringData(convert.ToValue(ps.ComplianceState)),
				"resourceId":                  llx.StringData(resourceId),
				"resourceType":                llx.StringData(convert.ToValue(ps.ResourceType)),
				"resourceGroup":               llx.StringData(convert.ToValue(ps.ResourceGroup)),
				"resourceLocation":            llx.StringData(convert.ToValue(ps.ResourceLocation)),
				"policyAssignmentName":        llx.StringData(convert.ToValue(ps.PolicyAssignmentName)),
				"policyAssignmentScope":       llx.StringData(convert.ToValue(ps.PolicyAssignmentScope)),
				"policyDefinitionName":        llx.StringData(convert.ToValue(ps.PolicyDefinitionName)),
				"policyDefinitionReferenceId": llx.StringData(policyDefinitionReferenceId),
				"policyDefinitionAction":      llx.StringData(convert.ToValue(ps.PolicyDefinitionAction)),
				"policyDefinitionCategory":    llx.StringData(convert.ToValue(ps.PolicyDefinitionCategory)),
				"policySetDefinitionName":     llx.StringData(convert.ToValue(ps.PolicySetDefinitionName)),
				"timestamp":                   llx.TimeDataPtr(ps.Timestamp),
			})
			if err != nil {
				return nil, err
			}
			st := mqlState.(*mqlAzureSubscriptionPolicyState)
			st.subscriptionId = a.SubscriptionId.Data
			st.policyAssignmentId = policyAssignmentId
			st.policyDefinitionId = policyDefinitionId
			st.policySetDefinitionId = policySetDefinitionId
			res = append(res, mqlState)
		}
	}
	return res, nil
}

// mqlAzureSubscriptionPolicyStateInternal caches the raw assignment, definition,
// and set-definition IDs so the typed references can resolve them lazily against
// the subscription's policy collections.
type mqlAzureSubscriptionPolicyStateInternal struct {
	subscriptionId        string
	policyAssignmentId    string
	policyDefinitionId    string
	policySetDefinitionId string
}

// policyForState returns the subscription's policy resource, whose assignment,
// definition, and set-definition lists are cached and shared across all states.
func (a *mqlAzureSubscriptionPolicyState) policyForState() (*mqlAzureSubscriptionPolicy, error) {
	res, err := CreateResource(a.MqlRuntime, "azure.subscription.policy", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.subscriptionId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionPolicy), nil
}

func (a *mqlAzureSubscriptionPolicyState) policyAssignment() (*mqlAzureSubscriptionPolicyAssignment, error) {
	if a.policyAssignmentId == "" {
		a.PolicyAssignment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pol, err := a.policyForState()
	if err != nil {
		return nil, err
	}
	list := pol.GetAssignments()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, x := range list.Data {
		asg, ok := x.(*mqlAzureSubscriptionPolicyAssignment)
		if ok && strings.EqualFold(asg.AssignmentId.Data, a.policyAssignmentId) {
			return asg, nil
		}
	}
	a.PolicyAssignment.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAzureSubscriptionPolicyState) policyDefinition() (*mqlAzureSubscriptionPolicyDefinition, error) {
	if a.policyDefinitionId == "" {
		a.PolicyDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pol, err := a.policyForState()
	if err != nil {
		return nil, err
	}
	list := pol.GetDefinitions()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, x := range list.Data {
		def, ok := x.(*mqlAzureSubscriptionPolicyDefinition)
		if ok && strings.EqualFold(def.Id.Data, a.policyDefinitionId) {
			return def, nil
		}
	}
	a.PolicyDefinition.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAzureSubscriptionPolicyState) policySetDefinition() (*mqlAzureSubscriptionPolicySetDefinition, error) {
	if a.policySetDefinitionId == "" {
		a.PolicySetDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pol, err := a.policyForState()
	if err != nil {
		return nil, err
	}
	list := pol.GetSetDefinitions()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, x := range list.Data {
		setDef, ok := x.(*mqlAzureSubscriptionPolicySetDefinition)
		if ok && strings.EqualFold(setDef.Id.Data, a.policySetDefinitionId) {
			return setDef, nil
		}
	}
	a.PolicySetDefinition.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAzureSubscriptionPolicy) complianceSummary() (*mqlAzureSubscriptionPolicyComplianceSummary, error) {
	res, err := NewResource(a.MqlRuntime, "azure.subscription.policy.complianceSummary", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionPolicyComplianceSummary), nil
}

// mqlAzureSubscriptionPolicyComplianceSummaryInternal caches the single
// SummarizeForSubscription response so every compliance field shares one call.
type mqlAzureSubscriptionPolicyComplianceSummaryInternal struct {
	fetched                     atomic.Bool
	lock                        sync.Mutex
	cachedNonCompliantResources int64
	cachedNonCompliantPolicies  int64
	cachedResourceCounts        map[string]any
	cachedPolicyCounts          map[string]any
	cachedAssignments           []any
}

func (a *mqlAzureSubscriptionPolicyComplianceSummary) fetchSummary() error {
	if a.fetched.Load() {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched.Load() {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := armpolicyinsights.NewPolicyStatesClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return err
	}

	resp, err := client.SummarizeForSubscription(ctx, armpolicyinsights.PolicyStatesSummaryResourceTypeLatest, a.SubscriptionId.Data, nil)
	if err != nil {
		return err
	}

	a.cachedResourceCounts = map[string]any{}
	a.cachedPolicyCounts = map[string]any{}
	a.cachedAssignments = []any{}

	if len(resp.Value) > 0 && resp.Value[0] != nil {
		summary := resp.Value[0]
		if results := summary.Results; results != nil {
			a.cachedNonCompliantResources = int64(convert.ToValue(results.NonCompliantResources))
			a.cachedNonCompliantPolicies = int64(convert.ToValue(results.NonCompliantPolicies))
			a.cachedResourceCounts = complianceCounts(results.ResourceDetails)
			a.cachedPolicyCounts = complianceCounts(results.PolicyDetails)
		}
		for _, pa := range summary.PolicyAssignments {
			if pa == nil {
				continue
			}
			entry := map[string]any{
				"policyAssignmentId":    convert.ToValue(pa.PolicyAssignmentID),
				"policySetDefinitionId": convert.ToValue(pa.PolicySetDefinitionID),
				"nonCompliantResources": int64(0),
				"nonCompliantPolicies":  int64(0),
			}
			if pa.Results != nil {
				entry["nonCompliantResources"] = int64(convert.ToValue(pa.Results.NonCompliantResources))
				entry["nonCompliantPolicies"] = int64(convert.ToValue(pa.Results.NonCompliantPolicies))
			}
			a.cachedAssignments = append(a.cachedAssignments, entry)
		}
	}

	a.fetched.Store(true)
	return nil
}

func (a *mqlAzureSubscriptionPolicyComplianceSummary) nonCompliantResources() (int64, error) {
	if err := a.fetchSummary(); err != nil {
		return 0, err
	}
	return a.cachedNonCompliantResources, nil
}

func (a *mqlAzureSubscriptionPolicyComplianceSummary) nonCompliantPolicies() (int64, error) {
	if err := a.fetchSummary(); err != nil {
		return 0, err
	}
	return a.cachedNonCompliantPolicies, nil
}

func (a *mqlAzureSubscriptionPolicyComplianceSummary) resourceComplianceCounts() (map[string]any, error) {
	if err := a.fetchSummary(); err != nil {
		return nil, err
	}
	return a.cachedResourceCounts, nil
}

func (a *mqlAzureSubscriptionPolicyComplianceSummary) policyComplianceCounts() (map[string]any, error) {
	if err := a.fetchSummary(); err != nil {
		return nil, err
	}
	return a.cachedPolicyCounts, nil
}

func (a *mqlAzureSubscriptionPolicyComplianceSummary) assignments() ([]any, error) {
	if err := a.fetchSummary(); err != nil {
		return nil, err
	}
	return a.cachedAssignments, nil
}

func complianceCounts(details []*armpolicyinsights.ComplianceDetail) map[string]any {
	counts := map[string]any{}
	for _, d := range details {
		if d == nil || d.ComplianceState == nil {
			continue
		}
		counts[*d.ComplianceState] = int64(convert.ToValue(d.Count))
	}
	return counts
}
