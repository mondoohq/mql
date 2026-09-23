// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"go.mondoo.com/mql/providers/azure/connection"
)

type armSecurityConn struct {
	subscriptionId string
	host           string
	token          azcore.TokenCredential
}

func (a armSecurityConn) GetToken(ctx context.Context) (azcore.AccessToken, error) {
	return a.token.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.core.windows.net//.default"},
	})
}

func getArmSecurityConnection(ctx context.Context, conn *connection.AzureConnection, subId string) (armSecurityConn, error) {
	token := conn.Token()

	ep := cloud.AzurePublic.Services[cloud.ResourceManager].Endpoint
	return armSecurityConn{subId, ep, token}, nil
}

func getPolicyAssignments(ctx context.Context, conn armSecurityConn) (PolicyAssignments, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments"
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(conn.subscriptionId))
	urlPath = runtime.JoinPaths(conn.host, urlPath)

	// Build the first request URL with the api-version query parameter. The
	// service returns a fully-formed absolute nextLink for subsequent pages, so
	// we only need to assemble the query on the initial request.
	firstURL, err := url.Parse(urlPath)
	if err != nil {
		return PolicyAssignments{}, err
	}
	q := firstURL.Query()
	// Pinned to the api-version the armpolicy SDK uses for the single-assignment
	// lookup, so both paths return the same property set. Versions before
	// 2023-04-01 omit the definition-version fields, before 2024-04-01 omit
	// assignmentType, and before 2025-11-01 omit selfServeExemptionSettings.
	q.Set("api-version", policyAssignmentsAPIVersion)
	firstURL.RawQuery = q.Encode()

	result := PolicyAssignments{}
	err = fetchArmPages(ctx, conn.GetToken, firstURL.String(), "policy assignments", func(raw []byte) (string, error) {
		page := PolicyAssignments{}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		result.PolicyAssignments = append(result.PolicyAssignments, page.PolicyAssignments...)
		if page.NextLink == nil {
			return "", nil
		}
		return *page.NextLink, nil
	})
	if err != nil {
		return PolicyAssignments{}, err
	}
	return result, nil
}

// mdvmSelectedProvider is the value ARM reports when a subscription's server
// vulnerability assessment is Microsoft Defender Vulnerability Management.
const mdvmSelectedProvider = "MdeTvm"

// azureServersSetting identifies the subscription-wide server VA setting.
//
// ARM spells it two ways on the same record, differing only in the leading
// capital: "AzureServersSetting" is the kind (the discriminator) and
// "azureServersSetting" is the resource name. The SDK models them as two
// separate enums for that reason.
const azureServersSetting = "azureServersSetting"

// mdvmVulnerabilityAssessmentEnabled reports whether any server VA setting
// selects Microsoft Defender Vulnerability Management.
//
// It matches either field, case-insensitively, rather than picking one: the
// call behind these records is pinned to an older api-version whose casing we
// cannot assume, and matching the wrong one is silent -- the loop simply never
// fires and the subscription reports no vulnerability management tool.
func mdvmVulnerabilityAssessmentEnabled(settings []ServerVulnerabilityAssessmentsSettings) bool {
	for _, sett := range settings {
		if !strings.EqualFold(sett.Properties.SelectedProvider, mdvmSelectedProvider) {
			continue
		}
		if strings.EqualFold(sett.Kind, azureServersSetting) ||
			strings.EqualFold(sett.Name, azureServersSetting) {
			return true
		}
	}
	return false
}

func getServerVulnAssessmentSettings(ctx context.Context, conn armSecurityConn) (ServerVulnerabilityAssessmentsSettingsList, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings"
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(conn.subscriptionId))
	urlPath = runtime.JoinPaths(conn.host, urlPath)

	firstURL, err := url.Parse(urlPath)
	if err != nil {
		return ServerVulnerabilityAssessmentsSettingsList{}, err
	}
	q := firstURL.Query()
	q.Set("api-version", "2022-01-01-preview")
	firstURL.RawQuery = q.Encode()

	result := ServerVulnerabilityAssessmentsSettingsList{}
	err = fetchArmPages(ctx, conn.GetToken, firstURL.String(), "server vulnerability assessment settings", func(raw []byte) (string, error) {
		page := ServerVulnerabilityAssessmentsSettingsList{}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", err
		}
		result.Settings = append(result.Settings, page.Settings...)
		if page.NextLink == nil {
			return "", nil
		}
		return *page.NextLink, nil
	})
	if err != nil {
		return ServerVulnerabilityAssessmentsSettingsList{}, err
	}
	return result, nil
}

// https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/policyassignments?pivots=deployment-language-bicep#property-values
type PolicyAssignment struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	Location   string `json:"location,omitempty"`
	SystemData any    `json:"systemData,omitempty"`
	Identity   struct {
		Type        string `json:"type"`
		PrincipalID string `json:"principalId"`
		TenantID    string `json:"tenantId"`
	} `json:"identity,omitempty"`
	Properties struct {
		DisplayName     string `json:"displayName"`
		Description     string `json:"description"`
		AssignmentType  string `json:"assignmentType"`
		EnforcementMode string `json:"enforcementMode"`
		// Metadata is open-ended: Azure and tooling write arbitrary keys here
		// (assignedBy, createdBy, category, and more). Modeling it as a closed
		// struct silently drops everything except the named key.
		Metadata                   map[string]any `json:"metadata"`
		DefinitionVersion          string         `json:"definitionVersion"`
		EffectiveDefinitionVersion string         `json:"effectiveDefinitionVersion"`
		LatestDefinitionVersion    string         `json:"latestDefinitionVersion"`
		NonComplianceMessages      []any          `json:"nonComplianceMessages"`
		Overrides                  []any          `json:"overrides"`
		ResourceSelectors          []any          `json:"resourceSelectors"`
		PolicyDefinitionID         string         `json:"policyDefinitionId"`
		// Parameters is an open map keyed by parameter name, each value an
		// object of the form {"value": <any>}. It must not be modeled as a
		// closed struct: the parameter set differs per policy definition, and
		// naming a fixed subset both drops every other parameter and reports
		// the named ones as present-but-empty on assignments that lack them.
		Parameters map[string]any `json:"parameters"`
		Scope      string         `json:"scope"`
		NotScopes  []any          `json:"notScopes"`
		// Pointer so an assignment without self-serve settings stays
		// distinguishable from one that explicitly disables them.
		SelfServeExemptionSettings *policySelfServeExemptionSettings `json:"selfServeExemptionSettings"`
	} `json:"properties"`
}

// policyAssignmentsAPIVersion matches the armpolicy SDK's api-version.
const policyAssignmentsAPIVersion = "2026-06-01"

type policySelfServeExemptionSettings struct {
	Enabled                      *bool    `json:"enabled"`
	PolicyDefinitionReferenceIDs []string `json:"policyDefinitionReferenceIds"`
}

type PolicyAssignments struct {
	PolicyAssignments []PolicyAssignment `json:"value"`
	NextLink          *string            `json:"nextLink"`
}

type ServerVulnerabilityAssessmentsSettings struct {
	Properties struct {
		SelectedProvider string `json:"selectedProvider"`
	} `json:"properties"`
	SystemData struct {
		CreatedBy          string    `json:"createdBy"`
		CreatedByType      string    `json:"createdByType"`
		CreatedAt          time.Time `json:"createdAt"`
		LastModifiedBy     string    `json:"lastModifiedBy"`
		LastModifiedByType string    `json:"lastModifiedByType"`
		LastModifiedAt     time.Time `json:"lastModifiedAt"`
	} `json:"systemData"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Type string `json:"type"`
	ID   string `json:"id"`
}

type ServerVulnerabilityAssessmentsSettingsList struct {
	Settings []ServerVulnerabilityAssessmentsSettings `json:"value"`
	// The endpoint is paginated. Without this field the cursor was discarded at
	// unmarshal, so the settings past the first page were not merely unfetched
	// but invisible -- there was nothing to notice.
	NextLink *string `json:"nextLink"`
}
