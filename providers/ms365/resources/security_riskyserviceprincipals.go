// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/identityprotection"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// riskyServicePrincipalsFilter selects the service principals that are
// currently at risk, using the same states as riskyUsersFilter.
const riskyServicePrincipalsFilter = "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"

const (
	permIdentityRiskyServicePrincipalReadAll = "IdentityRiskyServicePrincipal.Read.All"
	permIdentityRiskEventReadAll             = "IdentityRiskEvent.Read.All"
)

type mqlMicrosoftSecurityServicePrincipalRiskDetectionInternal struct {
	cacheServicePrincipalId *string
}

// riskyServicePrincipals returns the workload identities Microsoft Entra ID
// Protection reports as at risk.
// requires IdentityRiskyServicePrincipal.Read.All permission and a
// Microsoft Entra Workload ID Premium license
// see https://learn.microsoft.com/en-us/graph/api/identityprotectionroot-list-riskyserviceprincipals
func (a *mqlMicrosoftSecurity) riskyServicePrincipals() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	filter := riskyServicePrincipalsFilter
	resp, err := graphClient.IdentityProtection().RiskyServicePrincipals().Get(ctx, &identityprotection.RiskyServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &identityprotection.RiskyServicePrincipalsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	})
	if err != nil {
		return nil, classifyWorkloadIdentityProtectionError(err, permIdentityRiskyServicePrincipalReadAll)
	}
	sps, err := iterate[models.RiskyServicePrincipalable](ctx, resp, graphClient.GetAdapter(), models.CreateRiskyServicePrincipalCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyWorkloadIdentityProtectionError(err, permIdentityRiskyServicePrincipalReadAll)
	}

	res := []any{}
	for i := range sps {
		if sps[i] == nil {
			continue
		}
		mqlResource, err := newMqlMicrosoftRiskyServicePrincipal(a.MqlRuntime, sps[i])
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}
	return res, nil
}

func newMqlMicrosoftRiskyServicePrincipal(runtime *plugin.Runtime, sp models.RiskyServicePrincipalable) (*mqlMicrosoftSecurityRiskyServicePrincipal, error) {
	mqlResource, err := CreateResource(runtime, "microsoft.security.riskyServicePrincipal", riskyServicePrincipalArgs(sp))
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftSecurityRiskyServicePrincipal), nil
}

func riskyServicePrincipalArgs(sp models.RiskyServicePrincipalable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                    llx.StringDataPtr(sp.GetId()),
		"id":                      llx.StringDataPtr(sp.GetId()),
		"appId":                   llx.StringDataPtr(sp.GetAppId()),
		"displayName":             llx.StringDataPtr(sp.GetDisplayName()),
		"servicePrincipalType":    llx.StringDataPtr(sp.GetServicePrincipalType()),
		"isEnabled":               llx.BoolDataPtr(sp.GetIsEnabled()),
		"isProcessing":            llx.BoolDataPtr(sp.GetIsProcessing()),
		"riskLevel":               llx.StringDataPtr(enumPtrString(sp.GetRiskLevel())),
		"riskState":               llx.StringDataPtr(enumPtrString(sp.GetRiskState())),
		"riskDetail":              llx.StringDataPtr(enumPtrString(sp.GetRiskDetail())),
		"riskLastUpdatedDateTime": llx.TimeDataPtr(sp.GetRiskLastUpdatedDateTime()),
	}
}

// servicePrincipal resolves the service principal behind the risky entry. The
// risky service principal id is the service principal's object id.
func (r *mqlMicrosoftSecurityRiskyServicePrincipal) servicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	return resolveRiskServicePrincipal(r.MqlRuntime, r.Id.Data, &r.ServicePrincipal)
}

// servicePrincipalRiskDetections returns Microsoft Entra ID Protection risk
// detections raised against workload identities.
// requires IdentityRiskEvent.Read.All permission and a Microsoft Entra
// Workload ID Premium license
// see https://learn.microsoft.com/en-us/graph/api/identityprotectionroot-list-serviceprincipalriskdetections
func (a *mqlMicrosoftSecurity) servicePrincipalRiskDetections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	resp, err := graphClient.IdentityProtection().ServicePrincipalRiskDetections().Get(ctx, nil)
	if err != nil {
		return nil, classifyWorkloadIdentityProtectionError(err, permIdentityRiskEventReadAll)
	}
	detections, err := iterate[models.ServicePrincipalRiskDetectionable](ctx, resp, graphClient.GetAdapter(), models.CreateServicePrincipalRiskDetectionCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyWorkloadIdentityProtectionError(err, permIdentityRiskEventReadAll)
	}

	res := []any{}
	for i := range detections {
		if detections[i] == nil {
			continue
		}
		mqlResource, err := newMqlMicrosoftServicePrincipalRiskDetection(a.MqlRuntime, detections[i])
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}
	return res, nil
}

func newMqlMicrosoftServicePrincipalRiskDetection(runtime *plugin.Runtime, d models.ServicePrincipalRiskDetectionable) (*mqlMicrosoftSecurityServicePrincipalRiskDetection, error) {
	mqlResource, err := CreateResource(runtime, "microsoft.security.servicePrincipalRiskDetection", servicePrincipalRiskDetectionArgs(d))
	if err != nil {
		return nil, err
	}
	resource := mqlResource.(*mqlMicrosoftSecurityServicePrincipalRiskDetection)
	resource.cacheServicePrincipalId = d.GetServicePrincipalId()
	return resource, nil
}

func servicePrincipalRiskDetectionArgs(d models.ServicePrincipalRiskDetectionable) map[string]*llx.RawData {
	var city, state, countryOrRegion *string
	if loc := d.GetLocation(); loc != nil {
		city = loc.GetCity()
		state = loc.GetState()
		countryOrRegion = loc.GetCountryOrRegion()
	}

	keyIds := []any{}
	for _, k := range d.GetKeyIds() {
		keyIds = append(keyIds, k)
	}

	return map[string]*llx.RawData{
		"__id":                        llx.StringDataPtr(d.GetId()),
		"id":                          llx.StringDataPtr(d.GetId()),
		"riskEventType":               llx.StringDataPtr(d.GetRiskEventType()),
		"riskState":                   llx.StringDataPtr(enumPtrString(d.GetRiskState())),
		"riskLevel":                   llx.StringDataPtr(enumPtrString(d.GetRiskLevel())),
		"riskDetail":                  llx.StringDataPtr(enumPtrString(d.GetRiskDetail())),
		"source":                      llx.StringDataPtr(d.GetSource()),
		"detectionTimingType":         llx.StringDataPtr(enumPtrString(d.GetDetectionTimingType())),
		"activity":                    llx.StringDataPtr(enumPtrString(d.GetActivity())),
		"tokenIssuerType":             llx.StringDataPtr(enumPtrString(d.GetTokenIssuerType())),
		"ipAddress":                   llx.StringDataPtr(d.GetIpAddress()),
		"city":                        llx.StringDataPtr(city),
		"state":                       llx.StringDataPtr(state),
		"countryOrRegion":             llx.StringDataPtr(countryOrRegion),
		"keyIds":                      llx.ArrayData(keyIds, "string"),
		"servicePrincipalDisplayName": llx.StringDataPtr(d.GetServicePrincipalDisplayName()),
		"correlationId":               llx.StringDataPtr(d.GetCorrelationId()),
		"requestId":                   llx.StringDataPtr(d.GetRequestId()),
		"additionalInfo":              llx.StringDataPtr(d.GetAdditionalInfo()),
		"activityDateTime":            llx.TimeDataPtr(d.GetActivityDateTime()),
		"detectedDateTime":            llx.TimeDataPtr(d.GetDetectedDateTime()),
		"lastUpdatedDateTime":         llx.TimeDataPtr(d.GetLastUpdatedDateTime()),
	}
}

// servicePrincipal resolves the service principal the detection was raised against.
func (r *mqlMicrosoftSecurityServicePrincipalRiskDetection) servicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	id := ""
	if r.cacheServicePrincipalId != nil {
		id = *r.cacheServicePrincipalId
	}
	return resolveRiskServicePrincipal(r.MqlRuntime, id, &r.ServicePrincipal)
}

// resolveRiskServicePrincipal looks up a service principal by object id
// through the tenant's cached service principal list. A risk entry can outlive
// the service principal it was raised against, so a deleted service principal
// reads as null rather than failing the field.
func resolveRiskServicePrincipal(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlMicrosoftServiceprincipal]) (*mqlMicrosoftServiceprincipal, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	sp, err := NewResource(runtime, "microsoft.serviceprincipal", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if errors.Is(err, errServicePrincipalNotFound) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return sp.(*mqlMicrosoftServiceprincipal), nil
}

// classifyWorkloadIdentityProtectionError maps a refused Identity Protection
// call for workload identities to its ADR 046 kind. Graph answers both a token
// without the required scope and a tenant without a Microsoft Entra Workload ID
// Premium license with HTTP 403 and the generic code "Forbidden", so the
// message is the only signal that tells the two apart: a refusal naming a
// missing license is NotApplicable, every other 403 is Forbidden with the
// permission the call needs. Anything else, including transport failures, is
// returned unclassified.
func classifyWorkloadIdentityProtectionError(err error, permission string) error {
	if graphStatusCode(err) == http.StatusForbidden && isNotLicensedMessage(graphErrorMessage(err)) {
		return llx.NotApplicable(transformError(err))
	}
	return classifyGraphError(err, permission)
}

// graphErrorMessage returns the message carried by a v1 Graph ODataError, or
// "" when there is none.
func graphErrorMessage(err error) string {
	var oDataErr *odataerrors.ODataError
	if errors.As(err, &oDataErr) && oDataErr != nil {
		if payload := oDataErr.GetErrorEscaped(); payload != nil && payload.GetMessage() != nil {
			return *payload.GetMessage()
		}
	}
	return ""
}

// isNotLicensedMessage reports whether a Graph error message says the tenant
// lacks the license for the feature, as in "Your tenant is not licensed for
// this feature."
func isNotLicensedMessage(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "not licensed") || strings.Contains(m, "license is required") || strings.Contains(m, "does not have a valid license")
}
