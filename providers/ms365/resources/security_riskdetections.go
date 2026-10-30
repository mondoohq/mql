// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

type mqlMicrosoftSecurityRiskDetectionInternal struct {
	cacheUserId *string
}

// enumPtrString renders a Graph enum pointer as its string value, or nil.
func enumPtrString[T interface{ String() string }](v *T) *string {
	if v == nil {
		return nil
	}
	s := (*v).String()
	return &s
}

// riskDetections returns Microsoft Entra ID Protection risk detections.
// requires IdentityRiskEvent.Read.All permission
// see https://learn.microsoft.com/en-us/graph/api/resources/riskdetection
func (a *mqlMicrosoftSecurity) riskDetections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	resp, err := graphClient.IdentityProtection().RiskDetections().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	detections, err := iterate[models.RiskDetectionable](ctx, resp, graphClient.GetAdapter(), models.CreateRiskDetectionCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range detections {
		mqlResource, err := newMqlMicrosoftRiskDetection(a.MqlRuntime, detections[i])
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}
	return res, nil
}

func newMqlMicrosoftRiskDetection(runtime *plugin.Runtime, d models.RiskDetectionable) (*mqlMicrosoftSecurityRiskDetection, error) {
	var city, state, countryOrRegion *string
	if loc := d.GetLocation(); loc != nil {
		city = loc.GetCity()
		state = loc.GetState()
		countryOrRegion = loc.GetCountryOrRegion()
	}

	mqlResource, err := CreateResource(runtime, "microsoft.security.riskDetection",
		map[string]*llx.RawData{
			"__id":                llx.StringDataPtr(d.GetId()),
			"id":                  llx.StringDataPtr(d.GetId()),
			"riskEventType":       llx.StringDataPtr(d.GetRiskEventType()),
			"riskState":           llx.StringDataPtr(enumPtrString(d.GetRiskState())),
			"riskLevel":           llx.StringDataPtr(enumPtrString(d.GetRiskLevel())),
			"riskDetail":          llx.StringDataPtr(enumPtrString(d.GetRiskDetail())),
			"source":              llx.StringDataPtr(d.GetSource()),
			"detectionTimingType": llx.StringDataPtr(enumPtrString(d.GetDetectionTimingType())),
			"activity":            llx.StringDataPtr(enumPtrString(d.GetActivity())),
			"ipAddress":           llx.StringDataPtr(d.GetIpAddress()),
			"city":                llx.StringDataPtr(city),
			"state":               llx.StringDataPtr(state),
			"countryOrRegion":     llx.StringDataPtr(countryOrRegion),
			"userPrincipalName":   llx.StringDataPtr(d.GetUserPrincipalName()),
			"userDisplayName":     llx.StringDataPtr(d.GetUserDisplayName()),
			"correlationId":       llx.StringDataPtr(d.GetCorrelationId()),
			"additionalInfo":      llx.StringDataPtr(d.GetAdditionalInfo()),
			"activityDateTime":    graphTimeData(d.GetActivityDateTime()),
			"detectedDateTime":    graphTimeData(d.GetDetectedDateTime()),
			"lastUpdatedDateTime": graphTimeData(d.GetLastUpdatedDateTime()),
		})
	if err != nil {
		return nil, err
	}
	resource := mqlResource.(*mqlMicrosoftSecurityRiskDetection)
	resource.cacheUserId = d.GetUserId()
	return resource, nil
}

// user resolves the Entra ID user the detection was raised against.
func (r *mqlMicrosoftSecurityRiskDetection) user() (*mqlMicrosoftUser, error) {
	if r.cacheUserId == nil || *r.cacheUserId == "" {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	user, err := NewResource(r.MqlRuntime, "microsoft.user", map[string]*llx.RawData{
		"id": llx.StringDataPtr(r.cacheUserId),
	})
	if err != nil {
		return nil, err
	}
	return user.(*mqlMicrosoftUser), nil
}
