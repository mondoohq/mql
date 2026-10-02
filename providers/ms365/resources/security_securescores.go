// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/security"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

func (m *mqlMicrosoftSecuritySecurityscore) id() (string, error) {
	return m.Id.Data, nil
}

func newMqlMicrosoftSecureScore(runtime *plugin.Runtime, score models.SecureScoreable) (*mqlMicrosoftSecuritySecurityscore, error) {
	if score == nil {
		return nil, nil
	}
	averageComparativeScores := []any{}
	graphAverageComparativeScores := score.GetAverageComparativeScores()
	for j := range graphAverageComparativeScores {
		entry, err := convert.JsonToDict(newAverageComparativeScore(graphAverageComparativeScores[j]))
		if err != nil {
			return nil, err
		}
		averageComparativeScores = append(averageComparativeScores, entry)
	}

	// controlScores is the deprecated raw-dict form; controls is the typed form.
	controlScores := []any{}
	controls := []any{}
	graphControlScores := score.GetControlScores()
	for j := range graphControlScores {
		cs := newControlScore(graphControlScores[j])
		if cs == nil {
			continue
		}
		entry, err := convert.JsonToDict(cs)
		if err != nil {
			return nil, err
		}
		controlScores = append(controlScores, entry)

		// __id must be unique per control within a score. controlName is the
		// natural key; fall back to the loop index when it is empty so unnamed
		// controls don't collide in the resource cache.
		controlName := convert.ToValue(cs.ControlName)
		controlID := convert.ToValue(score.GetId()) + "/" + controlName
		if controlName == "" {
			controlID = convert.ToValue(score.GetId()) + "/#" + strconv.Itoa(j)
		}
		csResource, err := CreateResource(runtime, "microsoft.security.securityscore.controlScore",
			map[string]*llx.RawData{
				"__id":            llx.StringData(controlID),
				"controlCategory": llx.StringDataPtr(cs.ControlCategory),
				"controlName":     llx.StringDataPtr(cs.ControlName),
				"description":     llx.StringDataPtr(cs.Description),
				"score":           llx.FloatData(convert.ToValue(cs.Score)),
			})
		if err != nil {
			return nil, err
		}
		controls = append(controls, csResource)
	}

	vendorInformation, err := convert.JsonToDict(newSecurityVendorInformation(score.GetVendorInformation()))
	if err != nil {
		return nil, err
	}

	enabledServices := []any{}
	for _, service := range score.GetEnabledServices() {
		enabledServices = append(enabledServices, service)
	}
	mqlResource, err := CreateResource(runtime, "microsoft.security.securityscore",
		map[string]*llx.RawData{
			"id":                       llx.StringDataPtr(score.GetId()),
			"activeUserCount":          llx.IntDataDefault(score.GetActiveUserCount(), 0),
			"averageComparativeScores": llx.ArrayData(averageComparativeScores, types.Any),
			"azureTenantId":            llx.StringDataPtr(score.GetAzureTenantId()),
			"controlScores":            llx.ArrayData(controlScores, types.Any),
			"controls":                 llx.ArrayData(controls, types.Resource("microsoft.security.securityscore.controlScore")),
			"createdDateTime":          graphTimeData(score.GetCreatedDateTime()),
			"currentScore":             llx.FloatData(convert.ToValue(score.GetCurrentScore())),
			"enabledServices":          llx.ArrayData(enabledServices, types.String),
			"licensedUserCount":        llx.IntDataDefault(score.GetLicensedUserCount(), 0),
			"maxScore":                 llx.FloatData(convert.ToValue(score.GetMaxScore())),
			"vendorInformation":        llx.DictData(vendorInformation),
		})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftSecuritySecurityscore), nil
}

func (a *mqlMicrosoftSecurity) latestSecureScores() (*mqlMicrosoftSecuritySecurityscore, error) {
	secureScores := a.GetSecureScores()
	if secureScores.Error != nil {
		return nil, secureScores.Error
	}
	if len(secureScores.Data) == 0 {
		return nil, errors.New("could not retrieve any score")
	}

	latest := secureScores.Data[0].(*mqlMicrosoftSecuritySecurityscore)
	for _, s := range secureScores.Data {
		mqlS := s.(*mqlMicrosoftSecuritySecurityscore)
		// createdDateTime is nilable; guard before dereferencing to avoid a panic.
		if mqlS.CreatedDateTime.Data == nil {
			continue
		}
		if latest.CreatedDateTime.Data == nil || mqlS.CreatedDateTime.Data.After(*latest.CreatedDateTime.Data) {
			latest = mqlS
		}
	}
	return latest, nil
}

// see https://learn.microsoft.com/en-us/graph/api/securescore-get?view=graph-rest-1.0&tabs=http
func (a *mqlMicrosoftSecurity) secureScores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Security().SecureScores().Get(ctx, &security.SecureScoresRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}
	scores, err := iterate[models.SecureScoreable](ctx, resp, graphClient.GetAdapter(), models.CreateSecureScoreCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range scores {
		score := scores[i]
		mqlResource, err := newMqlMicrosoftSecureScore(a.MqlRuntime, score)
		if err != nil {
			return nil, err
		}

		res = append(res, mqlResource)
	}
	return res, nil
}
