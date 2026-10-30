// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	advisor "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/advisor/armadvisor"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionAdvisorService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

// id keys the advisor service on its subscription, the way every other
// per-subscription service resource does.
//
// Without it the cache key is "azure.subscription.advisorService\x00" for every
// subscription, so a query that walks more than one -- azure.subscriptions
// { advisor { ... } } -- gets the first subscription's advisor object back for
// all of them, carrying the first subscription's recommendations and scores.
func (a *mqlAzureSubscriptionAdvisorService) id() (string, error) {
	return "azure.subscription.advisor/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionAdvisorService) recommendations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	client, err := advisor.NewRecommendationsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(&advisor.RecommendationsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Value {
			if r == nil {
				continue
			}
			props, err := convert.JsonToDict(r.Properties)
			if err != nil {
				return nil, err
			}
			// Properties is a nullable pointer dereferenced throughout the
			// arg map; normalize to an empty struct to avoid a panic on a
			// null-properties recommendation (mirrors newMqlRoleAssignment).
			recProps := r.Properties
			if recProps == nil {
				recProps = &advisor.RecommendationProperties{}
			}
			args := map[string]*llx.RawData{
				"id":                   llx.StringDataPtr(r.ID),
				"name":                 llx.StringDataPtr(r.Name),
				"type":                 llx.StringDataPtr(r.Type),
				"category":             llx.StringDataPtr((*string)(recProps.Category)),
				"impact":               llx.StringDataPtr((*string)(recProps.Impact)),
				"risk":                 llx.StringDataPtr((*string)(recProps.Risk)),
				"properties":           llx.DictData(props),
				"impactedResourceType": llx.StringDataPtr(recProps.ImpactedField),
				"impactedResource":     llx.StringDataPtr(recProps.ImpactedValue),
			}
			if recProps.ShortDescription != nil {
				// the 'Description' field in the API response is always empty, use the short description instead
				args["description"] = llx.StringDataPtr(recProps.ShortDescription.Problem)
				args["remediation"] = llx.StringDataPtr(recProps.ShortDescription.Solution)
			}
			mqlRecomm, err := CreateResource(a.MqlRuntime, "azure.subscription.advisorService.recommendation", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRecomm)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionAdvisorService) scores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	rawToken, err := token.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.core.windows.net//.default"},
	})
	if err != nil {
		return nil, err
	}
	ep := cloud.AzurePublic.Services[cloud.ResourceManager].Endpoint
	scores, err := getAdvisorScoresByCategory(ctx, subId, ep, rawToken.Token)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, s := range scores {
		timeSeries := []any{}
		for tsIdx, ts := range s.Properties.TimeSeries {
			scores := []any{}
			for idx, sh := range ts.ScoreHistory {
				dt, err := time.Parse(time.RFC3339, sh.Date)
				if err != nil {
					return nil, err
				}
				id := fmt.Sprintf("%s/timeSeries/%d/scores/%d", s.ID, tsIdx, idx)
				mqlTsScore, err := CreateResource(a.MqlRuntime, "azure.subscription.advisorService.securityScore", map[string]*llx.RawData{
					"id":               llx.StringData(id),
					"date":             llx.TimeData(dt),
					"score":            llx.FloatData(sh.Score),
					"consumptionUnits": llx.FloatData(sh.ConsumptionUnits),
					// time series do not have a category count
					"categoryCount":          llx.NilData,
					"impactedResourcesCount": llx.IntData(int64(sh.ImpactedResourceCount)),
					"potentialScoreIncrease": llx.FloatData(sh.PotentialScoreIncrease),
				})
				if err != nil {
					return nil, err
				}
				scores = append(scores, mqlTsScore)
			}

			mqlTs, err := CreateResource(a.MqlRuntime, "azure.subscription.advisorService.timeSeries", map[string]*llx.RawData{
				"id":               llx.StringData(fmt.Sprintf("%s/timeSeries/%d", s.ID, tsIdx)),
				"aggregationLevel": llx.StringData(ts.AggregationLevel),
				"scores":           llx.ArrayData(scores, types.ResourceLike),
			})
			if err != nil {
				return nil, err
			}
			timeSeries = append(timeSeries, mqlTs)
		}
		dt, err := time.Parse(time.RFC3339, s.Properties.LastRefreshedScore.Date)
		if err != nil {
			return nil, err
		}
		lastScore, err := CreateResource(a.MqlRuntime, "azure.subscription.advisorService.securityScore", map[string]*llx.RawData{
			"id":                     llx.StringData(fmt.Sprintf("%s/%s", s.ID, "lastRefreshedScore")),
			"date":                   llx.TimeData(dt),
			"score":                  llx.FloatData(s.Properties.LastRefreshedScore.Score),
			"consumptionUnits":       llx.FloatData(s.Properties.LastRefreshedScore.ConsumptionUnits),
			"categoryCount":          llx.IntData(int64(s.Properties.LastRefreshedScore.CategoryCount)),
			"impactedResourcesCount": llx.IntData(int64(s.Properties.LastRefreshedScore.ImpactedResourceCount)),
			"potentialScoreIncrease": llx.FloatData(s.Properties.LastRefreshedScore.PotentialScoreIncrease),
		})
		if err != nil {
			return nil, err
		}
		mqlAdvisoryScore, err := CreateResource(a.MqlRuntime, "azure.subscription.advisorService.score", map[string]*llx.RawData{
			"id":           llx.StringData(s.ID),
			"name":         llx.StringData(s.Name),
			"type":         llx.StringData(s.Type),
			"currentScore": llx.ResourceData(lastScore, lastScore.MqlName()),
			"timeSeries":   llx.ArrayData(timeSeries, types.ResourceLike),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAdvisoryScore)

	}
	return res, nil
}

// meanOfPresentScores averages the non-nil values, dividing by the count of
// values actually summed (not the input length) so the average isn't skewed
// toward zero by unresolved/absent scores. Returns 0 when none are present.
func meanOfPresentScores(values []*float64) float64 {
	sum := float64(0)
	count := 0
	for _, v := range values {
		if v == nil {
			continue
		}
		sum += *v
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func (a *mqlAzureSubscriptionAdvisorService) averageScore() (float64, error) {
	scores := a.GetScores()
	if scores.Error != nil {
		return 0, scores.Error
	}
	values := make([]*float64, 0, len(scores.Data))
	for _, s := range scores.Data {
		score, ok := s.(*mqlAzureSubscriptionAdvisorServiceScore)
		if !ok {
			continue
		}
		if score.CurrentScore.Data == nil {
			continue
		}
		v := score.CurrentScore.Data.Score.Data
		values = append(values, &v)
	}
	return meanOfPresentScores(values), nil
}

func (a *mqlAzureSubscriptionAdvisorServiceRecommendation) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAdvisorServiceScore) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAdvisorServiceTimeSeries) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAdvisorServiceSecurityScore) id() (string, error) {
	return a.Id.Data, nil
}

func getAdvisorScoresByCategory(ctx context.Context, subscriptionId, host, token string) ([]AdvisorScoreByCategory, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Advisor/advisorScore"
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(subscriptionId))
	urlPath = runtime.JoinPaths(host, urlPath)
	// The Advisor score endpoint is genuinely single-page: AdvisorScoreResponse
	// carries only `value`, with no nextLink, and armadvisor ships no client for
	// it -- which is why this is hand-rolled at all. It still needs the shared
	// client's timeout, since nothing else bounds a request made outside the
	// azcore pipeline.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlPath, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("api-version", "2023-01-01")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := armHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch advisor scores " + urlPath + ": " + resp.Status)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	result := AdvisorScoresResponse{}
	err = json.Unmarshal(raw, &result)
	if err != nil {
		return nil, err
	}
	return result.Value, nil
}

type AdvisorScoresResponse struct {
	Value []AdvisorScoreByCategory `json:"value"`
}

type AdvisorScoreByCategory struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Properties struct {
		LastRefreshedScore struct {
			Date                   string  `json:"date"`
			Score                  float64 `json:"score"`
			ConsumptionUnits       float64 `json:"consumptionUnits"`
			ImpactedResourceCount  int     `json:"impactedResourceCount"`
			PotentialScoreIncrease float64 `json:"potentialScoreIncrease"`
			CategoryCount          int     `json:"categoryCount"`
		} `json:"lastRefreshedScore"`
		TimeSeries []struct {
			AggregationLevel string `json:"aggregationLevel"`
			ScoreHistory     []struct {
				Date                   string  `json:"date"`
				Score                  float64 `json:"score"`
				ConsumptionUnits       float64 `json:"consumptionUnits"`
				ImpactedResourceCount  int     `json:"impactedResourceCount"`
				PotentialScoreIncrease float64 `json:"potentialScoreIncrease"`
			} `json:"scoreHistory"`
		} `json:"timeSeries"`
	} `json:"properties"`
}
