// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	recommender "cloud.google.com/go/recommender/apiv1"
	"cloud.google.com/go/recommender/apiv1/recommenderpb"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func newMqlRecommendation(runtime *plugin.Runtime, item *recommenderpb.Recommendation) (*mqlGcpRecommendation, error) {
	category := ""
	if item.PrimaryImpact != nil {
		category = item.PrimaryImpact.Category.String()
	}

	// protojson, not encoding/json: encoding/json over a protobuf-generated
	// struct emits the snake_case json tags and renders enums as their numeric
	// values, so `category` came back as `2` and the projection oneof appeared
	// under its bare Go field name rather than as `costProjection` and friends.
	primaryImpact, err := protoToDict(item.PrimaryImpact)
	if err != nil {
		return nil, err
	}
	additionalImpact, err := protoToDictSlice(item.AdditionalImpact)
	if err != nil {
		return nil, err
	}
	content, err := protoToDict(item.Content)
	if err != nil {
		return nil, err
	}
	lastRefreshTime := item.LastRefreshTime.AsTime()
	priority := item.Priority.String()
	state, err := protoToDict(item.StateInfo)
	if err != nil {
		return nil, err
	}

	// projects/{projectid}/locations/{zone}/recommenders/{recommender}/recommendations/{id}
	values := strings.Split(item.Name, "/")
	if len(values) < 8 {
		return nil, fmt.Errorf("unexpected recommendation name format: %q", item.Name)
	}

	res, err := CreateResource(runtime, "gcp.recommendation", map[string]*llx.RawData{
		"id":               llx.StringData(values[7]),
		"projectId":        llx.StringData(values[1]),
		"zoneName":         llx.StringData(values[3]),
		"name":             llx.StringData(item.Description),
		"recommender":      llx.StringData(values[5]),
		"primaryImpact":    llx.DictData(primaryImpact),
		"additionalImpact": llx.ArrayData(additionalImpact, types.Dict),
		"content":          llx.DictData(content),
		"category":         llx.StringData(category),
		"priority":         llx.StringData(priority),
		"lastRefreshTime":  llx.TimeData(lastRefreshTime),
		"state":            llx.DictData(state),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpRecommendation), nil
}

// https://docs.cloud.google.com/recommender/docs/recommenders#recommenders
var recommenders = []string{
	"google.bigquery.capacityCommitments.Recommender",
	"google.cloudsql.instance.IdleRecommender",
	"google.cloudsql.instance.OverprovisionedRecommender",
	"google.compute.commitment.UsageCommitmentRecommender",
	//"google.cloudbilling.commitment.SpendBasedCommitmentRecommender", // API returns errors with that recommender on project level
	"google.compute.image.IdleResourceRecommender",
	"google.compute.address.IdleResourceRecommender",
	"google.compute.disk.IdleResourceRecommender",
	"google.compute.instance.IdleResourceRecommender",
	//"google.accounts.security.SecurityKeyRecommender", // API returns errors with that recommender on project level
	"google.iam.policy.Recommender",
	"google.gmp.project.ManagementRecommender",
	"google.run.service.IdentityRecommender",
	"google.run.service.SecurityRecommender",
	"google.cloudsql.instance.OutOfDiskRecommender",
	"google.compute.instanceGroupManager.MachineTypeRecommender",
	"google.compute.instance.MachineTypeRecommender",
	"google.clouderrorreporting.Recommender",
	"google.logging.productSuggestion.ContainerRecommender",
	"google.container.DiagnosisRecommender",
	"google.resourcemanager.projectUtilization.Recommender",
}

// GetRecommendations returns recommendations from Google Cloud
func (g *mqlGcpProject) recommendations() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	// Recommenders are published at three location scopes: global (IAM policy,
	// project utilization, error reporting, ...), regional (Cloud Run identity
	// and security, Cloud SQL, commitments, ...) and zonal (idle compute
	// resources). Querying zones alone means every global and regional
	// recommender — including google.iam.policy.Recommender — returns nothing,
	// forever, with no error.
	//
	// The region and zone listing is shared with the insights lister and cached
	// on the project, so querying both fields in one scan does not walk the
	// Compute API twice.
	regions, zones, err := g.computeLocations(projectId)
	if err != nil {
		return nil, err
	}
	locations := make([]string, 0, len(regions)+len(zones)+1)
	locations = append(locations, "global")
	locations = append(locations, regions...)
	locations = append(locations, zones...)

	ctx := context.Background()

	// gather all recommendations
	credentials, err := conn.Credentials(recommender.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	c, err := recommender.NewClient(ctx, option.WithCredentials(credentials), connection.GRPCClientTraceOption())
	if err != nil {
		log.Info().Err(err).Msg("could not create client")
		return nil, err
	}

	res := []any{}
	var wg sync.WaitGroup
	wg.Add(len(locations))
	mux := &sync.Mutex{}
	// Bound the fan-out: the location set now spans global + regions + zones, so
	// an unbounded goroutine per location would open ~90 concurrent workers.
	sem := make(chan struct{}, 10)

	for i := range locations {
		location := locations[i]
		// we run a worker routine per location
		go func(locationValue string) {
			// Deferred so an early return or a panic in the body can never leave
			// wg.Wait() blocked forever.
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for j := range recommenders {
				recommender := recommenders[j]

				parent := fmt.Sprintf("projects/%s/locations/%s/recommenders/%s", projectId, locationValue, recommender)
				it := c.ListRecommendations(ctx, &recommenderpb.ListRecommendationsRequest{
					Parent: parent,
				})

				for {
					item, err := it.Next()
					if err == iterator.Done {
						break
					}
					if err != nil {
						log.Error().Str("parent", parent).Err(err).Msg("could not request recommendations")
						break
					}

					mqlRecommendation, err := newMqlRecommendation(g.MqlRuntime, item)
					if err != nil {
						log.Error().Str("parent", parent).Err(err).Msg("could not create mql recommendation")
						break
					}
					mux.Lock()
					res = append(res, mqlRecommendation)
					mux.Unlock()
				}
			}
		}(location)
	}
	wg.Wait()
	return res, nil
}

func (g *mqlGcpRecommendation) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}

	return "gcp.recommendation/" + g.Id.Data, nil
}
