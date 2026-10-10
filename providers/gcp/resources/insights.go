// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"

	recommender "cloud.google.com/go/recommender/apiv1"
	"cloud.google.com/go/recommender/apiv1/recommenderpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// insightLocationScope records which location scope an insight type is published
// at, so the lister queries each type only where it can return results.
type insightLocationScope int

const (
	// insightGlobal types are published only under locations/global.
	insightGlobal insightLocationScope = iota
	// insightRegional types are published per region.
	insightRegional
	// insightZonal types are published per zone.
	insightZonal
)

type insightType struct {
	name  string
	scope insightLocationScope
}

// insightTypes lists the insight types worth collecting, each paired with the
// location scope it is published at.
//
// Scoping matters for cost as much as correctness: querying every type against
// every zone and region would multiply one lister into hundreds of calls that
// can only ever return empty. It also matters for completeness in the other
// direction, since a global type queried only against zones returns nothing
// forever with no error.
//
// https://docs.cloud.google.com/recommender/docs/insights/insight-types
var insightTypes = []insightType{
	// Least-privilege and credential hygiene.
	{"google.iam.policy.Insight", insightGlobal},
	{"google.iam.serviceAccount.Insight", insightGlobal},
	// Network reachability: rules shadowed by a higher-priority rule, and rules
	// that have never matched traffic.
	{"google.compute.firewall.Insight", insightGlobal},
	// Workload posture.
	{"google.run.service.IdentityInsight", insightRegional},
	{"google.run.service.SecurityInsight", insightRegional},
	{"google.cloudsql.instance.SecurityInsight", insightRegional},
	{"google.container.DiagnosisInsight", insightZonal},
	// Resource-management signals that carry security weight, such as an
	// unattached address or an idle disk still holding data.
	{"google.compute.address.IdleResourceInsight", insightRegional},
	{"google.compute.disk.IdleResourceInsight", insightZonal},
	{"google.compute.image.IdleResourceInsight", insightGlobal},
	{"google.compute.instance.IdleResourceInsight", insightZonal},
	{"google.resourcemanager.projectUtilization.Insight", insightGlobal},
}

func (g *mqlGcpInsight) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "gcp.insight/" + g.Id.Data, nil
}

// newMqlInsight maps a Recommender insight onto the MQL resource. The project,
// location, insight type, and insight ID are parsed out of the insight's own
// resource name, which has the form
// projects/{project}/locations/{location}/insightTypes/{type}/insights/{id}.
func newMqlInsight(runtime *plugin.Runtime, item *recommenderpb.Insight) (*mqlGcpInsight, error) {
	values := strings.Split(item.GetName(), "/")
	if len(values) < 8 {
		return nil, fmt.Errorf("unexpected insight name format: %q", item.GetName())
	}

	var content any
	if item.GetContent() != nil {
		content = item.GetContent().AsMap()
	}
	// protojson, not encoding/json: encoding/json over a protobuf-generated
	// struct emits the snake_case json tags, so this dict documented `state`
	// and `stateMetadata` while carrying `state` and `state_metadata`.
	stateInfo, err := protoToDict(item.GetStateInfo())
	if err != nil {
		return nil, err
	}

	observationPeriod := ""
	if item.GetObservationPeriod() != nil {
		observationPeriod = item.GetObservationPeriod().AsDuration().String()
	}

	associated := make([]any, 0, len(item.GetAssociatedRecommendations()))
	for _, r := range item.GetAssociatedRecommendations() {
		if name := r.GetRecommendation(); name != "" {
			associated = append(associated, name)
		}
	}

	res, err := CreateResource(runtime, "gcp.insight", map[string]*llx.RawData{
		"id":                        llx.StringData(values[7]),
		"projectId":                 llx.StringData(values[1]),
		"location":                  llx.StringData(values[3]),
		"insightType":               llx.StringData(values[5]),
		"description":               llx.StringData(item.GetDescription()),
		"insightSubtype":            llx.StringData(item.GetInsightSubtype()),
		"targetResources":           llx.ArrayData(convert.SliceAnyToInterface(item.GetTargetResources()), types.String),
		"category":                  llx.StringData(item.GetCategory().String()),
		"severity":                  llx.StringData(item.GetSeverity().String()),
		"content":                   llx.DictData(content),
		"observationPeriod":         llx.StringData(observationPeriod),
		"stateInfo":                 llx.DictData(stateInfo),
		"lastRefreshTime":           llx.TimeDataPtr(timestampAsTimePtr(item.GetLastRefreshTime())),
		"associatedRecommendations": llx.ArrayData(associated, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpInsight), nil
}

// insights collects Recommender insights across the project. Each insight type
// is queried only at the location scope it is published at.
func (g *mqlGcpProject) insights() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil
	}

	regions, zones, err := g.computeLocations(projectId)
	if err != nil {
		return nil, err
	}

	// Build the (insightType, location) work list up front so the fan-out is over
	// real work rather than over a location set that most types ignore.
	type insightQuery struct {
		insightType string
		location    string
	}
	var queries []insightQuery
	for _, it := range insightTypes {
		var locations []string
		switch it.scope {
		case insightGlobal:
			locations = []string{"global"}
		case insightRegional:
			locations = regions
		case insightZonal:
			locations = zones
		}
		for _, loc := range locations {
			queries = append(queries, insightQuery{insightType: it.name, location: loc})
		}
	}

	credentials, err := conn.Credentials(recommender.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := recommender.NewClient(ctx, option.WithCredentials(credentials), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	res := []any{}
	mux := &sync.Mutex{}
	var wg sync.WaitGroup
	// Bound the fan-out the same way the recommendations lister does; the work
	// list spans every region and zone, so an unbounded goroutine per query
	// would open hundreds of concurrent streams.
	sem := make(chan struct{}, 10)

	wg.Add(len(queries))
	for i := range queries {
		q := queries[i]
		go func() {
			// Deferred so an early return or a panic in the body can never leave
			// wg.Wait() blocked forever.
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			parent := fmt.Sprintf("projects/%s/locations/%s/insightTypes/%s", projectId, q.location, q.insightType)
			it := client.ListInsights(ctx, &recommenderpb.ListInsightsRequest{Parent: parent})
			for {
				item, err := it.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					log.Debug().Str("parent", parent).Err(err).Msg("could not request insights")
					break
				}

				mqlInsight, err := newMqlInsight(g.MqlRuntime, item)
				if err != nil {
					// Mapping failures are per-insight (an unexpected resource name
					// shape, a content value that will not convert), so skip the one
					// item rather than abandoning the rest of this insight type.
					log.Error().Str("parent", parent).Err(err).Msg("could not create mql insight")
					continue
				}
				mux.Lock()
				res = append(res, mqlInsight)
				mux.Unlock()
			}
		}()
	}
	wg.Wait()

	return res, nil
}

// computeLocations lists the project's regions and zones, the location scopes
// Recommender publishes regional and zonal types at.
//
// The result is cached on the project: both the recommendations and the insights
// listers need it, and without the cache a scan that queries both hits the
// Compute API twice for the same answer.
func (g *mqlGcpProject) computeLocations(projectId string) (regions, zones []string, err error) {
	g.computeLocationsOnce.Do(func() {
		g.computeRegions, g.computeZones, g.computeLocationsErr = g.fetchComputeLocations(projectId)
	})
	return g.computeRegions, g.computeZones, g.computeLocationsErr
}

func (g *mqlGcpProject) fetchComputeLocations(projectId string) (regions, zones []string, err error) {
	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, nil
	}

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, nil, err
	}

	if err := computeSvc.Regions.List(projectId).Pages(ctx, func(page *compute.RegionList) error {
		for _, region := range page.Items {
			regions = append(regions, region.Name)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	if err := computeSvc.Zones.List(projectId).Pages(ctx, func(page *compute.ZoneList) error {
		for _, zone := range page.Items {
			zones = append(zones, zone.Name)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}

	return regions, zones, nil
}
