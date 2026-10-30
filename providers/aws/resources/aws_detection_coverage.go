// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// regionSet marks the regions a detection service is enabled in.
type regionSet map[string]bool

// detectionService describes one service in the coverage matrix. enabledRegions
// reads the service's own resources, so the coverage roll-up costs no API calls
// beyond the ones a direct query of that service would make, and shares the
// runtime cache with them.
type detectionService struct {
	// field is the name of the matching field on aws.detectionCoverage.region.
	field          string
	enabledRegions func(runtime *plugin.Runtime, regions []string) (regionSet, error)
}

func detectionServices() []detectionService {
	return []detectionService{
		{field: "cloudTrail", enabledRegions: cloudTrailCoverage},
		{field: "guardDuty", enabledRegions: guardDutyCoverage},
		{field: "config", enabledRegions: configRecorderCoverage},
		{field: "securityHub", enabledRegions: securityHubCoverage},
		{field: "inspector", enabledRegions: inspectorCoverage},
		{field: "macie", enabledRegions: macieCoverage},
		{field: "detective", enabledRegions: detectiveCoverage},
		{field: "securityLake", enabledRegions: securityLakeCoverage},
	}
}

func (a *mqlAwsDetectionCoverage) regions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}

	coverage := map[string]regionSet{}
	unreadable := []string{}
	for _, service := range detectionServices() {
		enabled, err := service.enabledRegions(a.MqlRuntime, regions)
		if err != nil {
			// A service we cannot read is reported as unreadable rather than as
			// absent, so a denied call does not masquerade as a coverage gap.
			log.Warn().Err(err).Str("service", service.field).
				Msg("could not determine detection coverage for service")
			unreadable = append(unreadable, service.field)
			coverage[service.field] = regionSet{}
			continue
		}
		coverage[service.field] = enabled
	}
	sort.Strings(unreadable)

	res := make([]any, 0, len(regions))
	for _, region := range regions {
		mqlRegion, err := CreateResource(a.MqlRuntime, ResourceAwsDetectionCoverageRegion,
			coverageRowArgs(region, coverage, unreadable))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRegion)
	}
	return res, nil
}

// coverageRowArgs builds one region's row. Every service field is set
// explicitly, including for a service that could not be read: leaving it null
// would let a three-valued assertion such as `{ cloudTrail && guardDuty }` pass
// on data nobody ever collected.
func coverageRowArgs(region string, coverage map[string]regionSet, unreadable []string) map[string]*llx.RawData {
	enabledServices := []any{}
	args := map[string]*llx.RawData{
		"__id":               llx.StringData("aws.detectionCoverage.region/" + region),
		"region":             llx.StringData(region),
		"unreadableServices": llx.ArrayData(convert.SliceAnyToInterface(unreadable), types.String),
	}
	for _, service := range detectionServices() {
		enabled := coverage[service.field][region]
		args[service.field] = llx.BoolData(enabled)
		if enabled {
			enabledServices = append(enabledServices, service.field)
		}
	}
	args["detectionServices"] = llx.ArrayData(enabledServices, types.String)
	return args
}

// cloudTrailCoverage marks the regions a logging trail covers. A multi-region
// trail covers every region, which is why per-region trail lists alone cannot
// answer the question.
func cloudTrailCoverage(runtime *plugin.Runtime, regions []string) (regionSet, error) {
	obj, err := CreateResource(runtime, ResourceAwsCloudtrail, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	trails := obj.(*mqlAwsCloudtrail).GetTrails()
	if trails.Error != nil {
		return nil, trails.Error
	}
	return trailCoverage(trails.Data, regions), nil
}

// trailCoverage resolves a trail list to the regions those trails log. A trail
// that is not currently logging covers nothing, and a multi-region trail covers
// every enabled region rather than only its home region.
func trailCoverage(trails []any, regions []string) regionSet {
	res := regionSet{}
	for _, raw := range trails {
		trail, ok := raw.(*mqlAwsCloudtrailTrail)
		if !ok {
			continue
		}
		logging := trail.GetIsLogging()
		if logging.Error != nil || !logging.Data {
			continue
		}
		if trail.IsMultiRegionTrail.Data {
			for _, region := range regions {
				res[region] = true
			}
			continue
		}
		res[trail.Region.Data] = true
	}
	return res
}

func guardDutyCoverage(runtime *plugin.Runtime, _ []string) (regionSet, error) {
	obj, err := CreateResource(runtime, ResourceAwsGuardduty, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	detectors := obj.(*mqlAwsGuardduty).GetDetectors()
	if detectors.Error != nil {
		return nil, detectors.Error
	}

	res := regionSet{}
	for _, raw := range detectors.Data {
		detector, ok := raw.(*mqlAwsGuarddutyDetector)
		if !ok {
			continue
		}
		status := detector.GetStatus()
		if status.Error != nil || status.Data != "ENABLED" {
			continue
		}
		res[detector.Region.Data] = true
	}
	return res, nil
}

func configRecorderCoverage(runtime *plugin.Runtime, _ []string) (regionSet, error) {
	obj, err := CreateResource(runtime, ResourceAwsConfig, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	recorders := obj.(*mqlAwsConfig).GetRecorders()
	if recorders.Error != nil {
		return nil, recorders.Error
	}

	res := regionSet{}
	for _, raw := range recorders.Data {
		recorder, ok := raw.(*mqlAwsConfigRecorder)
		if !ok {
			continue
		}
		if !recorder.Recording.Data {
			continue
		}
		res[recorder.Region.Data] = true
	}
	return res, nil
}

func securityHubCoverage(runtime *plugin.Runtime, _ []string) (regionSet, error) {
	obj, err := CreateResource(runtime, ResourceAwsSecurityhub, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	hubs := obj.(*mqlAwsSecurityhub).GetHubs()
	if hubs.Error != nil {
		return nil, hubs.Error
	}

	// A hub resource exists only for a region where Security Hub is enabled.
	res := regionSet{}
	for _, raw := range hubs.Data {
		hub, ok := raw.(*mqlAwsSecurityhubHub)
		if !ok {
			continue
		}
		res[hub.Region.Data] = true
	}
	return res, nil
}

func inspectorCoverage(runtime *plugin.Runtime, _ []string) (regionSet, error) {
	obj, err := CreateResource(runtime, ResourceAwsInspector, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	statuses := obj.(*mqlAwsInspector).GetAccountStatuses()
	if statuses.Error != nil {
		return nil, statuses.Error
	}

	res := regionSet{}
	for _, raw := range statuses.Data {
		status, ok := raw.(*mqlAwsInspectorAccountStatus)
		if !ok {
			continue
		}
		if status.Status.Data != "ENABLED" {
			continue
		}
		res[status.Region.Data] = true
	}
	return res, nil
}

func macieCoverage(runtime *plugin.Runtime, _ []string) (regionSet, error) {
	obj, err := CreateResource(runtime, ResourceAwsMacie, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	sessions := obj.(*mqlAwsMacie).GetSessions()
	if sessions.Error != nil {
		return nil, sessions.Error
	}

	res := regionSet{}
	for _, raw := range sessions.Data {
		session, ok := raw.(*mqlAwsMacieSession)
		if !ok {
			continue
		}
		if session.Status.Data != "ENABLED" {
			continue
		}
		res[session.Region.Data] = true
	}
	return res, nil
}

func detectiveCoverage(runtime *plugin.Runtime, _ []string) (regionSet, error) {
	obj, err := CreateResource(runtime, ResourceAwsDetective, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	graphs := obj.(*mqlAwsDetective).GetGraphs()
	if graphs.Error != nil {
		return nil, graphs.Error
	}

	// A behavior graph exists only where Detective is enabled.
	res := regionSet{}
	for _, raw := range graphs.Data {
		graph, ok := raw.(*mqlAwsDetectiveGraph)
		if !ok {
			continue
		}
		res[graph.Region.Data] = true
	}
	return res, nil
}

func securityLakeCoverage(runtime *plugin.Runtime, _ []string) (regionSet, error) {
	obj, err := CreateResource(runtime, ResourceAwsSecuritylake, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	dataLakes := obj.(*mqlAwsSecuritylake).GetDataLakes()
	if dataLakes.Error != nil {
		return nil, dataLakes.Error
	}

	res := regionSet{}
	for _, raw := range dataLakes.Data {
		dataLake, ok := raw.(*mqlAwsSecuritylakeDataLake)
		if !ok {
			continue
		}
		// A lake that is still initializing or has failed is not collecting yet.
		if dataLake.CreateStatus.Data != "COMPLETED" {
			continue
		}
		res[dataLake.Region.Data] = true
	}
	return res, nil
}
