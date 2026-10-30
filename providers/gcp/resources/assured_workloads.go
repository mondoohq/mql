// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/assuredworkloads/v1"
	"google.golang.org/api/option"
)

// assuredWorkloadsLocations are the locations an Assured Workloads
// environment can be created in, from
// https://cloud.google.com/assured-workloads/docs/locations.
//
// The API has no locations list and no locations/- wildcard, and every
// location is served by its own regional endpoint
// (<location>-assuredworkloads.googleapis.com), which is how gcloud reaches
// it. Listing the workloads of an organization therefore asks each location.
var assuredWorkloadsLocations = []string{
	// Multi-regions
	"us", "europe", "ca",
	// Americas
	"us-central1", "us-east1", "us-east4", "us-east5", "us-south1",
	"us-west1", "us-west2", "us-west3", "us-west4",
	"northamerica-northeast1", "northamerica-northeast2",
	"southamerica-east1", "southamerica-west1",
	// Europe
	"europe-central2", "europe-north1", "europe-north2", "europe-southwest1",
	"europe-west1", "europe-west2", "europe-west3", "europe-west4",
	"europe-west6", "europe-west8", "europe-west9", "europe-west10", "europe-west12",
	// Asia Pacific
	"asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
	"asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2",
	"australia-southeast1", "australia-southeast2",
	// Africa and Middle East
	"africa-south1", "me-central1", "me-central2", "me-west1",
}

var (
	assuredWorkloadsLocationPattern = regexp.MustCompile(`^[a-z0-9-]+$`)
	assuredWorkloadNamePattern      = regexp.MustCompile(`^organizations/[^/]+/locations/[a-z0-9-]+/workloads/[^/]+$`)
)

// assuredWorkloadsEndpoint returns the regional endpoint that serves location.
//
// The location becomes part of the host the authenticated client talks to, so
// anything but a plain location id is rejected: a value such as
// "evil.com/x?" would otherwise send the OAuth token to another host.
func assuredWorkloadsEndpoint(location string) (string, error) {
	if !assuredWorkloadsLocationPattern.MatchString(location) {
		return "", fmt.Errorf("invalid assured workloads location %q", location)
	}
	return "https://" + location + "-assuredworkloads.googleapis.com/", nil
}

// assuredWorkloadLocation returns the location segment of a workload or
// violation name (organizations/{org}/locations/{location}/workloads/...), or
// an empty string when the name has none.
func assuredWorkloadLocation(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

// assuredWorkloadsClient returns the HTTP client for Assured Workloads calls.
// Each caller builds its own regional service from it with NewService, which
// is what the permissions extractor recognizes to attribute the calls made on
// it.
func assuredWorkloadsClient(runtime *plugin.Runtime) (*http.Client, error) {
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return conn.Client(assuredworkloads.CloudPlatformScope)
}

// listAcrossAssuredWorkloadsLocations calls list once per location and
// collects what the locations returned.
//
// A refusal (the API not enabled, or permission denied) is the same in every
// location, since both are decided for the organization and the quota project
// rather than per region, so the first one fails the whole listing. Any other
// error, such as a location the endpoint does not serve, is logged and the
// location skipped, keeping what the others returned (ADR 046 section 8).
// When no location answered at all, the first error is returned rather than an
// empty list that would pass every assertion over it.
func listAcrossAssuredWorkloadsLocations[T any](locations []string, permission string, list func(location string) ([]T, error)) ([]T, error) {
	var (
		mu       sync.Mutex
		results  = make([][]T, len(locations))
		answered int
		firstErr error
		grp      errgroup.Group
		refusal  error
	)
	grp.SetLimit(8)
	for i, loc := range locations {
		grp.Go(func() error {
			items, err := list(loc)
			if err == nil {
				mu.Lock()
				results[i] = items
				answered++
				mu.Unlock()
				return nil
			}
			if rerr := classifyRefusal(err, permission); rerr != nil {
				mu.Lock()
				if refusal == nil {
					refusal = rerr
				}
				mu.Unlock()
				return nil
			}
			log.Debug().Err(err).Str("location", loc).Msg("could not list assured workloads in location, skipping")
			mu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
			return nil
		})
	}
	_ = grp.Wait()

	if refusal != nil {
		return nil, refusal
	}
	if answered == 0 && firstErr != nil {
		return nil, firstErr
	}
	res := []T{}
	for _, r := range results {
		res = append(res, r...)
	}
	return res, nil
}

func (g *mqlGcpOrganization) assuredWorkloads() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	org := organizationResourceName(g.Id.Data)
	ctx := context.Background()
	client, err := assuredWorkloadsClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}

	workloads, err := listAcrossAssuredWorkloadsLocations(assuredWorkloadsLocations, "assuredworkloads.workload.list",
		func(location string) ([]*assuredworkloads.GoogleCloudAssuredworkloadsV1Workload, error) {
			endpoint, err := assuredWorkloadsEndpoint(location)
			if err != nil {
				return nil, err
			}
			svc, err := assuredworkloads.NewService(ctx, option.WithHTTPClient(client), option.WithEndpoint(endpoint))
			if err != nil {
				return nil, err
			}
			var items []*assuredworkloads.GoogleCloudAssuredworkloadsV1Workload
			err = svc.Organizations.Locations.Workloads.List(org+"/locations/"+location).Pages(ctx,
				func(page *assuredworkloads.GoogleCloudAssuredworkloadsV1ListWorkloadsResponse) error {
					for _, w := range page.Workloads {
						if w != nil {
							items = append(items, w)
						}
					}
					return nil
				})
			return items, err
		})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(workloads))
	for _, w := range workloads {
		mqlWorkload, err := CreateResource(g.MqlRuntime, "gcp.organization.assuredWorkload", assuredWorkloadArgs(w))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlWorkload)
	}
	return res, nil
}

func assuredWorkloadArgs(w *assuredworkloads.GoogleCloudAssuredworkloadsV1Workload) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"name":                           llx.StringData(w.Name),
		"displayName":                    llx.StringData(w.DisplayName),
		"location":                       llx.StringData(assuredWorkloadLocation(w.Name)),
		"complianceRegime":               llx.StringData(w.ComplianceRegime),
		"createTime":                     llx.TimeDataPtr(parseTime(w.CreateTime)),
		"billingAccount":                 llx.StringData(w.BillingAccount),
		"partner":                        llx.StringData(w.Partner),
		"partnerPermissions":             llx.DictData(partnerPermissionsDict(w.PartnerPermissions)),
		"resources":                      llx.ArrayData(workloadResourcesDicts(w.Resources), types.Dict),
		"labels":                         llx.MapData(convert.MapToInterfaceMap(w.Labels), types.String),
		"enableSovereignControls":        llx.BoolData(w.EnableSovereignControls),
		"kajEnrollmentState":             llx.StringData(w.KajEnrollmentState),
		"resourceMonitoringEnabled":      llx.BoolData(w.ResourceMonitoringEnabled),
		"violationNotificationsEnabled":  llx.BoolData(w.ViolationNotificationsEnabled),
		"compliantButDisallowedServices": llx.ArrayData(convert.SliceAnyToInterface(w.CompliantButDisallowedServices), types.String),
		"complianceStatus":               llx.DictData(complianceStatusDict(w.ComplianceStatus)),
	}
}

// partnerPermissionsDict returns nil when the workload grants its partner
// nothing, so the field reads null rather than a set of false flags nobody
// configured.
func partnerPermissionsDict(p *assuredworkloads.GoogleCloudAssuredworkloadsV1WorkloadPartnerPermissions) any {
	if p == nil {
		return nil
	}
	return map[string]any{
		"dataLogsViewer":                          p.DataLogsViewer,
		"serviceAccessApprover":                   p.ServiceAccessApprover,
		"assuredWorkloadsMonitoring":              p.AssuredWorkloadsMonitoring,
		"accessTransparencyLogsSupportCaseViewer": p.AccessTransparencyLogsSupportCaseViewer,
	}
}

func complianceStatusDict(s *assuredworkloads.GoogleCloudAssuredworkloadsV1WorkloadComplianceStatus) any {
	if s == nil {
		return nil
	}
	return map[string]any{
		"activeViolationCount":               s.ActiveViolationCount,
		"acknowledgedViolationCount":         s.AcknowledgedViolationCount,
		"activeResourceViolationCount":       s.ActiveResourceViolationCount,
		"acknowledgedResourceViolationCount": s.AcknowledgedResourceViolationCount,
	}
}

func workloadResourcesDicts(resources []*assuredworkloads.GoogleCloudAssuredworkloadsV1WorkloadResourceInfo) []any {
	res := make([]any, 0, len(resources))
	for _, r := range resources {
		if r == nil {
			continue
		}
		res = append(res, map[string]any{
			"resourceId":   strconv.FormatInt(r.ResourceId, 10),
			"resourceType": r.ResourceType,
		})
	}
	return res
}

func (g *mqlGcpOrganizationAssuredWorkload) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpOrganizationAssuredWorkload) violations() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data
	if !assuredWorkloadNamePattern.MatchString(name) {
		return nil, fmt.Errorf("invalid assured workload name %q", name)
	}
	endpoint, err := assuredWorkloadsEndpoint(assuredWorkloadLocation(name))
	if err != nil {
		return nil, err
	}
	client, err := assuredWorkloadsClient(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := assuredworkloads.NewService(ctx, option.WithHTTPClient(client), option.WithEndpoint(endpoint))
	if err != nil {
		return nil, err
	}

	res := []any{}
	err = svc.Organizations.Locations.Workloads.Violations.List(name).Pages(ctx,
		func(page *assuredworkloads.GoogleCloudAssuredworkloadsV1ListViolationsResponse) error {
			for _, v := range page.Violations {
				if v == nil {
					continue
				}
				mqlViolation, err := CreateResource(g.MqlRuntime, "gcp.organization.assuredWorkload.violation", assuredWorkloadViolationArgs(v))
				if err != nil {
					return err
				}
				res = append(res, mqlViolation)
			}
			return nil
		})
	if err != nil {
		if rerr := classifyRefusal(err, "assuredworkloads.violations.list"); rerr != nil {
			return nil, rerr
		}
		return nil, err
	}
	return res, nil
}

func assuredWorkloadViolationArgs(v *assuredworkloads.GoogleCloudAssuredworkloadsV1Violation) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"name":                  llx.StringData(v.Name),
		"category":              llx.StringData(v.Category),
		"state":                 llx.StringData(v.State),
		"violationType":         llx.StringData(v.ViolationType),
		"description":           llx.StringData(v.Description),
		"orgPolicyConstraint":   llx.StringData(v.OrgPolicyConstraint),
		"nonCompliantOrgPolicy": llx.StringData(v.NonCompliantOrgPolicy),
		"resourceName":          llx.StringData(v.ResourceName),
		"resourceType":          llx.StringData(v.ResourceType),
		"acknowledged":          llx.BoolData(v.Acknowledged),
		"acknowledgementTime":   llx.TimeDataPtr(parseTime(v.AcknowledgementTime)),
		"beginTime":             llx.TimeDataPtr(parseTime(v.BeginTime)),
		"resolveTime":           llx.TimeDataPtr(parseTime(v.ResolveTime)),
		"updateTime":            llx.TimeDataPtr(parseTime(v.UpdateTime)),
	}
}

func (g *mqlGcpOrganizationAssuredWorkloadViolation) id() (string, error) {
	return g.Name.Data, g.Name.Error
}
