// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/assuredworkloads/v1"
	"google.golang.org/api/googleapi"
)

func TestAssuredWorkloadLocation(t *testing.T) {
	cases := map[string]string{
		"organizations/1/locations/us-central1/workloads/w1":               "us-central1",
		"organizations/1/locations/europe-west3/workloads/w1/violations/v": "europe-west3",
		"organizations/1/workloads/w1":                                     "",
		"organizations/1/locations":                                        "",
		"":                                                                 "",
	}
	for name, want := range cases {
		assert.Equal(t, want, assuredWorkloadLocation(name), name)
	}
}

func TestAssuredWorkloadsEndpoint(t *testing.T) {
	got, err := assuredWorkloadsEndpoint("us-central1")
	require.NoError(t, err)
	assert.Equal(t, "https://us-central1-assuredworkloads.googleapis.com/", got)

	// Synthetic: the location becomes part of the host the authenticated
	// client calls, so anything but a plain location id must be refused.
	for _, bad := range []string{"evil.com/x?", "a.b", "", "US-CENTRAL1", "us-central1@evil.com", "x/../y"} {
		_, err := assuredWorkloadsEndpoint(bad)
		assert.Error(t, err, bad)
	}
}

// Synthetic: a workload name that would steer the request elsewhere is
// refused before any client is built or call made.
func TestAssuredWorkloadViolationsRejectsInvalidName(t *testing.T) {
	env := setupTestEnv(t, []string{assuredworkloads.CloudPlatformScope})
	called := false
	env.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { called = true })
	for _, bad := range []string{
		"organizations/1/locations/evil.com/x?/workloads/w",
		"organizations/1/locations/a.b/workloads/w",
		"organizations/1/locations/US/workloads/w",
		"organizations/1/locations//workloads/w",
		"organizations/1/locations/us/workloads/w/extra",
		"",
	} {
		w := &mqlGcpOrganizationAssuredWorkload{MqlRuntime: env.Runtime}
		w.Name.Data, w.Name.State = bad, plugin.StateIsSet
		_, err := w.violations()
		assert.Error(t, err, bad)
	}
	assert.False(t, called, "no request may be sent for an invalid name")
}

// Measured: the error the global and regional endpoints return when the
// Assured Workloads API is not enabled on the quota project, 2026-10-27.
var awDisabledErr = &googleapi.Error{
	Code:    http.StatusForbidden,
	Message: "Assured Workloads API has not been used in project 123456 before or it is disabled. Enable it by visiting https://console.developers.google.com/apis/api/assuredworkloads.googleapis.com/overview?project=123456 then retry.",
}

func TestListAcrossAssuredWorkloadsLocations(t *testing.T) {
	locs := []string{"a", "b", "c"}

	t.Run("a failing location is skipped", func(t *testing.T) {
		got, err := listAcrossAssuredWorkloadsLocations(locs, "p", func(loc string) ([]string, error) {
			if loc == "b" {
				return nil, &googleapi.Error{Code: http.StatusBadRequest, Message: "location not supported"}
			}
			return []string{loc + "1", loc + "2"}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"a1", "a2", "c1", "c2"}, got)
	})

	t.Run("api disabled fails the listing as not applicable", func(t *testing.T) {
		_, err := listAcrossAssuredWorkloadsLocations(locs, "p", func(loc string) ([]string, error) {
			if loc == "c" {
				return nil, awDisabledErr
			}
			return []string{loc}, nil
		})
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
	})

	t.Run("permission denied fails the listing as forbidden", func(t *testing.T) {
		_, err := listAcrossAssuredWorkloadsLocations(locs, "assuredworkloads.workload.list", func(loc string) ([]string, error) {
			return nil, &googleapi.Error{Code: http.StatusForbidden, Message: "Permission 'assuredworkloads.workload.list' denied"}
		})
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	})

	t.Run("no location answering is an error, not an empty list", func(t *testing.T) {
		_, err := listAcrossAssuredWorkloadsLocations(locs, "p", func(loc string) ([]string, error) {
			return nil, errors.New("dial tcp: no such host")
		})
		require.Error(t, err)
	})

	t.Run("no workloads anywhere is an empty list", func(t *testing.T) {
		got, err := listAcrossAssuredWorkloadsLocations(locs, "p", func(loc string) ([]string, error) {
			return nil, nil
		})
		require.NoError(t, err)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})
}

// Synthetic: no organization available for verification had a workload, so
// the record follows the v1 Workload and Violation schemas.
func TestOrganizationAssuredWorkloads(t *testing.T) {
	env := setupTestEnv(t, []string{assuredworkloads.CloudPlatformScope})
	env.Mux.HandleFunc("/v1/organizations/123/locations/us-central1/workloads", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"workloads":[{
			"name":"organizations/123/locations/us-central1/workloads/w1",
			"displayName":"fedramp prod",
			"complianceRegime":"DATA_BOUNDARY_FOR_FEDRAMP_HIGH",
			"createTime":"2025-02-03T04:05:06Z",
			"billingAccount":"billingAccounts/012345-567890-ABCDEF",
			"labels":{"team":"sec"},
			"enableSovereignControls":true,
			"kajEnrollmentState":"KAJ_ENROLLMENT_STATE_COMPLETE",
			"resourceMonitoringEnabled":true,
			"compliantButDisallowedServices":["bigquery.googleapis.com"],
			"resources":[{"resourceId":"987654321","resourceType":"CONSUMER_FOLDER"},{"resourceId":"42","resourceType":"ENCRYPTION_KEYS_PROJECT"}],
			"complianceStatus":{"activeViolationCount":2,"acknowledgedResourceViolationCount":1}
		}]}`)
	})
	env.Mux.HandleFunc("/v1/organizations/123/locations/us-central1/workloads/w1/violations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"violations":[{
			"name":"organizations/123/locations/us-central1/workloads/w1/violations/v1",
			"category":"Location",
			"state":"UNRESOLVED",
			"violationType":"ORG_POLICY",
			"description":"OrgPolicy gcp.resourceLocations has non compliant value",
			"orgPolicyConstraint":"constraints/gcp.resourceLocations",
			"nonCompliantOrgPolicy":"projects/42/policies/gcp.resourceLocations",
			"beginTime":"2025-03-01T00:00:00Z"
		}]}`)
	})
	// Every other location answers 404 from the mux and is skipped.

	org := newTestOrganization(env, "organizations/123")
	workloads, err := org.assuredWorkloads()
	require.NoError(t, err)
	require.Len(t, workloads, 1)

	w := workloads[0].(*mqlGcpOrganizationAssuredWorkload)
	assert.Equal(t, "fedramp prod", w.DisplayName.Data)
	assert.Equal(t, "us-central1", w.Location.Data)
	assert.Equal(t, "DATA_BOUNDARY_FOR_FEDRAMP_HIGH", w.ComplianceRegime.Data)
	assert.Equal(t, "billingAccounts/012345-567890-ABCDEF", w.BillingAccount.Data)
	assert.Equal(t, "", w.Partner.Data)
	assert.Nil(t, w.PartnerPermissions.Data, "no partner permissions reads null, not four false flags")
	assert.True(t, w.EnableSovereignControls.Data)
	assert.True(t, w.ResourceMonitoringEnabled.Data)
	assert.False(t, w.ViolationNotificationsEnabled.Data)
	assert.Equal(t, "KAJ_ENROLLMENT_STATE_COMPLETE", w.KajEnrollmentState.Data)
	assert.Equal(t, map[string]any{"team": "sec"}, w.Labels.Data)
	assert.Equal(t, []any{"bigquery.googleapis.com"}, w.CompliantButDisallowedServices.Data)
	assert.Equal(t, []any{
		map[string]any{"resourceId": "987654321", "resourceType": "CONSUMER_FOLDER"},
		map[string]any{"resourceId": "42", "resourceType": "ENCRYPTION_KEYS_PROJECT"},
	}, w.Resources.Data)
	assert.Equal(t, map[string]any{
		"activeViolationCount":               int64(2),
		"acknowledgedViolationCount":         int64(0),
		"activeResourceViolationCount":       int64(0),
		"acknowledgedResourceViolationCount": int64(1),
	}, w.ComplianceStatus.Data)
	require.NotNil(t, w.CreateTime.Data)
	assert.Equal(t, 2025, w.CreateTime.Data.Year())

	violations, err := w.violations()
	require.NoError(t, err)
	require.Len(t, violations, 1)
	v := violations[0].(*mqlGcpOrganizationAssuredWorkloadViolation)
	assert.Equal(t, "Location", v.Category.Data)
	assert.Equal(t, "UNRESOLVED", v.State.Data)
	assert.Equal(t, "ORG_POLICY", v.ViolationType.Data)
	assert.Equal(t, "constraints/gcp.resourceLocations", v.OrgPolicyConstraint.Data)
	assert.Equal(t, "projects/42/policies/gcp.resourceLocations", v.NonCompliantOrgPolicy.Data)
	assert.False(t, v.Acknowledged.Data)
	require.NotNil(t, v.BeginTime.Data)
	assert.Nil(t, v.ResolveTime.Data, "an unresolved violation has no resolve time")
}

// Synthetic: partner permissions present.
func TestPartnerPermissionsDict(t *testing.T) {
	got := partnerPermissionsDict(&assuredworkloads.GoogleCloudAssuredworkloadsV1WorkloadPartnerPermissions{
		DataLogsViewer:        true,
		ServiceAccessApprover: true,
	})
	assert.Equal(t, map[string]any{
		"dataLogsViewer":                          true,
		"serviceAccessApprover":                   true,
		"assuredWorkloadsMonitoring":              false,
		"accessTransparencyLogsSupportCaseViewer": false,
	}, got)
}
