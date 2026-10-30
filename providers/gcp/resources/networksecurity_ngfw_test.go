// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/googleapi"
	networksecurity "google.golang.org/api/networksecurity/v1"
)

var errWildcardUnsupported = &googleapi.Error{
	Code:    http.StatusBadRequest,
	Message: "aggregated list (locations=-) is not supported for method=ListGatewaySecurityPolicies",
}

func TestWildcardLocationUnsupported(t *testing.T) {
	assert.True(t, wildcardLocationUnsupported(errWildcardUnsupported))
	assert.False(t, wildcardLocationUnsupported(&googleapi.Error{Code: http.StatusBadRequest, Message: "invalid page token"}))
	assert.False(t, wildcardLocationUnsupported(&googleapi.Error{Code: http.StatusForbidden, Message: "aggregated list denied"}))
	assert.False(t, wildcardLocationUnsupported(errors.New("aggregated list")))
	assert.False(t, wildcardLocationUnsupported(nil))
}

func TestListAcrossLocationsUsesWildcard(t *testing.T) {
	var parents []string
	err := listAcrossLocations("projects/p", func() ([]string, error) {
		t.Fatal("locations must not be listed when the wildcard works")
		return nil, nil
	}, func(parent string) error {
		parents = append(parents, parent)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"projects/p/locations/-"}, parents)
}

func TestListAcrossLocationsFallsBackPerLocation(t *testing.T) {
	var parents []string
	err := listAcrossLocations("organizations/1", func() ([]string, error) {
		return []string{"us-central1-a", "europe-west1-b", "asia-east1-c"}, nil
	}, func(parent string) error {
		parents = append(parents, parent)
		switch parent {
		case "organizations/1/locations/-":
			return errWildcardUnsupported
		case "organizations/1/locations/europe-west1-b":
			// One refused location must not take the others with it.
			return &googleapi.Error{Code: http.StatusForbidden}
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"organizations/1/locations/-",
		"organizations/1/locations/us-central1-a",
		"organizations/1/locations/europe-west1-b",
		"organizations/1/locations/asia-east1-c",
	}, parents)
}

func TestListAcrossLocationsReturnsOtherErrors(t *testing.T) {
	boom := &googleapi.Error{Code: http.StatusInternalServerError}
	err := listAcrossLocations("projects/p", func() ([]string, error) {
		t.Fatal("locations must not be listed for an error other than the wildcard one")
		return nil, nil
	}, func(parent string) error { return boom })
	assert.Same(t, boom, err)

	// A location failing with a real error is not skipped.
	err = listAcrossLocations("projects/p", func() ([]string, error) {
		return []string{"us-central1"}, nil
	}, func(parent string) error {
		if parent == "projects/p/locations/-" {
			return errWildcardUnsupported
		}
		return boom
	})
	assert.Same(t, boom, err)
}

func TestZonesOnly(t *testing.T) {
	locs := []*networksecurity.Location{
		{LocationId: "us-central1"},
		{LocationId: "us-central1-a"},
		nil,
		{LocationId: ""},
		{LocationId: "global"},
		{LocationId: "europe-west4-c"},
	}
	assert.Equal(t, []string{"us-central1-a", "europe-west4-c"}, zonesOnly(locs))
}

func TestGoogleDurationMillis(t *testing.T) {
	assert.Nil(t, googleDurationMillis(""))
	assert.Nil(t, googleDurationMillis("not-a-duration"))
	if got := googleDurationMillis("1s"); assert.NotNil(t, got) {
		assert.Equal(t, int64(1000), *got)
	}
	if got := googleDurationMillis("0.250s"); assert.NotNil(t, got) {
		assert.Equal(t, int64(250), *got)
	}
}

func TestFirewallEndpointWildfireArgs(t *testing.T) {
	keys := []string{
		"wildfireEnabled", "wildfireLookupTimeoutAction", "wildfireLookupDurationMs",
		"wildfireRegion", "wildfireInlineCloudAnalysis",
	}

	// An endpoint without WildFire settings must not read as WildFire disabled.
	t.Run("absent settings make every field null", func(t *testing.T) {
		args := firewallEndpointWildfireArgs(nil)
		for _, k := range keys {
			if assert.Contains(t, args, k) {
				assert.Nil(t, args[k].Value, k)
			}
		}
	})

	t.Run("maps the settings", func(t *testing.T) {
		args := firewallEndpointWildfireArgs(&networksecurity.FirewallEndpointWildfireSettings{
			Enabled:                             true,
			WildfireRealtimeLookupTimeoutAction: "DENY",
			WildfireRealtimeLookupDuration:      "2s",
			WildfireRegion:                      "GERMANY",
			WildfireInlineCloudAnalysisSettings: &networksecurity.FirewallEndpointWildfireSettingsWildfireInlineCloudAnalysisSettings{
				MaxAnalysisDuration:              "30s",
				SubmissionTimeoutLoggingDisabled: true,
				TimeoutAction:                    "DENY",
			},
		})
		assert.Equal(t, true, args["wildfireEnabled"].Value)
		assert.Equal(t, "DENY", args["wildfireLookupTimeoutAction"].Value)
		assert.Equal(t, int64(2000), args["wildfireLookupDurationMs"].Value)
		assert.Equal(t, "GERMANY", args["wildfireRegion"].Value)
		assert.Equal(t, map[string]any{
			"timeoutAction":                    "DENY",
			"maxAnalysisDurationMs":            int64(30000),
			"submissionTimeoutLoggingDisabled": true,
		}, args["wildfireInlineCloudAnalysis"].Value)
	})

	t.Run("unset lookup duration and inline analysis are null", func(t *testing.T) {
		args := firewallEndpointWildfireArgs(&networksecurity.FirewallEndpointWildfireSettings{})
		assert.Equal(t, false, args["wildfireEnabled"].Value)
		assert.Nil(t, args["wildfireLookupDurationMs"].Value)
		assert.Nil(t, args["wildfireInlineCloudAnalysis"].Value)
	})

	t.Run("unset max analysis duration is null inside the dict", func(t *testing.T) {
		args := firewallEndpointWildfireArgs(&networksecurity.FirewallEndpointWildfireSettings{
			WildfireInlineCloudAnalysisSettings: &networksecurity.FirewallEndpointWildfireSettingsWildfireInlineCloudAnalysisSettings{
				TimeoutAction: "ALLOW",
			},
		})
		m := args["wildfireInlineCloudAnalysis"].Value.(map[string]any)
		assert.Contains(t, m, "maxAnalysisDurationMs")
		assert.Nil(t, m["maxAnalysisDurationMs"])
	})
}
