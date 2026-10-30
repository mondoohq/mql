// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func setBool(v bool) plugin.TValue[bool] {
	return plugin.TValue[bool]{Data: v, State: plugin.StateIsSet}
}

func trail(region string, multiRegion, logging bool) *mqlAwsCloudtrailTrail {
	return &mqlAwsCloudtrailTrail{
		Region:             setString(region),
		IsMultiRegionTrail: setBool(multiRegion),
		IsLogging:          setBool(logging),
	}
}

func TestTrailCoverage(t *testing.T) {
	regions := []string{"us-east-1", "us-west-2", "eu-central-1"}

	t.Run("single region trail covers only its home region", func(t *testing.T) {
		got := trailCoverage([]any{trail("us-east-1", false, true)}, regions)
		assert.Equal(t, regionSet{"us-east-1": true}, got)
	})

	// The reason a per-region trail list cannot answer the coverage question on
	// its own: one multi-region trail covers every enabled region.
	t.Run("multi region trail covers every region", func(t *testing.T) {
		got := trailCoverage([]any{trail("us-east-1", true, true)}, regions)
		assert.Equal(t, regionSet{"us-east-1": true, "us-west-2": true, "eu-central-1": true}, got)
	})

	t.Run("trail that is not logging covers nothing", func(t *testing.T) {
		got := trailCoverage([]any{trail("us-east-1", true, false)}, regions)
		assert.Equal(t, regionSet{}, got)
	})

	t.Run("mixed trails union their coverage", func(t *testing.T) {
		got := trailCoverage([]any{
			trail("us-east-1", false, true),
			trail("eu-central-1", false, false),
			trail("us-west-2", false, true),
		}, regions)
		assert.Equal(t, regionSet{"us-east-1": true, "us-west-2": true}, got)
	})

	t.Run("non-trail element is skipped", func(t *testing.T) {
		got := trailCoverage([]any{"not a trail"}, regions)
		assert.Equal(t, regionSet{}, got)
	})

	t.Run("no trails", func(t *testing.T) {
		assert.Equal(t, regionSet{}, trailCoverage(nil, regions))
	})
}

func TestCoverageRowArgs(t *testing.T) {
	coverage := map[string]regionSet{
		"cloudTrail": {"us-east-1": true, "us-west-2": true},
		"guardDuty":  {"us-east-1": true},
		"config":     {},
	}

	t.Run("covered region", func(t *testing.T) {
		args := coverageRowArgs("us-east-1", coverage, nil)
		assert.Equal(t, llx.BoolData(true), args["cloudTrail"])
		assert.Equal(t, llx.BoolData(true), args["guardDuty"])
		assert.Equal(t, llx.BoolData(false), args["config"])
		assert.Equal(t, []any{"cloudTrail", "guardDuty"}, args["detectionServices"].Value)
	})

	t.Run("partially covered region", func(t *testing.T) {
		args := coverageRowArgs("us-west-2", coverage, nil)
		assert.Equal(t, llx.BoolData(true), args["cloudTrail"])
		assert.Equal(t, llx.BoolData(false), args["guardDuty"])
		assert.Equal(t, []any{"cloudTrail"}, args["detectionServices"].Value)
	})

	// The case the resource exists to surface: an enabled region nothing watches.
	t.Run("region with no coverage still gets a row", func(t *testing.T) {
		args := coverageRowArgs("ap-south-1", coverage, nil)
		assert.Equal(t, llx.StringData("ap-south-1"), args["region"])
		assert.Equal(t, []any{}, args["detectionServices"].Value)
		for _, service := range detectionServices() {
			assert.Equal(t, llx.BoolData(false), args[service.field],
				"expected %s to be false, not null", service.field)
		}
	})

	// Every service field must be set even when nothing could be read, so that a
	// `{ cloudTrail && guardDuty }` assertion fails instead of passing on nulls.
	t.Run("unreadable services are false and named", func(t *testing.T) {
		args := coverageRowArgs("us-east-1", map[string]regionSet{}, []string{"macie", "securityHub"})
		for _, service := range detectionServices() {
			assert.Equal(t, llx.BoolData(false), args[service.field])
		}
		assert.Equal(t, []any{"macie", "securityHub"}, args["unreadableServices"].Value)
		assert.Equal(t, []any{}, args["detectionServices"].Value)
	})

	// Each service in the matrix needs a matching field, or its column silently
	// never gets set.
	t.Run("every service has a field on the row", func(t *testing.T) {
		args := coverageRowArgs("us-east-1", coverage, nil)
		for _, service := range detectionServices() {
			assert.Contains(t, args, service.field)
		}
		assert.Len(t, detectionServices(), 8)
	})
}
