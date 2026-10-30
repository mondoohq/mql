// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kmsinventory "google.golang.org/api/kmsinventory/v1"
)

func TestProtectedResourcesWarnings(t *testing.T) {
	warn := func(code string) *kmsinventory.GoogleCloudKmsInventoryV1Warning {
		return &kmsinventory.GoogleCloudKmsInventoryV1Warning{WarningCode: code}
	}

	tests := []struct {
		name     string
		in       []*kmsinventory.GoogleCloudKmsInventoryV1Warning
		expCodes []any
		expPart  bool
	}{
		{
			name:     "no warnings is a complete summary",
			in:       nil,
			expCodes: []any{},
			expPart:  false,
		},
		{
			// The failure this guards: the service agent cannot search every
			// asset, the API answers with a count anyway, and a resourceCount of
			// 0 reads as an orphaned key.
			name:     "insufficient permissions is partial",
			in:       []*kmsinventory.GoogleCloudKmsInventoryV1Warning{warn("INSUFFICIENT_PERMISSIONS_PARTIAL_DATA")},
			expCodes: []any{"INSUFFICIENT_PERMISSIONS_PARTIAL_DATA"},
			expPart:  true,
		},
		{
			name:     "resource limit exceeded is partial",
			in:       []*kmsinventory.GoogleCloudKmsInventoryV1Warning{warn("RESOURCE_LIMIT_EXCEEDED_PARTIAL_DATA")},
			expCodes: []any{"RESOURCE_LIMIT_EXCEEDED_PARTIAL_DATA"},
			expPart:  true,
		},
		{
			name:     "org-less project is partial",
			in:       []*kmsinventory.GoogleCloudKmsInventoryV1Warning{warn("ORG_LESS_PROJECT_PARTIAL_DATA")},
			expCodes: []any{"ORG_LESS_PROJECT_PARTIAL_DATA"},
			expPart:  true,
		},
		{
			// WARNING_CODE_UNSPECIFIED is documented as unused, and an
			// unrecognized code must not flip a complete summary into a lower
			// bound on the strength of a string we do not know.
			name:     "unspecified code is reported but not partial",
			in:       []*kmsinventory.GoogleCloudKmsInventoryV1Warning{warn("WARNING_CODE_UNSPECIFIED")},
			expCodes: []any{"WARNING_CODE_UNSPECIFIED"},
			expPart:  false,
		},
		{
			name: "codes are sorted and de-duplicated",
			in: []*kmsinventory.GoogleCloudKmsInventoryV1Warning{
				warn("RESOURCE_LIMIT_EXCEEDED_PARTIAL_DATA"),
				warn("INSUFFICIENT_PERMISSIONS_PARTIAL_DATA"),
				warn("RESOURCE_LIMIT_EXCEEDED_PARTIAL_DATA"),
			},
			expCodes: []any{"INSUFFICIENT_PERMISSIONS_PARTIAL_DATA", "RESOURCE_LIMIT_EXCEEDED_PARTIAL_DATA"},
			expPart:  true,
		},
		{
			name: "nil and empty entries are dropped",
			in: []*kmsinventory.GoogleCloudKmsInventoryV1Warning{
				nil,
				warn(""),
				warn("ORG_LESS_PROJECT_PARTIAL_DATA"),
			},
			expCodes: []any{"ORG_LESS_PROJECT_PARTIAL_DATA"},
			expPart:  true,
		},
		{
			name: "one partial code among several sets the flag",
			in: []*kmsinventory.GoogleCloudKmsInventoryV1Warning{
				warn("WARNING_CODE_UNSPECIFIED"),
				warn("INSUFFICIENT_PERMISSIONS_PARTIAL_DATA"),
			},
			expCodes: []any{"INSUFFICIENT_PERMISSIONS_PARTIAL_DATA", "WARNING_CODE_UNSPECIFIED"},
			expPart:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			codes, partial := protectedResourcesWarnings(tc.in)
			assert.Equal(t, tc.expCodes, codes)
			assert.Equal(t, tc.expPart, partial)
		})
	}
}

func TestProtectedResourcesArgs(t *testing.T) {
	const keyPath = "projects/p/locations/global/keyRings/kr/cryptoKeys/k"

	t.Run("a key that protects nothing still reports zero counts", func(t *testing.T) {
		args := protectedResourcesArgs(keyPath, &kmsinventory.GoogleCloudKmsInventoryV1ProtectedResourcesSummary{})

		require.Contains(t, args, "resourceCount")
		assert.Equal(t, int64(0), args["resourceCount"].Value)
		assert.Equal(t, int64(0), args["projectCount"].Value)
		assert.Equal(t, false, args["partialData"].Value)
		assert.Equal(t, []any{}, args["warnings"].Value)
	})

	t.Run("counts and breakdowns are carried through", func(t *testing.T) {
		args := protectedResourcesArgs(keyPath, &kmsinventory.GoogleCloudKmsInventoryV1ProtectedResourcesSummary{
			ResourceCount: 42,
			ProjectCount:  3,
			CloudProducts: map[string]string{"Compute Engine": "40", "Cloud Storage": "2"},
			ResourceTypes: map[string]string{"compute.googleapis.com/Disk": "40"},
			Locations:     map[string]string{"us-central1": "42"},
		})

		assert.Equal(t, int64(42), args["resourceCount"].Value)
		// The cross-project blast radius: the reason projectCount is modelled
		// separately from resourceCount.
		assert.Equal(t, int64(3), args["projectCount"].Value)
		assert.Equal(t, map[string]any{"Compute Engine": "40", "Cloud Storage": "2"}, args["cloudProducts"].Value)
		assert.Equal(t, map[string]any{"compute.googleapis.com/Disk": "40"}, args["resourceTypes"].Value)
		assert.Equal(t, map[string]any{"us-central1": "42"}, args["locations"].Value)
	})

	t.Run("__id carries the key path so two keys cannot collide", func(t *testing.T) {
		a := protectedResourcesArgs("projects/p/locations/global/keyRings/kr/cryptoKeys/one",
			&kmsinventory.GoogleCloudKmsInventoryV1ProtectedResourcesSummary{})
		b := protectedResourcesArgs("projects/p/locations/global/keyRings/kr/cryptoKeys/two",
			&kmsinventory.GoogleCloudKmsInventoryV1ProtectedResourcesSummary{})

		assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
		assert.Equal(t, keyPath+"/protectedResourcesSummary",
			protectedResourcesArgs(keyPath, &kmsinventory.GoogleCloudKmsInventoryV1ProtectedResourcesSummary{})["__id"].Value)
	})

	t.Run("a zero count carrying a partial-data warning is flagged", func(t *testing.T) {
		args := protectedResourcesArgs(keyPath, &kmsinventory.GoogleCloudKmsInventoryV1ProtectedResourcesSummary{
			ResourceCount: 0,
			Warnings: []*kmsinventory.GoogleCloudKmsInventoryV1Warning{
				{WarningCode: "INSUFFICIENT_PERMISSIONS_PARTIAL_DATA"},
			},
		})

		assert.Equal(t, int64(0), args["resourceCount"].Value)
		assert.Equal(t, true, args["partialData"].Value,
			"a zero count with a partial-data warning must not read as an orphaned key")
	})
}
