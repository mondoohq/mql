// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	testRoleArn  = "arn:aws:iam::111122223333:role/shared"
	testTableArn = "arn:aws:dynamodb:us-east-1:111122223333:table/orders"
)

// Synthetic: an unused-access finding on a role is not external access, so the
// role's edge drops it.
func TestEdgeTypeFilterDropsUnused(t *testing.T) {
	stub := &accessAnalyzerStub{v2Findings: map[string][]aatypes.FindingSummaryV2{
		testAnalyzerArn:       {v2Finding("f-ext", "ExternalAccess", testRoleArn)},
		testUnusedAnalyzerArn: {v2Finding("f-unused", "UnusedIAMRole", testRoleArn)},
	}}
	rt := stub.runtime(t)
	rootWithAnalyzers(t, rt,
		testAnalyzer(testAnalyzerArn, "ACCOUNT", "ACTIVE", "us-east-1"),
		testAnalyzer(testUnusedAnalyzerArn, "ACCOUNT_UNUSED_ACCESS", "ACTIVE", "us-east-1"))

	role := &mqlAwsIamRole{MqlRuntime: rt, Arn: setString(testRoleArn)}
	edge := role.GetExternalAccessFindings()
	require.NoError(t, edge.Error)
	assert.Equal(t, []string{"f-ext"}, findingIDs(t, edge.Data))
}

// Synthetic: a new edge in a region without an external-access analyzer is
// NotApplicable naming the region, whatever the flag; in a covered region it
// returns the resource's findings.
func TestEdgeCoverageStrict(t *testing.T) {
	newRuntime := func(t *testing.T) *plugin.Runtime {
		stub := &accessAnalyzerStub{v2Findings: map[string][]aatypes.FindingSummaryV2{
			testEuAnalyzerArn: {
				v2Finding("f-table", "ExternalAccess", testTableArn),
				v2Finding("f-other", "ExternalAccess", "arn:aws:dynamodb:eu-west-1:111122223333:table/other"),
			},
		}}
		rt := stub.runtime(t)
		rootWithAnalyzers(t, rt, testAnalyzer(testEuAnalyzerArn, "ACCOUNT", "ACTIVE", "eu-west-1"))
		return rt
	}

	for _, structured := range []bool{false, true} {
		t.Run(map[bool]string{false: "flag off", true: "flag on"}[structured], func(t *testing.T) {
			if structured {
				enableStructuredErrors(t)
			}
			rt := newRuntime(t)
			table := &mqlAwsDynamodbTable{MqlRuntime: rt, Arn: setString(testTableArn), Region: setString("us-east-1")}
			err := table.GetExternalAccessFindings().Error
			require.Error(t, err)
			assert.ErrorIs(t, err, llx.ErrNotApplicable)
			assert.Contains(t, err.Error(), "us-east-1")

			covered := &mqlAwsDynamodbTable{MqlRuntime: rt, Arn: setString(testTableArn), Region: setString("eu-west-1")}
			edge := covered.GetExternalAccessFindings()
			require.NoError(t, edge.Error)
			assert.Equal(t, []string{"f-table"}, findingIDs(t, edge.Data))
		})
	}
}

// Synthetic: an existing edge in a region without an analyzer is NotApplicable
// with structured errors and an empty list without them; a refused list is
// likewise an error only with structured errors.
func TestExistingEdgeCoverageUnderFlag(t *testing.T) {
	bucket := func(rt *plugin.Runtime) *mqlAwsS3Bucket {
		return &mqlAwsS3Bucket{
			MqlRuntime: rt,
			Arn:        setString("arn:aws:s3:::shared"),
			Exists:     plugin.TValue[bool]{Data: true, State: plugin.StateIsSet},
			Location:   setString("us-east-1"),
		}
	}
	noAnalyzerRuntime := func(t *testing.T) *plugin.Runtime {
		stub := &accessAnalyzerStub{}
		rt := stub.runtime(t)
		rootWithAnalyzers(t, rt, testAnalyzer(testEuAnalyzerArn, "ACCOUNT", "ACTIVE", "eu-west-1"))
		return rt
	}

	t.Run("flag off", func(t *testing.T) {
		edge := bucket(noAnalyzerRuntime(t)).GetExternalAccessFindings()
		require.NoError(t, edge.Error)
		assert.Equal(t, []any{}, edge.Data)
	})

	t.Run("flag on", func(t *testing.T) {
		enableStructuredErrors(t)
		err := bucket(noAnalyzerRuntime(t)).GetExternalAccessFindings().Error
		require.Error(t, err)
		assert.ErrorIs(t, err, llx.ErrNotApplicable)
		assert.Contains(t, err.Error(), "us-east-1")
	})

	refusedRuntime := func(t *testing.T) *plugin.Runtime {
		stub := &accessAnalyzerStub{v2Err: map[string]error{testAnalyzerArn: accessAnalyzerDenied("access-analyzer:ListFindings")}}
		rt := stub.runtime(t)
		rootWithAnalyzers(t, rt, testAnalyzer(testAnalyzerArn, "ACCOUNT", "ACTIVE", "us-east-1"))
		return rt
	}

	t.Run("refused, flag off", func(t *testing.T) {
		key := &mqlAwsKmsKey{MqlRuntime: refusedRuntime(t), Arn: setString("arn:aws:kms:us-east-1:111122223333:key/k"), Region: setString("us-east-1")}
		edge := key.GetExternalAccessFindings()
		require.NoError(t, edge.Error)
		assert.Equal(t, []any{}, edge.Data)
	})

	t.Run("refused, flag on", func(t *testing.T) {
		enableStructuredErrors(t)
		key := &mqlAwsKmsKey{MqlRuntime: refusedRuntime(t), Arn: setString("arn:aws:kms:us-east-1:111122223333:key/k"), Region: setString("us-east-1")}
		assert.ErrorIs(t, key.GetExternalAccessFindings().Error, llx.ErrForbidden)
	})
}
