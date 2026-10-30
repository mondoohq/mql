// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// The IAM Access Analyzer sub-resources were renamed from the lowercase
// `aws.iam.accessanalyzer.*` to camelCase `aws.iam.accessAnalyzer.*`. These
// tests guard the backward-compatibility aliases so existing queries that use
// the previous names keep resolving.
func TestAwsAccessAnalyzerAliases(t *testing.T) {
	awsSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "aws"})

	// every previous name -> the canonical resource it must now resolve to
	aliases := map[string]string{
		// renamed sub-resources (the actual rename in #8067)
		"aws.iam.accessanalyzer.analyzer": "aws.iam.accessAnalyzer.analyzer",
		"aws.iam.accessanalyzer.finding":  "aws.iam.accessAnalyzer.finding",
		// pre-existing public short forms that must keep working
		"aws.accessAnalyzer":          "aws.iam.accessAnalyzer",
		"aws.accessAnalyzer.analyzer": "aws.iam.accessAnalyzer.analyzer",
		// lowercase short forms
		"aws.accessanalyzer":          "aws.iam.accessAnalyzer",
		"aws.accessanalyzer.analyzer": "aws.iam.accessAnalyzer.analyzer",
	}

	t.Run("aliases resolve to the canonical resource", func(t *testing.T) {
		for old, canonical := range aliases {
			t.Run(old, func(t *testing.T) {
				// the canonical resource must exist
				want := awsSchema.Lookup(canonical)
				require.NotNil(t, want, "canonical resource %q missing from schema", canonical)

				// the old name must resolve...
				got := awsSchema.Lookup(old)
				require.NotNil(t, got, "alias %q does not resolve", old)

				// ...to the very same resource definition
				assert.Equal(t, canonical, got.Id,
					"alias %q should resolve to %q", old, canonical)
				assert.Same(t, want, got,
					"alias %q should point at the same ResourceInfo as %q", old, canonical)
				assert.NotEmpty(t, got.Fields,
					"resolved resource %q should expose fields", old)
			})
		}
	})

	t.Run("queries using the previous names compile", func(t *testing.T) {
		queries := []string{
			// previously-documented public short form
			"aws.accessAnalyzer.analyzers { name }",
			// lowercase short form
			"aws.accessanalyzer.analyzers { name }",
			// reaching a renamed sub-resource field through the parent
			"aws.iam.accessAnalyzer.findings { resourceType }",
		}
		for _, query := range queries {
			t.Run(query, func(t *testing.T) {
				_, err := mqlc.Compile(query, nil, mqlc.NewConfig(awsSchema, features))
				require.NoError(t, err, "query %q should compile", query)
			})
		}
	})
}
