// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAWSServiceReference(t *testing.T) {
	c := awsCatalog(t)
	assert.True(t, c.hasExact("s3:GetBucketCORS"))
	assert.True(t, c.hasExact("vpc-lattice:GetService"))
	assert.False(t, c.hasExact("vpclattice:GetService"))
	assert.True(t, c.hasService("ec2:Anything"), "a service in the index counts even when not fetched")
	assert.False(t, c.hasService("vpclattice:GetService"))

	canon, ok := c.canonical("s3:getbucketcors")
	assert.True(t, ok)
	assert.Equal(t, "s3:GetBucketCORS", canon)

	// Operation mappings: present with actions, present without, absent.
	assert.Equal(t, []string{"access-analyzer:GetFinding"}, c.operations["access-analyzer/GetFindingV2"])
	auth, listed := c.operations["bedrock/GetVpcConfiguration"]
	assert.True(t, listed)
	assert.Empty(t, auth)
	_, listed = c.operations["bedrock/Nope"]
	assert.False(t, listed)

	assert.Error(t, parseAWSServiceReference([]byte(`{"Name":"x","Actions":[]}`), newCatalog()), "no actions is a fetch problem, not a clean bill")
	assert.Error(t, parseAWSServiceReference([]byte(`{"Actions":[{"Name":"A"}]}`), newCatalog()), "a file without a service name")
}

func TestCheckManifestAWS(t *testing.T) {
	m := manifest{Provider: "aws", Permissions: []string{
		"s3:GetBucketCORS",      // known
		"s3:GetBucketCors",      // wrong case: AWS matches exactly
		"vpclattice:GetService", // wrong prefix
		"s3:GetBucketCorsX",     // unknown action in a known service
	}}
	r := checkManifest(m, awsCatalog(t))

	assert.Equal(t, 4, r.Total)
	assert.Equal(t, 2, r.Valid, "the right spelling and the wrong-case one, which IAM also matches")
	require.Len(t, r.Notes, 1)
	assert.Equal(t, "s3:GetBucketCors", r.Notes[0].Permission)
	assert.Equal(t, "usable, but the reference spells it s3:GetBucketCORS", r.Notes[0].Message)
	require.Len(t, r.Problems, 2)
	assert.Equal(t, "s3:GetBucketCorsX", r.Problems[0].Permission)
	assert.Equal(t, "not a known IAM action", r.Problems[0].Message)
	assert.Equal(t, "vpclattice:GetService", r.Problems[1].Permission)
	assert.Equal(t, `not a known IAM action: IAM service prefix "vpclattice"`, r.Problems[1].Message)
	assert.False(t, r.ok())
}

func TestCheckOperationsUsesAWSMapping(t *testing.T) {
	m := manifest{Provider: "aws",
		Permissions: []string{"access-analyzer:GetFinding", "access-analyzer:ListFindings", "s3:GetBucketPolicy"},
		Details: []detail{
			// Right: the manifest names the action AWS maps the operation to.
			{Permission: "access-analyzer:GetFinding", Service: "access-analyzer", Action: "GetFindingV2", SourceFile: "a.go"},
			// Wrong: a real action, but not the one that authorizes this operation.
			{Permission: "access-analyzer:ListFindings", Service: "access-analyzer", Action: "GetFindingV2", SourceFile: "b.go"},
			{Permission: "access-analyzer:ListFindings", Service: "access-analyzer", Action: "GetFindingV2", SourceFile: "c.go"}, // same pair, reported once
			// No mapping published for the operation: not judged.
			{Permission: "s3:GetBucketPolicy", Service: "s3", Action: "GetBucketPolicy", SourceFile: "d.go"},
			// Operation not in the reference at all: not judged.
			{Permission: "s3:GetBucketPolicy", Service: "s3", Action: "GetBucketPolicyV9", SourceFile: "e.go"},
		},
	}
	r := checkManifest(m, awsCatalog(t))
	assert.Equal(t, 3, r.Total)
	assert.Equal(t, 2, r.Valid, "every named action exists, but ListFindings is not the one its operation needs")
	require.Len(t, r.Problems, 1)
	assert.Equal(t, "access-analyzer:ListFindings", r.Problems[0].Permission)
	assert.Contains(t, r.Problems[0].Message, "GetFindingV2 is authorized by access-analyzer:GetFinding")
	assert.Contains(t, r.Problems[0].Message, "b.go")
}
