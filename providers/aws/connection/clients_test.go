// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
)

// testConn builds a connection with a stubbed config. NewFromConfig constructs
// SDK clients lazily, so no network or credentials are touched by these tests.
func testConn(region string) *AwsConnection {
	return &AwsConnection{cfg: aws.Config{Region: region}}
}

// A regional client is built for the requested region.
func TestRegionalClientUsesRequestedRegion(t *testing.T) {
	conn := testConn("us-east-1")

	client := conn.Ec2("eu-west-1")
	require.NotNil(t, client)
	require.Equal(t, "eu-west-1", client.Options().Region)
}

// The same service+region returns the identical cached client instance.
func TestRegionalClientIsCachedPerRegion(t *testing.T) {
	conn := testConn("us-east-1")

	first := conn.Ec2("us-east-1")
	second := conn.Ec2("us-east-1")
	require.NotNil(t, first)
	require.Same(t, first, second, "same region must return the cached client")
}

// Different regions of the same service are cached independently.
func TestRegionalClientDistinctPerRegion(t *testing.T) {
	conn := testConn("us-east-1")

	east := conn.Ec2("us-east-1")
	west := conn.Ec2("eu-west-1")
	require.NotSame(t, east, west, "different regions must be distinct clients")
	require.Equal(t, "us-east-1", east.Options().Region)
	require.Equal(t, "eu-west-1", west.Options().Region)
}

// An empty region falls back to the connection's configured region, and shares
// the same cache entry as an explicit call for that region.
func TestRegionalClientEmptyRegionDefaultsToConfigured(t *testing.T) {
	conn := testConn("ap-south-1")

	defaulted := conn.Ec2("")
	explicit := conn.Ec2("ap-south-1")
	require.Equal(t, "ap-south-1", defaulted.Options().Region)
	require.Same(t, defaulted, explicit, "empty region must reuse the configured-region cache entry")
}

// Distinct services do not collide in the shared client cache: a wrong or
// duplicated service cache-key would surface here as a type-assertion panic.
func TestDistinctServicesDoNotCollide(t *testing.T) {
	conn := testConn("us-east-1")

	require.NotNil(t, conn.Ec2("us-east-1"))
	require.NotNil(t, conn.S3("us-east-1"))
	require.NotNil(t, conn.Iam("us-east-1"))
	require.NotNil(t, conn.Rds("us-east-1"))
	require.NotNil(t, conn.Lambda("us-east-1"))
}

// Global services (CostExplorer, Budgets) pin us-east-1 regardless of the
// connection's configured region, and are still cached.
func TestGlobalClientsPinUsEast1(t *testing.T) {
	conn := testConn("eu-west-1")

	ce := conn.CostExplorer()
	require.NotNil(t, ce)
	require.Equal(t, "us-east-1", ce.Options().Region, "cost explorer is pinned to us-east-1")
	require.Same(t, ce, conn.CostExplorer(), "global client must be cached")

	bud := conn.Budgets()
	require.NotNil(t, bud)
	require.Equal(t, "us-east-1", bud.Options().Region, "budgets is pinned to us-east-1")
	require.Same(t, bud, conn.Budgets(), "global client must be cached")
}

// A representative sweep across many getters, guarding the 112 mechanical
// rewrites: each must return a non-nil client built for the requested region.
// A wrong cache-key (collision) would panic on the type assertion; a wrong
// pinned region would fail the region assertion.
func TestGettersSmokeSweep(t *testing.T) {
	conn := testConn("us-east-1")
	const region = "eu-central-1"

	// name -> region the built client reports for the requested region.
	getters := map[string]func() string{
		"Ec2":            func() string { return conn.Ec2(region).Options().Region },
		"S3":             func() string { return conn.S3(region).Options().Region },
		"Iam":            func() string { return conn.Iam(region).Options().Region },
		"Rds":            func() string { return conn.Rds(region).Options().Region },
		"Lambda":         func() string { return conn.Lambda(region).Options().Region },
		"Kms":            func() string { return conn.Kms(region).Options().Region },
		"Ecs":            func() string { return conn.Ecs(region).Options().Region },
		"Eks":            func() string { return conn.Eks(region).Options().Region },
		"Sns":            func() string { return conn.Sns(region).Options().Region },
		"Sqs":            func() string { return conn.Sqs(region).Options().Region },
		"Dynamodb":       func() string { return conn.Dynamodb(region).Options().Region },
		"Cloudtrail":     func() string { return conn.Cloudtrail(region).Options().Region },
		"Cloudwatch":     func() string { return conn.Cloudwatch(region).Options().Region },
		"Sagemaker":      func() string { return conn.Sagemaker(region).Options().Region },
		"Efs":            func() string { return conn.Efs(region).Options().Region },
		"Elbv2":          func() string { return conn.Elbv2(region).Options().Region },
		"Redshift":       func() string { return conn.Redshift(region).Options().Region },
		"Secretsmanager": func() string { return conn.Secretsmanager(region).Options().Region },
		"Guardduty":      func() string { return conn.Guardduty(region).Options().Region },
		"Wafv2":          func() string { return conn.Wafv2(region).Options().Region },
		"Acm":            func() string { return conn.Acm(region).Options().Region },
		"Organizations":  func() string { return conn.Organizations(region).Options().Region },
		"Batch":          func() string { return conn.Batch(region).Options().Region },
		"CloudFormation": func() string { return conn.CloudFormation(region).Options().Region },
		"STS":            func() string { return conn.STS(region).Options().Region },
		"WorkspacesWeb":  func() string { return conn.WorkspacesWeb(region).Options().Region },
		"Bedrock":        func() string { return conn.Bedrock(region).Options().Region },
		"IdentityStore":  func() string { return conn.IdentityStore(region).Options().Region },
	}

	for name, regionOf := range getters {
		require.Equal(t, region, regionOf(), "%s should build a client for the requested region", name)
	}
}

// Concurrent access to the client cache must be data-race free (run with -race)
// and must converge to a stable cached client afterwards.
func TestClientCacheConcurrentAccess(t *testing.T) {
	conn := testConn("us-east-1")

	const goroutines = 64
	var wg sync.WaitGroup
	results := make([]any, goroutines)
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = conn.Ec2("us-east-1")
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		require.NotNil(t, results[i], "concurrent getter must never return nil")
	}
	// Every goroutine must receive the same cached client: newClient uses
	// LoadOrStore, so racing constructions collapse to a single instance.
	for i := 1; i < goroutines; i++ {
		require.Same(t, results[0], results[i], "all goroutines should get the same cached client")
	}
	// After the burst, the cache is settled: repeated calls are stable.
	require.Same(t, conn.Ec2("us-east-1"), conn.Ec2("us-east-1"))
}
