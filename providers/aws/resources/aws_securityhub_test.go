// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/stretchr/testify/assert"
)

func TestStandardNameFromArn(t *testing.T) {
	t.Run("aws foundational standards ARN", func(t *testing.T) {
		name := standardNameFromArn("arn:aws:securityhub:us-west-2::standards/aws-foundational-security-best-practices/v/1.0.0")
		assert.Equal(t, "aws-foundational-security-best-practices", name)
	})

	t.Run("cis ruleset ARN", func(t *testing.T) {
		name := standardNameFromArn("arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0")
		assert.Equal(t, "cis-aws-foundations-benchmark", name)
	})

	t.Run("pci-dss standards ARN", func(t *testing.T) {
		name := standardNameFromArn("arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1")
		assert.Equal(t, "pci-dss", name)
	})

	t.Run("nist standards ARN", func(t *testing.T) {
		name := standardNameFromArn("arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0")
		assert.Equal(t, "nist-800-53", name)
	})

	t.Run("ARN without standards or ruleset prefix returns full ARN", func(t *testing.T) {
		arn := "arn:aws:securityhub:us-west-2:123456789012:hub/default"
		name := standardNameFromArn(arn)
		assert.Equal(t, arn, name)
	})

	t.Run("empty string returns empty", func(t *testing.T) {
		assert.Equal(t, "", standardNameFromArn(""))
	})

	t.Run("standards ARN without version suffix", func(t *testing.T) {
		name := standardNameFromArn("arn:aws:securityhub:::standards/my-standard")
		assert.Equal(t, "my-standard", name)
	})
}

// TestSecurityHubEnabledStandardsUsesCache verifies that once
// getEnabledStandards has populated its cache (standardsFetched == true),
// subsequent calls return the cached slice without invoking the paginator.
// This pins down the shared-cache behavior that lets enabledStandards and
// standardSubscriptions both read from a single GetEnabledStandards fetch.
func TestSecurityHubEnabledStandardsUsesCache(t *testing.T) {
	cached := []types.StandardsSubscription{
		{
			StandardsArn:             aws.String("arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"),
			StandardsSubscriptionArn: aws.String("arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.4.0"),
			StandardsStatus:          types.StandardsStatusReady,
		},
		{
			StandardsArn:             aws.String("arn:aws:securityhub:::ruleset/aws-foundational-security-best-practices/v/1.0.0"),
			StandardsSubscriptionArn: aws.String("arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0"),
			StandardsStatus:          types.StandardsStatusReady,
		},
	}

	hub := &mqlAwsSecurityhubHub{
		standardsFetched: true,
		standards:        cached,
	}

	// Cache hit path: returns the pre-populated slice without touching the
	// runtime. If this ever regresses to call MqlRuntime.Connection, the
	// nil-deref panic on the zero-value hub will catch it.
	got, err := hub.getEnabledStandards()
	assert.NoError(t, err)
	assert.Equal(t, cached, got)
}

// TestSecurityHubStandardsCacheConcurrentHits exercises the double-check
// pattern: many concurrent callers on a cache-populated hub all read the
// same slice with no data race (meaningful under `go test -race`).
func TestSecurityHubStandardsCacheConcurrentHits(t *testing.T) {
	hub := &mqlAwsSecurityhubHub{
		standardsFetched: true,
		standards: []types.StandardsSubscription{
			{StandardsArn: aws.String("arn:aws:securityhub:::ruleset/x")},
		},
	}

	var wg sync.WaitGroup
	var got int64
	for range 50 {
		wg.Go(func() {
			standards, err := hub.getEnabledStandards()
			if err == nil && len(standards) == 1 {
				atomic.AddInt64(&got, 1)
			}
		})
	}
	wg.Wait()
	assert.Equal(t, int64(50), got)
}
