// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	"sync"
	"testing"
	"time"

	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
)

func TestIsServiceNotAvailableInRegionError(t *testing.T) {
	t.Run("nil error returns false", func(t *testing.T) {
		assert.False(t, IsServiceNotAvailableInRegionError(nil))
	})

	t.Run("unrelated error returns false", func(t *testing.T) {
		assert.False(t, IsServiceNotAvailableInRegionError(errors.New("some random error")))
	})

	t.Run("no such host", func(t *testing.T) {
		err := errors.New("dial tcp: lookup memorydb.us-west-1.amazonaws.com: no such host")
		assert.True(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("UnknownEndpoint", func(t *testing.T) {
		err := errors.New("UnknownEndpoint: could not resolve endpoint")
		assert.True(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("could not resolve endpoint", func(t *testing.T) {
		err := errors.New("could not resolve endpoint for region")
		assert.True(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("EC2 InvalidAction (Verified Access in unsupported region)", func(t *testing.T) {
		err := fmt.Errorf("operation error EC2: DescribeVerifiedAccessInstances, https response error StatusCode: 400, api error InvalidAction: The action DescribeVerifiedAccessInstances is not valid for this web service.")
		assert.True(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("Bedrock UnknownOperationException", func(t *testing.T) {
		err := fmt.Errorf("operation error Bedrock: ListCustomModels, https response error StatusCode: 404, api error UnknownOperationException: Unknown Operation")
		assert.True(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("Bedrock ValidationException Unknown operation", func(t *testing.T) {
		err := fmt.Errorf("operation error Bedrock: ListCustomModels, https response error StatusCode: 400, ValidationException: Unknown operation")
		assert.True(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("Bedrock Unknown Operation (capitalized)", func(t *testing.T) {
		err := fmt.Errorf("operation error Bedrock: ListCustomModels, https response error StatusCode: 400, ValidationException: Unknown Operation")
		assert.True(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("retry exhaustion with request send failure (bedrock-agent us-west-1 5xx)", func(t *testing.T) {
		// us-west-1 returns HTTP 500 for ListFlows on every retry; after the
		// SDK exhausts attempts the wrapped error contains both phrases.
		err := fmt.Errorf("operation error Bedrock Agent: ListFlows, exceeded maximum number of attempts, 3, https response error StatusCode: 0, RequestID: , request send failed, Get \"https://bedrock-agent.us-west-1.amazonaws.com/flows/\": GET https://bedrock-agent.us-west-1.amazonaws.com/flows/ giving up after 3 attempt(s)")
		assert.True(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("retry exhaustion WITHOUT send failure is NOT swallowed (throttling, real 5xx)", func(t *testing.T) {
		// Throttling/transient 5xx errors that successfully reach the server
		// must propagate up to the caller — the helper should not match
		// "exceeded maximum number of attempts" by itself.
		err := fmt.Errorf("operation error S3: GetObject, exceeded maximum number of attempts, 3, https response error StatusCode: 503, RequestID: ABC, api error SlowDown: Please reduce your request rate.")
		assert.False(t, IsServiceNotAvailableInRegionError(err))
	})

	t.Run("plain request send failed (no retry exhaustion) does NOT match", func(t *testing.T) {
		// A single transient network error without retry exhaustion is also
		// not enough — both phrases must be present together.
		err := fmt.Errorf("operation error EC2: DescribeInstances, https response error StatusCode: 0, request send failed, Get \"https://ec2.amazonaws.com/\": net/http: TLS handshake timeout")
		assert.False(t, IsServiceNotAvailableInRegionError(err))
	})
}

// macieHTTPError builds a Macie-style error carrying an HTTP status code.
func macieHTTPError(code int, msg string) error {
	return &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &nethttp.Response{StatusCode: code}},
		Err:      errors.New(msg),
	}
}

// TestIsMacieNotEnabledError guards the over-broad branch: matching a bare
// AccessDenied with no Macie-specific message swallowed genuine macie2:*
// permission gaps across 15 call sites, so every Macie resource degraded to
// empty and any data-classification policy passed with nothing to fail on.
func TestIsMacieNotEnabledError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.False(t, IsMacieNotEnabledError(nil))
	})

	t.Run("bare permission denial is not a not-enabled signal", func(t *testing.T) {
		assert.False(t, IsMacieNotEnabledError(macieHTTPError(403,
			"AccessDeniedException: User is not authorized to perform macie2:ListFindings")))
	})

	t.Run("401 with Macie message", func(t *testing.T) {
		assert.True(t, IsMacieNotEnabledError(macieHTTPError(401,
			"AccessDeniedException: Macie is not enabled")))
	})

	t.Run("404 with Macie message", func(t *testing.T) {
		assert.True(t, IsMacieNotEnabledError(macieHTTPError(404,
			"ResourceNotFoundException: Amazon Macie isn't enabled for your account")))
	})

	// The regression. Macie writes this message with U+2019, not the ASCII
	// apostrophe, so a guard spelled with a plain quote never matched it and
	// ListAllowLists reported a failure in every account without Macie. The
	// literals below are deliberately the curly form - normalising them to
	// ASCII here would test nothing.
	t.Run("403 with a typographic apostrophe", func(t *testing.T) {
		assert.True(t, IsMacieNotEnabledError(macieHTTPError(403,
			"AccessDeniedException: The request failed because Macie isn’t enabled in the specified AWS Region.")))
	})

	t.Run("404 with a typographic apostrophe", func(t *testing.T) {
		assert.True(t, IsMacieNotEnabledError(macieHTTPError(404,
			"ResourceNotFoundException: Amazon Macie isn’t enabled")))
	})

	// GetAutomatedDiscoveryConfiguration never names Macie at all.
	t.Run("403 not onboarded", func(t *testing.T) {
		assert.True(t, IsMacieNotEnabledError(macieHTTPError(403,
			"AccessDeniedException: Account Id: [123456789012] has not been onboarded")))
	})

	// The onboarding branch must not widen into the swallowing problem the
	// Macie-named condition exists to prevent.
	t.Run("permission gap is still an error under the onboarding branch", func(t *testing.T) {
		assert.False(t, IsMacieNotEnabledError(macieHTTPError(403,
			"AccessDeniedException: User is not authorized to perform macie2:GetAutomatedDiscoveryConfiguration")))
	})
}

func TestAwsNormalizeApostrophes(t *testing.T) {
	assert.Equal(t, "isn't", awsNormalizeApostrophes("isn’t"))
	assert.Equal(t, "isn't", awsNormalizeApostrophes("isn't"), "ASCII input is left alone")
	assert.Equal(t, "", awsNormalizeApostrophes(""))
}

// TestIsSecurityLakeNotEnabledError covers the shape neither the access-denied
// nor the not-available-in-region guard caught, which failed the subscriber
// listing for every account that has not adopted Security Lake.
func TestIsSecurityLakeNotEnabledError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		assert.False(t, IsSecurityLakeNotEnabledError(nil))
	})

	t.Run("404 not enabled for the account", func(t *testing.T) {
		assert.True(t, IsSecurityLakeNotEnabledError(macieHTTPError(404,
			"ResourceNotFoundException: The request failed because Security Lake isn’t enabled for your account in any Regions.")))
	})

	t.Run("permission denial is not a not-enabled signal", func(t *testing.T) {
		assert.False(t, IsSecurityLakeNotEnabledError(macieHTTPError(403,
			"AccessDeniedException: User is not authorized to perform securitylake:ListSubscribers")))
	})

	t.Run("an unrelated 404 is not a not-enabled signal", func(t *testing.T) {
		assert.False(t, IsSecurityLakeNotEnabledError(macieHTTPError(404,
			"ResourceNotFoundException: Subscriber not found")))
	})
}

func TestFetchTagsConcurrently(t *testing.T) {
	t.Run("no keys makes no calls", func(t *testing.T) {
		called := false
		res := fetchTagsConcurrently(context.Background(), []string{}, func(context.Context, string) (map[string]string, error) {
			called = true
			return nil, nil
		})
		assert.Empty(t, res)
		assert.False(t, called)
	})

	t.Run("nil keys returns an empty, usable map", func(t *testing.T) {
		res := fetchTagsConcurrently(context.Background(), nil, func(context.Context, string) (map[string]string, error) {
			return map[string]string{"env": "prod"}, nil
		})
		assert.Empty(t, res)
		assert.Nil(t, res["anything"])
	})

	t.Run("resolves every key", func(t *testing.T) {
		keys := []string{"a", "b", "c"}
		res := fetchTagsConcurrently(context.Background(), keys, func(_ context.Context, k string) (map[string]string, error) {
			return map[string]string{"name": k}, nil
		})
		assert.Len(t, res, 3)
		for _, k := range keys {
			assert.Equal(t, map[string]string{"name": k}, res[k])
		}
	})

	t.Run("a failing key is absent, the rest still resolve", func(t *testing.T) {
		res := fetchTagsConcurrently(context.Background(), []string{"ok", "boom", "fine"}, func(_ context.Context, k string) (map[string]string, error) {
			if k == "boom" {
				return nil, errors.New("access denied")
			}
			return map[string]string{"name": k}, nil
		})

		// An errored key yields a nil map, which IsFilteredOutByTags treats as
		// an empty tag set rather than aborting the whole listing.
		assert.Len(t, res, 2)
		assert.Nil(t, res["boom"])
		assert.Equal(t, map[string]string{"name": "ok"}, res["ok"])
		assert.Equal(t, map[string]string{"name": "fine"}, res["fine"])
	})

	// Callers seed the fetched tags onto the resource, so "we read it and there
	// were none" must stay distinguishable from "we could not read it". Presence
	// in the map is the signal; a successful fetch is never a nil map.
	t.Run("untagged resolves to an empty map, not absence", func(t *testing.T) {
		res := fetchTagsConcurrently(context.Background(), []string{"untagged", "failed"}, func(_ context.Context, k string) (map[string]string, error) {
			if k == "failed" {
				return nil, errors.New("access denied")
			}
			return nil, nil // successful call, resource simply has no tags
		})

		untagged, ok := res["untagged"]
		assert.True(t, ok, "a successful fetch must be present in the map")
		assert.NotNil(t, untagged, "a successful fetch must never yield a nil map")
		assert.Empty(t, untagged)

		_, ok = res["failed"]
		assert.False(t, ok, "a failed fetch must be absent from the map")
	})

	t.Run("every key failing is not fatal", func(t *testing.T) {
		res := fetchTagsConcurrently(context.Background(), []string{"a", "b"}, func(context.Context, string) (map[string]string, error) {
			return nil, errors.New("access denied")
		})
		assert.Empty(t, res)
	})

	t.Run("duplicate keys are tolerated", func(t *testing.T) {
		res := fetchTagsConcurrently(context.Background(), []string{"dup", "dup"}, func(_ context.Context, k string) (map[string]string, error) {
			return map[string]string{"name": k}, nil
		})
		assert.Len(t, res, 1)
		assert.Equal(t, map[string]string{"name": "dup"}, res["dup"])
	})

	t.Run("concurrency stays within the bound", func(t *testing.T) {
		keys := make([]string, 100)
		for i := range keys {
			keys[i] = fmt.Sprintf("key-%d", i)
		}

		var mu sync.Mutex
		inFlight, maxInFlight := 0, 0

		res := fetchTagsConcurrently(context.Background(), keys, func(_ context.Context, k string) (map[string]string, error) {
			mu.Lock()
			inFlight++
			if inFlight > maxInFlight {
				maxInFlight = inFlight
			}
			mu.Unlock()

			// Hold the slot long enough that the pool saturates.
			time.Sleep(2 * time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
			return map[string]string{"name": k}, nil
		})

		assert.Len(t, res, len(keys))
		assert.LessOrEqual(t, maxInFlight, fetchTagsConcurrency)
		// Guard against the bound silently collapsing to serial execution.
		assert.Greater(t, maxInFlight, 1)
	})
}
