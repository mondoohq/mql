// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/hetznercloud/hcloud-go/v2/hcloud/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// requireDictSerializes runs a dict through the exact llx conversion path a
// queried `dict` field takes. The dict-to-primitive converter only accepts
// bool/int64/float64/string/[]any/map[string]any; a raw `int` or `time.Time`
// errors here, which is how the load balancer health-check and deprecation
// dicts silently broke. This is the regression guard for those bugs.
func requireDictSerializes(t *testing.T, d map[string]any) {
	t.Helper()
	res := llx.DictData(d).Result()
	require.Empty(t, res.Error, "dict must serialize through the llx dict converter")
}

// requireDictArraySerializes is requireDictSerializes for a `[]dict` field.
func requireDictArraySerializes(t *testing.T, a []any) {
	t.Helper()
	res := llx.ArrayData(a, types.Dict).Result()
	require.Empty(t, res.Error, "[]dict must serialize through the llx dict converter")
}

func TestDeprecationDict(t *testing.T) {
	t.Run("nil is an empty dict and serializes", func(t *testing.T) {
		d := deprecationDict(nil)
		assert.Equal(t, map[string]any{}, d)
		requireDictSerializes(t, d)
	})

	t.Run("deprecated uses RFC3339 strings and serializes", func(t *testing.T) {
		announced := time.Date(2025, 9, 24, 12, 0, 0, 0, time.UTC)
		unavailable := time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC)
		d := deprecationDict(&hcloud.DeprecationInfo{
			Announced:        announced,
			UnavailableAfter: unavailable,
		})
		// Values must be strings, not time.Time — a time.Time fails serialization.
		assert.Equal(t, "2025-09-24T12:00:00Z", d["announced"])
		assert.Equal(t, "2026-03-24T12:00:00Z", d["unavailableAfter"])
		requireDictSerializes(t, d)
	})

	t.Run("zero timestamps are omitted", func(t *testing.T) {
		d := deprecationDict(&hcloud.DeprecationInfo{})
		assert.NotContains(t, d, "announced")
		assert.NotContains(t, d, "unavailableAfter")
		requireDictSerializes(t, d)
	})
}

// The image deprecation schedule has to survive the whole path the field
// relies on: the deprecation object in an images API response, through the
// hcloud schema decode, into the dict the resource serves. Wiring the field off
// a struct member the decode never fills passes a hand-built-struct test and
// fails here.
func TestImageDeprecationFromAPIPayload(t *testing.T) {
	decode := func(t *testing.T, payload string) *hcloud.Image {
		t.Helper()
		var s schema.Image
		require.NoError(t, json.Unmarshal([]byte(payload), &s))
		return hcloud.ImageFromSchema(s)
	}

	t.Run("deprecated image carries both timestamps", func(t *testing.T) {
		img := decode(t, `{
			"id": 4711,
			"type": "system",
			"status": "available",
			"name": "ubuntu-20.04",
			"deprecation": {
				"announced": "2025-09-24T12:00:00+00:00",
				"unavailable_after": "2026-03-24T12:00:00+00:00"
			}
		}`)

		require.True(t, img.IsDeprecated())
		d := deprecationDict(img.Deprecation)
		assert.Equal(t, "2025-09-24T12:00:00Z", d["announced"])
		// unavailableAfter is the reason the field exists: deprecated never
		// carried the date the image stops being served.
		assert.Equal(t, "2026-03-24T12:00:00Z", d["unavailableAfter"])
		requireDictSerializes(t, d)

		// The shipped deprecated field keeps reporting the announcement.
		require.NotNil(t, timePtr(img.Deprecated))
		assert.Equal(t, "2025-09-24T12:00:00Z", timePtr(img.Deprecated).UTC().Format(time.RFC3339))
	})

	t.Run("image with no deprecation reports nothing, not a zero date", func(t *testing.T) {
		img := decode(t, `{
			"id": 4712,
			"type": "system",
			"status": "available",
			"name": "ubuntu-24.04",
			"deprecation": null
		}`)

		assert.False(t, img.IsDeprecated())
		assert.Empty(t, deprecationDict(img.Deprecation))
		// deprecated must be null rather than year 1: a year-1 timestamp
		// reads as "deprecated long ago" in any date comparison.
		assert.Nil(t, timePtr(img.Deprecated))
	})
}

func TestZonePrimaryNameserverDicts(t *testing.T) {
	got := zonePrimaryNameserverDicts([]hcloud.ZonePrimaryNameserver{
		{Address: "203.0.113.53", Port: 53, TSIGAlgorithm: hcloud.ZoneTSIGAlgorithmHMACSHA256, TSIGKey: "c2VjcmV0"},
		{Address: "198.51.100.53", Port: 5353},
	})
	require.Len(t, got, 2)

	authenticated := got[0].(map[string]any)
	assert.Equal(t, "203.0.113.53", authenticated["address"])
	assert.Equal(t, int64(53), authenticated["port"])
	assert.Equal(t, true, authenticated["tsigConfigured"])
	// The shared secret itself must never reach queryable data, under any key.
	for k, v := range authenticated {
		assert.NotEqual(t, "c2VjcmV0", v, "TSIG key leaked via key %q", k)
	}

	unauthenticated := got[1].(map[string]any)
	assert.Equal(t, false, unauthenticated["tsigConfigured"])
	assert.Equal(t, "", unauthenticated["tsigAlgorithm"])

	requireDictArraySerializes(t, got)
	assert.Empty(t, zonePrimaryNameserverDicts(nil))
}

func TestLoadBalancerHealthCheckDict(t *testing.T) {
	t.Run("tcp check widens int ports and serializes", func(t *testing.T) {
		d := loadBalancerHealthCheckDict(hcloud.LoadBalancerServiceHealthCheck{
			Protocol: hcloud.LoadBalancerServiceProtocolTCP,
			Port:     80,
			Interval: 15 * time.Second,
			Timeout:  10 * time.Second,
			Retries:  3,
		})
		// Port and Retries are hcloud `int` — must be widened to int64 to serialize.
		assert.Equal(t, int64(80), d["port"])
		assert.Equal(t, int64(3), d["retries"])
		assert.Equal(t, float64(15), d["interval"])
		requireDictSerializes(t, d)
	})

	t.Run("http check with nested dict serializes", func(t *testing.T) {
		d := loadBalancerHealthCheckDict(hcloud.LoadBalancerServiceHealthCheck{
			Protocol: hcloud.LoadBalancerServiceProtocolHTTP,
			Port:     443,
			Interval: 15 * time.Second,
			Timeout:  10 * time.Second,
			Retries:  3,
			HTTP: &hcloud.LoadBalancerServiceHealthCheckHTTP{
				Domain:      "example.com",
				Path:        "/health",
				Response:    "OK",
				StatusCodes: []string{"200", "201"},
				TLS:         true,
			},
		})
		requireDictSerializes(t, d)
	})
}

func TestLoadBalancerHealthStatusDicts(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		a := loadBalancerHealthStatusDicts(nil)
		assert.Empty(t, a)
		requireDictArraySerializes(t, a)
	})

	t.Run("widens int listenPort and serializes", func(t *testing.T) {
		a := loadBalancerHealthStatusDicts([]hcloud.LoadBalancerTargetHealthStatus{
			{ListenPort: 443, Status: hcloud.LoadBalancerTargetHealthStatusStatusHealthy},
			{ListenPort: 80, Status: hcloud.LoadBalancerTargetHealthStatusStatusUnhealthy},
		})
		require.Len(t, a, 2)
		first := a[0].(map[string]any)
		// ListenPort is hcloud `int` — must be widened to int64 to serialize.
		assert.Equal(t, int64(443), first["listenPort"])
		assert.Equal(t, "healthy", first["status"])
		requireDictArraySerializes(t, a)
	})
}
