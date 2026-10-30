// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestOciIpIsPublic(t *testing.T) {
	yes, no := true, false

	tests := []struct {
		name        string
		isPublic    *bool
		lbIsPrivate bool
		want        bool
	}{
		// An explicit flag always wins.
		{"explicitly public", &yes, false, true},
		{"explicitly private", &no, false, false},
		{"explicitly public on a private balancer", &yes, true, true},

		// The case that matters: isPublic is optional on both load balancer
		// SDK models. Absent on a balancer that is not private means public.
		// Defaulting to false here reported a genuinely internet-facing
		// balancer as unreachable, so an "no load balancer may be exposed"
		// policy passed with nothing to fail on.
		{"absent on a public balancer", nil, false, true},
		{"absent on a private balancer", nil, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociIpIsPublic(tt.isPublic, tt.lbIsPrivate))
		})
	}
}

func TestOciLoadBalancerHasPublicIp(t *testing.T) {
	// A classic load balancer address whose isPublic the service reported.
	ip := func(addr string, isPublic bool) any {
		return &mqlOciLoadBalancerIpAddress{
			IpAddress: plugin.TValue[string]{Data: addr, State: plugin.StateIsSet},
			IsPublic:  plugin.TValue[bool]{Data: isPublic, State: plugin.StateIsSet},
		}
	}
	// An address the service returned with no isPublic at all.
	nullIp := func(addr string) any {
		return &mqlOciLoadBalancerIpAddress{
			IpAddress: plugin.TValue[string]{Data: addr, State: plugin.StateIsSet},
			IsPublic:  plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull},
		}
	}
	// A network load balancer address, the other resource sharing the shape.
	nlbIp := func(addr string, isPublic bool) any {
		return &mqlOciNetworkLoadBalancerIpAddress{
			IpAddress: plugin.TValue[string]{Data: addr, State: plugin.StateIsSet},
			IsPublic:  plugin.TValue[bool]{Data: isPublic, State: plugin.StateIsSet},
		}
	}

	tests := []struct {
		name      string
		ips       []any
		isPrivate bool
		want      bool
	}{
		// A balancer that is not private answers on a public address by
		// definition, so an address list with nothing readable in it is an
		// unread fact, not a private balancer. Reporting false here would let
		// an address list that failed to load be the reason a public balancer
		// passes an "must not be exposed" policy.
		{"no addresses at all", nil, false, true},
		{"empty address list", []any{}, false, true},
		{"no addresses on a private balancer", nil, true, false},
		{"one public address", []any{ip("203.0.113.10", true)}, false, true},
		{"only private addresses", []any{ip("10.0.0.5", false)}, false, false},
		{"a public address among private ones", []any{
			ip("10.0.0.5", false), ip("203.0.113.10", true),
		}, false, true},

		// Both load balancer address resources have to be read, since the
		// exposure resource collects addresses from either kind.
		{"network load balancer address", []any{nlbIp("203.0.113.10", true)}, false, true},
		{"private network load balancer address", []any{nlbIp("10.0.0.5", false)}, false, false},

		// A private balancer's addresses are internal whatever the individual
		// flags say, so the balancer flag short-circuits.
		{"private balancer with a public-looking address", []any{
			ip("203.0.113.10", true),
		}, true, false},

		// The regression: the network load balancer marshalled the SDK slice
		// straight to JSON, so an optional isPublic arrived as null. Reading
		// that back as "not public" cleared the balancer entirely.
		{"null isPublic on a public balancer", []any{nullIp("203.0.113.10")}, false, true},
		{"null isPublic on a private balancer", []any{nullIp("10.0.0.5")}, true, false},

		// An entry of some other type must not panic. Nothing was read from it
		// either, so it lands on the same unread-fact answer as an empty list.
		// This is the shape the regression took: the deprecated ipAddresses
		// dicts were passed in, every map failed the type assertion, and the
		// balancer read as having no public address at all.
		{"foreign entry is not a private verdict", []any{"203.0.113.10"}, false, true},
		{"foreign entry on a private balancer", []any{"10.0.0.5"}, true, false},
		{"foreign entry alongside a public one", []any{
			"garbage", ip("203.0.113.10", true),
		}, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociLoadBalancerHasPublicIp(tt.ips, tt.isPrivate))
		})
	}
}
