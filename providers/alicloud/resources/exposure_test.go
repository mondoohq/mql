// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestEcsInstanceInternetExposed(t *testing.T) {
	t.Run("directly-assigned public IP is exposed", func(t *testing.T) {
		i := &mqlAlicloudEcsInstance{
			PublicIpAddresses: plugin.TValue[[]any]{Data: []any{"1.2.3.4"}, State: plugin.StateIsSet},
			EipAddress:        plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
		}
		got, err := i.internetExposed()
		assert.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("associated elastic IP is exposed", func(t *testing.T) {
		i := &mqlAlicloudEcsInstance{
			PublicIpAddresses: plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet},
			EipAddress:        plugin.TValue[string]{Data: "47.98.1.2", State: plugin.StateIsSet},
		}
		got, err := i.internetExposed()
		assert.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("no public IP and no EIP is not exposed", func(t *testing.T) {
		i := &mqlAlicloudEcsInstance{
			PublicIpAddresses: plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet},
			EipAddress:        plugin.TValue[string]{Data: "", State: plugin.StateIsSet},
		}
		got, err := i.internetExposed()
		assert.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("whitespace-only EIP is not exposed", func(t *testing.T) {
		i := &mqlAlicloudEcsInstance{
			PublicIpAddresses: plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet},
			EipAddress:        plugin.TValue[string]{Data: "  ", State: plugin.StateIsSet},
		}
		got, err := i.internetExposed()
		assert.NoError(t, err)
		assert.False(t, got)
	})
}

func TestSlbLoadBalancerInternetFacing(t *testing.T) {
	cases := map[string]bool{
		"internet": true,
		"Internet": true,
		"intranet": false,
		"":         false,
	}
	for addressType, want := range cases {
		lb := &mqlAlicloudSlbLoadBalancer{
			AddressType: plugin.TValue[string]{Data: addressType, State: plugin.StateIsSet},
		}
		got, err := lb.internetFacing()
		assert.NoError(t, err)
		assert.Equalf(t, want, got, "addressType=%q", addressType)
	}
}
