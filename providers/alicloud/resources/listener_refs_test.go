// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestListenerLoadBalancerWithoutParent covers the case where a listener was
// constructed without the load balancer it was listed from.
//
// The reference must resolve to an explicit null. Returning (nil, nil) without
// marking the field set leaves it unset, which crosses the plugin boundary as a
// primitive with no type information and surfaces client-side as a coercion
// error rather than a null.
func TestListenerLoadBalancerWithoutParent(t *testing.T) {
	t.Run("slb", func(t *testing.T) {
		l := &mqlAlicloudSlbListener{}
		got, err := l.loadBalancer()
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, l.LoadBalancer.State)
	})
	t.Run("alb", func(t *testing.T) {
		l := &mqlAlicloudAlbListener{}
		got, err := l.loadBalancer()
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, l.LoadBalancer.State)
	})
	t.Run("nlb", func(t *testing.T) {
		l := &mqlAlicloudNlbListener{}
		got, err := l.loadBalancer()
		require.NoError(t, err)
		assert.Nil(t, got)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, l.LoadBalancer.State)
	})
}

// TestListenerLoadBalancerReturnsParent confirms the reference hands back the
// load balancer carried from the listing context, without an API call.
func TestListenerLoadBalancerReturnsParent(t *testing.T) {
	t.Run("slb", func(t *testing.T) {
		lb := &mqlAlicloudSlbLoadBalancer{}
		l := &mqlAlicloudSlbListener{}
		l.parentLoadBalancer = lb
		got, err := l.loadBalancer()
		require.NoError(t, err)
		assert.Same(t, lb, got)
	})
	t.Run("alb", func(t *testing.T) {
		lb := &mqlAlicloudAlbLoadBalancer{}
		l := &mqlAlicloudAlbListener{}
		l.parentLoadBalancer = lb
		got, err := l.loadBalancer()
		require.NoError(t, err)
		assert.Same(t, lb, got)
	})
	t.Run("nlb", func(t *testing.T) {
		lb := &mqlAlicloudNlbLoadBalancer{}
		l := &mqlAlicloudNlbListener{}
		l.parentLoadBalancer = lb
		got, err := l.loadBalancer()
		require.NoError(t, err)
		assert.Same(t, lb, got)
	})
}
