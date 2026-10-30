// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBackendIsEcs covers the backend-type check that decides whether a load
// balancer backend resolves to an ECS instance. The three load balancer
// families spell the type differently, and getting this wrong in either
// direction is bad: too strict leaves the instance reference null on a real
// backend, too loose sends an ENI or IP id to the instance lookup.
func TestBackendIsEcs(t *testing.T) {
	tests := []struct {
		name       string
		serverType string
		want       bool
	}{
		{"ALB and NLB spelling", "Ecs", true},
		{"CLB spelling", "ecs", true},
		{"upper case", "ECS", true},
		{"surrounding whitespace", " Ecs ", true},
		{"elastic network interface", "Eni", false},
		{"clb network interface", "eni", false},
		{"ip backend", "Ip", false},
		{"function compute backend", "Fc", false},
		{"empty type", "", false},
		{"a type that merely contains ecs", "ecs-instance", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, backendIsEcs(tt.serverType))
		})
	}
}

// TestBackendServerKey covers the backend cache key, which all three load
// balancer families share. A server can sit under one owner on several ports,
// and the same server can back several owners, so both have to separate or
// backends collapse onto one another and disappear from the listing.
func TestBackendServerKey(t *testing.T) {
	base := backendServerKey("cn-hangzhou", "sgp-abc", "i-bp1abc", 80)

	t.Run("shape", func(t *testing.T) {
		assert.Equal(t, "cn-hangzhou/sgp-abc/i-bp1abc/80", base)
	})
	t.Run("port separates", func(t *testing.T) {
		assert.NotEqual(t, base, backendServerKey("cn-hangzhou", "sgp-abc", "i-bp1abc", 443))
	})
	t.Run("owner separates", func(t *testing.T) {
		assert.NotEqual(t, base, backendServerKey("cn-hangzhou", "sgp-def", "i-bp1abc", 80))
	})
	t.Run("a load balancer owner and a vServer group owner stay distinct", func(t *testing.T) {
		// the CLB case: the same instance attached directly and inside a group
		direct := backendServerKey("cn-hangzhou", "lb-abc", "i-bp1abc", 0)
		grouped := backendServerKey("cn-hangzhou", "rsp-abc", "i-bp1abc", 0)
		assert.NotEqual(t, direct, grouped)
	})
	t.Run("region separates", func(t *testing.T) {
		assert.NotEqual(t, base, backendServerKey("ap-southeast-1", "sgp-abc", "i-bp1abc", 80))
	})
	t.Run("server separates", func(t *testing.T) {
		assert.NotEqual(t, base, backendServerKey("cn-hangzhou", "sgp-abc", "i-bp1def", 80))
	})
	t.Run("a zero port is still a distinct key", func(t *testing.T) {
		assert.Equal(t, "cn-hangzhou/sgp-abc/i-bp1abc/0", backendServerKey("cn-hangzhou", "sgp-abc", "i-bp1abc", 0))
	})
}
