// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNatForwardsAllPorts(t *testing.T) {
	tests := []struct {
		name                       string
		externalPort, internalPort *string
		expected                   bool
	}{
		{"single port mapping", new("443"), new("8443"), false},
		// "any" on either end publishes every listening service on the private
		// address, not the one that was meant to be exposed
		{"any inbound", new("any"), new("any"), true},
		{"any only outside", new("any"), new("22"), true},
		{"any only inside", new("22"), new("any"), true},
		{"case insensitive", new("Any"), new("Any"), true},
		{"whitespace tolerated", new(" any "), new("443"), true},
		{"absent ports", nil, nil, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, natForwardsAllPorts(test.externalPort, test.internalPort))
		})
	}
}

func TestNatPortIsAny(t *testing.T) {
	assert.True(t, natPortIsAny(new("any")))
	assert.True(t, natPortIsAny(new("ANY")))
	assert.False(t, natPortIsAny(new("443")))
	assert.False(t, natPortIsAny(new("")))
	assert.False(t, natPortIsAny(nil))
}
