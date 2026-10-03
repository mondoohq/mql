// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// network.interfaces and the cloud instance metadata both build ipAddress
// resources with every field already supplied, and NewResource runs the init
// on each one. The init has to hand those straight back: resolving the host's
// primary address for them would replace every address on every interface with
// that one address.
//
// The nil runtime is the point of the test. Reaching past the fast path is
// what a regression here looks like, and with nothing to reach for it fails
// loudly instead of quietly returning the wrong address.
func TestInitIpAddressPassesThroughSuppliedArgs(t *testing.T) {
	args := map[string]*llx.RawData{
		"__id":      llx.StringData("10.91.0.2"),
		"ip":        llx.IPData(llx.ParseIP("10.91.0.2")),
		"cidr":      llx.IPData(llx.ParseIP("10.91.0.2/24")),
		"subnet":    llx.IPData(llx.ParseIP("10.91.0.0/24")),
		"broadcast": llx.IPData(llx.ParseIP("10.91.0.255")),
		"gateway":   llx.IPData(llx.ParseIP("10.91.0.1")),
	}

	got, res, err := initIpAddress(nil, args)
	require.NoError(t, err)
	assert.Nil(t, res, "a supplied address must not be resolved into a different resource")
	assert.Equal(t, args, got)
}

// A single field is still a supplied address, not a request to resolve one.
// cloudInstance builds these from metadata that carries the address alone.
func TestInitIpAddressPassesThroughAPartialAddress(t *testing.T) {
	args := map[string]*llx.RawData{
		"ip": llx.IPData(llx.ParseIP("192.168.65.3")),
	}

	got, res, err := initIpAddress(nil, args)
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.Equal(t, args, got)
}
