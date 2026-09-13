// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestWhitelistEntryAllowsAllAddresses covers the per-entry classifier. Every
// case names a real whitelist entry shape, and an entry that opens the database
// to the internet must be reported as open regardless of how it is spelled,
// because the check built on this field passes when it reads false.
func TestWhitelistEntryAllowsAllAddresses(t *testing.T) {
	open := []string{
		"0.0.0.0/0",               // the explicit any-address block
		"0.0.0.0",                 // the bare form the console writes for it
		"10.0.0.0/0",              // a zero-length prefix on any address is still every address
		"%",                       // the wildcard host
		"0.0.0.0-255.255.255.255", // a range covering the whole space
		"::/0",                    // the IPv6 any-address block
		"::",                      // the bare IPv6 unspecified address
		" 0.0.0.0/0 ",             // padded by the comma-separated API response
	}
	for _, entry := range open {
		t.Run("open: "+entry, func(t *testing.T) {
			assert.True(t, whitelistEntryAllowsAllAddresses(entry))
		})
	}

	closed := []string{
		"192.168.0.0/16",          // a real private block, and the /16 must not read as /0
		"10.0.0.1",                // a single host
		"10.0.0.1-10.0.0.5",       // a range covering five addresses
		"0.0.0.1-255.255.255.255", // a range starting one address in
		"0.0.0.0-10.0.0.255",      // a range starting at zero but stopping early
		"127.0.0.1/32",            // a single host written as a block
		"0.0.0.0/8",               // the zero block, which is not the zero-length prefix
		"",                        // an empty entry
		"not-an-address",          // garbage: a parse failure is not evidence of exposure
		"999.0.0.0/0",             // a malformed block that a substring check would call open
		"0.0.0.0-",                // a truncated range
		"%.example.com",           // a wildcard hostname, not the wildcard host
	}
	for _, entry := range closed {
		t.Run("closed: "+entry, func(t *testing.T) {
			assert.False(t, whitelistEntryAllowsAllAddresses(entry))
		})
	}
}

// TestWhitelistAllowsAllAddresses covers the list-level classifier: one open
// entry anywhere in the list opens the database, an empty list is not an open
// whitelist, and a list of restricted entries stays closed.
func TestWhitelistAllowsAllAddresses(t *testing.T) {
	t.Run("empty whitelist is not open", func(t *testing.T) {
		assert.False(t, whitelistAllowsAllAddresses([]string{}))
	})

	t.Run("nil whitelist is not open", func(t *testing.T) {
		assert.False(t, whitelistAllowsAllAddresses(nil))
	})

	t.Run("restricted entries stay closed", func(t *testing.T) {
		assert.False(t, whitelistAllowsAllAddresses([]string{"10.0.0.1", "192.168.0.0/16", "172.16.0.0/12"}))
	})

	t.Run("one open entry among restricted ones opens the list", func(t *testing.T) {
		assert.True(t, whitelistAllowsAllAddresses([]string{"10.0.0.1", "192.168.0.0/16", "0.0.0.0/0"}))
	})

	t.Run("garbage alongside restricted entries stays closed", func(t *testing.T) {
		assert.False(t, whitelistAllowsAllAddresses([]string{"not-an-address", "10.0.0.1"}))
	})
}

// TestResolveWhitelistAllowsAllAddresses covers the bridge from the computed
// whitelist field to the classifier: a fetch error must surface instead of
// reading as a closed whitelist, and non-string list members are ignored rather
// than crashing the field.
func TestResolveWhitelistAllowsAllAddresses(t *testing.T) {
	t.Run("open entry in the field data", func(t *testing.T) {
		field := &plugin.TValue[[]any]{Data: []any{"10.0.0.1", "0.0.0.0"}, State: plugin.StateIsSet}
		got, err := resolveWhitelistAllowsAllAddresses(field)
		require.NoError(t, err)
		assert.True(t, got)
	})

	t.Run("restricted entries in the field data", func(t *testing.T) {
		field := &plugin.TValue[[]any]{Data: []any{"10.0.0.1", "192.168.0.0/16"}, State: plugin.StateIsSet}
		got, err := resolveWhitelistAllowsAllAddresses(field)
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("a whitelist that could not be read is an error, not a false", func(t *testing.T) {
		field := &plugin.TValue[[]any]{Error: assert.AnError, State: plugin.StateIsSet}
		got, err := resolveWhitelistAllowsAllAddresses(field)
		assert.Error(t, err)
		assert.False(t, got)
	})

	t.Run("non-string members are skipped", func(t *testing.T) {
		field := &plugin.TValue[[]any]{Data: []any{42, "10.0.0.1"}, State: plugin.StateIsSet}
		got, err := resolveWhitelistAllowsAllAddresses(field)
		require.NoError(t, err)
		assert.False(t, got)
	})
}
