// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dottedPathHusks returns every path that is simultaneously a field path on one
// resource and the name of another resource, and that has no Init to fill it in.
//
// The compiler resolves the longest matching resource name before it considers a
// field, so such a path instantiates the sub-resource instead of calling the
// parent's accessor. Where the sub-resource's fields are plain schema fields
// that only the parent populates, none of them is ever set: the query reports
// null for every field with "provider returned no data and no error", and the
// values convert as primitives carrying no type information. An Init that
// delegates to the parent's accessor is what makes the dotted form resolve.
func dottedPathHusks() []string {
	var res []string
	for path := range getDataFields {
		factory, ok := resourceFactories[path]
		if !ok || factory.Init != nil {
			continue
		}
		res = append(res, path)
	}
	sort.Strings(res)
	return res
}

// The DNS server's server-wide configuration hangs off singleton sub-resources
// whose names are exactly the field paths that reach them. Without an Init, an
// operator asking for the recursion, forwarder, rate-limiting or scavenging
// configuration by its own path gets null for every field rather than the
// server's actual configuration — and a check reading "recursion is disabled"
// off a null passes on a server that has recursion enabled.
//
// The list fields are deliberately absent: `zones` and `rootHints` reach
// singular element resources (`windows.dnsServer.zone`), so their field paths
// match no resource name and were never affected.
func TestWindowsDnsServerSingletonsAreReachableByTheirOwnPath(t *testing.T) {
	paths := []string{
		"windows.dnsServer.settings",
		"windows.dnsServer.recursion",
		"windows.dnsServer.cache",
		"windows.dnsServer.diagnostics",
		"windows.dnsServer.scavenging",
		"windows.dnsServer.responseRateLimiting",
		"windows.dnsServer.forwarderConfiguration",
		"windows.dnsServer.zone.dnssec",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			// Each of these is genuinely both a field path and a resource
			// name; that is the condition that makes the Init necessary.
			_, isField := getDataFields[path]
			require.True(t, isField, "%s should be a field path on its parent", path)

			factory, isResource := resourceFactories[path]
			require.True(t, isResource, "%s should also be a registered resource name", path)

			assert.NotNil(t, factory.Init,
				"%s resolves to the resource, not the field, so without an Init every field reads null", path)
		})
	}
}

// A ratchet, not a clean bill of health. The paths below share the shape and
// predate this test; they are recorded so the set can shrink but not grow. A
// new entry here means a newly added resource is unreachable by its own path
// and reports null for every field instead of an error.
func TestNoNewDottedPathHusks(t *testing.T) {
	known := map[string]bool{
		"file.permissions":                true,
		"kernel.aslr":                     true,
		"kernel.cmdline":                  true,
		"kernel.lockdown":                 true,
		"kernel.taint":                    true,
		"luks.volume.cipher":              true,
		"os.date":                         true,
		"windows.exploitProtection":       true,
		"windows.scheduledTask.principal": true,
		"windows.scheduledTask.settings":  true,
		"windows.smartScreen":             true,
	}

	var unexpected []string
	for _, path := range dottedPathHusks() {
		if !known[path] {
			unexpected = append(unexpected, path)
		}
	}

	assert.Empty(t, unexpected,
		"these resources share a name with the field path that reaches them and have no Init, so querying them by that path reports null for every field; add an Init that delegates to the parent's accessor")
}
