// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnsshake

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDnsShake(t *testing.T) {
	dnsShaker, err := New("mondoo.io")
	require.NoError(t, err)

	records, err := dnsShaker.Query("A", "MX")
	require.NoError(t, err)
	assert.True(t, len(records) > 0)
}

func TestAuthoritativeNameserversRejectsRoot(t *testing.T) {
	// Guards the walk's stopping condition. Falling through to the root would
	// return the root servers, which answer referrals rather than the records
	// the caller asked for, so an unresolvable name has to fail instead.
	for _, fqdn := range []string{"", "."} {
		c, err := New(fqdn)
		require.NoError(t, err)

		_, err = c.authoritativeNameservers()
		assert.Error(t, err, "fqdn %q should not resolve to the root servers", fqdn)
	}
}

func TestAuthoritativeNameserversWalksUpToTheZone(t *testing.T) {
	// NS records live at the zone apex, not at every name inside it, so a
	// subdomain has to walk up before it finds a delegation. Both of these are
	// served by the same zone and must therefore find the same nameservers.
	apex, err := New("mondoo.com")
	require.NoError(t, err)
	apexServers, err := apex.authoritativeNameservers()
	require.NoError(t, err)
	require.NotEmpty(t, apexServers)

	sub, err := New("www.mondoo.com")
	require.NoError(t, err)
	subServers, err := sub.authoritativeNameservers()
	require.NoError(t, err)

	assert.ElementsMatch(t, apexServers, subServers,
		"a subdomain should resolve to its zone's nameservers")
}

func TestQueryAuthoritativeReportsConfiguredTTL(t *testing.T) {
	// The reason this path exists: a caching resolver reports the time left on
	// its cached entry, so the same query answers a different TTL depending on
	// when it runs. The authoritative answer is the configured value and does
	// not move between consecutive reads.
	c, err := New("mondoo.com")
	require.NoError(t, err)

	first, err := c.QueryAuthoritative("A")
	require.NoError(t, err)
	require.Contains(t, first, "A")

	second, err := c.QueryAuthoritative("A")
	require.NoError(t, err)
	require.Contains(t, second, "A")

	assert.Equal(t, first["A"].TTL, second["A"].TTL,
		"authoritative TTL should not vary between reads")
	assert.Positive(t, first["A"].TTL)
}
