// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestServiceAddress covers both names RouterOS has used for the
// /ip/service source restriction: `address` up to 7.23.2 and
// `available-from` on 7.25.1.
func TestServiceAddress(t *testing.T) {
	byName := func(rows []map[string]string) map[string]string {
		out := map[string]string{}
		for _, row := range rows {
			out[row["name"]] = serviceAddress(row)
		}
		return out
	}

	t.Run("address on 7.23.2", func(t *testing.T) {
		for _, row := range liveRows(t, "ip-service.json") {
			_, hasAvailableFrom := row["available-from"]
			assert.False(t, hasAvailableFrom, row["name"])
			assert.Equal(t, row["address"], serviceAddress(row), row["name"])
		}
	})

	t.Run("available-from on 7.25.1", func(t *testing.T) {
		got := byName(liveRows(t, "ip-service-7.25.json"))
		assert.Equal(t, "192.0.2.0/24", got["ssh"])
		assert.Equal(t, "192.0.2.0/24,2001:db8::/32", got["winbox"])
		assert.Equal(t, "", got["telnet"])
		// Dynamic rows carry neither attribute.
		assert.Equal(t, "", got["btest"])
	})

	t.Run("available-from wins when both are present", func(t *testing.T) {
		assert.Equal(t, "192.0.2.0/24", serviceAddress(map[string]string{
			"address":        "198.51.100.0/24",
			"available-from": "192.0.2.0/24",
		}))
	})

	t.Run("address is used when available-from is absent", func(t *testing.T) {
		assert.Equal(t, "198.51.100.0/24", serviceAddress(map[string]string{
			"address": "198.51.100.0/24",
		}))
	})
}

// TestServiceRows covers the session rows RouterOS mixes into /ip/service: the
// captured reply holds the scanner's own API session as a second "api" row.
func TestServiceRows(t *testing.T) {
	rows := liveRows(t, "ip-service.json")
	kept := serviceRows(rows)

	names := map[string]int{}
	for _, row := range kept {
		assert.NotEqual(t, "true", row["connection"], row["name"])
		names[row["name"]]++
	}
	assert.Equal(t, len(rows)-1, len(kept))
	assert.Equal(t, 1, names["api"], "the API session row must not duplicate the api service")
	// Dynamic listeners are services, not sessions, and stay in the list. The
	// two ipsec listeners (500 and 4500) share a name and differ only in port.
	assert.Equal(t, 2, names["ipsec"])
	assert.Equal(t, 1, names["btest"])

	ids := map[string]bool{}
	for _, row := range kept {
		id := rowID("mikrotik.ip.service/", row, row["name"], row["port"], row["proto"])
		assert.False(t, ids[id], "duplicate resource id %s", id)
		ids[id] = true
	}
}
