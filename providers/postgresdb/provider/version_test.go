// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// `asset.version` is the field every provider answers the same question with,
// and it is only worth having if it is comparable - sortable, matchable against
// an advisory's affected range. Postgres reports a banner, so the number has to
// be pulled out of it; the banner itself stays on postgresdb.instance.version.
func TestServerVersion(t *testing.T) {
	for _, tc := range []struct {
		banner string
		want   string
	}{
		{
			"PostgreSQL 16.1 on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit",
			"16.1",
		},
		{
			"PostgreSQL 9.6.24 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit",
			"9.6.24",
		},
		// A major-only release still reports one component.
		{"PostgreSQL 17 on aarch64-unknown-linux-musl", "17"},
		// Forks keep the PostgreSQL prefix and are picked up the same way.
		{"PostgreSQL 15.5 (Debian 15.5-1.pgdg120+1) on x86_64", "15.5"},
		// The banner is returned unchanged when it carries no version:
		// unparseable is better than nothing, and inventing a number is worse
		// than either.
		{"CockroachDB CCL v23.1.0", "CockroachDB CCL v23.1.0"},
		{"", ""},
	} {
		assert.Equalf(t, tc.want, serverVersion(tc.banner), "banner %q", tc.banner)
	}
}
