// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import "regexp"

// serverVersion is the leading version number in the banner `SELECT version()`
// returns, e.g. "16.1" out of
// "PostgreSQL 16.1 on x86_64-pc-linux-gnu, compiled by gcc ...".
//
// `asset.version` is the one field every provider answers the same question
// with, and the only reason it is worth having is that it is comparable: sorted,
// matched against an advisory's affected range, compared across a fleet. A
// banner is none of those things - it carries the compiler and the build host -
// so it belongs on the resource, where postgresdb.instance.version keeps it,
// and not here.
//
// Returns the banner unchanged when there is no version in it. Something
// unparseable is still better than nothing, and inventing a number would be
// worse than either.
var pgVersion = regexp.MustCompile(`(?i)postgresql\s+([0-9]+(?:\.[0-9]+)*)`)

func serverVersion(banner string) string {
	if m := pgVersion.FindStringSubmatch(banner); m != nil {
		return m[1]
	}
	return banner
}
