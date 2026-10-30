// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pnpmlock

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func TestScopeOf(t *testing.T) {
	// An explicit dev flag always wins.
	assert.Equal(t, languages.PackageScopeDev, scopeOf(pnpmPackageEntry{Dev: true}, 6.0))
	assert.Equal(t, languages.PackageScopeDev, scopeOf(pnpmPackageEntry{Dev: true}, 9.0))
	// v5/v6 set dev:true on dev packages, so a flag-less entry is genuinely prod.
	assert.Equal(t, languages.PackageScopeProd, scopeOf(pnpmPackageEntry{}, 6.0))
	// v9 carries no per-entry dev flag, so a flag-less entry is unknown — not prod
	// (mislabeling a dev-only package as production is worse than leaving it blank).
	assert.Equal(t, "", scopeOf(pnpmPackageEntry{}, 9.0))
}
