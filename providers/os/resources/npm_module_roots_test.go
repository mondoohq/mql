// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNodeModuleRootPath(t *testing.T) {
	for _, p := range []string{
		"/usr/share/nodejs",
		"/usr/share/nodejs/",
		"/usr/lib/nodejs",
		"/usr/lib/x86_64-linux-gnu/nodejs",
		"/usr/lib/*/nodejs",
		"/usr/lib/node_modules",
		"/usr/lib/node_modules_24",
		"/srv/app/node_modules",
	} {
		assert.True(t, isNodeModuleRootPath(p), p)
	}
	for _, p := range []string{
		"/usr/lib",
		"/usr/local/lib",
		"/srv/nodejs",
		"/usr/share/nodejs/npm",
		"/srv/app",
		"/srv/app/package.json",
	} {
		assert.False(t, isNodeModuleRootPath(p), p)
	}
}
