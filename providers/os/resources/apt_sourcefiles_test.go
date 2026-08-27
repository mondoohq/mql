// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// apt reads exactly two extensions out of sources.list.d. The previous filter
// passed a regex to files.find's `name`, which is an fnmatch glob, so it
// matched nothing and every fragment was dropped -- including the deb822
// .sources files that are the norm on Debian 12+ and Ubuntu 24.04+.
func TestIsAptSourceFile(t *testing.T) {
	included := []string{
		"/etc/apt/sources.list.d/debian.list",
		"/etc/apt/sources.list.d/kali.sources",
		"/etc/apt/sources.list.d/ubuntu.sources",
		"/etc/apt/sources.list.d/docker.list",
	}
	for _, p := range included {
		t.Run("include/"+p, func(t *testing.T) {
			assert.True(t, isAptSourceFile(p), "apt reads this file")
		})
	}

	excluded := []string{
		// apt's own backups, which must not be parsed as live config
		"/etc/apt/sources.list.d/debian.list.save",
		"/etc/apt/sources.list.d/debian.list.distUpgrade",
		"/etc/apt/sources.list.d/kali.sources.bak",
		// unrelated files that share the directory
		"/etc/apt/sources.list.d/README",
		"/etc/apt/sources.list.d/deadsnakes.gpg",
		"/etc/apt/sources.list.d/",
		"",
	}
	for _, p := range excluded {
		name := p
		if name == "" {
			name = "empty"
		}
		t.Run("exclude/"+name, func(t *testing.T) {
			assert.False(t, isAptSourceFile(p), "apt ignores this file")
		})
	}
}
