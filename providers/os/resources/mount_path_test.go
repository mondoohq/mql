// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMountPathMatcherWindows(t *testing.T) {
	for _, asked := range []string{`C:`, `C:\`, `c:\`, `c:/`} {
		assert.True(t, mountPathMatcher(true, asked)(`C:\`), "%q selects C:\\", asked)
	}
	folder := mountPathMatcher(true, `c:\MNT\data\`)
	assert.True(t, folder(`C:\mnt\data`))
	assert.False(t, folder(`C:\`))

	assert.False(t, mountPathMatcher(true, `D:`)(`C:\`))
	assert.False(t, mountPathMatcher(true, ``)(`C:\`))
	assert.False(t, mountPathMatcher(true, `\`)(`C:\`))
}

// Unix paths are case-sensitive and a trailing slash is part of what was
// asked for: the Windows folding must not leak into them.
func TestMountPathMatcherUnix(t *testing.T) {
	assert.True(t, mountPathMatcher(false, "/var")("/var"))
	assert.False(t, mountPathMatcher(false, "/VAR")("/var"))
	assert.False(t, mountPathMatcher(false, "/var/")("/var"))
}
