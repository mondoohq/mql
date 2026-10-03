// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindNameMatcherIsABasenameGlob(t *testing.T) {
	m, err := findNameMatcher("*.conf")
	require.NoError(t, err, "a glob is not a regular expression")
	assert.True(t, m("/etc/c3-links/crlf.conf"))
	assert.True(t, m("/etc/c3-links/space name.conf"))
	assert.False(t, m("/etc/c3-links/crlf.conf.bak"))
	assert.False(t, m("/etc/c3-links.conf/x"), "only the last component is matched")

	m, err = findNameMatcher("in.conf")
	require.NoError(t, err)
	assert.True(t, m("/etc/c3-links/realdir/in.conf"))
	assert.False(t, m("/etc/c3-links/realdir/main.conf"), "a name is not a substring match")
	assert.False(t, m("/etc/in.confx"))

	m, err = findNameMatcher("su")
	require.NoError(t, err)
	assert.False(t, m("/usr/bin/sudo"))

	m, err = findNameMatcher("[!.]*")
	require.NoError(t, err)
	assert.True(t, m("/etc/x"))
	assert.False(t, m("/etc/.hidden"), "fnmatch's [! negation")

	m, err = findNameMatcher("")
	require.NoError(t, err)
	assert.Nil(t, m, "no name is no filter")

	_, err = findNameMatcher("[")
	assert.Error(t, err)
}
