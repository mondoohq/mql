// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OpenWrt as non-root: /tmp is 0755 root. The provider failed to start with
// go-plugin's "the plugin was not compiled for this architecture".
func TestPickPluginSocketDir(t *testing.T) {
	writable := func(ok ...string) func(string) bool {
		return func(dir string) bool {
			for _, d := range ok {
				if d == dir {
					return true
				}
			}
			return false
		}
	}

	dir, err := pickPluginSocketDir("/tmp", []string{"", "/dev/shm", "/home/u"}, writable("/tmp", "/dev/shm"))
	require.NoError(t, err)
	assert.Equal(t, "", dir, "a writable TMPDIR is left alone")

	dir, err = pickPluginSocketDir("/tmp", []string{"", "/dev/shm", "/home/u"}, writable("/home/u"))
	require.NoError(t, err)
	assert.Equal(t, "/home/u", dir)

	_, err = pickPluginSocketDir("/tmp", []string{"", "/dev/shm"}, writable())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/tmp is not writable")
}

func TestDirWritable(t *testing.T) {
	assert.True(t, dirWritable(t.TempDir()))
	assert.False(t, dirWritable("/nonexistent-mql-dir"))
	assert.False(t, dirWritable(""))
}
