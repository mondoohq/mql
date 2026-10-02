// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Entry sub-resources are reachable through their singular accessor with no
// arguments. The runtime then builds the resource with `file` unset, so id()
// runs against a nil *mqlFile. It must report that, not dereference it.
func TestLimitsEntryID(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		id, err := (&mqlLimitsEntry{}).id()
		require.Error(t, err)
		assert.Empty(t, id)
		assert.Contains(t, err.Error(), "missing file")
	})

	t.Run("with file", func(t *testing.T) {
		f := &mqlFile{}
		f.Path.Data = "/etc/security/limits.conf"
		f.Path.State = plugin.StateIsSet

		e := &mqlLimitsEntry{}
		e.File.Data = f
		e.File.State = plugin.StateIsSet
		e.LineNumber.Data = 42
		e.LineNumber.State = plugin.StateIsSet

		id, err := e.id()
		require.NoError(t, err)
		assert.Equal(t, "/etc/security/limits.conf:42", id)
	})
}

func limitsTestFiles(paths ...string) []*mqlFile {
	files := make([]*mqlFile, len(paths))
	for i, p := range paths {
		f := &mqlFile{}
		f.Path.Data = p
		f.Path.State = plugin.StateIsSet
		files[i] = f
	}
	return files
}

func limitsTestPaths(files []*mqlFile) []string {
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.Path.Data
	}
	return paths
}

// pam_limits reads limits.d files sorted by file name with strcmp, across
// /etc/security/limits.d and the vendor directory (read_limits_dir in
// pam_limits.c).
func TestSortLimitsDropIns(t *testing.T) {
	t.Run("Debian 13 directory order", func(t *testing.T) {
		// the order files.find returned them on Debian 13
		files := limitsTestFiles(
			"/etc/security/limits.d/60-mqltest.conf",
			"/etc/security/limits.d/10-coredump-debian.conf",
		)
		sortLimitsDropIns(files)
		assert.Equal(t, []string{
			"/etc/security/limits.d/10-coredump-debian.conf",
			"/etc/security/limits.d/60-mqltest.conf",
		}, limitsTestPaths(files))
	})

	t.Run("merged across /etc and /usr/etc by file name", func(t *testing.T) {
		files := limitsTestFiles(
			"/etc/security/limits.d/90-local.conf",
			"/etc/security/limits.d/10-site.conf",
			"/usr/etc/security/limits.d/50-vendor.conf",
		)
		sortLimitsDropIns(files)
		assert.Equal(t, []string{
			"/etc/security/limits.d/10-site.conf",
			"/usr/etc/security/limits.d/50-vendor.conf",
			"/etc/security/limits.d/90-local.conf",
		}, limitsTestPaths(files))
	})

	t.Run("byte order, not natural order", func(t *testing.T) {
		files := limitsTestFiles(
			"/etc/security/limits.d/a.conf",
			"/etc/security/limits.d/9-x.conf",
			"/etc/security/limits.d/Z.conf",
			"/etc/security/limits.d/10-x.conf",
		)
		sortLimitsDropIns(files)
		assert.Equal(t, []string{
			"/etc/security/limits.d/10-x.conf",
			"/etc/security/limits.d/9-x.conf",
			"/etc/security/limits.d/Z.conf",
			"/etc/security/limits.d/a.conf",
		}, limitsTestPaths(files))
	})
}

func TestIsLimitsDropIn(t *testing.T) {
	assert.True(t, isLimitsDropIn("60-mqltest.conf"))
	assert.False(t, isLimitsDropIn("mqltest.notconf"))
	assert.False(t, isLimitsDropIn(".hidden.conf"))
	assert.False(t, isLimitsDropIn("60-mqltest.conf.dpkg-old"))
}
