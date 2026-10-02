// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package nfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata/ubuntu24.04 is real /etc/exports and /etc/exports.d content
// from Ubuntu 24.04 (nfs-utils 2.6.4), with the `exportfs -v` output the
// NFS server reported for it. It covers a share with neither ro nor rw
// (/srv/nfs/def), a leading default-options token with a bare client and
// a client that overrides it (/srv/nfs/sq), and conflicting squash options
// where the last one wins (/srv/nfs/sq2).

type exportfsRow struct {
	readOnly     bool
	noRootSquash bool
}

// parseExportfsV reads `exportfs -v`: path, then client(options) with the
// options the server applies, ro or rw and root_squash or no_root_squash
// always spelled out. <world> is the client written as `*`.
func parseExportfsV(t *testing.T, out string) map[[2]string]exportfsRow {
	t.Helper()
	res := map[[2]string]exportfsRow{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		require.Len(t, fields, 2, line)
		client, opts, ok := strings.Cut(strings.TrimSuffix(fields[1], ")"), "(")
		require.True(t, ok, line)
		if client == "<world>" {
			client = "*"
		}
		o := strings.Split(opts, ",")
		require.NotEqual(t, containsString(o, "ro"), containsString(o, "rw"), line)
		require.NotEqual(t, containsString(o, "root_squash"), containsString(o, "no_root_squash"), line)
		res[[2]string{fields[0], client}] = exportfsRow{
			readOnly:     containsString(o, "ro"),
			noRootSquash: containsString(o, "no_root_squash"),
		}
	}
	return res
}

func TestParseLinuxExports_MatchesExportfs(t *testing.T) {
	dir := filepath.Join("testdata", "ubuntu24.04")
	var got []ExportEntry
	for _, name := range []string{"exports", filepath.Join("exports.d", "g05.exports")} {
		f, err := os.Open(filepath.Join(dir, name))
		require.NoError(t, err)
		entries, err := ParseExports(f, PlatformLinux)
		f.Close()
		require.NoError(t, err)
		got = append(got, entries...)
	}

	data, err := os.ReadFile(filepath.Join(dir, "exportfs_v.txt"))
	require.NoError(t, err)
	want := parseExportfsV(t, string(data))
	require.Len(t, want, 9)

	gotByKey := map[[2]string]ExportEntry{}
	for _, e := range got {
		gotByKey[[2]string{e.Path, e.Client}] = e
	}
	assert.Len(t, gotByKey, len(got), "duplicate (path, client)")
	for key, w := range want {
		e, ok := gotByKey[key]
		if !assert.True(t, ok, "missing %v", key) {
			continue
		}
		assert.Equal(t, w.readOnly, e.ReadOnly, "%v readOnly", key)
		assert.Equal(t, w.noRootSquash, e.NoRootSquash, "%v noRootSquash", key)
	}
	for key := range gotByKey {
		_, ok := want[key]
		assert.True(t, ok, "not exported by the server: %v", key)
	}

	// The default options lead each client's own options.
	assert.Equal(t, []string{"rw", "sync", "no_subtree_check"}, gotByKey[[2]string{"/srv/nfs/sq", "192.0.2.11"}].Options)
	assert.Equal(t, []string{"rw", "sync", "no_subtree_check", "ro"}, gotByKey[[2]string{"/srv/nfs/sq", "192.0.2.12"}].Options)
}
