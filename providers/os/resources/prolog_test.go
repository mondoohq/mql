// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// regexPackPl is the pack.pl `pack_install(regex)` writes, read from a Fedora 44 host.
const regexPackPl = `name(regex).
title('Regular expressions').

version('0.3.3').
download('https://github.com/mndrix/regex/archive/v0.3.3.zip').

author('Michael Hendricks','michael@ndrix.org').
packager('Michael Hendricks','michael@ndrix.org').
maintainer('Michael Hendricks','michael@ndrix.org').
home('https://github.com/mndrix/regex').
`

func TestScanPrologPackDirs_globalPackDirs(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	// SWI-Prolog's common_app_data pack directory, where a root
	// pack_install puts packs, with the Downloads archive cache beside them
	require.NoError(t, afs.WriteFile("/usr/local/share/swi-prolog/pack/regex/pack.pl", []byte(regexPackPl), 0o644))
	require.NoError(t, afs.WriteFile("/usr/local/share/swi-prolog/pack/Downloads/regex-0.3.3.zip", []byte("PK"), 0o644))
	require.NoError(t, afs.WriteFile("/usr/share/swi-prolog/pack/func/pack.pl", []byte("name(func).\nversion('0.4.2').\n"), 0o644))
	require.NoError(t, afs.WriteFile("/usr/lib/swi-prolog/pack/list_util/pack.pl", []byte("name(list_util).\nversion('0.13.0').\n"), 0o644))

	packs, dirs := scanPrologPackDirs(afs, defaultPrologPackDirs)

	got := map[string]string{}
	for _, p := range packs {
		got[p.Name] = p.Version + " " + p.FilePath
	}
	assert.Equal(t, map[string]string{
		"regex":     "0.3.3 /usr/local/share/swi-prolog/pack/regex/pack.pl",
		"func":      "0.4.2 /usr/share/swi-prolog/pack/func/pack.pl",
		"list_util": "0.13.0 /usr/lib/swi-prolog/pack/list_util/pack.pl",
	}, got)
	assert.ElementsMatch(t, []string{
		"/usr/local/share/swi-prolog/pack",
		"/usr/share/swi-prolog/pack",
		"/usr/lib/swi-prolog/pack",
	}, dirs)
}

func TestScanPrologPackDirs_missingAndEmptyDirs(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	// a pack directory holding only the download cache has no packs and is
	// not reported as an evidence file
	require.NoError(t, afs.WriteFile("/usr/local/share/swi-prolog/pack/Downloads/regex-0.3.3.zip", []byte("PK"), 0o644))

	packs, dirs := scanPrologPackDirs(afs, defaultPrologPackDirs)
	assert.Empty(t, packs)
	assert.Empty(t, dirs)
}
