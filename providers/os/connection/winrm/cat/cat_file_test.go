// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// fakeRunner answers the scripts this package sends: openScript reports
// dirs as directories and anything else as a file with content "hi", and
// listDirScript answers with listing.
type fakeRunner struct {
	t        *testing.T
	dirs     map[string]bool
	listing  string
	exit     int
	stderr   string
	listRuns int
}

func (r *fakeRunner) RunCommand(command string) (*shared.Command, error) {
	script := decodeCommand(r.t, command)
	res := &shared.Command{Stdout: &bytes.Buffer{}, Stderr: bytes.NewBufferString(r.stderr)}
	switch {
	case strings.Contains(script, "Get-ChildItem"):
		r.listRuns++
		res.Stdout = bytes.NewBufferString(r.listing)
		res.ExitStatus = r.exit
	case strings.Contains(script, "Test-Path"):
		for dir := range r.dirs {
			if strings.Contains(script, "'"+dir+"'") {
				res.ExitStatus = dirExitStatus
				return res, nil
			}
		}
		res.Stdout = bytes.NewBufferString("hi\n")
	}
	return res, nil
}

// A listing as listDirScript prints it on Windows Server 2025, for
// C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\OptGuideOnDeviceModel\2025.8.21.1028
const chromeComponentListing = `[{"Name":"_metadata","Length":0,"Attributes":16,"CreationTime":1791320309000,"LastAccessTime":1791320327000,"LastWriteTime":1791320309000},` +
	`{"Name":"manifest.json","Length":239,"Attributes":32,"CreationTime":1791320309000,"LastAccessTime":1791320327000,"LastWriteTime":315532800000},` +
	`{"Name":"weights.bin","Length":2862920655,"Attributes":32,"CreationTime":1791320309000,"LastAccessTime":1791320327000,"LastWriteTime":315532800000}]`

func TestReadDirThroughAfero(t *testing.T) {
	dir := `C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\OptGuideOnDeviceModel\2025.8.21.1028`
	runner := &fakeRunner{t: t, dirs: map[string]bool{dir: true}, listing: chromeComponentListing}
	afs := &afero.Afero{Fs: New(runner)}

	entries, err := afs.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	byName := map[string]os.FileInfo{}
	for _, e := range entries {
		byName[e.Name()] = e
	}
	require.Contains(t, byName, "_metadata")
	assert.True(t, byName["_metadata"].IsDir())

	require.Contains(t, byName, "weights.bin")
	weights := byName["weights.bin"]
	assert.False(t, weights.IsDir())
	assert.Equal(t, int64(2862920655), weights.Size())
	assert.Equal(t, time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC), weights.ModTime().UTC())
	assert.Equal(t, 1, runner.listRuns)
}

func TestOpenFileStillReadsContent(t *testing.T) {
	runner := &fakeRunner{t: t}
	f, err := New(runner).Open(`C:\test.txt`)
	require.NoError(t, err)

	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "hi\n", string(data))

	_, err = f.Readdir(-1)
	assert.Error(t, err)
	assert.Equal(t, 0, runner.listRuns)
}

func TestReadOnDirectoryFails(t *testing.T) {
	runner := &fakeRunner{t: t, dirs: map[string]bool{`C:\Windows`: true}}
	f, err := New(runner).Open(`C:\Windows`)
	require.NoError(t, err)

	_, err = f.Read(make([]byte, 8))
	assert.ErrorContains(t, err, "is a directory")
	assert.Equal(t, 0, runner.listRuns, "opening a directory must not list it")
}

func TestReaddirPages(t *testing.T) {
	runner := &fakeRunner{t: t, dirs: map[string]bool{`C:\d`: true}, listing: chromeComponentListing}
	f, err := New(runner).Open(`C:\d`)
	require.NoError(t, err)

	first, err := f.Readdirnames(2)
	require.NoError(t, err)
	assert.Equal(t, []string{"_metadata", "manifest.json"}, first)

	second, err := f.Readdirnames(2)
	require.NoError(t, err)
	assert.Equal(t, []string{"weights.bin"}, second)

	_, err = f.Readdirnames(2)
	assert.ErrorIs(t, err, io.EOF)

	rest, err := f.Readdir(-1)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, 1, runner.listRuns)
}

func TestReaddirErrors(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
		want   error
	}{
		{"missing", "PathNotFound,Microsoft.PowerShell.Commands.GetChildItemCommand", os.ErrNotExist},
		{"other", "SomethingElse,Microsoft.PowerShell.Commands.GetChildItemCommand", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{t: t, dirs: map[string]bool{`C:\d`: true}, listing: "[]", exit: 1, stderr: test.stderr}
			f, err := New(runner).Open(`C:\d`)
			require.NoError(t, err)

			_, err = f.Readdir(-1)
			require.Error(t, err)
			if test.want != nil {
				assert.ErrorIs(t, err, test.want)
			} else {
				assert.ErrorContains(t, err, "SomethingElse")
			}
		})
	}
}

func TestReaddirAccessDeniedIsEmptyWithoutStructuredErrors(t *testing.T) {
	runner := &fakeRunner{t: t, dirs: map[string]bool{`C:\d`: true}, listing: "[]", exit: 1,
		stderr: "DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand"}
	f, err := New(runner).Open(`C:\d`)
	require.NoError(t, err)

	entries, err := f.Readdir(-1)
	require.NoError(t, err)
	assert.Empty(t, entries)

	assert.ErrorIs(t, listDirError(`C:\d`, runner.stderr), os.ErrPermission)
}

func TestParseDirListing(t *testing.T) {
	t.Run("array", func(t *testing.T) {
		entries, err := parseDirListing([]byte(chromeComponentListing))
		require.NoError(t, err)
		require.Len(t, entries, 3)
		assert.Equal(t, "manifest.json", entries[1].Name())
		assert.Equal(t, int64(239), entries[1].Size())
	})

	t.Run("bare object", func(t *testing.T) {
		entries, err := parseDirListing([]byte(`{"Name":"only.txt","Length":5,"Attributes":32,"LastWriteTime":0}`))
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "only.txt", entries[0].Name())
		assert.Equal(t, time.Unix(0, 0).UTC(), entries[0].ModTime().UTC())
	})

	t.Run("empty", func(t *testing.T) {
		for _, in := range []string{"", "  \r\n", "[]"} {
			entries, err := parseDirListing([]byte(in))
			require.NoError(t, err)
			assert.Empty(t, entries)
		}
	})

	t.Run("absent time is null, not the epoch", func(t *testing.T) {
		entries, err := parseDirListing([]byte(`[{"Name":"x","Length":1,"Attributes":32}]`))
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Nil(t, entries[0].(*fileStat).LastWriteTime)
	})

	t.Run("malformed", func(t *testing.T) {
		_, err := parseDirListing([]byte(`[{"Name":`))
		assert.Error(t, err)
	})
}
