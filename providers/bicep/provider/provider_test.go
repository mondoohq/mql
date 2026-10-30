// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseNameFromPath used to call filepath.Abs(name) — i.e. on the
// "." sentinel instead of the original path argument — so the asset
// name read "Bicep file .". The fix passes `file` to Abs so the
// directory basename is recovered.
func TestParseNameFromPath_DotResolvesToBasename(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	require.NoError(t, os.Chdir(dir))
	got := parseNameFromPath(".")
	// On macOS, t.TempDir() can live under /var/folders/... which is a
	// symlink to /private/var/...; resolve both before comparing.
	expected, _ := filepath.EvalSymlinks(dir)
	gotExpected := "directory " + filepath.Base(expected)
	assert.Equal(t, gotExpected, got, "bare `.` should resolve to the directory basename")
}

func TestParseNameFromPath_FileStripsExtension(t *testing.T) {
	dir := t.TempDir()
	bicepFile := filepath.Join(dir, "main.bicep")
	require.NoError(t, os.WriteFile(bicepFile, []byte("// empty"), 0o644))

	assert.Equal(t, "main", parseNameFromPath(bicepFile))
}

func TestParseNameFromPath_MissingFileFallsBack(t *testing.T) {
	assert.Equal(t, "doesnotexist", parseNameFromPath("/no/such/path/doesnotexist.bicep"))
}
