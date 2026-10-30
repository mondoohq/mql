// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPwqualityModule(t *testing.T) {
	assert.True(t, isPwqualityModule("pam_pwquality.so"))
	assert.True(t, isPwqualityModule("/usr/lib64/security/pam_pwquality.so"))
	assert.True(t, isPwqualityModule("/lib/x86_64-linux-gnu/security/pam_pwquality.so"))
	assert.False(t, isPwqualityModule("pam_unix.so"))
	assert.False(t, isPwqualityModule("pam_cracklib.so"))
	assert.False(t, isPwqualityModule("pam_pwquality.so.bak"))
}

// fakeInfo is a FileInfo with a given mode, as the command-based file systems
// report it.
type fakeInfo struct{ mode os.FileMode }

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func TestIsRegularTarget(t *testing.T) {
	assert.True(t, isRegularTarget(fakeInfo{0o644}))
	// SSH with sudo: stat -L of a symlink to a file, with the symlink bit added
	assert.True(t, isRegularTarget(fakeInfo{0o644 | fs.ModeSymlink}))
	assert.False(t, isRegularTarget(fakeInfo{0o755 | fs.ModeDir}))
	assert.False(t, isRegularTarget(fakeInfo{0o755 | fs.ModeDir | fs.ModeSymlink}))
	assert.False(t, isRegularTarget(fakeInfo{0o644 | fs.ModeNamedPipe}))
}

func TestPwqualityExists(t *testing.T) {
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/etc/security/pwquality.conf", []byte("minlen = 14\n"), 0o644))
	require.NoError(t, mem.MkdirAll("/etc/security/pwquality.conf.d/dir.conf", 0o755))

	ok, err := pwqualityExists(mem, "/etc/security/pwquality.conf")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = pwqualityExists(mem, "/usr/lib/security/pwquality.conf")
	require.NoError(t, err)
	assert.False(t, ok, "a missing file")

	ok, err = pwqualityExists(mem, "/etc/security/pwquality.conf.d/dir.conf")
	require.NoError(t, err)
	assert.False(t, ok, "a directory named like a drop-in is not read")
}
