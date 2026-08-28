// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logrotate_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/logrotate"
)

func TestPaths(t *testing.T) {
	paths := logrotate.Paths("/var/log/dpkg.log", logrotate.DefaultMaxRotations)

	require.Equal(t, "/var/log/dpkg.log", paths[0], "the live log must be tried first")
	assert.Equal(t, "/var/log/dpkg.log.1", paths[1])
	assert.Equal(t, "/var/log/dpkg.log.1.gz", paths[2])
	assert.Len(t, paths, 1+2*logrotate.DefaultMaxRotations)

	assert.Equal(t, []string{"/var/log/dpkg.log"}, logrotate.Paths("/var/log/dpkg.log", 0))
	assert.Equal(t, []string{"/var/log/dpkg.log"}, logrotate.Paths("/var/log/dpkg.log", -3),
		"a negative rotation count must not panic")
}

func TestOpenPlainFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log", []byte("hello"), 0o644))

	f, err := logrotate.Open(fs, "/var/log/dpkg.log")
	require.NoError(t, err)
	defer f.Close()

	got, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
}

func TestOpenGzip(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte("compressed"))
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log.2.gz", buf.Bytes(), 0o644))

	f, err := logrotate.Open(fs, "/var/log/dpkg.log.2.gz")
	require.NoError(t, err)
	defer f.Close()

	got, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "compressed", string(got))
}

// A corrupt archive must report an error rather than hand back a reader, and it
// must not leak the file descriptor it opened to find that out.
func TestOpenCorruptGzip(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log.1.gz", []byte("not gzip"), 0o644))

	f, err := logrotate.Open(fs, "/var/log/dpkg.log.1.gz")
	require.Error(t, err)
	assert.Nil(t, f)
}

func TestOpenMissingFile(t *testing.T) {
	f, err := logrotate.Open(afero.NewMemMapFs(), "/var/log/dpkg.log")
	require.Error(t, err)
	assert.Nil(t, f)
}
