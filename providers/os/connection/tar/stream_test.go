// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar_test

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

// closeTrackingReader wraps a reader and records whether Close was called.
type closeTrackingReader struct {
	io.Reader
	closed bool
}

func (c *closeTrackingReader) Close() error {
	c.closed = true
	return nil
}

// errReader always fails on Read, to simulate an io.Copy failure.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

func newTmpFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stream-test-*")
	require.NoError(t, err)
	return f
}

func TestStreamToTmpFile_ClosesSourceOnSuccess(t *testing.T) {
	src := &closeTrackingReader{Reader: strings.NewReader("hello world")}
	out := newTmpFile(t)

	err := tar.StreamToTmpFile(src, out)
	require.NoError(t, err)
	assert.True(t, src.closed, "source reader should be closed on the success path")

	// content was actually written
	data, err := os.ReadFile(out.Name())
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(data))
}

func TestStreamToTmpFile_ClosesSourceOnCopyError(t *testing.T) {
	src := &closeTrackingReader{Reader: errReader{}}
	out := newTmpFile(t)

	err := tar.StreamToTmpFile(src, out)
	require.Error(t, err, "copy failure should be surfaced as an error")
	assert.True(t, src.closed, "source reader should be closed even when the copy fails")
}
