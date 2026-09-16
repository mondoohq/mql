// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fsutil

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func TestStreamFileAsTar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	// a body whose length is not a multiple of 512, so the tar block padding
	// is observable
	content := []byte("hello tar stream\nsecond line\n")
	require.NoError(t, os.WriteFile(path, content, 0o644))

	stat, err := os.Stat(path)
	require.NoError(t, err)
	f, err := os.Open(path)
	require.NoError(t, err)

	var buf bytes.Buffer
	StreamFileAsTar(path, stat, f, nopWriteCloser{Writer: &buf})

	// The body must be written through the tar writer so it is framed with
	// the rest of the archive (block padding + trailer). With the previous
	// bug the body was copied straight to the underlying writer, bypassing
	// the tar framing, which produced a malformed archive: header + raw body
	// + trailer with no padding of the data record to a 512-byte boundary.
	roundUp := func(n, mult int) int { return ((n + mult - 1) / mult) * mult }
	wantLen := 512 /* header */ + roundUp(len(content), 512) /* padded data */ + 2*512 /* trailer */
	assert.Equal(t, wantLen, buf.Len(), "archive must be framed in 512-byte tar records")

	// And the archive must read back as a well-formed tar yielding the
	// original bytes, ending in a clean EOF.
	tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	hdr, err := tr.Next()
	require.NoError(t, err)
	assert.Equal(t, path, hdr.Name)
	assert.Equal(t, int64(len(content)), hdr.Size)
	got, err := io.ReadAll(tr)
	require.NoError(t, err)
	assert.Equal(t, content, got)
	_, err = tr.Next()
	assert.Equal(t, io.EOF, err, "archive must terminate with a valid tar trailer")
}

// TestExtractFileFromTarStreamLyingHeader checks that a header which declares far more data
// than the entry holds does not drive the allocation. The read must fail instead.
func TestExtractFileFromTarStreamLyingHeader(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// Write a small entry, then rewrite its header to claim a huge size.
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4}))
	_, err := tw.Write([]byte("data"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	raw := buf.Bytes()
	// Overwrite the size field of the first header block with 1 TiB in octal.
	copy(raw[124:136], []byte("20000000000\x00"))

	_, err = ExtractFileFromTarStream("big", bytes.NewReader(raw))
	require.Error(t, err)
}

// TestExtractFileFromTarStreamEmptyEntry checks that a zero length match returns an empty
// reader and no error, the same as a path that is not present at all.
func TestExtractFileFromTarStreamEmptyEntry(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "empty", Typeflag: tar.TypeReg, Mode: 0o644, Size: 0}))
	require.NoError(t, tw.Close())

	r, err := ExtractFileFromTarStream("empty", bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	content, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Empty(t, content)

	r, err = ExtractFileFromTarStream("missing", bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	content, err = io.ReadAll(r)
	require.NoError(t, err)
	assert.Empty(t, content)
}

// TestExtractFileFromTarStreamLargeEntry checks the incremental path above the prealloc cap.
func TestExtractFileFromTarStreamLargeEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates more than the prealloc cap")
	}
	size := maxTarEntryPrealloc + (1 << 20)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "large", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(size)}))
	_, err := tw.Write(make([]byte, size))
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	r, err := ExtractFileFromTarStream("large", bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	n, err := io.Copy(io.Discard, r)
	require.NoError(t, err)
	assert.Equal(t, int64(size), n)
}
