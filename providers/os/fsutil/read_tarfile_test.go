// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fsutil

import (
	"archive/tar"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tarStreamWith builds a tar stream that holds one entry per content item.
func tarStreamWith(tb testing.TB, contents ...[]byte) []byte {
	tb.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i, content := range contents {
		hdr := &tar.Header{
			Name:     "file" + string(rune('a'+i)),
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		require.NoError(tb, tw.WriteHeader(hdr))
		_, err := tw.Write(content)
		require.NoError(tb, err)
	}
	require.NoError(tb, tw.Close())
	return buf.Bytes()
}

func TestReadFileFromTarStream(t *testing.T) {
	t.Run("single entry", func(t *testing.T) {
		content := []byte("hello world")
		data, err := ReadFileFromTarStream(bytes.NewReader(tarStreamWith(t, content)))
		require.NoError(t, err)
		assert.Equal(t, content, data)
	})

	t.Run("entries are concatenated", func(t *testing.T) {
		data, err := ReadFileFromTarStream(bytes.NewReader(
			tarStreamWith(t, []byte("abc"), []byte("def"), []byte("ghi"))))
		require.NoError(t, err)
		assert.Equal(t, []byte("abcdefghi"), data)
	})

	t.Run("empty entry", func(t *testing.T) {
		data, err := ReadFileFromTarStream(bytes.NewReader(tarStreamWith(t, []byte{})))
		require.NoError(t, err)
		assert.Empty(t, data)
	})

	t.Run("empty stream", func(t *testing.T) {
		data, err := ReadFileFromTarStream(bytes.NewReader(tarStreamWith(t)))
		require.NoError(t, err)
		assert.Empty(t, data)
	})

	t.Run("large entry", func(t *testing.T) {
		content := bytes.Repeat([]byte("0123456789"), 200000)
		data, err := ReadFileFromTarStream(bytes.NewReader(tarStreamWith(t, content)))
		require.NoError(t, err)
		assert.Equal(t, content, data)
	})

	t.Run("not a tar stream", func(t *testing.T) {
		_, err := ReadFileFromTarStream(bytes.NewReader([]byte("this is not a tar")))
		assert.Error(t, err)
	})
}

func benchmarkReadFileFromTarStream(b *testing.B, size int) {
	stream := tarStreamWith(b, bytes.Repeat([]byte("a"), size))

	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := ReadFileFromTarStream(bytes.NewReader(stream))
		if err != nil {
			b.Fatal(err)
		}
		if len(data) != size {
			b.Fatalf("expected %d bytes, got %d", size, len(data))
		}
	}
}

func BenchmarkReadFileFromTarStream1MB(b *testing.B) {
	benchmarkReadFileFromTarStream(b, 1<<20)
}

func BenchmarkReadFileFromTarStream8MB(b *testing.B) {
	benchmarkReadFileFromTarStream(b, 8<<20)
}
