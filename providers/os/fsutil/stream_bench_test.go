// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fsutil

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// benchTar builds a tar with n small entries, one entry of targetSize bytes,
// then n more small entries. This models a flattened container image layer.
func benchTar(n int, targetSize int) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, size int) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(size)})
		if size > 0 {
			_, _ = tw.Write(make([]byte, size))
		}
	}
	for i := 0; i < n; i++ {
		write(fmt.Sprintf("usr/share/doc/f-%06d", i), 128)
	}
	write("usr/bin/target", targetSize)
	for i := 0; i < n; i++ {
		write(fmt.Sprintf("usr/lib/g-%06d", i), 128)
	}
	tw.Close()
	return buf.Bytes()
}

func benchmarkExtractFileFromTarStream(b *testing.B, entries, size int) {
	data := benchTar(entries, size)
	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := ExtractFileFromTarStream("usr/bin/target", bytes.NewReader(data))
		require.NoError(b, err)
		n, err := io.Copy(io.Discard, r)
		require.NoError(b, err)
		require.Equal(b, int64(size), n)
	}
}

func BenchmarkExtractFileFromTarStream1MB(b *testing.B) {
	benchmarkExtractFileFromTarStream(b, 500, 1<<20)
}

func BenchmarkExtractFileFromTarStream16MB(b *testing.B) {
	benchmarkExtractFileFromTarStream(b, 500, 16<<20)
}

// 64 MiB is the largest entry that still uses the exact prealloc path.
func BenchmarkExtractFileFromTarStream64MB(b *testing.B) {
	benchmarkExtractFileFromTarStream(b, 200, 64<<20)
}

// 128 MiB is above maxTarEntryPrealloc, so this uses the incremental growth path.
func BenchmarkExtractFileFromTarStream128MB(b *testing.B) {
	benchmarkExtractFileFromTarStream(b, 200, 128<<20)
}

func BenchmarkExtractFileFromTarStream4KB(b *testing.B) {
	benchmarkExtractFileFromTarStream(b, 2000, 4096)
}
