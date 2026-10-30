// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar

import (
	archivetar "archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// absSlow is the implementation Abs used before the fast path was added. The tests
// compare Abs against it, so the fast path must return the same string.
func absSlow(path string) string {
	return join("/", path)
}

var absCases = []string{
	"",
	".",
	"..",
	"/",
	"//",
	"usr",
	"usr/bin/ls",
	"/usr/bin/ls",
	"./usr/bin/ls",
	"usr//bin/ls",
	"usr/bin/",
	"usr/./bin/ls",
	"usr/../bin/ls",
	"../etc/passwd",
	"etc/",
	"/etc",
	"a/b/c/d/e/f/g",
	"var/lib/dpkg/info/base-files.list",
	"...",
	"a/.../b",
	".hidden/file",
	"a/..b/c",
	"a/b../c",
}

func TestAbsMatchesJoinAndClean(t *testing.T) {
	for _, path := range absCases {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, absSlow(path), Abs(path))
		})
	}
}

func FuzzAbsMatchesJoinAndClean(f *testing.F) {
	for _, path := range absCases {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		assert.Equal(t, absSlow(path), Abs(path))
	})
}

func BenchmarkAbs(b *testing.B) {
	paths := []string{
		"usr/bin/ls",
		"usr/share/doc/package-000123/module_1.py",
		"etc/ssl/certs/ca-certificates.crt",
		"/var/lib/dpkg/info/base-files.list",
		"usr/lib/python3.11/site-packages/pip/_vendor/urllib3/util/ssl_.py",
		"./opt/app/config.yaml",
		"var/log/",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Abs(paths[i%len(paths)])
	}
}

// buildImageTar writes a tar whose entry names look like a flattened container image.
func buildImageTar(b *testing.B, n int) string {
	b.Helper()
	p := filepath.Join(b.TempDir(), "image.tar")
	f, err := os.Create(p)
	require.NoError(b, err)
	tw := archivetar.NewWriter(f)
	dirs := []string{"usr/share/doc", "usr/lib/python3.11/site-packages", "usr/bin", "etc", "var/lib/dpkg/info"}
	for i := range n {
		name := fmt.Sprintf("%s/package-%06d/module_%d.py", dirs[i%len(dirs)], i/7, i)
		require.NoError(b, tw.WriteHeader(&archivetar.Header{
			Name: name, Typeflag: archivetar.TypeReg, Mode: 0o644, Uname: "root", Gname: "root",
		}))
	}
	require.NoError(b, tw.Close())
	require.NoError(b, f.Close())
	return p
}

// BenchmarkLoadImageTar loads a 50000 entry image tar, which calls Abs once per entry.
func BenchmarkLoadImageTar(b *testing.B) {
	p := buildImageTar(b, 50000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := &Connection{fs: NewFs(p)}
		require.NoError(b, c.LoadFile(p))
	}
}
