// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fsutil

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// benchTree builds a directory tree on disk, the shape a node scan walks.
func benchTree(tb testing.TB, dirs, filesPerDir int) string {
	root := tb.TempDir()
	for d := range dirs {
		dir := filepath.Join(root, "dir"+strconv.Itoa(d))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			tb.Fatal(err)
		}
		for f := range filesPerDir {
			name := filepath.Join(dir, "file"+strconv.Itoa(f)+".conf")
			if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
				tb.Fatal(err)
			}
		}
	}
	return root
}

func benchmarkFindFiles(b *testing.B, typ string, rx string, perm *uint32) {
	root := benchTree(b, 200, 50)
	iofs := os.DirFS(root)

	var r *regexp.Regexp
	if rx != "" {
		r = regexp.MustCompile(rx)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := FindFiles(iofs, ".", r, typ, perm, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFindFilesType has no permission filter, so no path is stat-ed.
func BenchmarkFindFilesType(b *testing.B) {
	benchmarkFindFiles(b, "f", "", nil)
}

// BenchmarkFindFilesRegex has no permission filter and a pattern that matches
// nothing.
func BenchmarkFindFilesRegex(b *testing.B) {
	benchmarkFindFiles(b, "f", `.*\.nomatch$`, nil)
}

// BenchmarkFindFilesPerm sets a permission filter next to a pattern that
// matches nothing. The permission test stats a path, so it is the expensive
// one, and the pattern already decides the result.
func BenchmarkFindFilesPerm(b *testing.B) {
	p := uint32(0o600)
	benchmarkFindFiles(b, "f", `.*\.nomatch$`, &p)
}
