// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar

import (
	archivetar "archive/tar"
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// imageTarBytes builds a tar whose entry names look like a flattened container image.
func imageTarBytes(t testing.TB, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := archivetar.NewWriter(&buf)
	dirs := []string{"usr/share/doc", "usr/lib/python3.11/site-packages", "usr/bin", "etc", "var/lib/dpkg/info"}
	for i := range n {
		name := fmt.Sprintf("%s/package-%06d/module_%d.py", dirs[i%len(dirs)], i/7, i)
		require.NoError(t, tw.WriteHeader(&archivetar.Header{
			Name: name, Typeflag: archivetar.TypeReg, Mode: 0o644, Uname: "root", Gname: "root",
		}))
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

// TestLoadKeepsHeaderNames checks that sharing the backing array of the map key does not
// change the value of Header.Name. fs.open matches that name against the tar stream.
func TestLoadKeepsHeaderNames(t *testing.T) {
	names := []string{
		"usr/bin/ls",
		"./etc/hosts",
		"/var/log/syslog",
		"usr//share/doc",
		"opt/app/../app/config.yaml",
		"srv/data/",
	}

	var buf bytes.Buffer
	tw := archivetar.NewWriter(&buf)
	for _, name := range names {
		typ := byte(archivetar.TypeReg)
		if strings.HasSuffix(name, "/") {
			typ = archivetar.TypeDir
		}
		require.NoError(t, tw.WriteHeader(&archivetar.Header{Name: name, Typeflag: typ, Mode: 0o644}))
	}
	require.NoError(t, tw.Close())

	// Read the names back the way archive/tar reports them, so the expectation does not
	// depend on how the writer normalizes them.
	expected := map[string]string{}
	tr := archivetar.NewReader(bytes.NewReader(buf.Bytes()))
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		expected[Abs(h.Name)] = h.Name
	}
	require.NotEmpty(t, expected)

	c := &Connection{fs: NewFs("")}
	require.NoError(t, c.Load(bytes.NewReader(buf.Bytes())))

	require.Len(t, c.fs.FileMap, len(expected))
	for path, want := range expected {
		h, ok := c.fs.FileMap[path]
		require.True(t, ok, "missing entry for %q", path)
		assert.Equal(t, want, h.Name, "header name changed for %q", path)
	}
}

// BenchmarkLoad loads a 50000 entry image tar. It also reports the heap that the file map
// holds after the load, as retained-B/entry.
func BenchmarkLoad(b *testing.B) {
	const entries = 50000
	data := imageTarBytes(b, entries)

	b.ReportAllocs()
	b.ResetTimer()
	var c *Connection
	for i := 0; i < b.N; i++ {
		c = &Connection{fs: NewFs("")}
		require.NoError(b, c.Load(bytes.NewReader(data)))
	}
	b.StopTimer()

	runtime.GC()
	var withMap runtime.MemStats
	runtime.ReadMemStats(&withMap)
	held := withMap.HeapAlloc
	c.fs.FileMap = nil
	runtime.GC()
	var withoutMap runtime.MemStats
	runtime.ReadMemStats(&withoutMap)
	b.ReportMetric(float64(held-withoutMap.HeapAlloc)/float64(entries), "retained-B/entry")
}
