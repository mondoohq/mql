// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package processes

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

type benchSocketFs struct {
	afero.Fs
	links       map[string]string
	fdDirOpens  int64
	readlinkOps int64
}

func (fs *benchSocketFs) Open(path string) (afero.File, error) {
	if strings.HasPrefix(path, "/proc/") && strings.HasSuffix(path, "/fd") {
		fs.fdDirOpens++
	}
	return fs.Fs.Open(path)
}

func (fs *benchSocketFs) ReadlinkIfPossible(path string) (string, error) {
	fs.readlinkOps++
	link, ok := fs.links[path]
	if !ok {
		return "", os.ErrNotExist
	}
	return link, nil
}

func writeBenchProcEntry(b *testing.B, fs afero.Fs, pid int) {
	pidStr := strconv.Itoa(pid)
	require.NoError(b, fs.MkdirAll("/proc/"+pidStr, 0o755))
	require.NoError(b, afero.WriteFile(fs, "/proc/"+pidStr+"/cmdline", []byte("/usr/bin/proc"+pidStr+"\x00"), 0o644))
	require.NoError(b, afero.WriteFile(fs, "/proc/"+pidStr+"/status", []byte("Name:\tproc"+pidStr+"\nState:\tS (sleeping)\nPid:\t"+pidStr+"\n"), 0o644))
}

func writeBenchProcSockets(b *testing.B, fs afero.Fs, links map[string]string, pid, socketsPerProcess int) {
	fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	require.NoError(b, fs.MkdirAll(fdDir, 0o755))

	for fd := 0; fd < socketsPerProcess; fd++ {
		fdPath := filepath.Join(fdDir, strconv.Itoa(fd+3))
		require.NoError(b, afero.WriteFile(fs, fdPath, []byte{}, 0o644))
		inode := int64(pid*100000 + fd)
		links[fdPath] = "socket:[" + strconv.FormatInt(inode, 10) + "]"
	}
}

func buildBenchLinuxProcManager(b *testing.B, processCount, socketsPerProcess int) (*LinuxProcManager, *benchSocketFs) {
	baseFs := afero.NewMemMapFs()
	require.NoError(b, baseFs.MkdirAll("/proc", 0o755))

	links := map[string]string{}
	for pid := 1; pid <= processCount; pid++ {
		writeBenchProcEntry(b, baseFs, pid)
		writeBenchProcSockets(b, baseFs, links, pid, socketsPerProcess)
	}

	fs := &benchSocketFs{Fs: baseFs, links: links}
	return &LinuxProcManager{conn: &fakeProcConn{fs: fs}}, fs
}

func BenchmarkLinuxProcManagerListDeferred(b *testing.B) {
	lpm, fs := buildBenchLinuxProcManager(b, 300, 120)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := lpm.List()
		require.NoError(b, err)
	}

	b.StopTimer()
	b.ReportMetric(float64(fs.fdDirOpens)/float64(b.N), "fd-dir-open/op")
	b.ReportMetric(float64(fs.readlinkOps)/float64(b.N), "readlink/op")
}

func BenchmarkLinuxProcManagerListWithSocketEnumeration(b *testing.B) {
	lpm, fs := buildBenchLinuxProcManager(b, 300, 120)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := lpm.List()
		require.NoError(b, err)

		_, err = lpm.ListSocketInodesByProcess()
		require.NoError(b, err)
	}

	b.StopTimer()
	b.ReportMetric(float64(fs.fdDirOpens)/float64(b.N), "fd-dir-open/op")
	b.ReportMetric(float64(fs.readlinkOps)/float64(b.N), "readlink/op")
}

func BenchmarkLinuxProcManagerProcessDeferred(b *testing.B) {
	lpm, fs := buildBenchLinuxProcManager(b, 300, 120)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := lpm.Process(42)
		require.NoError(b, err)
	}

	b.StopTimer()
	b.ReportMetric(float64(fs.fdDirOpens)/float64(b.N), "fd-dir-open/op")
	b.ReportMetric(float64(fs.readlinkOps)/float64(b.N), "readlink/op")
}

func BenchmarkLinuxProcManagerProcessWithSocketEnumeration(b *testing.B) {
	lpm, fs := buildBenchLinuxProcManager(b, 300, 120)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := lpm.Process(42)
		require.NoError(b, err)

		_, err = lpm.ListSocketInodesByProcess()
		require.NoError(b, err)
	}

	b.StopTimer()
	b.ReportMetric(float64(fs.fdDirOpens)/float64(b.N), "fd-dir-open/op")
	b.ReportMetric(float64(fs.readlinkOps)/float64(b.N), "readlink/op")
}
