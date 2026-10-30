// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
)

// fakeContainer answers the listing commands the way a container's shell
// does for /usr/lib/systemd/journald.conf.d on ubuntu:24.04, which holds one
// regular file, a symlink and a subdirectory.
type fakeContainer struct{}

func (c *fakeContainer) RunCommand(command string) (*shared.Command, error) {
	res := &shared.Command{Command: command, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	switch {
	case strings.HasPrefix(command, "ls -1A /usr/lib/systemd/journald.conf.d"):
		res.Stdout.(*bytes.Buffer).WriteString(".hidden.conf\nsyslog.conf\nlinked.conf\nsub\n")
	// /run is a tmpfs: the archive API does not see /run/nginx.pid, the
	// container's shell does.
	case command == "uname -s":
		res.Stdout.(*bytes.Buffer).WriteString("Linux\n")
	case command == "command -v base64":
		res.ExitStatus = 1
	case strings.Contains(command, "test -L") && strings.HasSuffix(command, "/run/nginx.pid"):
		res.Stdout.(*bytes.Buffer).WriteString("0.3.81a4.0.0.1700000000.1700000000.?\n")
	case command == "cat /run/nginx.pid":
		res.Stdout.(*bytes.Buffer).WriteString("71\n")
	case command == "readlink /proc/71/fd/6":
		res.Stdout.(*bytes.Buffer).WriteString("socket:[20845]\n")
	default:
		res.ExitStatus = 1
		res.Stderr.(*bytes.Buffer).WriteString("ls: cannot access: No such file or directory\n")
	}
	return res, nil
}

// Readdirnames lists every entry, not only subdirectories. It used to run
// `find -maxdepth 1 -type d`, so every Glob and directory listing over the
// docker-container transport lost its regular files: journald drop-ins,
// polkit actions, python packages.
func TestReaddirnamesListsEveryEntry(t *testing.T) {
	runner := &fakeContainer{}
	f := &File{path: "/usr/lib/systemd/journald.conf.d", catFs: cat.New(runner)}

	names, err := f.Readdirnames(-1)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{".hidden.conf", "syslog.conf", "linked.conf", "sub"}, names)
}

func TestReaddirnamesOfAMissingDirectoryIsAnError(t *testing.T) {
	f := &File{path: "/nope", catFs: cat.New(&fakeContainer{})}
	_, err := f.Readdirnames(-1)
	assert.Error(t, err, "a failed listing is not an empty directory")
}

// fakeArchive answers the Docker archive API: a stat of a path, and a copy of
// it as a tar stream.
type fakeArchive struct {
	// err, when set, is what the daemon answers to every request
	err    error
	stats  map[string]container.PathStat
	files  map[string]string
	copies []string
}

func (a *fakeArchive) ContainerStatPath(_ context.Context, _ string, options client.ContainerStatPathOptions) (client.ContainerStatPathResult, error) {
	if a.err != nil {
		return client.ContainerStatPathResult{}, a.err
	}
	stat, ok := a.stats[options.Path]
	if !ok {
		return client.ContainerStatPathResult{}, fmt.Errorf("Could not find the file %s in container: %w", options.Path, cerrdefs.ErrNotFound)
	}
	return client.ContainerStatPathResult{Stat: stat}, nil
}

func (a *fakeArchive) CopyFromContainer(_ context.Context, _ string, options client.CopyFromContainerOptions) (client.CopyFromContainerResult, error) {
	a.copies = append(a.copies, options.SourcePath)
	stat, ok := a.stats[options.SourcePath]
	if !ok {
		return client.CopyFromContainerResult{}, fmt.Errorf("Could not find the file %s in container: %w", options.SourcePath, cerrdefs.ErrNotFound)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// a directory is archived with everything below it
	for path, content := range a.files {
		if path == options.SourcePath || strings.HasPrefix(path, options.SourcePath+"/") {
			_ = tw.WriteHeader(&tar.Header{Name: path, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte(content))
		}
	}
	_ = tw.Close()
	return client.CopyFromContainerResult{Content: io.NopCloser(&buf), Stat: stat}, nil
}

func etcArchive() *fakeArchive {
	return &fakeArchive{
		stats: map[string]container.PathStat{
			"/etc":                        {Name: "etc", Mode: os.ModeDir | 0o755},
			"/etc/hostname":               {Name: "hostname", Size: 13, Mode: 0o644},
			"/etc/adduser.conf":           {Name: "adduser.conf", Size: 12, Mode: 0o644},
			"/etc/localtime":              {Name: "localtime", Mode: os.ModeSymlink | 0o777, LinkTarget: "/usr/share/zoneinfo/Etc/UTC"},
			"/usr/share/zoneinfo/Etc/UTC": {Name: "UTC", Size: 4, Mode: 0o644},
		},
		files: map[string]string{
			"/etc/hostname":               "c52f9e841644\n",
			"/etc/adduser.conf":           "DSHELL=/bin/bash\n",
			"/usr/share/zoneinfo/Etc/UTC": "TZif",
		},
	}
}

// Opening a directory used to copy it out of the container, which archives
// its whole subtree, and its content then read as every file below it
// concatenated: file("/etc").content was all of /etc, and afero.Walk copied
// the subtree of every directory it visited.
func TestOpenDirectoryDoesNotCopyIt(t *testing.T) {
	archive := etcArchive()
	f, err := FileOpen(archive, "/etc", "ctr", nil, cat.New(&fakeContainer{}))
	require.NoError(t, err)
	assert.Empty(t, archive.copies)

	_, err = io.ReadAll(f)
	assert.ErrorIs(t, err, syscall.EISDIR)
	assert.Empty(t, archive.copies)
}

func TestOpenFileCopiesItOnRead(t *testing.T) {
	archive := etcArchive()
	f, err := FileOpen(archive, "/etc/hostname", "ctr", nil, cat.New(&fakeContainer{}))
	require.NoError(t, err)
	assert.Empty(t, archive.copies, "opening a file only stats it")

	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "c52f9e841644\n", string(data))
	assert.Equal(t, []string{"/etc/hostname"}, archive.copies)
}

func TestOpenSymlinkReadsItsTarget(t *testing.T) {
	f, err := FileOpen(etcArchive(), "/etc/localtime", "ctr", nil, cat.New(&fakeContainer{}))
	require.NoError(t, err)
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "TZif", string(data))
}

// A tmpfs mount such as /run is not part of the container's root filesystem
// the archive API reads, so its files were reported as present (the shell
// stat found them) with no content. nginx's master pid in /run/nginx.pid went
// unread, and with it the -g directives nginx runs with.
func TestOpenFileOnATmpfsReadsItInsideTheContainer(t *testing.T) {
	f, err := FileOpen(etcArchive(), "/run/nginx.pid", "ctr", nil, cat.New(&fakeContainer{}))
	require.NoError(t, err)
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, "71\n", string(data))
}

func TestOpenMissingFile(t *testing.T) {
	_, err := FileOpen(etcArchive(), "/etc/nope", "ctr", nil, cat.New(&fakeContainer{}))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// A daemon that cannot answer is an error, not a missing file, and the
// in-container read is only a fallback for a path the archive API does not
// find.
func TestOpenWhenTheDaemonFails(t *testing.T) {
	archive := etcArchive()
	archive.err = fmt.Errorf("Cannot connect to the Docker daemon: %w", cerrdefs.ErrUnavailable)
	_, err := FileOpen(archive, "/run/nginx.pid", "ctr", nil, cat.New(&fakeContainer{}))
	require.Error(t, err)
	assert.NotErrorIs(t, err, os.ErrNotExist)
	assert.ErrorIs(t, err, cerrdefs.ErrUnavailable)
}

// countingContainer counts the commands run in the container.
type countingContainer struct {
	fakeContainer
	commands int
}

func (c *countingContainer) RunCommand(command string) (*shared.Command, error) {
	c.commands++
	return c.fakeContainer.RunCommand(command)
}

// Reading a file stats it for its size. The stat comes from the archive API
// answer Open already has, not from a command in the container per file.
func TestStatOfAnOpenedFile(t *testing.T) {
	runner := &countingContainer{}
	f, err := FileOpen(etcArchive(), "/etc/hostname", "ctr", nil, cat.New(runner))
	require.NoError(t, err)

	fi, err := f.Stat()
	require.NoError(t, err)
	assert.Equal(t, "hostname", fi.Name())
	assert.Equal(t, int64(13), fi.Size())
	assert.Equal(t, os.FileMode(0o644), fi.Mode())
	assert.False(t, fi.IsDir())
	assert.Equal(t, 0, runner.commands)

	dir, err := FileOpen(etcArchive(), "/etc", "ctr", nil, cat.New(runner))
	require.NoError(t, err)
	fi, err = dir.Stat()
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	assert.Equal(t, 0, runner.commands)
}
