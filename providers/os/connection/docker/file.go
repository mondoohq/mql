// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"syscall"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
	"go.mondoo.com/mql/providers/os/fsutil"
)

// containerFiles is the part of the Docker API a File reads through.
type containerFiles interface {
	ContainerStatPath(ctx context.Context, containerID string, options client.ContainerStatPathOptions) (client.ContainerStatPathResult, error)
	CopyFromContainer(ctx context.Context, containerID string, options client.CopyFromContainerOptions) (client.CopyFromContainerResult, error)
}

func FileOpen(dockerClient containerFiles, path string, container string, conn *ContainerConnection, catFs *cat.Fs) (afero.File, error) {
	f := &File{
		path:         path,
		dockerClient: dockerClient,
		container:    container,
		connection:   conn,
		catFs:        catFs,
	}
	err := f.Open()
	return f, err
}

type File struct {
	path         string
	container    string
	dockerClient containerFiles
	connection   *ContainerConnection
	catFs        *cat.Fs

	// isDir is set for a directory, which has no content to read.
	isDir bool
	// viaCat is set for a file the Docker archive API cannot see, which is
	// read from inside the container instead.
	viaCat bool
	// stat is what the archive API reported when the file was opened
	stat container.PathStat

	loadOnce sync.Once
	reader   *bytes.Reader
	loadErr  error
}

// Open checks that the file exists. Its content is only fetched when it is
// read: afero.Walk and Readdir open every directory they visit, and copying
// a directory out of the container archives its whole subtree.
func (f *File) Open() error {
	stat, err := f.statFollow(f.path, 0)
	if err != nil {
		// a daemon that cannot answer does not say the file is missing
		if !cerrdefs.IsNotFound(err) {
			return &os.PathError{Op: "stat", Path: f.path, Err: err}
		}
		// The Docker archive API sees the container's root filesystem and
		// its volumes, but not a tmpfs mount such as /run. A file there
		// exists all the same, so it is read from inside the container.
		if _, catErr := f.catFs.Stat(f.path); catErr == nil {
			f.viaCat = true
			return nil
		}
		return os.ErrNotExist
	}
	f.isDir = stat.Mode.IsDir()
	f.stat = stat
	return nil
}

// statFollow stats path through the Docker archive API, following symlinks.
func (f *File) statFollow(path string, depth int) (container.PathStat, error) {
	if depth > maxSymlinkDepth {
		return container.PathStat{}, fmt.Errorf("too many levels of symbolic links: %s", path)
	}
	res, err := f.dockerClient.ContainerStatPath(context.Background(), f.container, client.ContainerStatPathOptions{Path: path})
	if err != nil {
		return container.PathStat{}, err
	}
	if len(res.Stat.LinkTarget) > 0 {
		return f.statFollow(res.Stat.LinkTarget, depth+1)
	}
	return res.Stat, nil
}

// content fetches the file's content on first use.
func (f *File) content() (*bytes.Reader, error) {
	f.loadOnce.Do(func() {
		f.reader, f.loadErr = f.load()
	})
	return f.reader, f.loadErr
}

func (f *File) load() (*bytes.Reader, error) {
	if f.isDir {
		return nil, &os.PathError{Op: "read", Path: f.path, Err: syscall.EISDIR}
	}

	if f.viaCat {
		cf, err := f.catFs.Open(f.path)
		if err != nil {
			return nil, err
		}
		defer cf.Close()
		data, err := io.ReadAll(cf)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(data), nil
	}

	r, _, err := f.getFileDockerReader(f.path)
	if err != nil {
		return nil, os.ErrNotExist
	}
	defer r.Close()
	data, err := fsutil.ReadFileFromTarStream(r)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

func (f *File) Close() error {
	return nil
}

func (f *File) Name() string {
	return f.path
}

// Stat reports what the archive API said when the file was opened. Reading
// a file (afero.ReadFile) stats it for its size, and asking the container
// again cost an exec per file read: most of the three minutes the npm
// inventory of a running container took. The owner is not part of it, it
// is -1; FileInfo, which reports ownership, stats through the container.
func (f *File) Stat() (os.FileInfo, error) {
	if f.viaCat {
		return f.catFs.Stat(f.path)
	}
	return &shared.FileInfo{
		FName:    path.Base(f.path),
		FSize:    f.stat.Size,
		FMode:    f.stat.Mode,
		FIsDir:   f.stat.Mode.IsDir(),
		FModTime: f.stat.Mtime,
		Uid:      -1,
		Gid:      -1,
	}, nil
}

func (f *File) Sync() error {
	return errors.New("not implemented")
}

func (f *File) Truncate(size int64) error {
	return errors.New("not implemented")
}

func (f *File) Read(b []byte) (n int, err error) {
	r, err := f.content()
	if err != nil {
		return 0, err
	}
	return r.Read(b)
}

func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	r, err := f.content()
	if err != nil {
		return 0, err
	}
	return r.ReadAt(b, off)
}

func (f *File) Readdir(count int) (res []os.FileInfo, err error) {
	return f.catFs.ReadDir(f.path)
}

// Readdirnames lists every entry of the directory: files, links and
// subdirectories, dotfiles included. It used to run `find <dir> -maxdepth 1
// -type d`, which lists subdirectories only, so every Glob and directory
// listing over this transport lost its regular files (journald drop-ins,
// polkit actions, python packages). The cat filesystem already lists a
// directory this way for Readdir, so both now agree.
func (f *File) Readdirnames(n int) ([]string, error) {
	return cat.NewFile(f.catFs, f.path, false).Readdirnames(n)
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	return 0, errors.New("not implemented")
}

func (f *File) Write(b []byte) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (f *File) WriteString(s string) (ret int, err error) {
	return 0, errors.New("not implemented")
}

// maxSymlinkDepth caps how many symlinks we follow before giving up,
// mirroring the Linux kernel's limit. It guards against symlink cycles
// (e.g. A->B->A) that would otherwise recurse forever, overflow the
// stack, and leak a reader on every frame.
const maxSymlinkDepth = 40

func (f *File) getFileDockerReader(path string) (io.ReadCloser, container.PathStat, error) {
	return f.getFileDockerReaderFollow(path, 0)
}

func (f *File) getFileDockerReaderFollow(path string, depth int) (io.ReadCloser, container.PathStat, error) {
	if depth > maxSymlinkDepth {
		return nil, container.PathStat{}, fmt.Errorf("too many levels of symbolic links: %s", path)
	}

	res, err := f.dockerClient.CopyFromContainer(context.Background(), f.container, client.CopyFromContainerOptions{SourcePath: path})
	if err != nil {
		return res.Content, res.Stat, err
	}

	// follow symlink if stat.LinkTarget is set
	if len(res.Stat.LinkTarget) > 0 {
		// close the reader we just opened before following the link,
		// otherwise each symlink hop leaks the tar stream / connection
		if res.Content != nil {
			res.Content.Close()
		}
		return f.getFileDockerReaderFollow(res.Stat.LinkTarget, depth+1)
	}

	return res.Content, res.Stat, err
}

// returns a TarReader stream the caller is responsible for closing the stream
func (f *File) Tar() (io.ReadCloser, error) {
	r, _, err := f.getFileDockerReader(f.path)
	return r, err
}

// func (f *File) Exists() bool {
// 	if strings.HasPrefix(f.path, "/proc") {
// 		entries := f.procls()
// 		for i := range entries {
// 			if entries[i] == f.path {
// 				return true
// 			}
// 		}
// 		return false
// 	}

// 	r, _, err := f.getFileReader(f.path)
// 	if err != nil {
// 		return false
// 	}
// 	r.Close()
// 	return true
// }
