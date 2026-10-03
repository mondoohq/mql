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

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/ssh/cat"
	"go.mondoo.com/mql/providers/os/fsutil"
)

func FileOpen(dockerClient *client.Client, path string, container string, conn *ContainerConnection, catFs *cat.Fs) (afero.File, error) {
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
	dockerClient *client.Client
	connection   *ContainerConnection
	reader       *bytes.Reader
	catFs        *cat.Fs
}

func (f *File) Open() error {
	r, _, err := f.getFileDockerReader(f.path)
	if err != nil {
		return os.ErrNotExist
	}
	defer r.Close()
	data, err := fsutil.ReadFileFromTarStream(r)
	if err != nil {
		return err
	}
	f.reader = bytes.NewReader(data)
	return nil
}

func (f *File) Close() error {
	return nil
}

func (f *File) Name() string {
	return f.path
}

func (f *File) Stat() (os.FileInfo, error) {
	return f.catFs.Stat(f.path)
}

func (f *File) Sync() error {
	return errors.New("not implemented")
}

func (f *File) Truncate(size int64) error {
	return errors.New("not implemented")
}

func (f *File) Read(b []byte) (n int, err error) {
	return f.reader.Read(b)
}

func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	return f.reader.ReadAt(b, off)
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
