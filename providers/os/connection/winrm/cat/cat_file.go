// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func NewFile(name string, buf *bytes.Buffer) *File {
	return &File{path: name, buf: buf}
}

// newDir returns an open directory. Its entries are listed on the first
// Readdir or Readdirnames, so opening one costs nothing beyond the open.
func newDir(catfs *Fs, name string) *File {
	return &File{path: name, catfs: catfs, isDir: true}
}

type File struct {
	buf  *bytes.Buffer
	path string

	catfs   *Fs
	isDir   bool
	entries []os.FileInfo
	listed  bool
	dirPos  int
}

func (f *File) Close() error {
	return nil
}

func (f *File) Name() string {
	return f.path
}

func (f *File) Stat() (os.FileInfo, error) {
	return nil, errors.New("not implemented")
}

func (f *File) Sync() error {
	return nil
}

func (f *File) Truncate(size int64) error {
	return nil
}

func (f *File) Read(b []byte) (n int, err error) {
	if f.isDir {
		return 0, &os.PathError{Op: "read", Path: f.path, Err: errors.New("is a directory")}
	}
	return f.buf.Read(b)
}

func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	return 0, errors.New("not implemented")
}

// Readdir follows os.File.Readdir: count <= 0 returns every remaining entry,
// count > 0 returns at most count and io.EOF once none are left.
func (f *File) Readdir(count int) ([]os.FileInfo, error) {
	if !f.isDir {
		return nil, &os.PathError{Op: "readdir", Path: f.path, Err: errors.New("not a directory")}
	}
	if !f.listed {
		entries, err := f.catfs.listDir(f.path)
		if err != nil {
			return nil, err
		}
		f.entries = entries
		f.listed = true
	}

	rest := f.entries[f.dirPos:]
	if count <= 0 {
		f.dirPos = len(f.entries)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	if count > len(rest) {
		count = len(rest)
	}
	f.dirPos += count
	return rest[:count], nil
}

func (f *File) Readdirnames(n int) ([]string, error) {
	entries, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i := range entries {
		names[i] = entries[i].Name()
	}
	return names, nil
}

func (cat *Fs) listDir(path string) ([]os.FileInfo, error) {
	cmd, err := cat.commandRunner.RunCommand(listDirScript(path))
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		var stderr []byte
		if cmd.Stderr != nil {
			stderr, _ = io.ReadAll(cmd.Stderr)
		}
		err = listDirError(path, string(stderr))
		if errors.Is(err, os.ErrPermission) && !plugin.StructuredErrors() {
			return []os.FileInfo{}, nil
		}
		return nil, err
	}

	entries, err := parseDirListing(data)
	if err != nil {
		return nil, &os.PathError{Op: "readdir", Path: path, Err: err}
	}
	return entries, nil
}

type dirEntry struct {
	Name           string `json:"Name"`
	Length         int64  `json:"Length"`
	Attributes     uint32 `json:"Attributes"`
	CreationTime   *int64 `json:"CreationTime"`
	LastAccessTime *int64 `json:"LastAccessTime"`
	LastWriteTime  *int64 `json:"LastWriteTime"`
}

// parseDirListing decodes the output of listDirScript. It also accepts a
// bare object and empty output, which is what ConvertTo-Json produces for one
// entry and for none when it is given a pipeline instead of -InputObject.
func parseDirListing(data []byte) ([]os.FileInfo, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return []os.FileInfo{}, nil
	}
	if data[0] == '{' {
		data = append(append([]byte{'['}, data...), ']')
	}

	var raw []dirEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	entries := make([]os.FileInfo, 0, len(raw))
	for _, e := range raw {
		if e.Name == "" {
			continue
		}
		entries = append(entries, &fileStat{
			name:           e.Name,
			FileSize:       e.Length,
			FileAttributes: e.Attributes,
			CreationTime:   unixMilli(e.CreationTime),
			LastAccessTime: unixMilli(e.LastAccessTime),
			LastWriteTime:  unixMilli(e.LastWriteTime),
		})
	}
	return entries, nil
}

func unixMilli(ms *int64) *time.Time {
	if ms == nil {
		return nil
	}
	t := time.UnixMilli(*ms)
	return &t
}

// listDirError turns the error ids listDirScript writes to stderr into the
// error os.ReadDir would return for the same cause.
func listDirError(path string, stderr string) error {
	msg := strings.TrimSpace(stderr)
	var cause error
	switch {
	case strings.Contains(msg, "UnauthorizedAccess"):
		cause = os.ErrPermission
	case strings.Contains(msg, "PathNotFound"), strings.Contains(msg, "ItemNotFound"):
		cause = os.ErrNotExist
	default:
		if msg == "" {
			msg = "could not list directory"
		}
		cause = errors.New(msg)
	}
	return &os.PathError{Op: "readdir", Path: path, Err: cause}
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
