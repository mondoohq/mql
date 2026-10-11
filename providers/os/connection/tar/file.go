// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
)

type File struct {
	path string
	// key is the archive path the file resolved to, with every link in the
	// path followed. A directory reached through a symlink lists the children
	// of key, not of path: the archive holds no entries under the link name.
	key    string
	header *tar.Header
	Fs     *FS
	reader io.Reader
}

func (f *File) Name() string {
	return f.path
}

func (f *File) Close() error {
	return nil
}

func (f *File) Stat() (os.FileInfo, error) {
	return f.Fs.stat(f.header)
}

func (f *File) Sync() error {
	return errors.New("not implemented")
}

func (f *File) Truncate(size int64) error {
	return errors.New("not implemented")
}

// errIsDirectory is what reading a directory returns, as EISDIR does on a
// live system.
var errIsDirectory = errors.New("is a directory")

func (f *File) Read(b []byte) (n int, err error) {
	if f.header != nil && f.header.Typeflag == tar.TypeDir {
		return 0, &os.PathError{Op: "read", Path: f.path, Err: errIsDirectory}
	}
	if f.reader == nil {
		return 0, errors.New("no tar data available")
	}
	return f.reader.Read(b)
}

// ReadAt gives random access to the entry, which platform detection needs to
// parse an ELF header. The tar entry is already extracted into memory, so the
// underlying reader supports it directly.
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	if f.reader == nil {
		return 0, errors.New("no tar data available")
	}
	ra, ok := f.reader.(io.ReaderAt)
	if !ok {
		return 0, errors.New("tar entry does not support random access")
	}
	return ra.ReadAt(b, off)
}

// children returns the direct children of the directory, by name, with the
// archive entry for each. A child the archive has no entry for, a directory
// that is only implied by the paths below it, maps to nil.
func (f *File) children() map[string]*tar.Header {
	dir := f.key
	if dir == "" {
		dir = Abs(f.path)
	}
	prefix := dir
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	res := map[string]*tar.Header{}
	for k, h := range f.Fs.FileMap {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rel := k[len(prefix):]
		if rel == "" {
			continue
		}
		if i := strings.IndexByte(rel, '/'); i >= 0 {
			if _, ok := res[rel[:i]]; !ok {
				res[rel[:i]] = nil
			}
			continue
		}
		res[rel] = h
	}
	return res
}

// Readdir returns the direct children of the directory, as lstat reports
// them: a symlink child is reported as the link.
func (f *File) Readdir(n int) ([]os.FileInfo, error) {
	children := f.children()
	names := make([]string, 0, len(children))
	for name := range children {
		names = append(names, name)
	}
	sort.Strings(names)

	fi := make([]os.FileInfo, 0, len(names))
	for _, name := range names {
		h := children[name]
		if h == nil {
			h = &tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}
		}
		fi = append(fi, h.FileInfo())
	}
	return fi, nil
}

// Readdirnames returns the names of the direct children of the directory.
func (f *File) Readdirnames(n int) ([]string, error) {
	children := f.children()
	names := make([]string, 0, len(children))
	for name := range children {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	return 0, errors.New("seek not implemented")
}

func (f *File) Write(b []byte) (n int, err error) {
	return 0, errors.New("write not implemented")
}

func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	return 0, errors.New("writeat not implemented")
}

func (f *File) WriteString(s string) (ret int, err error) {
	return 0, errors.New("writestring not implemented")
}
