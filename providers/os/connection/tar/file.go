// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type File struct {
	path   string
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

func (f *File) Read(b []byte) (n int, err error) {
	if f.reader == nil {
		return 0, errors.New("no tar data available")
	}
	return f.reader.Read(b)
}

func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	return 0, errors.New("not implemented yet")
}

func (f *File) Readdir(n int) ([]os.FileInfo, error) {
	fi := []os.FileInfo{}
	// search all child items
	for k := range f.Fs.FileMap {
		entry := f.Fs.FileMap[k].Name
		if strings.HasPrefix(Abs(entry), f.path) {
			fi = append(fi, f.Fs.FileMap[k].FileInfo())
		}
	}
	return fi, nil
}

// Readdirnames returns the direct directories
func (f *File) Readdirnames(n int) ([]string, error) {
	fi := []string{}
	// search all child items
	for k := range f.Fs.FileMap {
		entry := f.Fs.FileMap[k].Name

		if strings.HasPrefix(Abs(entry), f.path) {
			// extract file name
			rel, err := filepath.Rel(f.path, Abs(entry))
			if err != nil {
				return nil, err
			}

			// skip own path
			if rel == "." {
				continue
			}

			// we only look into the direct dependencies
			entries := strings.Split(rel, string("/"))
			if len(entries) > 1 {
				rel = entries[0]
			}

			// log.Debug().Str("entry", Abs(entry)).Str("path", f.path).Str("rel", rel).Msg("rel")
			fi = append(fi, rel)
		}
	}

	// since we iterate over nested paths, we need to compact the list
	sort.Strings(fi)
	fi = slices.Compact(fi)
	return fi, nil
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
