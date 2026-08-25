// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/fsutil"
)

var _ shared.FileSearch = (*FS)(nil)

func NewFs(source string) *FS {
	return &FS{
		Source:  source,
		FileMap: make(map[string]*tar.Header),
	}
}

type FS struct {
	Source  string
	FileMap map[string]*tar.Header
}

func (fs *FS) Name() string {
	return "tarfs"
}

func (fs *FS) Create(name string) (afero.File, error) {
	return nil, errors.New("create not implemented")
}

func (fs *FS) Mkdir(name string, perm os.FileMode) error {
	return errors.New("mkdir not implemented")
}

func (fs *FS) MkdirAll(path string, perm os.FileMode) error {
	return errors.New("mkdirall not implemented")
}

func (fs *FS) Open(path string) (afero.File, error) {
	h, ok := fs.FileMap[path]
	if !ok {
		return nil, os.ErrNotExist
	}

	if h.Typeflag == tar.TypeSymlink {
		resolvedPath := fs.resolveSymlink(h)
		log.Debug().Str("path", path).Str("resolved", Abs(resolvedPath)).Msg("file is a symlink, resolved it")
		h, ok = fs.FileMap[Abs(resolvedPath)]
		if !ok {
			return nil, os.ErrNotExist
		}
	}

	reader, err := fs.open(h)
	if err != nil {
		return nil, err
	}

	return &File{
		path:   path,
		header: h,
		Fs:     fs,
		reader: reader,
	}, nil
}

func (fs *FS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	return nil, errors.New("openfile not implemented")
}

func (fs *FS) Remove(name string) error {
	return errors.New("remove not implemented")
}

func (fs *FS) RemoveAll(path string) error {
	return errors.New("removeall not implemented")
}

func (fs *FS) Rename(oldname, newname string) error {
	return errors.New("rename not implemented")
}

func (fs *FS) Stat(name string) (os.FileInfo, error) {
	h, ok := fs.FileMap[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return fs.stat(h)
}

func (fs *FS) Chmod(name string, mode os.FileMode) error {
	return errors.New("chmod not implemented")
}

func (fs *FS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return errors.New("chtimes not implemented")
}

func (fs *FS) Chown(name string, uid, gid int) error {
	return errors.New("chown not implemented")
}

func (fs *FS) stat(header *tar.Header) (os.FileInfo, error) {
	statHeader := header
	if header.Typeflag == tar.TypeSymlink {
		path := fs.resolveSymlink(header)
		h, ok := fs.FileMap[Abs(path)]
		if !ok {
			return nil, errors.New("could not find " + path)
		}
		statHeader = h
	}
	return statHeader.FileInfo(), nil
}

// resolve symlink file
func (fs *FS) resolveSymlink(header *tar.Header) string {
	dest := header.Name
	link := header.Linkname

	var path string
	if filepath.IsAbs(link) {
		var err error
		// we need to remove the root / then
		path, err = filepath.Rel("/", link)
		if err != nil {
			log.Error().Str("link", link).Msg("could not determine the relative root path")
		}

	} else {
		path = Clean(join(dest, "..", link))
	}
	log.Debug().Str("link", link).Str("file", dest).Str("path", path).Msg("tar> is symlink")
	return path
}

func (fs *FS) open(header *tar.Header) (io.Reader, error) {
	log.Debug().Str("file", header.Name).Msg("tar> load file content")

	// open tar file
	f, err := os.Open(fs.Source)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	path := header.Name
	if header.Typeflag == tar.TypeSymlink {
		path = fs.resolveSymlink(header)
	}

	// extract file from tar stream
	reader, err := fsutil.ExtractFileFromTarStream(path, f)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

// Find searches for files and returns the file info, regex can be nil
func (fs *FS) Find(from string, r *regexp.Regexp, typ string, perm *uint32, depth *int) ([]string, error) {
	list := []string{}
	for k := range fs.FileMap {
		p := strings.HasPrefix(k, from)
		m := true
		if r != nil {
			m = r.MatchString(k)
		}
		if !depthMatch(from, k, depth) {
			continue
		}
		log.Trace().Str("path", k).Str("from", from).Str("prefix", from).Bool("prefix", p).Bool("m", m).Msg("check if matches")
		if p && m {
			entry := fs.FileMap[k]
			if (typ == "directory" && entry.Typeflag == tar.TypeDir) || (typ == "file" && entry.Typeflag == tar.TypeReg) || typ == "" {
				list = append(list, k)
				log.Debug().Msg("matches")
				continue
			}
		}
	}
	return list, nil
}

func depthMatch(from, filepath string, depth *int) bool {
	if depth == nil {
		return true
	}

	trimmed := strings.TrimPrefix(filepath, from)
	// WalkDir always uses slash for separating, ignoring the OS separator. This is why we need to replace it.
	normalized := strings.ReplaceAll(trimmed, string(os.PathSeparator), "/")
	fileDepth := strings.Count(normalized, "/")
	return fileDepth <= *depth
}
