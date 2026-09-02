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
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/fsutil"
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

	h, ok = fs.resolveHeader(h)
	if !ok {
		return nil, os.ErrNotExist
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
	statHeader, ok := fs.resolveHeader(header)
	if !ok {
		// A link whose target is not in the archive is dangling, which is what
		// os.Stat reports as not-exist. Returning a bare error here made callers
		// that branch on os.IsNotExist treat it as a hard failure instead: a
		// systemd unit masked by a symlink to /dev/null aborted the whole
		// service list, because /dev/null is never in a container image. Open
		// already returns os.ErrNotExist for the same case.
		return nil, &os.PathError{Op: "stat", Path: header.Name, Err: os.ErrNotExist}
	}
	return statHeader.FileInfo(), nil
}

// maxLinkHops bounds link resolution. A tar can carry a symlink cycle, and
// following one forever would hang the scan on a malformed or hostile image.
const maxLinkHops = 32

// LstatIfPossible reports on the link itself rather than on its target, so a
// symlink is reported as a symlink. It satisfies afero.Lstater, which callers
// probe for when the distinction matters: systemd unit lookup needs it to tell
// an alias and a masked unit apart from a regular unit file.
func (fs *FS) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	h, ok := fs.FileMap[name]
	if !ok {
		return nil, true, &os.PathError{Op: "lstat", Path: name, Err: os.ErrNotExist}
	}
	// true: this is a real lstat, not a Stat standing in for one.
	return h.FileInfo(), true, nil
}

// ReadlinkIfPossible returns the target a symlink points at, without resolving
// it against the archive. It satisfies afero.LinkReader. The target may well not
// be in the archive at all, as with a unit masked to /dev/null, so reading the
// link and resolving it are deliberately separate steps.
func (fs *FS) ReadlinkIfPossible(name string) (string, error) {
	h, ok := fs.FileMap[name]
	if !ok {
		return "", &os.PathError{Op: "readlink", Path: name, Err: os.ErrNotExist}
	}
	if h.Typeflag != tar.TypeSymlink {
		return "", &os.PathError{Op: "readlink", Path: name, Err: os.ErrInvalid}
	}
	return h.Linkname, nil
}

// resolveHeader follows link entries to the one that actually holds the bytes,
// and reports whether it found it.
//
// The two link kinds resolve differently. A symlink's target is interpreted
// relative to the directory the link sits in, the way it would be on a real
// filesystem. A hardlink's Linkname is a path inside the archive itself,
// always relative to the archive root.
//
// Following hardlinks is what makes OSTree and bootc images readable. They
// keep the bytes in the ostree object store and expose every real path as a
// hardlink to it:
//
//	sysroot/ostree/repo/objects/a2/69745d...file   the content
//	usr/lib/os-release                             hardlink to it
//	etc/os-release                                 symlink to ../usr/lib/os-release
//
// A hardlink entry carries Size 0 and no payload of its own, so reading it
// without following the link yields an empty file rather than an error. That
// left /etc/os-release empty on Fedora CoreOS, Fedora bootc and the uBlue
// images, so detection named no platform and every one of them was reported
// as "scratch": a container image with no packages and no findings.
//
// The chain is followed rather than resolved once, because the path detection
// opens is a symlink whose target is itself a hardlink.
func (fs *FS) resolveHeader(header *tar.Header) (*tar.Header, bool) {
	h := header

	// The path the entry is being reached through. A hardlink is another name
	// for the same inode rather than a pointer to a path, so a relative
	// symlink reached through one resolves against the directory of the name
	// we came in on, not the directory of the entry that stores it. On an
	// OSTree image /etc/redhat-release is a hardlink to an object that is
	// itself a symlink to "fedora-release": that has to land on
	// /etc/fedora-release, not on a sibling of the object in the store.
	accessPath := header.Name

	for range maxLinkHops {
		var target string
		switch h.Typeflag {
		case tar.TypeSymlink:
			target = Abs(fs.resolveSymlinkFrom(accessPath, h.Linkname))
			accessPath = target
			log.Debug().Str("path", h.Name).Str("resolved", target).Msg("file is a symlink, resolved it")
		case tar.TypeLink:
			target = Abs(h.Linkname)
			log.Debug().Str("path", h.Name).Str("resolved", target).Msg("file is a hardlink, resolved it")
		default:
			return h, true
		}

		next, ok := fs.FileMap[target]
		if !ok || next == h {
			return nil, false
		}
		h = next
	}

	log.Warn().Str("file", header.Name).Msg("tar> giving up on a link chain that does not end")
	return nil, false
}

// resolveSymlinkFrom resolves a symlink target against the path the link is
// being accessed through. That path is usually the entry's own name, but not
// when the link was reached through a hardlink: see resolveHeader.
func (fs *FS) resolveSymlinkFrom(dest string, link string) string {
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

// open reads the bytes of header out of the archive. header must already be
// resolved by resolveHeader: a link entry carries no payload of its own, so
// reading one directly would yield an empty file.
func (fs *FS) open(header *tar.Header) (io.Reader, error) {
	log.Debug().Str("file", header.Name).Msg("tar> load file content")

	// open tar file
	f, err := os.Open(fs.Source)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// extract file from tar stream
	reader, err := fsutil.ExtractFileFromTarStream(header.Name, f)
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
