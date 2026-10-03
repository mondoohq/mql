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
	h, key, err := fs.lookup(path)
	if err != nil {
		return nil, err
	}

	h, key, err = fs.resolveHeader(h, key)
	if err != nil {
		return nil, err
	}

	// A directory has no bytes to extract, and reading it is an error as on
	// a live system. Extracting it scanned the whole archive for nothing and
	// then read as an empty file, so a directory link inside a crontab spool
	// parsed as a user crontab with no entries.
	if h.Typeflag == tar.TypeDir {
		return &File{path: path, key: key, header: h, Fs: fs}, nil
	}

	reader, err := fs.open(h)
	if err != nil {
		return nil, err
	}

	return &File{
		path:   path,
		key:    key,
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
	h, key, err := fs.lookup(name)
	if err != nil {
		return nil, err
	}
	h, _, err = fs.resolveHeader(h, key)
	if err != nil {
		return nil, err
	}
	return h.FileInfo(), nil
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
	statHeader, _, err := fs.resolveHeader(header, Abs(header.Name))
	if err != nil {
		return nil, err
	}
	return statHeader.FileInfo(), nil
}

// maxLinkHops bounds link resolution. A tar can carry a symlink cycle, and
// following one forever would hang the scan on a malformed or hostile image.
// It matches Linux's limit on symlinks followed during one path lookup (40).
const maxLinkHops = 40

// errLinkLoop is what a path lookup returns when it follows more links than
// maxLinkHops, the way a live system returns ELOOP. It is deliberately not
// os.ErrNotExist: a link loop is a broken file, not a missing one.
var errLinkLoop = errors.New("too many levels of symbolic links")

func notExist(op, name string) error {
	// A link whose target is not in the archive is dangling, which is what
	// os.Stat reports as not-exist. Returning a bare error here made callers
	// that branch on os.IsNotExist treat it as a hard failure instead: a
	// systemd unit masked by a symlink to /dev/null aborted the whole
	// service list, because /dev/null is never in a container image.
	return &os.PathError{Op: op, Path: name, Err: os.ErrNotExist}
}

// lookup finds the archive entry a path names, the way the kernel resolves a
// path: every directory component that is a symlink is followed, the last
// component is not (lstat semantics). It returns the entry and the archive key
// it is stored under, which is the path with every directory link resolved.
//
// An archive stores each entry under its real path only. On a usr-merged image
// /bin is a symlink to usr/bin and there is no /bin/sh entry, only
// /usr/bin/sh, so an exact map lookup read /bin/sh, /sbin/sshd and
// /lib/systemd/system/* as absent.
//
// A directory with no entry of its own is not an error while walking: layer
// tars may omit the entries of parent directories. Whether the final path
// exists is decided by the final lookup.
func (fs *FS) lookup(name string) (*tar.Header, string, error) {
	p := Abs(name)
	if h, ok := fs.FileMap[p]; ok {
		return h, p, nil
	}

	hops := 0
walk:
	for {
		rest := strings.Split(strings.TrimPrefix(p, "/"), "/")
		cur := "/"
		for i, comp := range rest {
			next := join(cur, comp)
			h, ok := fs.FileMap[next]
			if i == len(rest)-1 {
				if !ok {
					return nil, "", notExist("lstat", name)
				}
				return h, next, nil
			}
			if ok && h.Typeflag == tar.TypeSymlink {
				hops++
				if hops > maxLinkHops {
					return nil, "", &os.PathError{Op: "lstat", Path: name, Err: errLinkLoop}
				}
				target := h.Linkname
				if !strings.HasPrefix(target, "/") {
					target = join(cur, target)
				}
				p = join(append([]string{"/", target}, rest[i+1:]...)...)
				if h, ok := fs.FileMap[p]; ok {
					return h, p, nil
				}
				continue walk
			}
			if ok && h.Typeflag != tar.TypeDir {
				// a regular file in the middle of a path: ENOTDIR on a live
				// system, absent for every caller here
				return nil, "", notExist("lstat", name)
			}
			cur = next
		}
		return nil, "", notExist("lstat", name)
	}
}

// LstatIfPossible reports on the link itself rather than on its target, so a
// symlink is reported as a symlink. It satisfies afero.Lstater, which callers
// probe for when the distinction matters: systemd unit lookup needs it to tell
// an alias and a masked unit apart from a regular unit file.
func (fs *FS) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	h, _, err := fs.lookup(name)
	if err != nil {
		return nil, true, err
	}
	// true: this is a real lstat, not a Stat standing in for one.
	return h.FileInfo(), true, nil
}

// ReadlinkIfPossible returns the target a symlink points at, without resolving
// it against the archive. It satisfies afero.LinkReader. The target may well not
// be in the archive at all, as with a unit masked to /dev/null, so reading the
// link and resolving it are deliberately separate steps.
func (fs *FS) ReadlinkIfPossible(name string) (string, error) {
	h, _, err := fs.lookup(name)
	if err != nil {
		return "", err
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
func (fs *FS) resolveHeader(header *tar.Header, key string) (*tar.Header, string, error) {
	h := header

	// The path the entry is being reached through. A hardlink is another name
	// for the same inode rather than a pointer to a path, so a relative
	// symlink reached through one resolves against the directory of the name
	// we came in on, not the directory of the entry that stores it. On an
	// OSTree image /etc/redhat-release is a hardlink to an object that is
	// itself a symlink to "fedora-release": that has to land on
	// /etc/fedora-release, not on a sibling of the object in the store.
	accessPath := key

	for range maxLinkHops {
		var target string
		switch h.Typeflag {
		case tar.TypeSymlink:
			target = Abs(fs.resolveSymlinkFrom(accessPath, h.Linkname))
			log.Debug().Str("path", h.Name).Str("resolved", target).Msg("file is a symlink, resolved it")
		case tar.TypeLink:
			target = Abs(h.Linkname)
			log.Debug().Str("path", h.Name).Str("resolved", target).Msg("file is a hardlink, resolved it")
		default:
			return h, key, nil
		}

		// the target may itself run through linked directories
		next, nextKey, err := fs.lookup(target)
		if err != nil {
			return nil, "", err
		}
		if next == h {
			return nil, "", &os.PathError{Op: "stat", Path: header.Name, Err: errLinkLoop}
		}
		if h.Typeflag == tar.TypeSymlink {
			accessPath = nextKey
		}
		h, key = next, nextKey
	}

	log.Warn().Str("file", header.Name).Msg("tar> giving up on a link chain that does not end")
	return nil, "", &os.PathError{Op: "stat", Path: header.Name, Err: errLinkLoop}
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
