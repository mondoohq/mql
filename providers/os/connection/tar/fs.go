// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/fsutil"
)

var _ shared.FileSearch = (*FS)(nil)

func NewFs(source string) *FS {
	return &FS{
		Source:      source,
		FileMap:     make(map[string]*tar.Header),
		dataOffsets: make(map[*tar.Header]int64),
	}
}

type FS struct {
	Source  string
	FileMap map[string]*tar.Header

	// dataOffsets is where the data of each entry starts in the archive at
	// Source, recorded when the archive was loaded. Reading a file used to
	// scan the archive from its start for the entry, so every read cost a
	// pass over the whole image: reading the package.json files of a Debian
	// image with nodejs installed took three minutes.
	dataOffsets map[*tar.Header]int64

	// dirIndex maps each directory to the names of its direct children. It
	// is built from FileMap on the first listing and rebuilt when FileMap
	// has grown since. Listing a directory used to scan every entry of the
	// archive, which made a walk quadratic in the size of the image: npm
	// and package file inventories took minutes on an image the same
	// scan inside the running container finished in a second.
	indexMu    sync.Mutex
	dirIndex   map[string][]string
	indexedLen int
}

// childNames returns the names of the direct children of the directory at
// archive key dir, sorted. A child that only appears as the parent of a
// deeper entry is included: layer tars may omit the entries of directories.
func (fs *FS) childNames(dir string) []string {
	fs.indexMu.Lock()
	defer fs.indexMu.Unlock()
	if fs.dirIndex == nil || fs.indexedLen != len(fs.FileMap) {
		fs.dirIndex = buildDirIndex(fs.FileMap)
		fs.indexedLen = len(fs.FileMap)
	}
	return fs.dirIndex[dir]
}

func buildDirIndex(files map[string]*tar.Header) map[string][]string {
	sets := map[string]map[string]struct{}{}
	for k := range files {
		for k != "/" && k != "" {
			parent, name := path.Split(k)
			if parent != "/" {
				parent = strings.TrimSuffix(parent, "/")
			}
			children, ok := sets[parent]
			if !ok {
				children = map[string]struct{}{}
				sets[parent] = children
			}
			if _, seen := children[name]; seen {
				// the rest of the chain was added with this name
				break
			}
			children[name] = struct{}{}
			k = parent
		}
	}
	index := make(map[string][]string, len(sets))
	for dir, children := range sets {
		names := make([]string, 0, len(children))
		for name := range children {
			names = append(names, name)
		}
		sort.Strings(names)
		index[dir] = names
	}
	return index
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

	if offset, ok := fs.dataOffsets[header]; ok {
		return fsutil.ReadTarEntryAt(f, offset, header.Size)
	}

	// extract file from tar stream
	reader, err := fsutil.ExtractFileFromTarStream(header.Name, f)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

// Find searches the archive the way the command-based files.find does with
// `find -L`, so an image scan and a scan of the running system agree:
//
//   - from is a directory: only entries below from (or from itself) match, not
//     siblings that merely share its name as a prefix.
//   - typ is a comma-separated list of find types (file, directory, link, ...
//     or their one-letter forms). A symlink and a hardlink are tested by their
//     target's type, so a link to a regular file is a "file"; "link" matches
//     every symlink. A dangling symlink is only ever a link.
//   - perm is a `find -perm -mode` mask: every bit in it must be set on the
//     target's mode. A zero mask is no filter.
//   - r must match the whole path, as `find -regex` does.
//   - a symlink loop is skipped, as find -L skips it with an error.
//
// Links to directories are reported but not descended into, as the command
// backend's `-xtype l -prune` does. The exception is from itself: like find
// -L, a start path that links to a directory (/bin -> usr/bin on a usr-merged
// image) is searched, and its entries are reported below from.
func (fs *FS) Find(from string, r *regexp.Regexp, typ string, perm *uint32, depth *int) ([]string, error) {
	return fs.FindWithOptions(from, r, typ, perm, depth, fsutil.FindOptions{CrossFileSystems: true})
}

func (fs *FS) FindWithOptions(from string, r *regexp.Regexp, typ string, perm *uint32, depth *int, options fsutil.FindOptions) ([]string, error) {
	// An archive has no mounted sub-filesystems. Keep its indexed search, but
	// apply the same cancellation and result budgets as a live filesystem.
	budget, cancel := fsutil.NewFindBudget(options)
	defer cancel()
	if err := budget.Check(); err != nil {
		return nil, err
	}

	from = Abs(from)
	root := fs.findRoot(from)
	prefix := root
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	types := findTypes(typ)
	if r != nil {
		anchored, err := regexp.Compile(`^(?:` + r.String() + `)$`)
		if err != nil {
			return nil, err
		}
		r = anchored
	}

	list := []string{}
	for k, entry := range fs.FileMap {
		if err := budget.Visit(); err != nil {
			return nil, err
		}
		if k != root && !strings.HasPrefix(k, prefix) {
			continue
		}
		// the path as find prints it, below from
		p := k
		if root != from {
			p = from + k[len(root):]
		}
		if !depthMatch(from, p, depth) {
			continue
		}
		if r != nil && !r.MatchString(p) {
			continue
		}
		// the target decides type and mode, as with find -L
		target := entry
		if entry.Typeflag == tar.TypeSymlink || entry.Typeflag == tar.TypeLink {
			info, err := fs.Stat(k)
			switch {
			case err == nil:
				if h, ok := info.Sys().(*tar.Header); ok {
					target = h
				}
			case !os.IsNotExist(err):
				// a link loop: find -L reports it as an error and skips it
				continue
			}
		}

		if len(types) > 0 && !matchesFindType(types, entry, target) {
			continue
		}
		if perm != nil && *perm != 0 && uint32(target.Mode)&*perm != *perm {
			continue
		}
		if err := budget.Match(); err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	// the index is a map, so without this the same image listed its files
	// in another order on every scan
	sort.Strings(list)
	return list, nil
}

// findRoot returns the archive path a search from `from` walks: from itself,
// or the directory it links to when from is a symlink to a directory.
func (fs *FS) findRoot(from string) string {
	h, ok := fs.FileMap[from]
	if !ok || h.Typeflag != tar.TypeSymlink {
		return from
	}
	info, err := fs.Stat(from)
	if err != nil {
		return from
	}
	target, ok := info.Sys().(*tar.Header)
	if !ok || target.Typeflag != tar.TypeDir {
		return from
	}
	root := Abs(target.Name)
	if root == "/" || root == from {
		return from
	}
	return root
}

// findTypes parses a files.find type list into find's one-letter types.
func findTypes(typ string) []byte {
	res := []byte{}
	for t := range strings.SplitSeq(typ, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		switch t[0] {
		case 'b', 'c', 'd', 'p', 'f', 'l', 's':
			res = append(res, t[0])
		}
	}
	return res
}

func matchesFindType(types []byte, entry *tar.Header, target *tar.Header) bool {
	for _, t := range types {
		var ok bool
		switch t {
		case 'l':
			ok = entry.Typeflag == tar.TypeSymlink
		case 'f':
			ok = target.Typeflag == tar.TypeReg
		case 'd':
			ok = target.Typeflag == tar.TypeDir
		case 'b':
			ok = target.Typeflag == tar.TypeBlock
		case 'c':
			ok = target.Typeflag == tar.TypeChar
		case 'p':
			ok = target.Typeflag == tar.TypeFifo
		case 's':
			// tar has no typeflag for a socket (tar and docker export skip
			// them), so no entry is one, as find -type s finds none in an
			// extracted image
			ok = false
		}
		if ok {
			return true
		}
	}
	return false
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
