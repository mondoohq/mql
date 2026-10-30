// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fsutil

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/afero"
)

// FindOptions bounds a native search. Zero limits mean a two-minute elapsed
// budget, at most 1,000,000 visited entries, and at most 100,000 matches. Callers
// can supply different positive budgets; MQL users can narrow from/depth/type
// instead of accepting an incomplete list. Every exhausted budget returns an error.
// Cancellation is cooperative: a filesystem operation already blocked in the
// kernel cannot be interrupted through io/fs.
type FindOptions struct {
	Context          context.Context
	CrossFileSystems bool
	// SingleFileSystem is only for a backend known to be virtual and unable
	// to contain host mounts. Missing stat device data alone never proves it.
	SingleFileSystem bool
	Timeout          time.Duration
	MaxEntries       int
	MaxMatches       int
}

// ErrFindLimit identifies an incomplete search that exhausted its entry or match budget.
var ErrFindLimit = errors.New("native file search budget exceeded")

// FindBudget is shared by the filesystem walker and the archive index search.
// Exceeding any limit is an error, never a successful partial inventory.
type FindBudget struct {
	ctx                    context.Context
	maxEntries, maxMatches int
	entries, matches       int
}

func NewFindBudget(options FindOptions) (*FindBudget, context.CancelFunc) {
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	entries, matches := options.MaxEntries, options.MaxMatches
	if entries <= 0 {
		entries = 1_000_000
	}
	if matches <= 0 {
		matches = 100_000
	}
	return &FindBudget{ctx: ctx, maxEntries: entries, maxMatches: matches}, cancel
}

func (b *FindBudget) Check() error {
	if err := b.ctx.Err(); err != nil {
		return fmt.Errorf("native file search interrupted: %w", err)
	}
	return nil
}
func (b *FindBudget) Visit() error {
	if err := b.Check(); err != nil {
		return err
	}
	b.entries++
	if b.entries > b.maxEntries {
		return fmt.Errorf("%w: exceeds %d entries; narrow from or depth", ErrFindLimit, b.maxEntries)
	}
	return nil
}
func (b *FindBudget) Match() error {
	if err := b.Check(); err != nil {
		return err
	}
	b.matches++
	if b.matches > b.maxMatches {
		return fmt.Errorf("%w: exceeds %d matches; narrow the search", ErrFindLimit, b.maxMatches)
	}
	return nil
}

// Only concrete backends with a known single-filesystem contract belong here.
// Wrappers with opaque metadata must opt in explicitly or report unsupported.
func knownVirtualFindFS(target fs.FS) bool {
	if afs, ok := target.(afero.IOFS); ok {
		_, ok := afs.Fs.(*afero.MemMapFs)
		return ok
	}
	return false
}

func FindFiles(iofs fs.FS, from string, r *regexp.Regexp, typ string, perm *uint32, depth *int) ([]string, error) {
	// Existing callers without mount options keep their historical scope.
	return FindFilesWithOptions(iofs, from, r, typ, perm, depth, FindOptions{CrossFileSystems: true})
}

func FindFilesWithOptions(iofs fs.FS, from string, r *regexp.Regexp, typ string, perm *uint32, depth *int, options FindOptions) ([]string, error) {
	budget, cancel := NewFindBudget(options)
	defer cancel()
	if err := budget.Check(); err != nil {
		return nil, err
	}
	var rootDevice uint64
	var hasDevice bool
	if !options.CrossFileSystems {
		info, err := fs.Stat(iofs, from)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			return nil, fmt.Errorf("native file search cannot stat root %q: %w", from, err)
		}
		if info != nil {
			rootDevice, hasDevice = fileDeviceID(info)
			if !hasDevice && !options.SingleFileSystem && !knownVirtualFindFS(iofs) {
				return nil, fmt.Errorf("native file search cannot enforce xdev:false for filesystem metadata %T", info.Sys())
			}
		}
	}

	matcher := createFindFilesMatcher(iofs, typ, from, r, perm, depth)
	matchedPaths := []string{}
	// Note: matcher.Match resolves a symlink to its target type so a symlink is
	// reported under the type it points at (mirroring `find -L`), but WalkDir
	// itself does not follow symlinks during traversal. So a symlinked directory
	// is reported for type:"directory" yet its contents are not walked. Full
	// `find -L` recursion would need explicit symlink following with loop
	// detection; it isn't required for the config-file discovery this powers.
	err := fs.WalkDir(iofs, from, func(p string, d fs.DirEntry, err error) error {
		if err := budget.Visit(); err != nil {
			return err
		}
		if d != nil && d.IsDir() && matcher.DepthReached(p) {
			return fs.SkipDir
		}

		// An absent root has no matches; a root we cannot inspect must not
		// look like a successfully completed, empty search.
		if err != nil && p == from && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("native file search cannot read root %q: %w", from, err)
		}
		skipFile, err := handleFsError(err)
		if err != nil {
			return err
		}

		if skipFile {
			return nil
		}
		pruneMount := false
		if hasDevice && d.IsDir() && p != from {
			info, err := d.Info()
			if err != nil {
				// ReadDir may still succeed when stat is denied. Without device
				// metadata we cannot prove that descending preserves xdev.
				return fmt.Errorf("native file search cannot determine filesystem boundary at %q: %w", p, err)
			}
			if info != nil {
				device, ok := fileDeviceID(info)
				if !ok {
					return fmt.Errorf("native file search cannot determine filesystem boundary at %q", p)
				}
				pruneMount = device != rootDevice
			}
		}
		if matcher.Match(p, d.Type()) {
			if err := budget.Match(); err != nil {
				return err
			}
			matchedPaths = append(matchedPaths, p)
		}
		// Like find -xdev, report the mount itself but never enter it.
		if pruneMount {
			return fs.SkipDir
		}
		return budget.Check()
	})
	if err != nil {
		return nil, err
	}
	return matchedPaths, nil
}

type findFilesMatcher struct {
	types []byte
	r     *regexp.Regexp
	perm  *uint32
	depth *int
	from  string
	iofs  fs.FS
}

// Depth 0 means we only walk the current directory
// Depth 1 means we walk the current directory and its children
// Depth 2 means we walk the current directory, its children and their children
func (m findFilesMatcher) DepthReached(p string) bool {
	if m.depth == nil {
		return false
	}

	trimmed := strings.TrimPrefix(p, m.from)
	// WalkDir always uses slash for separating, ignoring the OS separator. This is why we need to replace it.
	normalized := strings.ReplaceAll(trimmed, string(os.PathSeparator), "/")
	depth := strings.Count(normalized, "/")
	return depth > *m.depth
}

// Match reports whether a walked path passes every filter.
//
// The three tests are ordered by cost, and they short circuit. matchesType
// reads the mode the walk already carries. matchesRegex runs the pattern.
// matchesPerm stats the path, and matchesType stats a symlink as well, so both
// can cost a syscall per path. A path that fails an earlier test never pays for
// a later one.
//
// All three are pure, so the result does not depend on how many of them run.
func (m findFilesMatcher) Match(path string, t fs.FileMode) bool {
	return m.matchesType(path, t) && m.matchesRegex(path) && m.matchesPerm(path)
}

func (m findFilesMatcher) matchesRegex(path string) bool {
	if m.r == nil {
		return true
	}
	// We don't use r.Match because we need the entire path to match
	// if we want to be compatible with find. It would probably be
	// more efficient add anchors to the regular expression
	match := m.r.FindString(path)
	return match == path
}

func (m findFilesMatcher) matchesType(path string, entryType fs.FileMode) bool {
	if len(m.types) == 0 {
		return true
	}

	// WalkDir reports lstat info, so a symlink keeps fs.ModeSymlink and never
	// matches file/dir/etc. on its own. The command-based backend uses
	// `find -L`, which follows symlinks and tests the target's type; mirror
	// that here by resolving the symlink's target. Without this, a symlinked
	// regular file (e.g. authselect manages /etc/pam.d service files as
	// symlinks into /etc/authselect) is skipped by type:"file".
	// See https://github.com/mondoohq/mql/issues/8467
	// This is purely additive: a symlink still matches type:"link" (handled
	// against the original lstat mode below), it now ALSO matches the type of
	// whatever it points at. Broken symlinks fail to resolve and keep their
	// symlink type.
	resolvedType := entryType
	if entryType&fs.ModeSymlink != 0 && m.wantsNonSymlinkType() {
		if info, err := fs.Stat(m.iofs, path); err == nil {
			resolvedType = info.Mode()
		}
	}

	for _, at := range m.types {
		var matches bool
		switch at {
		case 'b':
			matches = (resolvedType&fs.ModeDevice) != 0 && (resolvedType&fs.ModeCharDevice) == 0
		case 'c':
			matches = (resolvedType&fs.ModeDevice) != 0 && (resolvedType&fs.ModeCharDevice) != 0
		case 'd':
			matches = resolvedType.IsDir()
		case 'p':
			matches = (resolvedType & fs.ModeNamedPipe) != 0
		case 'f':
			matches = resolvedType.IsRegular()
		case 'l':
			// match against the original mode so any symlink matches, including
			// one that points at a regular file or directory.
			matches = (entryType & fs.ModeSymlink) != 0
		}
		if matches {
			return true
		}
	}
	return false
}

// wantsNonSymlinkType reports whether any requested type other than "link" is
// set, i.e. whether resolving a symlink's target type could change the result.
// It lets us skip the extra stat for plain type:"link" lookups.
func (m findFilesMatcher) wantsNonSymlinkType() bool {
	for _, at := range m.types {
		if at != 'l' {
			return true
		}
	}
	return false
}

func (m findFilesMatcher) matchesPerm(path string) bool {
	if m.perm == nil {
		return true
	}
	// A zero permission mask is "no permission filter", matching `find -perm -0`
	// (every file has all of zero bits set) and the command-based find backend.
	// files.find created via CreateResource without a `permissions` argument
	// arrives here with a 0 mask (initFilesFind's 0o777 default only applies to
	// MQL-instantiated resources), and the pam/sudoers/modprobe/rsyslog/... `*.d`
	// discoveries all rely on that. Without this guard a 0 mask matched nothing
	// (`mode & 0 == 0`), so those lookups returned no files on filesystem and
	// tar connections. See https://github.com/mondoohq/mql/issues/8467
	if *m.perm == 0 {
		return true
	}
	info, err := fs.Stat(m.iofs, path)
	if err != nil {
		return false
	}

	// every bit of the mask must be set, as with `find -perm -mode`
	return uint32(info.Mode().Perm())&*m.perm == *m.perm
}

func createFindFilesMatcher(iofs fs.FS, typeStr string, from string, r *regexp.Regexp, perm *uint32, depth *int) findFilesMatcher {
	allowed := []byte{}
	types := strings.SplitSeq(typeStr, ",")
	for t := range types {
		if len(t) == 0 {
			continue
		}
		firstChar := t[0]
		switch firstChar {
		case 'b', 'c', 'd', 'p', 'f', 'l':
			allowed = append(allowed, firstChar)
		default:
		}
	}
	return findFilesMatcher{
		types: allowed,
		r:     r,
		perm:  perm,
		iofs:  iofs,
		depth: depth,
		from:  from,
	}
}
