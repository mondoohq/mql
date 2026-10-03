// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
)

// WalkOptions are the files.find filters, with the meaning BuildFilesFindCmd
// gives them on GNU find.
type WalkOptions struct {
	From string
	// Xdev false keeps the walk on the start path's filesystem (find -xdev).
	Xdev     bool
	FileType string
	Regex    string
	// Permission is find's -perm -MODE: every bit must be set. 0o777 means no
	// filter, as in BuildFilesFindCmd.
	Permission int64
	Name       string
	Depth      *int64
}

// ErrPartialWalk reports that some directories could not be read. The paths
// returned alongside it are every match the walk did reach.
var ErrPartialWalk = errors.New("some directories could not be read")

// Walk searches the local filesystem the way BuildFilesFindCmd's GNU find
// command does, for a host that has no find binary:
//
//   - like find -L, every test sees a symlink's target (a link to a regular
//     file is a "file"), and a broken link stays a "link"
//   - the start path is followed when it is a symlink, but the walk never
//     descends through a symlinked directory below it
//   - -perm -MODE needs every bit, setuid, setgid and sticky included
//   - -name globs the base name, -regex must match the whole path
//   - -maxdepth and -xdev as in find
//
// It reads the filesystem of the process it runs in, so it is only correct
// for a local connection without sudo.
func Walk(opts WalkOptions) ([]string, error) {
	var re *regexp.Regexp
	if opts.Regex != "" {
		var err error
		re, err = regexp.Compile("^(?:" + opts.Regex + ")$")
		if err != nil {
			return nil, err
		}
	}
	if opts.Name != "" {
		if _, err := path.Match(opts.Name, ""); err != nil {
			return nil, err
		}
	}

	start, err := os.Stat(opts.From)
	if err != nil {
		return nil, err
	}

	w := &walker{opts: opts, re: re, found: []string{}}
	if !opts.Xdev {
		w.dev, w.checkDev = deviceOf(start)
	}
	startLink := false
	if li, err := os.Lstat(opts.From); err == nil {
		startLink = li.Mode()&fs.ModeSymlink != 0
	}
	w.visit(opts.From, 0, start, startLink, true)

	if w.partial {
		if len(w.found) == 0 {
			return nil, w.firstErr
		}
		return w.found, ErrPartialWalk
	}
	return w.found, nil
}

type walker struct {
	opts     WalkOptions
	re       *regexp.Regexp
	dev      uint64
	checkDev bool
	found    []string
	partial  bool
	firstErr error
}

// visit tests p and descends into it. target is p's followed stat (nil for a
// broken link), isLink whether p itself is a symlink.
func (w *walker) visit(p string, depth int64, target fs.FileInfo, isLink bool, isStart bool) {
	if w.match(p, target, isLink) {
		w.found = append(w.found, p)
	}

	if target == nil || !target.IsDir() {
		return
	}
	if isLink && !isStart {
		return
	}
	if w.opts.Depth != nil && depth >= *w.opts.Depth {
		return
	}
	if w.checkDev && !isStart {
		if dev, ok := deviceOf(target); ok && dev != w.dev {
			return
		}
	}

	entries, err := os.ReadDir(p)
	if err != nil {
		w.fail(err)
		return
	}
	for _, e := range entries {
		child := filepath.Join(p, e.Name())
		childLink := e.Type()&fs.ModeSymlink != 0
		var info fs.FileInfo
		if childLink {
			info, _ = os.Stat(child) // a broken link has no target
		} else {
			info, err = e.Info()
			if err != nil {
				w.fail(err)
				continue
			}
		}
		w.visit(child, depth+1, info, childLink, false)
	}
}

func (w *walker) fail(err error) {
	if !w.partial {
		w.firstErr = err
	}
	w.partial = true
}

func (w *walker) match(p string, target fs.FileInfo, isLink bool) bool {
	if w.opts.FileType != "" {
		t, ok := findTypes[w.opts.FileType]
		if ok && !matchesFindType(t, target, isLink) {
			return false
		}
	}
	if w.re != nil && !w.re.MatchString(p) {
		return false
	}
	if w.opts.Permission != 0o777 {
		if target == nil {
			return false
		}
		want := uint32(w.opts.Permission)
		if unixMode(target.Mode())&want != want {
			return false
		}
	}
	if w.opts.Name != "" {
		if ok, _ := path.Match(w.opts.Name, filepath.Base(p)); !ok {
			return false
		}
	}
	return true
}

// matchesFindType is find -L's -type: the target's type, and "l" only for a
// link whose target cannot be read.
func matchesFindType(t string, target fs.FileInfo, isLink bool) bool {
	if t == "l" {
		return isLink
	}
	if target == nil {
		return false
	}
	m := target.Mode()
	switch t {
	case "f":
		return m.IsRegular()
	case "d":
		return m.IsDir()
	case "c":
		return m&fs.ModeDevice != 0 && m&fs.ModeCharDevice != 0
	case "b":
		return m&fs.ModeDevice != 0 && m&fs.ModeCharDevice == 0
	case "s":
		return m&fs.ModeSocket != 0
	}
	return false
}

// unixMode converts a Go file mode to the st_mode permission bits -perm tests.
func unixMode(m fs.FileMode) uint32 {
	out := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		out |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		out |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		out |= 0o1000
	}
	return out
}
