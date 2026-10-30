// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"time"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

// xprotectBundlePaths and mrtBundlePaths list the locations XProtect
// and MRT can live in, in order of preference. Modern macOS keeps
// them under /Library/Apple/System/...; older releases used the
// traditional /System/Library/CoreServices/ path.
var (
	xprotectBundlePaths = []string{
		"/Library/Apple/System/Library/CoreServices/XProtect.bundle",
		"/System/Library/CoreServices/XProtect.bundle",
	}
	mrtBundlePaths = []string{
		"/Library/Apple/System/Library/CoreServices/MRT.app",
		"/System/Library/CoreServices/MRT.app",
	}
)

type mqlMacosXprotectInternal struct {
	lock    sync.Mutex
	fetched bool
	state   xprotectState
}

type xprotectState struct {
	version     string
	modified    *time.Time
	mrtVersion  string
	mrtModified *time.Time
}

func (x *mqlMacosXprotect) id() (string, error) {
	return "macos.xprotect", nil
}

// fetchState locates XProtect.bundle and MRT.app, reads their
// Info.plist files for `CFBundleShortVersionString`, and stats them
// for modification time. A missing bundle leaves its fields at zero
// (empty string + nil pointer), which the typed accessors translate
// into MQL null/empty so audits fail soft on systems where Apple has
// retired the relevant component.
func (x *mqlMacosXprotect) fetchState() (xprotectState, error) {
	if x.fetched {
		return x.state, nil
	}
	x.lock.Lock()
	defer x.lock.Unlock()
	if x.fetched {
		return x.state, nil
	}

	conn := x.MqlRuntime.Connection.(shared.Connection)

	x.state.version, x.state.modified = readBundleVersionAndMtime(conn, xprotectBundlePaths)
	x.state.mrtVersion, x.state.mrtModified = readBundleVersionAndMtime(conn, mrtBundlePaths)

	x.fetched = true
	return x.state, nil
}

func (x *mqlMacosXprotect) version() (string, error) {
	s, err := x.fetchState()
	return s.version, err
}

func (x *mqlMacosXprotect) modified() (*time.Time, error) {
	s, err := x.fetchState()
	return s.modified, err
}

func (x *mqlMacosXprotect) mrtVersion() (string, error) {
	s, err := x.fetchState()
	return s.mrtVersion, err
}

func (x *mqlMacosXprotect) mrtModified() (*time.Time, error) {
	s, err := x.fetchState()
	return s.mrtModified, err
}

// readBundleVersionAndMtime walks `bundlePaths` looking for the first
// extant bundle, reads `Contents/Info.plist` for the version, and
// returns the bundle's filesystem modification time. Missing bundles
// (XProtect not installed on a non-Darwin host; MRT retired on macOS
// 13+) return ("", nil) so callers can surface MQL null.
func readBundleVersionAndMtime(conn shared.Connection, bundlePaths []string) (string, *time.Time) {
	fs := conn.FileSystem()
	for _, bundle := range bundlePaths {
		info, err := fs.Stat(bundle)
		if err != nil {
			continue
		}
		mtime := info.ModTime()
		version := readBundleVersion(conn, bundle+"/Contents/Info.plist")
		return version, &mtime
	}
	return "", nil
}

// readBundleVersion reads CFBundleShortVersionString from an
// Info.plist file. Missing file, unreadable plist, or absent key all
// surface as an empty string — the bundle existed (the caller already
// stat'd it) but its metadata is unreadable, which is unusual but
// shouldn't crash the audit.
func readBundleVersion(conn shared.Connection, infoPlistPath string) string {
	f, err := conn.FileSystem().Open(infoPlistPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	data, err := plist.Decode(f)
	if err != nil {
		return ""
	}
	if v, ok := data["CFBundleShortVersionString"].(string); ok {
		return v
	}
	return ""
}
