// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/mount"
	"go.mondoo.com/mql/providers/os/resources/nfs"
	"go.mondoo.com/mql/types"
)

const (
	nfsExportsPath    = "/etc/exports"
	nfsExportsDir     = "/etc/exports.d"
	nfsFragmentSuffix = ".exports"
)

func (n *mqlNfs) id() (string, error) {
	return "nfs", nil
}

func (n *mqlNfs) exports() ([]any, error) {
	conn, ok := n.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("wrong connection type")
	}
	platform, err := nfsPlatform(conn)
	if err != nil {
		return nil, err
	}

	fs := conn.FileSystem()
	if fs == nil {
		return nil, errors.New("filesystem not available")
	}

	entries, err := loadExports(fs, platform)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(entries))
	for _, e := range entries {
		options := make([]any, len(e.Options))
		for i, o := range e.Options {
			options[i] = o
		}
		res, err := CreateResource(n.MqlRuntime, "nfs.export", map[string]*llx.RawData{
			"__id":         llx.StringData(e.Path + "\x1f" + e.Client),
			"path":         llx.StringData(e.Path),
			"client":       llx.StringData(e.Client),
			"options":      llx.ArrayData(options, types.String),
			"readOnly":     llx.BoolData(e.ReadOnly),
			"noRootSquash": llx.BoolData(e.NoRootSquash),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (n *mqlNfs) mounts() ([]any, error) {
	conn, ok := n.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	mm, err := mount.ResolveManager(conn)
	if err != nil {
		return nil, fmt.Errorf("could not detect suitable mount manager: %w", err)
	}
	if mm == nil {
		return nil, errors.New("no mount manager available for this platform")
	}

	mounts, err := mm.List()
	if err != nil {
		return nil, fmt.Errorf("could not retrieve mount list: %w", err)
	}

	out := make([]any, 0)
	for _, m := range mounts {
		if !nfs.IsNFSFsType(m.FSType) {
			continue
		}
		info := nfs.BuildMountInfo(m.Device, m.MountPoint, m.FSType, m.Options)
		options := make([]any, len(info.Options))
		for i, o := range info.Options {
			options[i] = o
		}
		res, err := CreateResource(n.MqlRuntime, "nfs.mount", map[string]*llx.RawData{
			"__id":       llx.StringData(info.MountPoint),
			"device":     llx.StringData(info.Device),
			"mountpoint": llx.StringData(info.MountPoint),
			"server":     llx.StringData(info.Server),
			"remotePath": llx.StringData(info.RemotePath),
			"version":    llx.StringData(info.Version),
			"security":   llx.StringData(info.Security),
			"hardMount":  llx.BoolData(info.HardMount),
			"readOnly":   llx.BoolData(info.ReadOnly),
			"options":    llx.ArrayData(options, types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// loadExports reads `/etc/exports` and, on Linux, every `*.exports`
// fragment in `/etc/exports.d/` (the convention used by nfs-utils
// per `exportfs(8)`), parses them with the platform-appropriate
// syntax, and returns the concatenated entry list. Fragments are
// processed in lexicographic filename order so the result is
// deterministic across runs. A missing file or directory is not an
// error; only parse failures and unexpected I/O errors surface.
func loadExports(fs afero.Fs, platform string) ([]nfs.ExportEntry, error) {
	entries, err := parseExportsFile(fs, nfsExportsPath, platform)
	if err != nil {
		return nil, err
	}

	if platform != nfs.PlatformLinux {
		return entries, nil
	}

	names, err := listExportsFragments(fs, nfsExportsDir)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		parsed, err := parseExportsFile(fs, path.Join(nfsExportsDir, name), platform)
		if err != nil {
			return nil, err
		}
		entries = append(entries, parsed...)
	}
	return entries, nil
}

// parseExportsFile opens p and parses it as an exports file in the
// given platform's syntax. A file-not-found error is treated as no
// exports declared; any other open error (e.g. EACCES) is surfaced
// so a misconfigured target doesn't silently look like an empty
// export set.
func parseExportsFile(afs afero.Fs, p, platform string) ([]nfs.ExportEntry, error) {
	f, err := afs.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	defer f.Close()
	return nfs.ParseExports(f, platform)
}

// listExportsFragments returns the sorted names of `*.exports` files
// in dir. A missing directory or a directory read error caused by
// the path being a file (or otherwise not a directory) is treated
// as "no fragments" rather than a hard error, because the absence
// of `/etc/exports.d` is normal.
func listExportsFragments(afs afero.Fs, dir string) ([]string, error) {
	d, err := afs.Open(dir)
	if err != nil {
		return nil, nil
	}
	defer d.Close()

	all, err := d.Readdirnames(-1)
	if err != nil {
		return nil, nil
	}
	names := make([]string, 0, len(all))
	for _, n := range all {
		if strings.HasSuffix(n, nfsFragmentSuffix) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

// nfsPlatform maps the connection's reported platform onto one of the
// platform identifiers accepted by [nfs.ParseExports]. macOS reports
// itself with name "macos" and family "darwin", FreeBSD and AIX
// report by name, and Linux distributions all share the "linux"
// family.
func nfsPlatform(conn shared.Connection) (string, error) {
	pf := conn.Asset().Platform
	if pf == nil {
		return "", errors.New("missing platform information")
	}
	switch {
	case pf.IsFamily("linux"):
		return nfs.PlatformLinux, nil
	case pf.IsFamily("darwin"):
		return nfs.PlatformDarwin, nil
	case pf.Name == "freebsd":
		return nfs.PlatformFreeBSD, nil
	case pf.Name == "aix":
		return nfs.PlatformAIX, nil
	}
	return "", fmt.Errorf("nfs resource not supported on platform %q", pf.Name)
}
