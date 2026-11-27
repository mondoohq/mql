// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// Chocolatey keeps a record of every package version it installed under
// <root>\.chocolatey\<id>.<version>\. When the package's installer created
// Uninstall keys (an MSI, an Inno Setup or NSIS program), ".registry" lists
// them; a meta package, a portable one or an extension has no ".registry".
// ".sourceInstalledFrom" holds the feed the package came from and is missing
// for a package that was upgraded.
//
// The record joins to the Uninstall registry through the key's own name, the
// last segment of each KeyPath.
const (
	chocolateyDefaultRoot  = `C:\ProgramData\chocolatey`
	chocolateyRecordsDir   = ".chocolatey"
	chocolateyRegistryFile = ".registry"
	chocolateyFeedFile     = ".sourceInstalledFrom"

	chocolateyMaxRecords       = 4096
	chocolateyMaxRegistryBytes = 1 << 20
	chocolateyMaxFeedBytes     = 4 << 10
)

// chocolateyRecordName splits "<id>.<version>" at the version: up to four
// numeric parts and an optional pre-release suffix. Ids with dotted numeric
// tails ("dotnet.4.8") are ambiguous, which only costs the name.
var chocolateyRecordName = regexp.MustCompile(`^(.+?)\.(\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?)$`)

var utf8BOM = []byte("\xef\xbb\xbf")

// chocolateyRecord is one package version's claim on an Uninstall key.
type chocolateyRecord struct {
	id string
	// version is the package version, from the record's folder name.
	version string
	// displayVersion is the DisplayVersion the installer wrote.
	displayVersion string
	// scope and user are the install scope the key's hive stands for, as the
	// package listing derives it.
	scope string
	user  string
	// written is when Chocolatey wrote the record, unix seconds.
	written int64
	// url is the feed the package came from, "" when unknown.
	url string
}

// chocolateyIndex maps a lower-cased Uninstall key name to the records that
// name it.
type chocolateyIndex map[string][]chocolateyRecord

func (r chocolateyRecord) source() Source {
	return Source{OSProvided: osProvided(false), Channel: ChannelChocolatey, Name: r.id, URL: r.url}
}

// versionMatches reports a record for the version the Uninstall entry shows.
func (r chocolateyRecord) versionMatches(pkg Package) bool {
	return r.displayVersion != "" && strings.EqualFold(strings.TrimSpace(r.displayVersion), strings.TrimSpace(pkg.Version))
}

// matchesScope tells whether the record's key can be the package's: a key of
// the machine hive is only a machine-scope entry, a user's only that user's.
func (r chocolateyRecord) matchesScope(pkg Package) bool {
	pkgScope := pkg.InstallScope
	if pkgScope == "" {
		pkgScope = installScopeMachine
	}
	if r.scope != pkgScope {
		return false
	}
	if r.scope == installScopeUser && r.user != "" && pkg.InstallUser != "" {
		return strings.EqualFold(r.user, pkg.InstallUser)
	}
	return true
}

// best returns the record that decides the package's source. An upgrade leaves
// the old versions' records behind, all naming the same key: the one for the
// installed version wins, then the newest version, then the most recently
// written record.
func (idx chocolateyIndex) best(pkg Package) (chocolateyRecord, bool) {
	key := uninstallKeyOf(pkg)
	if len(idx) == 0 || key == "" {
		return chocolateyRecord{}, false
	}
	var best chocolateyRecord
	found := false
	for _, r := range idx[strings.ToLower(key)] {
		if !r.matchesScope(pkg) {
			continue
		}
		if !found || r.betterThan(best, pkg) {
			best, found = r, true
		}
	}
	return best, found
}

func (r chocolateyRecord) betterThan(o chocolateyRecord, pkg Package) bool {
	if rm, om := r.versionMatches(pkg), o.versionMatches(pkg); rm != om {
		return rm
	}
	rv, rok := windowsNumericVersion(r.version)
	ov, ook := windowsNumericVersion(o.version)
	if rok && ook {
		if c := compareWindowsNumericVersions(rv, ov); c != 0 {
			return c > 0
		}
	}
	return r.written > o.written
}

// chocolateyRegistry is the part of a ".registry" file the join needs.
type chocolateyRegistry struct {
	User string `xml:"user"`
	Keys []struct {
		DisplayVersion string `xml:"displayVersion,attr"`
		KeyPath        string `xml:"KeyPath"`
	} `xml:"keys>key"`
}

// readChocolateyRecords reads the package records of the Chocolatey install
// into one index. install is the ChocolateyInstall variable, "" when unknown;
// the default location is tried too. Nothing here fails: a file that cannot be
// read or parsed is skipped.
func readChocolateyRecords(fs afero.Fs, toFsPath func(string) (string, bool), install string) chocolateyIndex {
	roots := []string{}
	if install != "" {
		roots = append(roots, strings.TrimRight(install, `\/`))
	}
	if !strings.EqualFold(install, chocolateyDefaultRoot) {
		roots = append(roots, chocolateyDefaultRoot)
	}
	idx := chocolateyIndex{}
	for _, root := range roots {
		winDir := root + `\` + chocolateyRecordsDir
		dir, ok := toFsPath(winDir)
		if !ok {
			continue
		}
		infos, err := afero.ReadDir(fs, dir)
		if err != nil {
			continue
		}
		for i, fi := range infos {
			if i >= chocolateyMaxRecords {
				log.Debug().Str("path", dir).Msg("mql[packages]> too many Chocolatey package records, ignoring the rest")
				break
			}
			if fi.IsDir() {
				readChocolateyRecord(fs, toFsPath, winDir, fi.Name(), idx)
			}
		}
		// the first root with records is the install
		if len(idx) > 0 {
			break
		}
	}
	return idx
}

func readChocolateyRecord(fs afero.Fs, toFsPath func(string) (string, bool), winDir, name string, idx chocolateyIndex) {
	m := chocolateyRecordName.FindStringSubmatch(name)
	if m == nil {
		return
	}
	regPath, ok := toFsPath(winDir + `\` + name + `\` + chocolateyRegistryFile)
	if !ok {
		return
	}
	fi, err := fs.Stat(regPath)
	if err != nil || fi.IsDir() {
		return
	}
	data, err := readBounded(fs, regPath, fi.Size(), chocolateyMaxRegistryBytes)
	if err != nil {
		log.Debug().Err(err).Str("path", regPath).Msg("mql[packages]> could not read Chocolatey registry record")
		return
	}
	var reg chocolateyRegistry
	if err := xml.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &reg); err != nil {
		log.Debug().Err(err).Str("path", regPath).Msg("mql[packages]> could not parse Chocolatey registry record")
		return
	}

	var feed string
	if feedPath, ok := toFsPath(winDir + `\` + name + `\` + chocolateyFeedFile); ok {
		if ffi, err := fs.Stat(feedPath); err == nil && !ffi.IsDir() {
			if b, err := readBounded(fs, feedPath, ffi.Size(), chocolateyMaxFeedBytes); err == nil {
				// Chocolatey writes the feed with a UTF-8 byte order mark
				// and padding spaces
				feed = sanitizeRepoURL(string(bytes.TrimPrefix(b, utf8BOM)))
			}
		}
	}

	for _, k := range reg.Keys {
		keyPath := strings.TrimSpace(k.KeyPath)
		i := strings.LastIndex(keyPath, `\`)
		if i < 0 || i == len(keyPath)-1 {
			continue
		}
		scope, user := installScopeForRegistryPath(keyPath, strings.TrimSpace(reg.User))
		key := strings.ToLower(keyPath[i+1:])
		idx[key] = append(idx[key], chocolateyRecord{
			id:             m[1],
			version:        m[2],
			displayVersion: strings.TrimSpace(k.DisplayVersion),
			scope:          scope,
			user:           user,
			written:        fi.ModTime().Unix(),
			url:            feed,
		})
	}
}

// readBounded reads a whole file, refusing one over limit bytes.
func readBounded(fs afero.Fs, path string, size, limit int64) ([]byte, error) {
	if size > limit {
		return nil, io.ErrShortBuffer
	}
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}
