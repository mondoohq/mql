// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/parsers"
	"go.mondoo.com/mql/providers/os/resources/purl"
	plist "howett.net/plist"
)

const (
	MacosPkgFormat = "macos"
)

type sysProfilerItem struct {
	Name    string `plist:"_name"`
	Version string `plist:"version"`
	Path    string `plist:"path"`
	// Where the bundle came from, as classified by Gatekeeper:
	// "apple" (shipped with the OS), "mac_app_store", "ios_app_store"
	// (an iPhone/iPad app running on Apple Silicon),
	// "identified_developer" (signed with a Developer ID), or "unknown".
	// Surfaced as the package origin — see the assignment in
	// ParseMacOSPackages for why.
	ObtainedFrom string `plist:"obtained_from"`
}

type sysProfiler struct {
	Items []sysProfilerItem `plist:"_items"`
}

// infoPlist holds the keys we care about from an app bundle's
// Contents/Info.plist.
type infoPlist struct {
	ShortVersion  string `plist:"CFBundleShortVersionString"`
	BundleVersion string `plist:"CFBundleVersion"`
	BundleName    string `plist:"CFBundleName"`
	DisplayName   string `plist:"CFBundleDisplayName"`
}

// parse macos system version property list
func ParseMacOSPackages(conn shared.Connection, platform *inventory.Platform, input io.Reader) ([]Package, error) {
	var r io.ReadSeeker
	r, ok := input.(io.ReadSeeker)

	// if the read seaker is not implemented lets cache stdout in-memory
	if !ok {
		packageList, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		r = strings.NewReader(string(packageList))
	}

	var data []sysProfiler
	decoder := plist.NewDecoder(r)
	err := decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	if len(data) != 1 {
		return nil, errors.New("format not supported")
	}

	items := data[0].Items
	items = append(items, cryptexApplications(conn, items)...)

	pkgs := make([]Package, 0, len(items))
	for _, entry := range items {
		if !isApplicationBundlePath(entry.Path) {
			log.Debug().
				Str("name", entry.Name).
				Str("path", entry.Path).
				Msg("skipping entry that is not an installed application bundle")
			continue
		}

		// system_profiler only surfaces CFBundleShortVersionString as the
		// version. Some bundles (e.g. PWAs) ship a version only in
		// CFBundleVersion, so fall back to the bundle's Info.plist when
		// system_profiler reports no version, or a version we cannot use.
		version := entry.Version
		if !looksLikeVersion(version) {
			// Plenty of directories genuinely end in .app without being
			// applications: Firefox origin storage (https+++example.app),
			// app-group script containers (group.is.workflow.my.app) and bare
			// daemon directories all pass the path check above. An application
			// bundle always carries a Contents/Info.plist, so its absence means
			// this is not an installed application: drop the entry instead of
			// reporting it with a versionless purl that can never match
			// advisory data.
			//
			// Entries reporting a version we can use are never checked, because
			// some real applications have no Contents/Info.plist. Wrapped iOS
			// apps keep theirs under Wrapper/ and would otherwise be lost.
			bundleVersion, isBundle := bundleVersionFromInfoPlist(conn, entry.Path)
			if !isBundle {
				log.Debug().
					Str("name", entry.Name).
					Str("path", entry.Path).
					Msg("skipping entry that is not an application bundle")
				continue
			}
			// system_profiler reported something, and it was not a version.
			// CFBundleVersion is the one other place a version can come from,
			// so a bundle that fails both has no version to report under a name
			// that is reported as a product. Dropping it beats keeping it: the
			// string reaches Package.Version AND the purl, where it becomes an
			// identity no advisory bound can be compared against, sitting next
			// to the real product under the same name.
			if version != "" && !looksLikeVersion(bundleVersion) {
				log.Debug().
					Str("name", entry.Name).
					Str("path", entry.Path).
					Str("version", version).
					Msg("skipping entry whose reported version is not a version")
				continue
			}
			version = bundleVersion
		}

		// Whatever the version came from, it is about to become an identity in
		// two places, so take the padding off it first.
		version = normalizeVersion(version)

		// We need a special handling for Firefox to determine ESR installations
		purlQualifiers := getPurlQualifiers(conn, entry)

		pkg := Package{
			Name:    entry.Name,
			Version: version,
			// system_profiler is the only macOS source that says where a
			// bundle came from, and Origin is where the other backends already
			// put that: flatpak stores the remote it was installed from
			// ("flathub"), freebsd and netbsd store the ports origin path.
			// macOS left Origin empty until now, so this is purely additive.
			//
			// The value matters for remediation, not just inventory. An App
			// Store app cannot be upgraded by `brew upgrade` — the generated
			// script bails with "Package <name> is not installed by brew" — so
			// a consumer needs to be able to tell those installs apart before
			// choosing an update path.
			Origin:         entry.ObtainedFrom,
			Format:         MacosPkgFormat,
			FilesAvailable: PkgFilesIncluded,
			Arch:           platform.Arch,
			PUrl: purl.NewPackageURL(
				platform, purl.TypeMacos, entry.Name, version, purl.WithQualifiers(purlQualifiers),
			).String(),
		}
		if entry.Path != "" {
			pkg.Files = []FileRecord{
				{
					Path: entry.Path,
				},
			}
		}
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

// MacOS
type MacOSPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (mpm *MacOSPkgManager) Name() string {
	return "macOS Package Manager"
}

func (mpm *MacOSPkgManager) Format() string {
	return MacosPkgFormat
}

func (mpm *MacOSPkgManager) List() ([]Package, error) {
	cmd, err := mpm.conn.RunCommand("system_profiler SPApplicationsDataType -xml")
	if err != nil {
		return nil, fmt.Errorf("could not read package list")
	}

	return ParseMacOSPackages(mpm.conn, mpm.platform, cmd.Stdout)
}

func (mpm *MacOSPkgManager) Available() (map[string]PackageUpdate, error) {
	return nil, errors.New("cannot determine available packages for macOS")
}

func (mpm *MacOSPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	// nothing extra to be done here since the list is already included in the package list
	return nil, nil
}

// isApplicationBundlePath reports whether a path system_profiler listed is an
// application someone installed, as opposed to a directory that merely looks
// like a bundle or a helper that ships inside another application.
//
// system_profiler does not answer that question itself. It walks the
// filesystem, reports anything bundle-shaped it meets, and names each entry
// after the basename minus its final dot component. Two shapes come out of
// that, and both produce inventory rows that no upgrade can ever clear.
//
// A renamed bundle such as /Applications/Docker.app.back is still enumerated,
// under the name "Docker.app" and at whatever version was current when it was
// set aside. Reported as installed software it pins findings to a version that
// is not on the machine, and reinstalling the application does not touch the
// backup directory. An application bundle always ends in .app, so the
// extension of the final path segment settles it.
//
// Renaming also stops macOS treating the directory as one opaque bundle, so
// every helper bundle nested inside it gets walked and reported separately.
// Nested bundles are not separately installed in any case: an XPC service
// under a framework's Contents/, Finder's Contents/Applications/AirDrop.app,
// and an application's own login-item helper all ship with, and are patched
// by, whatever contains them. A Contents directory anywhere above the bundle
// marks that containment.
//
// A third shape is a bundle sitting in a dependency or build cache, which is
// build input or build output rather than installed software. See
// dependencyCacheMarkers.
func isApplicationBundlePath(path string) bool {
	if path == "" {
		return false
	}

	path = filepath.Clean(path)

	// macOS filesystems are case-insensitive by default, so a bundle stored as
	// .APP is a working application and must not be dropped.
	if !strings.EqualFold(filepath.Ext(path), ".app") {
		return false
	}

	// The surrounding separators make this a whole-segment match: a directory
	// named "Contents" matches, one named "TableOfContents" does not.
	if strings.Contains(path, "/Contents/") {
		return false
	}

	// macOS path comparison is case-insensitive for the same reason the
	// extension check above is.
	lower := strings.ToLower(path)
	for _, marker := range dependencyCacheMarkers {
		if strings.Contains(lower, marker) {
			return false
		}
	}

	return true
}

// dependencyCacheMarkers are whole-segment path markers for caches that hold
// dependencies and build products. Nothing under them is installed software:
// the contents are read-only artifacts that no upgrade path touches, and they
// are recreated on demand from a manifest.
//
// Matching is by path rather than by version, because the placeholder version
// is incidental. A vendored bundle carrying a real version would be just as
// wrong to report, and it would be indistinguishable from an install by any
// version-based rule.
//
// Each marker is the invariant part of the cache layout rather than its
// default location, so a relocated cache is still recognized: the Go module
// cache is $GOMODCACHE, which defaults to $GOPATH/pkg/mod but follows GOPATH
// wherever it points.
//
// Markers must be ASCII and lowercase. They are compared against a lowercased
// path, so an uppercase letter in a marker silently never matches: writing
// "/DerivedData/" here would disable the entry rather than fail loudly.
var dependencyCacheMarkers = []string{
	// Go module cache. github.com/ollama/ollama vendors a prebuilt
	// app/darwin/Ollama.app, so every host that has fetched the module reports
	// a phantom Ollama install once per cached module version.
	"/pkg/mod/",
	// npm and yarn dependency trees, which is where an Electron app keeps the
	// framework bundle it is built against.
	"/node_modules/",
	// Xcode build products, which are rebuilt from source and are not the
	// copy a user launches even when the project builds a real application.
	"/deriveddata/",
}

// versionShape matches a string that opens with a version number, optionally
// behind the single leading "v" some vendors ship (Raspberry Pi Imager reports
// "v2.0.6"). It deliberately anchors only the start: real
// CFBundleShortVersionString values carry all kinds of trailing decoration
// ("1.0 (1234)", "3.2 beta 4"), and that decoration never stops the leading
// number from being the version.
var versionShape = regexp.MustCompile(`^v?\d`)

// looksLikeVersion reports whether a string can be used as a package version.
//
// The check exists because system_profiler enumerates whatever Launch Services
// has registered, which is not limited to software installed on this Mac. A
// hypervisor's guest-application launcher (Parallels Coherence, VMware Unity)
// registers a stub bundle per guest application, under the guest
// application's own display name, and those stubs have been seen carrying the
// name of the guest OS where a version belongs -- a "Google Chrome" package
// at version "Windows 11". The browser that string names is installed in the
// virtual machine, which is scanned as its own asset.
//
// Nothing downstream can recover from that: the string lands in
// Package.Version and, verbatim, in the purl, so the stub takes an identity
// that looks like the product and compares against no advisory bound.
//
// The rule is a shape rule rather than a parse, because a parse is the wrong
// instrument here. versionx.Parse accepts every string by design, and a strict
// semver parse would reject real Mac versions ("1.0 (1234)") while accepting
// the packed and wrong values this cannot see anyway. Requiring the version to
// begin with a number is what separates a version from a sentence, and it is
// the only distinction available without reading each bundle's identifier.
//
// Measured against a stock developer Mac with 331 registered applications: one
// version in the set does not begin with a digit ("v2.0.6"), which the leading
// "v" covers, and nothing else is rejected.
func looksLikeVersion(version string) bool {
	return versionShape.MatchString(version)
}

// versionPaddedSeparators matches a version built only from numeric components
// and dot separators, where the separators carry whitespace padding. Adobe ships
// the Acrobat updater that way: CFBundleShortVersionString is literally
// "1 . 2 . 6", and system_profiler reports it verbatim.
//
// The pattern is deliberately narrow, because whitespace in a
// CFBundleShortVersionString is usually load-bearing and has to survive. Real
// values pair a version with a build number or a channel ("7.1.5 (84650)",
// "Build 2079", "Version 2.0", "EAP GO-262.6228.35"), and collapsing the space
// in those would fuse two separate fields into one token. Anchoring the whole
// string to digits, dots and padding keeps this to the case where the padding is
// the only thing wrong with the value.
var versionPaddedSeparators = regexp.MustCompile(`^\d+(?:[ \t]*\.[ \t]*\d+)+$`)

// normalizeVersion removes the padding from a version whose dot separators are
// padded with whitespace, and returns every other version unchanged.
//
// This is worth doing because the version is an identity here, not a label. It
// is copied into Package.Version and into the purl, and percent-encoding turns
// "1 . 2 . 6" into "1%20.%202%20.%206" -- a string that compares against no
// advisory bound, for a product whose actual version is perfectly ordinary. A
// consumer cannot repair it either, since by then the padding is indistinguishable
// from a vendor that really does put spaces in its versions.
func normalizeVersion(version string) string {
	if !versionPaddedSeparators.MatchString(version) {
		return version
	}
	// The pattern admits only digits, dots and padding, so dropping every run
	// of whitespace leaves the version and nothing else.
	return strings.Join(strings.Fields(version), "")
}

// bundleVersionFromInfoPlist recovers an app's version from its
// Contents/Info.plist when system_profiler did not report one. It prefers
// CFBundleShortVersionString (the user-facing version) and falls back to
// CFBundleVersion (the build version).
//
// The second return value reports whether the path is an application bundle at
// all, which is true whenever a Contents/Info.plist could be read. Callers use
// it to tell a real application that simply carries no version (some Apple
// CoreServices apps ship neither version key) from a directory that merely has
// a bundle-like extension.
func bundleVersionFromInfoPlist(conn shared.Connection, path string) (string, bool) {
	info, isBundle := readInfoPlist(conn, path)
	if info.ShortVersion != "" {
		return info.ShortVersion, isBundle
	}
	return info.BundleVersion, isBundle
}

// readInfoPlist reads an app bundle's Contents/Info.plist. The second return
// value reports whether the file could be read at all, which is what makes a
// path an application bundle; a plist that fails to parse still counts.
func readInfoPlist(conn shared.Connection, path string) (infoPlist, bool) {
	var info infoPlist
	if path == "" {
		return info, false
	}

	infoPath := filepath.Join(path, "Contents", "Info.plist")
	f, err := conn.FileSystem().Open(infoPath)
	if err != nil {
		log.Debug().Err(err).Str("path", infoPath).Msg("could not open Info.plist")
		return info, false
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		log.Debug().Err(err).Str("path", infoPath).Msg("could not read Info.plist")
		return info, false
	}

	// The Info.plist is there, so this is a bundle even if we cannot read a
	// version out of it.
	if _, err := plist.Unmarshal(content, &info); err != nil {
		log.Debug().Err(err).Str("path", infoPath).Msg("could not parse Info.plist")
		return infoPlist{}, true
	}
	return info, true
}

// cryptexRoot is where macOS 13 and later mount its cryptexes, the sealed
// images that let Apple patch parts of the OS outside a full OS update. Each
// subdirectory is one cryptex ("App", "OS", ...) laid out like the system
// volume.
const cryptexRoot = "/System/Cryptexes"

// cryptexPrebootRoot is the Preboot volume location the same cryptexes are
// reachable under.
const cryptexPrebootRoot = "/System/Volumes/Preboot/Cryptexes"

// cryptexApplicationDirs are the directories inside a cryptex that hold
// application bundles, the same ones system_profiler walks on the system
// volume.
var cryptexApplicationDirs = []string{
	"System/Applications",
	"System/Library/CoreServices",
}

// cryptexApplications lists the application bundles that live on a cryptex.
//
// system_profiler does not report them. Safari moved into the App cryptex so
// it can be patched through Rapid Security Responses, and /Applications only
// carries a symlink to it, so a host with Safari installed reports no Safari
// at all. Anything else Apple ships in a cryptex drops out the same way.
//
// Each bundle is returned in system_profiler's shape so it goes through the
// same checks as every other entry. A bundle is skipped when system_profiler
// already reported it under one of the paths it is reachable at, so a macOS
// release that starts reporting cryptex bundles does not double them.
func cryptexApplications(conn shared.Connection, reported []sysProfilerItem) []sysProfilerItem {
	if conn == nil {
		return nil
	}
	fs := conn.FileSystem()

	cryptexes, err := readDirNames(fs, cryptexRoot)
	if err != nil {
		log.Debug().Err(err).Str("path", cryptexRoot).Msg("no cryptexes to scan for applications")
		return nil
	}

	seen := make(map[string]struct{}, len(reported))
	for _, entry := range reported {
		if entry.Path != "" {
			seen[filepath.Clean(entry.Path)] = struct{}{}
		}
	}

	var items []sysProfilerItem
	for _, cryptex := range cryptexes {
		for _, dir := range cryptexApplicationDirs {
			base := filepath.Join(cryptexRoot, cryptex, dir)
			names, err := readDirNames(fs, base)
			if err != nil {
				continue
			}
			for _, name := range names {
				if !strings.EqualFold(filepath.Ext(name), ".app") {
					continue
				}
				rel := filepath.Join(dir, name)
				if isReportedCryptexBundle(seen, cryptex, rel) {
					continue
				}

				path := filepath.Join(base, name)
				info, isBundle := readInfoPlist(conn, path)
				if !isBundle {
					continue
				}
				version := info.ShortVersion
				if version == "" {
					version = info.BundleVersion
				}
				items = append(items, sysProfilerItem{
					Name:    cryptexBundleName(info, name),
					Version: version,
					Path:    path,
					// Only Apple can sign a cryptex.
					ObtainedFrom: "apple",
				})
			}
		}
	}
	return items
}

// isReportedCryptexBundle reports whether system_profiler already listed the
// cryptex bundle at rel (relative to its cryptex) under any path it can be
// reached at: the cryptex mount, the Preboot volume, the system volume path it
// is firmlinked to, or the /Applications symlink for applications.
func isReportedCryptexBundle(seen map[string]struct{}, cryptex, rel string) bool {
	aliases := []string{
		filepath.Join(cryptexRoot, cryptex, rel),
		filepath.Join(cryptexPrebootRoot, cryptex, rel),
		filepath.Join("/", rel),
	}
	if app, ok := strings.CutPrefix(rel, "System/Applications/"); ok {
		aliases = append(aliases, filepath.Join("/Applications", app))
	}
	for _, alias := range aliases {
		if _, ok := seen[alias]; ok {
			return true
		}
	}
	return false
}

// cryptexBundleName names a bundle the way system_profiler does: its display
// name, then its bundle name, then the directory name without .app.
func cryptexBundleName(info infoPlist, dirName string) string {
	if info.DisplayName != "" {
		return info.DisplayName
	}
	if info.BundleName != "" {
		return info.BundleName
	}
	return strings.TrimSuffix(dirName, filepath.Ext(dirName))
}

func readDirNames(fs afero.Fs, dir string) ([]string, error) {
	f, err := fs.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func getPurlQualifiers(conn shared.Connection, entry sysProfilerItem) map[string]string {
	qualifiers := make(map[string]string)
	if entry.Name == "Firefox" {
		appIni := ""
		if entry.Path != "" {
			appIni = filepath.Join(entry.Path, "Contents", "Resources", "application.ini")
		}
		if appIni != "" {
			f, err := conn.FileSystem().Open(appIni)
			if err != nil {
				log.Debug().Err(err).Msg("could not open application.ini")
				return nil
			}
			defer f.Close()
			content, err := io.ReadAll(f)
			if err != nil {
				log.Debug().Err(err).Msg("could not read application.ini")
				return nil
			}
			ini := parsers.ParseIni(string(content), "=")
			if ini != nil {
				if data, ok := ini.Fields["App"]; ok {
					fields, ok := data.(map[string]any)
					if ok {
						if name, ok := fields["RemotingName"]; ok {
							qualifiers["remoting-name"] = name.(string)
						}
					}
				}
			}
		}
	}
	return qualifiers
}
