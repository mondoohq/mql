// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

// packageID computes mqlPackage's cache/identity key: format://name/version/arch,
// with "/user/<sid>" appended when installScope is "user". Two users can
// install the identical app version into their own profile; without the SID,
// the id would be the same for both, and the runtime resource cache
// (CreateResource keys on __id) would silently return the FIRST user's
// resource for the SECOND user's declaration. Machine-scope and non-Windows
// ids are unaffected, since the suffix is only appended for installScope ==
// "user".
//
// macOS application bundles also carry their bundle path, with "/path" and the
// path appended. A macOS package is a bundle on disk rather than a record in a
// package database, so two bundles can share a name and version: Siri.app and
// Siri AI.app both report "Siri" 1.0, and a game copied to the Desktop repeats
// the one in ~/Applications. Keyed on name and version alone, the second
// bundle got the first one's cached resource, so it listed as a duplicate row
// pointing at the first bundle's path and its own path was never reported.
//
// Shared by fillPackageArgs (list.go), which precomputes this and passes it
// as args["__id"] because it has the SID as a plain string; by the time this
// package's mqlPackage.id() method below could see it, that SID is reachable
// only through the lazy installUser() accessor and its private
// installUserSid backing field (see mqlPackageInternal), which is not
// populated until AFTER CreateResource returns -- too late to influence the
// id CreateResource caches under.
func packageID(format, name, version, arch, installScope, installUser string, files []packages.FileRecord) string {
	id := format + "://" + name + "/" + version + "/" + arch
	if installScope == "user" {
		id += "/user/" + installUser
	}
	if path := macosBundlePath(format, files); path != "" {
		id += "/path" + path
	}
	return id
}

// macosBundlePath returns the bundle path of a macOS application package: its
// one file record is the bundle itself. Empty for every other format, and for
// a macOS package that came without its file record.
func macosBundlePath(format string, files []packages.FileRecord) string {
	if format != packages.MacosPkgFormat || len(files) != 1 {
		return ""
	}
	return files[0].Path
}

// A system package cannot be installed twice but there are edge cases:
// - the same package name could be installed for multiple archs
// - linux-kernel package get extra treatment and can co-exist in multiple versions
// We use identifiers similar to grafeas artifact identifier for packages
// - deb://name/version/arch
// - rpm://name/version/arch
//
// Only reached when a caller creates a "package" resource without going
// through list()/fillPackageArgs (which always precomputes args["__id"] via
// packageID above and so skips this method entirely -- see createPackage's
// generated `if res.__id == ""` guard). Kept correct anyway for such callers
// (e.g. tool_package.go), though none of them produce a user-scope package
// today.
func (x *mqlPackage) id() (string, error) {
	return packageID(x.Format.Data, x.Name.Data, x.Version.Data, x.Arch.Data, x.InstallScope.Data, x.installUserSid, x.filesOnDisks), nil
}

type mqlPackageInternal struct {
	filesState   packages.PkgFilesAvailable
	filesOnDisks []packages.FileRecord

	// installUserSid is the raw SID installUser() resolves against the users
	// collection. Kept off the .lr schema deliberately (see os.lr:
	// installUser() user) -- a SID identifies the `user` resource, so it gets
	// a typed accessor rather than a raw string field; this is that
	// accessor's backing value, populated by list() from
	// packages.Package.InstallUser (which stays the source of truth for the
	// raw SID, see packages/packages.go). For a macOS application it holds
	// the account name instead, see installUser().
	installUserSid string

	// macosApp backs the macos() accessor. Nil for every package that is not
	// a macOS application bundle.
	macosApp *packages.MacOSApp
}

// initPackageMacos keeps `package.macos` from resolving on its own. The
// details belong to one package, so the dotted form has nothing to delegate
// to; without this it would report null for every field, which reads like an
// application that is neither signed nor from the App Store.
func initPackageMacos(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	return nil, nil, errors.New("package.macos belongs to a package and cannot be queried on its own, read the macos field of a package instead")
}

// macos returns the macOS application details of a macOS application bundle,
// and null for every other package.
func (x *mqlPackage) macos() (*mqlPackageMacos, error) {
	app := x.macosApp
	if app == nil {
		x.Macos.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(x.MqlRuntime, ResourcePackageMacos, map[string]*llx.RawData{
		"__id":     llx.StringData(x.__id + "/macos"),
		"bundleId": llx.StringData(app.BundleID),
		"signer":   llx.StringData(app.Signer),
		"teamId":   llx.StringData(app.TeamID),
		"appStore": llx.BoolData(app.AppStore),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPackageMacos), nil
}

// installUser resolves the SID that reported this package (installScope ==
// "user") to a local user account, or on macOS the account name whose home
// directory holds the application bundle. Matched on SID only -- the same
// precedent as windows.logonSession.user (windows_logonsession.go): an
// account name is not unique across a machine and the domains it trusts.
// Null when installUserSid is empty (machine-scope, or a backend with no
// per-user concept) or when no current user matches it (a deleted profile).
//
// Resolution goes through the cached users collection rather than a lookup
// per package, since `user` declares no init and a per-package lookup would
// turn one enumeration into one per package.
func (x *mqlPackage) installUser() (*mqlUser, error) {
	sid := x.installUserSid
	if sid == "" {
		x.InstallUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	obj, err := CreateResource(x.MqlRuntime, "users", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	users := obj.(*mqlUsers)

	list := users.GetList()
	if list.Error != nil {
		return nil, list.Error
	}

	// A macOS bundle is attributed to the home directory it is in, so its
	// backing value is an account name rather than a SID; macOS accounts
	// carry no SID to match on.
	byName := x.Format.Data == packages.MacosPkgFormat
	for _, entry := range list.Data {
		usr, ok := entry.(*mqlUser)
		if !ok {
			continue
		}
		if byName && usr.Name.Data == sid {
			return usr, nil
		}
		if !byName && usr.Sid.Data == sid {
			return usr, nil
		}
	}

	// No current user has this SID -- most commonly a deleted profile. The
	// state has to be set explicitly, or the runtime does not know the field
	// resolved and may re-fetch it.
	x.InstallUser.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// TODO: this is not accurate enough, we need to tie it to the package
func (x *mqlPkgFileInfo) id() (string, error) {
	return x.Path.Data, nil
}

func initPackage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// we only look up the package, if we have been supplied by its name and nothing else
	raw, ok := args["name"]
	if !ok || len(args) != 1 {
		return args, nil, nil
	}
	name := raw.Value.(string)

	pkgs, err := CreateResource(runtime, "packages", nil)
	if err != nil {
		return nil, nil, multierr.Wrap(err, "cannot get list of packages")
	}
	packages := pkgs.(*mqlPackages)

	if err = packages.refreshCache(nil); err != nil {
		return nil, nil, err
	}

	if res, ok := packages.packagesByName[name]; ok {
		return nil, res, nil
	}

	res := &mqlPackage{}
	res.MqlRuntime = runtime
	res.Name = plugin.TValue[string]{Data: name, State: plugin.StateIsSet}
	res.Installed = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Outdated = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	// A package that is not installed is not held at a version either. Like
	// installed and outdated above, this is a concrete false rather than null:
	// there is nothing unknown about it.
	res.Pinned = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Version.State = plugin.StateIsSet | plugin.StateIsNull
	res.Epoch.State = plugin.StateIsSet | plugin.StateIsNull
	res.Available.State = plugin.StateIsSet | plugin.StateIsNull
	res.Description.State = plugin.StateIsSet | plugin.StateIsNull
	res.Purl.State = plugin.StateIsSet | plugin.StateIsNull
	res.Cpes.State = plugin.StateIsSet | plugin.StateIsNull
	res.Arch.State = plugin.StateIsSet | plugin.StateIsNull
	res.Format.State = plugin.StateIsSet | plugin.StateIsNull
	res.Origin.State = plugin.StateIsSet | plugin.StateIsNull
	res.Status.State = plugin.StateIsSet | plugin.StateIsNull
	res.Files.State = plugin.StateIsSet | plugin.StateIsNull
	res.License.State = plugin.StateIsSet | plugin.StateIsNull
	res.InstallDate.State = plugin.StateIsSet | plugin.StateIsNull
	res.Macos.State = plugin.StateIsSet | plugin.StateIsNull
	res.__id, _ = res.id()
	return nil, res, nil
}

func (p *mqlPackage) status() (string, error) {
	return "", nil
}

func (p *mqlPackage) outdated() (bool, error) {
	if len(p.Available.Data) > 0 {
		return true, nil
	}
	return false, nil
}

func (p *mqlPackage) origin() (string, error) {
	return "", nil
}

// license is the lazy fallback for package managers that don't surface
// license inline. Used today for dpkg, which keeps license metadata in
// the per-package copyright file rather than in /var/lib/dpkg/status.
// Other managers populate License eagerly during list() and never reach
// this method (see plugin.GetOrCompute wrapper in the generated code).
func (p *mqlPackage) license() (string, error) {
	if p.Format.Data != packages.DpkgPkgFormat || p.Name.Data == "" {
		return "", nil
	}
	conn, ok := p.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return "", nil
	}
	return packages.ParseDpkgCopyrightLicense(conn.FileSystem(), p.Name.Data), nil
}

func (p *mqlPackage) files() ([]any, error) {
	if p.filesState == packages.PkgFilesNotAvailable {
		return nil, nil
	}

	var filesOnDisk []packages.FileRecord

	if p.filesState == packages.PkgFilesIncluded {
		// we already have the data
		filesOnDisk = p.filesOnDisks
	} else {
		// we need to retrieve the data on-demand
		conn := p.MqlRuntime.Connection.(shared.Connection)
		pms, err := packages.ResolveSystemPkgManagers(conn)
		if len(pms) == 0 || err != nil {
			return nil, errors.New("could not detect suitable package manager for platform")
		}
		filesOnDisk = []packages.FileRecord{}
		for _, pm := range pms {
			filesOD, err := pm.Files(p.Name.Data, p.Version.Data, p.Arch.Data)
			if err != nil {
				return nil, err
			}
			filesOnDisk = append(filesOnDisk, filesOD...)
		}
	}

	var pkgFiles []any
	for _, file := range filesOnDisk {
		pkgFile, err := CreateResource(p.MqlRuntime, "pkgFileInfo", map[string]*llx.RawData{
			"path": llx.StringData(file.Path),
		})
		if err != nil {
			return nil, err
		}
		pkgFiles = append(pkgFiles, pkgFile)
	}
	return pkgFiles, nil
}

type mqlPackagesInternal struct {
	lock           sync.Mutex
	packagesByName map[string]*mqlPackage
}

// fillPackageArgs resets args and fills in the resource arguments for one
// package. It clears the map itself rather than expecting a fresh one, so
// list() can reuse a single map for the whole package list: CreateResource
// copies every value out via SetAllData and keeps no reference to it.
//
// The clear is load bearing. license is only set when the backend reported
// one, so a leftover key would hand one package's license to the next.
func fillPackageArgs(args map[string]*llx.RawData, osPkg *packages.Package, available string, cpes []any) {
	clear(args)

	args["name"] = llx.StringData(osPkg.Name)
	args["version"] = llx.StringData(osPkg.Version)
	args["available"] = llx.StringData(available)
	args["arch"] = llx.StringData(osPkg.Arch)
	args["status"] = llx.StringData(osPkg.Status)
	args["pinned"] = llx.BoolData(osPkg.Pinned)
	args["description"] = llx.StringData(osPkg.Description)
	args["format"] = llx.StringData(osPkg.Format)
	args["installed"] = llx.BoolData(true)
	args["origin"] = llx.StringData(osPkg.Origin)
	args["epoch"] = llx.StringData(osPkg.Epoch)
	args["purl"] = llx.StringData(osPkg.PUrl)
	args["cpes"] = llx.ArrayData(cpes, types.Resource("cpe"))
	args["vendor"] = llx.StringData(osPkg.Vendor)
	args["installScope"] = llx.StringData(osPkg.InstallScope)
	// installUser is a lazy user accessor (os.lr), not a settable raw field --
	// there is no args["installUser"] to fill. The raw SID a backend reported
	// (osPkg.InstallUser) is threaded through separately, as __id (below, so
	// two users' identical app version get distinct resources -- see
	// packageID) and as mqlPackageInternal.installUserSid (set by list() on
	// the resource this call builds, since that field cannot be reached via
	// args at all).
	args["__id"] = llx.StringData(packageID(osPkg.Format, osPkg.Name, osPkg.Version, osPkg.Arch, osPkg.InstallScope, osPkg.InstallUser, osPkg.Files))

	// Only eagerly set license when the backend populated it (rpm, apk,
	// pacman). dpkg leaves it empty here so the lazy `license()` method on
	// mqlPackage can fire and read /usr/share/doc/<pkg>/copyright on demand.
	// Setting "" here would short-circuit the GetOrCompute wrapper and the
	// lazy fallback would never run.
	if osPkg.License != "" {
		args["license"] = llx.StringData(osPkg.License)
	}

	// Install date: explicit null via llx.NilData when the backend didn't
	// report one (dpkg / apk / pacman / macOS / rpm gpg-pubkey). The generated
	// dispatcher routes Nil through RawToTValue[time.Time] which yields
	// State=StateIsSet|StateIsNull — MQL surfaces that as a real null. Leaving
	// the key absent would leave the field in an entirely unset state and MQL
	// fails with "no type information." Passing TimeData(zero) would surface
	// the Go zero time (0001-01-01) as if it were a real install date.
	if osPkg.InstallDate.IsZero() {
		args["installDate"] = llx.NilData
	} else {
		args["installDate"] = llx.TimeData(osPkg.InstallDate)
	}
}

func (x *mqlPackages) list() ([]any, error) {
	x.lock.Lock()
	defer x.lock.Unlock()

	conn := x.MqlRuntime.Connection.(shared.Connection)
	pms, err := packages.ResolveSystemPkgManagers(conn)
	if len(pms) == 0 || err != nil {
		return nil, errors.New("could not detect suitable package manager for platform")
	}

	for _, pm := range pms {
		if winPm, ok := pm.(*packages.WinPkgManager); ok {
			injectWindowsHotfixes(x.MqlRuntime, winPm)
		}
	}

	osPkgs := []packages.Package{}
	osAvailablePkgs := map[string]packages.PackageUpdate{}
	for _, pm := range pms {
		// retrieve all system packages
		pkgs, err := pm.List()
		if err != nil {
			return nil, multierr.Wrap(err, "could not retrieve package list for platform")
		}
		osPkgs = append(osPkgs, pkgs...)

		// TODO: do we really need to make this a blocking call, we could update available updates async
		// we try to retrieve the available updates
		available, err := pm.Available()
		if err != nil {
			log.Debug().Err(err).Msg("mql[packages]> could not retrieve available updates")
			available = map[string]packages.PackageUpdate{}
		}
		for k, v := range available {
			osAvailablePkgs[k] = v
		}
	}

	// make available updates easily findable
	// we use packagename-arch as identifier
	availableMap := make(map[string]packages.PackageUpdate)
	for _, a := range osAvailablePkgs {
		availableMap[a.Name+"/"+a.Arch] = a
	}

	// create MQL package os for each package
	pkgs := make([]any, len(osPkgs))

	// CreateResource copies every value out of this map (SetAllData) and keeps
	// no reference to it, so one map serves the whole loop. clear() empties it
	// while keeping the buckets, which matters because a package-heavy host
	// would otherwise build and discard thousands of 15-entry maps.
	pkgArgs := make(map[string]*llx.RawData, 15)

	for i, osPkg := range osPkgs {
		// check if we found a newer version
		available := ""
		update, ok := availableMap[osPkg.Name+"/"+osPkg.Arch]
		if ok {
			available = update.Available
			log.Debug().Str("package", osPkg.Name).Str("available", update.Available).Msg("mql[packages]> found newer version")
		}

		cpes := []any{}
		for _, osPkgCpe := range osPkg.CPEs {
			cpe, err := x.MqlRuntime.CreateSharedResource("cpe", map[string]*llx.RawData{
				"uri": llx.StringData(osPkgCpe),
			})
			if err != nil {
				return nil, err
			}
			cpes = append(cpes, cpe)
		}

		fillPackageArgs(pkgArgs, &osPkg, available, cpes)

		pkg, err := CreateResource(x.MqlRuntime, "package", pkgArgs)
		if err != nil {
			return nil, err
		}

		s := pkg.(*mqlPackage)
		s.filesState = osPkg.FilesAvailable
		s.filesOnDisks = osPkg.Files
		// installUser() (the lazy user accessor) resolves against this SID.
		// Not reachable via args (see fillPackageArgs), so it is set directly
		// here, same as filesState/filesOnDisks above.
		s.installUserSid = osPkg.InstallUser
		s.macosApp = osPkg.MacOS
		pkgs[i] = s
	}

	return pkgs, x.refreshCache(pkgs)
}

// injectWindowsHotfixes shares Get-HotFix's outcome between packages.list and
// windows.hotfixes through MQL's own per-runtime resource/field cache
// (NewResource's runtime.Resources lookup plus GetHotfixes' plugin.GetOrCompute
// memoization) instead of a bespoke connection-scoped cache: resolving both
// in one scan runs Get-HotFix once instead of twice.
//
// Leaves pm to run its own query (WinPkgManager.List's lenient direct path)
// in either case where there is nothing safe to inject:
//   - GetHotfixes() errored. windows.hotfixes treats a non-zero Get-HotFix
//     exit as an error; packages.list must not inherit that and fail the
//     whole package inventory over a single broken QFE entry.
//   - The raw slice was never populated by THIS runtime (rawHotfixes's
//     second return is false). GetHotfixes()'s field can be answered from a
//     recording without hotfixes() ever running (see createWindows), and an
//     unpopulated slice must not be mistaken for "this host has zero
//     hotfixes".
func injectWindowsHotfixes(runtime *plugin.Runtime, pm *packages.WinPkgManager) {
	obj, err := NewResource(runtime, "windows", nil)
	if err != nil {
		return
	}
	winResource, ok := obj.(*mqlWindows)
	if !ok {
		return
	}

	if hotfixes := winResource.GetHotfixes(); hotfixes.Error != nil {
		return
	}

	raw, ok := winResource.rawHotfixes()
	if !ok {
		return
	}
	pm.SetHotfixes(raw)
}

func (x *mqlPackages) refreshCache(all []any) error {
	if all == nil {
		raw := x.GetList()
		if raw.Error != nil {
			return raw.Error
		}
		all = raw.Data
	}

	x.packagesByName = map[string]*mqlPackage{}

	for i := range all {
		u := all[i].(*mqlPackage)
		x.packagesByName[u.Name.Data] = u
	}

	return nil
}
