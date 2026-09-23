// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/kernel"
)

func initKernel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// this resource is only supported on linux
	conn := runtime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	supported := platform.IsFamily("linux") || platform.IsFamily("darwin") || platform.IsFamily("bsd") || platform.Name == "aix"
	if !supported {
		return nil, nil, errors.New("kernel resource is only supported on linux, darwin, bsd, and aix platforms")
	}

	return args, nil, nil
}

type mqlKernelInternal struct {
	moduleByName map[string]*mqlKernelModule
	lock         sync.Mutex

	// modprobe-rule cache. Populated lazily on first access via
	// loadModprobeRules so the modprobe.d walk happens once per query
	// regardless of how many kernel.module accessors consult it.
	modprobeOnce  sync.Once
	modprobeRules map[string]modprobeRule
	modprobeErr   error

	// module-index cache. modules.dep (loadable .ko files) and
	// modules.builtin (features compiled into the kernel) for the running
	// kernel are read once per query via loadModuleIndex, so every
	// kernel.module.onDisk / .builtIn accessor shares a single read of
	// those two index files.
	moduleIndexOnce sync.Once
	moduleOnDisk    map[string]bool
	moduleBuiltIn   map[string]bool
	moduleIndexErr  error
}

type KernelVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Running bool   `json:"running"`
}

// stripRPMEpoch removes a leading "<epoch>:" prefix from an RPM package
// version string. /proc/version (and the rest of kernel.info) never carries
// the epoch, so it must be stripped before comparing a package version to
// the running kernel version. providers/os/resources/packages/rpm_packages.go
// concatenates a non-zero / non-"(none)" epoch into pkg.Version, so this
// matters whenever the underlying kernel rpm declares an Epoch.
func stripRPMEpoch(version string) string {
	if idx := strings.IndexByte(version, ':'); idx >= 0 {
		return version[idx+1:]
	}
	return version
}

// rpmKernelMatchesRunning reports whether the given RPM kernel package
// describes the currently running kernel, identified by the value
// /proc/version reports (e.g. "6.1.170-210.320.amzn2023.x86_64").
//
// AL2023's `kernel` package has epoch 1, so without stripRPMEpoch the bug
// is reproducible there for every installed kernel image (the entire list
// reports running:false). Same shape would hit any future RHEL / Oracle
// kernel that gains an epoch.
func rpmKernelMatchesRunning(pkgVersion, pkgArch, runningKernelVersion string) bool {
	return stripRPMEpoch(pkgVersion)+"."+pkgArch == runningKernelVersion
}

// photonKernelMatchesRunning reports whether the given Photon kernel
// package describes the currently running kernel. Photon's flavor lives
// in the package name suffix (e.g. "linux" → bare kernel, "linux-esx" →
// VMware-targeted) and the running-kernel string from /proc/version is
// version + "-flavor" — e.g. "4.19.97-1.ph3-esx". Mirrors
// rpmKernelMatchesRunning by stripping any leading epoch from the package
// version before joining.
func photonKernelMatchesRunning(pkgVersion, pkgName, runningKernelVersion string) bool {
	return stripRPMEpoch(pkgVersion)+strings.TrimPrefix(pkgName, "linux") == runningKernelVersion
}

// suseKernelMatchesRunning reports whether the given SUSE kernel package
// describes the currently running kernel.
//
// SUSE's running-kernel string from /proc/version looks like
// "4.12.14-122.23-default" — version + "-flavor". The package version is a
// slightly longer "4.12.14-122.23.1-default" (one extra dpkg-release
// segment), so the match uses HasSuffix on the flavor + HasPrefix on the
// trimmed running version against the package version. stripRPMEpoch
// keeps the HasPrefix check working if a SUSE kernel rpm ever declares an
// epoch (none do today, but the algebra is identical).
func suseKernelMatchesRunning(pkgVersion, pkgName, runningKernelVersion string) bool {
	kernelType := strings.TrimPrefix(pkgName, "kernel")
	if !strings.HasSuffix(runningKernelVersion, kernelType) {
		return false
	}
	versionPrefix := strings.TrimSuffix(runningKernelVersion, kernelType)
	return strings.HasPrefix(stripRPMEpoch(pkgVersion), versionPrefix)
}

// suseKernelName reports the flavor a SUSE kernel package carries, and whether
// the package holds a bootable kernel at all.
//
// SUSE names its bootable kernels "kernel-<flavor>" (kernel-default,
// kernel-azure, kernel-rt, kernel-kvmsmall), plus the stripped
// "kernel-<flavor>-base" variant that MicroOS boots. Everything else shipped
// under the kernel- prefix is a subpackage that contains no kernel:
// kernel-firmware-*, kernel-devel, kernel-macros, kernel-source, kernel-syms,
// kernel-docs, kernel-install-tools, kernel-obs-build, kernel-livepatch-*, and
// the per-flavor -devel/-extra/-optional/-vdso builds.
//
// Listing those invents installed kernels that are not on disk, and their
// versions are unrelated to any kernel release: a stock host with
// kernel-firmware-network and kernel-macros installed reported three
// "installed kernels", one of them at a higher version than the running one,
// which reads as a pending kernel upgrade that does not exist.
//
// A bootable name is therefore one flavor segment, optionally followed by
// "-base", and the flavor is not one of the subpackage words. A flavor SUSE
// adds later still resolves; a subpackage never does.
func suseKernelName(pkgName string) (string, bool) {
	flavor, ok := strings.CutPrefix(pkgName, "kernel-")
	if !ok || flavor == "" {
		return "", false
	}

	// kernel-default-base is bootable; kernel-default-devel and
	// kernel-firmware-network are not.
	flavor = strings.TrimSuffix(flavor, "-base")
	if strings.Contains(flavor, "-") {
		return "", false
	}

	if suseKernelSubpackages[flavor] {
		return "", false
	}

	return pkgName, true
}

// suseKernelSubpackages are the single-segment kernel-* packages that are not
// kernels. Multi-segment subpackages (kernel-firmware-network,
// kernel-obs-build, kernel-default-devel) are already excluded by shape.
// "base" only appears as a suffix on a real flavor (kernel-default-base); on
// its own it is not a kernel.
var suseKernelSubpackages = map[string]bool{
	"base":     true,
	"devel":    true,
	"docs":     true,
	"firmware": true,
	"macros":   true,
	"source":   true,
	"syms":     true,
}

// debianImageKernelName reports the kernel release a linux-image package
// carries, and whether the package holds a kernel at all.
//
// Debian and Ubuntu ship a metapackage alongside the versioned images:
// linux-image-cloud-amd64 on Debian, linux-image-aws on Ubuntu. Its only job
// is to depend on the newest kernel, so it contains no kernel of its own and
// listing it invents an installed kernel named after the flavour ("aws",
// "cloud-amd64") that is not on disk.
//
// A real image package always names a release, and a release always starts
// with a digit. A flavour never does.
func debianImageKernelName(pkgName string) (string, bool) {
	name, ok := strings.CutPrefix(pkgName, "linux-image-")
	if !ok {
		return "", false
	}

	// Ubuntu ships the unsigned build as linux-image-unsigned-<release>, so the
	// release is not in front. Debian appends -unsigned instead, which leaves it
	// where we expect.
	name = strings.TrimPrefix(name, "unsigned-")

	if name == "" || name[0] < '0' || name[0] > '9' {
		return "", false
	}
	return name, true
}

// dpkgStatusIsInstalled reports whether a dpkg status triple describes a
// package whose files are actually on disk.
//
// The triple is "<want> <flag> <state>" and only the state answers this. A
// package that was removed but not purged keeps its entry in
// /var/lib/dpkg/status as
//
//	Status: deinstall ok config-files
//
// with its files already gone. The kernel such an entry names cannot be
// booted, so counting it inflates the installed set with a phantom and can
// fail a "the running kernel is the newest installed" assertion against a
// kernel that is not there. The want field is deliberately ignored: a held
// package ("hold ok installed") is still installed, and isHeldStatus in the
// packages package is what reads that position.
//
// An entry carrying no status at all is not evidence of removal. Google
// distroless images keep their dpkg metadata in /var/lib/dpkg/status.d
// stanzas that omit the Status field entirely, so an absent or unparseable
// triple is treated as unknown and kept rather than silently dropped.
func dpkgStatusIsInstalled(status string) bool {
	fields := strings.Fields(status)
	if len(fields) < 3 {
		return true
	}
	return fields[2] == "installed"
}

// archKernelPackages is the set of Arch Linux packages that carry a kernel.
//
// It is an explicit allowlist rather than a "linux" prefix match because
// Arch pairs every kernel with a headers package and ships other linux-
// prefixed packages that hold no kernel at all: linux-headers,
// linux-lts-headers, linux-api-headers and linux-firmware would all pass a
// prefix test and none of them is bootable.
var archKernelPackages = map[string]bool{
	"linux":          true, // mainline
	"linux-lts":      true, // long-term support
	"linux-zen":      true, // desktop-tuned
	"linux-hardened": true, // security-hardened
}

// foldArchVersionSeparators rewrites the separators in an Arch kernel
// version to one canonical form, so the pacman spelling and the uname
// spelling of the same kernel compare equal. See archKernelMatchesRunning.
func foldArchVersionSeparators(version string) string {
	return strings.ReplaceAll(version, ".", "-")
}

// archKernelMatchesRunning reports whether the given pacman kernel package
// describes the currently running kernel.
//
// pacman and uname disagree on one separator. The package version joins the
// upstream version to the Arch patch level with a dot, while the release
// uname reports joins them with a dash:
//
//	pacman: linux 7.1.9.arch1-2
//	uname:  7.1.9-arch1-2
//
// so a direct string comparison never matches and every entry in the list
// would report running:false. Folding both separators into one form removes
// the disagreement without having to know which of the two a given flavor
// spells it with.
//
// The flavor lives in the package name suffix and is appended to the
// release uname reports: linux-lts 6.6.67-1 runs as "6.6.67-1-lts".
// Trimming that suffix from the running version first (the shape
// suseKernelMatchesRunning uses) leaves the two version strings directly
// comparable. The bare "linux" package has an empty suffix, for which the
// trim is a no-op.
func archKernelMatchesRunning(pkgVersion, pkgName, runningKernelVersion string) bool {
	if runningKernelVersion == "" {
		return false
	}

	flavor := strings.TrimPrefix(pkgName, "linux")
	if !strings.HasSuffix(runningKernelVersion, flavor) {
		return false
	}
	running := strings.TrimSuffix(runningKernelVersion, flavor)

	return foldArchVersionSeparators(pkgVersion) == foldArchVersionSeparators(running)
}

// kernelPackage is the subset of an installed package the per-family kernel
// filters read. Lifting it out of *mqlPackage keeps every filter a pure
// function of values, which is what makes them testable without a runtime.
type kernelPackage struct {
	Name    string
	Version string
	Arch    string
	Status  string
}

// kernelFilter maps one installed package to the kernel it carries. The
// second return is false when the package is not a kernel (a -headers
// package, a Debian metapackage, anything unrelated) or when it names a
// kernel the host cannot boot (a dpkg entry removed but not purged).
type kernelFilter func(pkg kernelPackage, runningKernelVersion string) (KernelVersion, bool)

// debianKernelVersion reads a dpkg linux-image package.
//
// kernel version is "4.19.0-13-cloud-amd64", carried by packages named
// "linux-image-*":
//
//	[{
//		name: "linux-image-4.19.0-12-cloud-amd64"
//		version: "4.19.152-1"
//	}, {
//		name: "linux-image-4.19.0-13-cloud-amd64"
//		version: "4.19.160-2"
//	}, {
//		name: "linux-image-cloud-amd64"
//		version: "4.19+105+deb10u8"
//	}]
func debianKernelVersion(pkg kernelPackage, runningKernelVersion string) (KernelVersion, bool) {
	kernelName, ok := debianImageKernelName(pkg.Name)
	if !ok {
		return KernelVersion{}, false
	}

	// A removed-but-not-purged image package still has a linux-image-<release>
	// name in the dpkg database long after its files are gone.
	if !dpkgStatusIsInstalled(pkg.Status) {
		return KernelVersion{}, false
	}

	return KernelVersion{
		Name:    kernelName,
		Version: pkg.Version,
		Running: kernelName == runningKernelVersion,
	}, true
}

// oracleKernelVersion reads an Oracle Linux kernel package. Oracle is rpm
// based but might be running the UEK kernel, so both "kernel" and
// "kernel-uek" count. Kernel version is "6.12.0-105.51.5.el9uek.x86_64".
func oracleKernelVersion(pkg kernelPackage, runningKernelVersion string) (KernelVersion, bool) {
	if pkg.Name != "kernel" && pkg.Name != "kernel-uek" {
		return KernelVersion{}, false
	}

	return KernelVersion{
		Name:    pkg.Name,
		Version: pkg.Version,
		Running: rpmKernelMatchesRunning(pkg.Version, pkg.Arch, runningKernelVersion),
	}, true
}

// redhatKernelVersion reads an rpm kernel package.
//
// kernel version is "3.10.0-1160.11.1.el7.x86_64", carried by packages
// named "kernel":
//
//	[{
//		name: "kernel"
//		version: "3.10.0-1127.el7"
//	}, {
//		name: "kernel"
//		version: "3.10.0-1160.11.1.el7"
//	}, {
//		name: "kernel"
//		version: "3.10.0-1127.19.1.el7"
//	}]
func redhatKernelVersion(pkg kernelPackage, runningKernelVersion string) (KernelVersion, bool) {
	if pkg.Name != "kernel" {
		return KernelVersion{}, false
	}

	return KernelVersion{
		Name:    pkg.Name,
		Version: pkg.Version,
		Running: rpmKernelMatchesRunning(pkg.Version, pkg.Arch, runningKernelVersion),
	}, true
}

// photonKernelVersion reads a Photon kernel package, whose flavor lives in
// the package name suffix ("linux" bare, "linux-esx" for VMware).
func photonKernelVersion(pkg kernelPackage, runningKernelVersion string) (KernelVersion, bool) {
	if !strings.HasPrefix(pkg.Name, "linux") {
		return KernelVersion{}, false
	}

	return KernelVersion{
		Name:    pkg.Name,
		Version: pkg.Version + strings.TrimPrefix(pkg.Name, "linux"),
		Running: photonKernelMatchesRunning(pkg.Version, pkg.Name, runningKernelVersion),
	}, true
}

// suseKernelVersion reads a SUSE kernel package.
//
//	kernel.info[version] == "4.12.14-122.23-default"
//	rpm -qa | grep -i kernel
//	kernel-default-4.12.14-122.23.1.x86_64
//	kernel-firmware-20190618-5.14.1.noarch
//	kernel-default-4.12.14-122.60.1.x86_64
//	cat /proc/version
//	Linux version 4.12.14-122.23-default (geeko@buildhost)
func suseKernelVersion(pkg kernelPackage, runningKernelVersion string) (KernelVersion, bool) {
	name, ok := suseKernelName(pkg.Name)
	if !ok {
		return KernelVersion{}, false
	}

	return KernelVersion{
		Name:    name,
		Version: pkg.Version + strings.TrimPrefix(name, "kernel"),
		Running: suseKernelMatchesRunning(pkg.Version, name, runningKernelVersion),
	}, true
}

// archKernelVersion reads a pacman kernel package. The installed version
// reads "7.1.9.arch1-2" while uname reports "7.1.8-arch1-3", so the running
// comparison has to normalise the separator (archKernelMatchesRunning).
func archKernelVersion(pkg kernelPackage, runningKernelVersion string) (KernelVersion, bool) {
	if !archKernelPackages[pkg.Name] {
		return KernelVersion{}, false
	}

	return KernelVersion{
		Name:    pkg.Name,
		Version: pkg.Version,
		Running: archKernelMatchesRunning(pkg.Version, pkg.Name, runningKernelVersion),
	}, true
}

// alpineKernelPackages is the set of Alpine packages that carry a kernel.
//
// An allowlist, like archKernelPackages: every flavor ships a -dev package
// beside it, and linux-firmware-*, linux-headers and linux-pam are linux-
// prefixed without being bootable. linux-stable is in edge; linux-rpi2 and
// linux-rpi4 are the Raspberry Pi flavors of older releases.
var alpineKernelPackages = map[string]bool{
	"linux-lts":    true,
	"linux-virt":   true,
	"linux-edge":   true,
	"linux-stable": true,
	"linux-rpi":    true,
	"linux-rpi2":   true,
	"linux-rpi4":   true,
}

// alpineKernelVersion reads an apk kernel package.
//
//	apk list --installed
//	linux-lts-6.6.142-r0 aarch64 {linux-lts} (GPL-2.0-only) [installed]
//	linux-virt-6.6.142-r0 aarch64 {linux-lts} (GPL-2.0-only) [installed]
//	ls /lib/modules
//	6.6.142-0-lts
//	6.6.142-0-virt
func alpineKernelVersion(pkg kernelPackage, runningKernelVersion string) (KernelVersion, bool) {
	if !alpineKernelPackages[pkg.Name] {
		return KernelVersion{}, false
	}

	return KernelVersion{
		Name:    pkg.Name,
		Version: pkg.Version,
		Running: alpineKernelMatchesRunning(pkg.Version, pkg.Name, runningKernelVersion),
	}, true
}

// alpineKernelMatchesRunning reports whether the given apk kernel package
// describes the currently running kernel.
//
// apk and uname spell the same kernel differently. The package version ends
// in the apk revision "-r<N>", while the release uname reports carries that
// revision as a plain "-<N>" followed by the flavor, which is the package
// name without its "linux" prefix:
//
//	apk:   linux-lts 6.6.142-r0
//	uname: 6.6.142-0-lts
//
// The flavor is trimmed from the running release first (the shape
// archKernelMatchesRunning uses), and the apk revision is rewritten into the
// uname form, which leaves the two strings directly comparable.
func alpineKernelMatchesRunning(pkgVersion, pkgName, runningKernelVersion string) bool {
	if runningKernelVersion == "" {
		return false
	}

	flavor := strings.TrimPrefix(pkgName, "linux")
	if flavor == "" || !strings.HasSuffix(runningKernelVersion, flavor) {
		return false
	}
	running := strings.TrimSuffix(runningKernelVersion, flavor)

	i := strings.LastIndex(pkgVersion, "-r")
	if i < 0 {
		return false
	}
	return running == pkgVersion[:i]+"-"+pkgVersion[i+2:]
}

// kernelFilterForPlatform picks the filter that knows how this platform's
// package manager names and versions kernel packages. The second return is
// false when no filter covers the platform; kernelInstalledFilter decides
// what that means.
//
// The order matters and matches the order these families were originally
// dispatched in: Oracle Linux is checked before the redhat family it
// belongs to, because it may be running the UEK kernel.
func kernelFilterForPlatform(platform *inventory.Platform) (kernelFilter, bool) {
	switch {
	case platform == nil || !platform.IsFamily(inventory.FAMILY_LINUX):
		return nil, false
	case platform.IsFamily("debian"):
		return debianKernelVersion, true
	case platform.Name == "oraclelinux":
		return oracleKernelVersion, true
	case platform.IsFamily("redhat") || platform.Name == "amazonlinux":
		return redhatKernelVersion, true
	case platform.Name == "photon":
		return photonKernelVersion, true
	case platform.IsFamily("suse"):
		return suseKernelVersion, true
	case platform.IsFamily("arch"):
		return archKernelVersion, true
	case platform.Name == "alpine":
		return alpineKernelVersion, true
	default:
		return nil, false
	}
}

// kernelInstalledFilter resolves the filter for a platform and decides how
// installed() must answer when there is none. The three outcomes are
// deliberately distinct:
//
//   - a filter, no error: enumerate the kernel packages.
//   - no filter, an error: a Linux host whose package manager has no case
//     here. A Linux host is running a kernel and got it from a package
//     manager, so "no kernels installed" is never the truth. Answering with
//     an empty list would be indistinguishable from a verified-empty result,
//     and a policy asserting "the running kernel is the newest installed"
//     would evaluate over the empty set and pass without checking anything.
//     The error names the platform so the missing case can be added.
//   - no filter, no error: not Linux at all. darwin, bsd and aix reach
//     installed() because initKernel admits them for kernel.info, modules
//     and parameters, but a package-managed kernel image is not a thing that
//     exists there. That answer stays the empty list it has always been:
//     whether it should be null instead is a separate question about a
//     platform where the concept barely applies, and not one this dispatch
//     should decide.
func kernelInstalledFilter(platform *inventory.Platform) (kernelFilter, error) {
	if filter, ok := kernelFilterForPlatform(platform); ok {
		return filter, nil
	}

	if platform.IsFamily(inventory.FAMILY_LINUX) {
		return nil, errors.New("kernel.installed is not supported on platform " + platformLabel(platform))
	}

	return nil, nil
}

func (k *mqlKernel) installed() ([]any, error) {
	conn := k.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	// NixOS has no kernel package to filter for. It keeps whole system
	// generations, each with the kernel it boots, so the kernels it has
	// installed are read off those instead. The running version is a fallback
	// here: nixosInstalledKernels prefers the booted kernel's store path,
	// which is why an empty version from kernel.info is not fatal.
	if platform != nil && platform.Name == "nixos" {
		runningVersion, err := k.runningKernelVersion()
		if err != nil {
			return nil, err
		}

		kernels, err := nixosInstalledKernels(conn.FileSystem(), runningVersion)
		if err != nil {
			return nil, err
		}
		return convert.JsonToDictSlice(kernels)
	}

	filterKernel, err := kernelInstalledFilter(platform)
	if err != nil {
		return nil, err
	}
	if filterKernel == nil {
		// Not Linux: unchanged, and deliberately so. See kernelInstalledFilter.
		return convert.JsonToDictSlice([]KernelVersion{})
	}

	// 1. gather running kernel information
	info := k.GetInfo()
	if info.Error != nil {
		return nil, errors.New("could not determine kernel version")
	}

	kernelInfo, ok := info.Data.(map[string]any)
	if !ok {
		return nil, errors.New("no structured kernel information found")
	}

	runningKernelVersion, ok := kernelInfo["version"].(string)
	if !ok {
		return nil, errors.New("no running kernel version found")
	}

	// 2. get all packages
	raw, err := CreateResource(k.MqlRuntime, "packages", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	packages := raw.(*mqlPackages)

	tlist := packages.GetList()
	if tlist.Error != nil {
		return nil, tlist.Error
	}
	mqlPkgs := tlist.Data

	res := []KernelVersion{}
	for i := range mqlPkgs {
		pkg, ok := mqlPkgs[i].(*mqlPackage)
		if !ok {
			continue
		}

		kernelVersion, ok := filterKernel(kernelPackage{
			Name:    pkg.Name.Data,
			Version: pkg.Version.Data,
			Arch:    pkg.Arch.Data,
			Status:  pkg.Status.Data,
		}, runningKernelVersion)
		if !ok {
			continue
		}

		res = append(res, kernelVersion)
	}

	return convert.JsonToDictSlice(res)
}

// platformLabel names a platform for an error message, falling back to the
// family when the name is empty so the message never trails off into
// nothing.
func platformLabel(platform *inventory.Platform) string {
	if platform == nil {
		return "unknown"
	}
	if platform.Name != "" {
		return platform.Name
	}
	if len(platform.Family) > 0 {
		return strings.Join(platform.Family, "/")
	}
	return "unknown"
}

func (k *mqlKernel) info() (any, error) {
	// find suitable kernel module manager
	conn := k.MqlRuntime.Connection.(shared.Connection)
	mm, err := kernel.ResolveManager(conn)
	if mm == nil || err != nil {
		return nil, errors.Wrap(err, "could not detect suitable kernel module manager for platform")
	}

	// retrieve all kernel modules
	kernelInfo, err := mm.Info()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(kernelInfo)
}

func (k *mqlKernel) parameters() (map[string]any, error) {
	// find suitable kernel module manager
	conn := k.MqlRuntime.Connection.(shared.Connection)
	mm, err := kernel.ResolveManager(conn)
	if mm == nil || err != nil {
		return nil, errors.Wrap(err, "could not detect suitable kernel module manager for platform")
	}

	// retrieve all kernel modules
	kernelParameters, err := mm.Parameters()
	if err != nil {
		return nil, err
	}

	// copy values to fulfill the interface
	res := make(map[string]any)
	for key, value := range kernelParameters {
		res[key] = value
	}

	return res, nil
}

func (k *mqlKernel) modules() ([]any, error) {
	k.lock.Lock()
	defer k.lock.Unlock()

	// find suitable kernel module manager
	conn := k.MqlRuntime.Connection.(shared.Connection)
	mm, err := kernel.ResolveManager(conn)
	if mm == nil || err != nil {
		return nil, errors.Wrap(err, "could not detect suitable kernel module manager for platform")
	}

	// retrieve all kernel modules
	kernelModules, err := mm.Modules()
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve kernel module list for platform")
	}
	log.Debug().Int("modules", len(kernelModules)).Msg("[kernel.modules]> modules")

	// create MQL kernel module entry resources for each entry
	moduleEntries := make([]any, len(kernelModules))
	for i, kernelModule := range kernelModules {

		raw, err := CreateResource(k.MqlRuntime, "kernel.module", map[string]*llx.RawData{
			"name":   llx.StringData(kernelModule.Name),
			"size":   llx.StringData(kernelModule.Size),
			"loaded": llx.BoolTrue,
		})
		if err != nil {
			return nil, err
		}

		moduleEntries[i] = raw.(*mqlKernelModule)
	}

	return moduleEntries, k.refreshCache(moduleEntries)
}

func (x *mqlKernel) refreshCache(all []any) error {
	if all == nil {
		raw := x.GetModules()
		if raw.Error != nil {
			return raw.Error
		}
		all = raw.Data
	}

	x.moduleByName = map[string]*mqlKernelModule{}

	for i := range all {
		u := all[i].(*mqlKernelModule)
		x.moduleByName[u.Name.Data] = u
	}

	return nil
}

func initKernelModule(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return args, nil, nil
	}
	name := nameRaw.Value.(string)

	obj, err := CreateResource(runtime, "kernel", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	kernel := obj.(*mqlKernel)

	if err = kernel.refreshCache(nil); err != nil {
		return nil, nil, err
	}

	if res, ok := kernel.moduleByName[name]; ok {
		return nil, res, nil
	}

	res := &mqlKernelModule{}
	res.MqlRuntime = runtime
	res.Name = plugin.TValue[string]{Data: name, State: plugin.StateIsSet}
	res.Size.State = plugin.StateIsSet | plugin.StateIsNull
	res.Loaded = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.__id, _ = res.id()
	return nil, res, nil
}

func (k *mqlKernelModule) id() (string, error) {
	return k.Name.Data, nil
}
