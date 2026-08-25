// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/kernel"
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

func (k *mqlKernel) installed() ([]any, error) {
	res := []KernelVersion{}

	conn := k.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	if platform.IsFamily(inventory.FAMILY_LINUX) {

		// 1. gather running kernel information
		info := k.GetInfo()
		if info.Error != nil {
			return nil, errors.New("could not determine kernel version")
		}

		kernelInfo, ok := info.Data.(map[string]any)
		if !ok {
			return nil, errors.New("no structured kernel information found")
		}

		runningKernelVersion := kernelInfo["version"].(string)

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

		filterKernel := func(pkg *mqlPackage) {}

		if platform.IsFamily("debian") {
			// debian based systems
			// kernel version is  "4.19.0-13-cloud-amd64"
			// filter by packages named "linux-image-*"
			//[{
			//	name: "linux-image-4.19.0-12-cloud-amd64"
			//	version: "4.19.152-1"
			//}, {
			//	name: "linux-image-4.19.0-13-cloud-amd64"
			//	version: "4.19.160-2"
			//}, {
			//	name: "linux-image-cloud-amd64"
			//	version: "4.19+105+deb10u8"
			//}]
			filterKernel = func(pkg *mqlPackage) {
				kernelName, ok := debianImageKernelName(pkg.Name.Data)
				if !ok {
					return
				}

				res = append(res, KernelVersion{
					Name:    kernelName,
					Version: pkg.Version.Data,
					Running: kernelName == runningKernelVersion,
				})
			}
		} else if platform.Name == "oraclelinux" {
			// ORacleLinux is an rpm based systems, but might be running the UEK kernel
			// kernel version is  "6.12.0-105.51.5.el9uek.x86_64"
			// filter by packages named "kernel" OR "kernel-uek"
			filterKernel = func(pkg *mqlPackage) {
				if pkg.Name.Data == "kernel" || pkg.Name.Data == "kernel-uek" {
					version := pkg.Version.Data
					res = append(res, KernelVersion{
						Name:    pkg.Name.Data,
						Version: version,
						Running: rpmKernelMatchesRunning(version, pkg.Arch.Data, runningKernelVersion),
					})
				}
			}
		} else if platform.IsFamily("redhat") || platform.Name == "amazonlinux" {
			// rpm based systems
			// kernel version is  "3.10.0-1160.11.1.el7.x86_64"
			// filter by packages named "kernel"
			//[{
			//	name: "kernel"
			//	version: "3.10.0-1127.el7"
			//}, {
			//	name: "kernel"
			//	version: "3.10.0-1160.11.1.el7"
			//}, {
			//	name: "kernel"
			//	version: "3.10.0-1127.19.1.el7"
			//}]
			filterKernel = func(pkg *mqlPackage) {
				if pkg.Name.Data == "kernel" {
					version := pkg.Version.Data
					res = append(res, KernelVersion{
						Name:    pkg.Name.Data,
						Version: version,
						Running: rpmKernelMatchesRunning(version, pkg.Arch.Data, runningKernelVersion),
					})
				}
			}
		} else if platform.Name == "photon" {
			filterKernel = func(pkg *mqlPackage) {
				name := pkg.Name.Data
				if strings.HasPrefix(name, "linux") {
					version := pkg.Version.Data

					res = append(res, KernelVersion{
						Name:    name,
						Version: version + strings.TrimPrefix(name, "linux"),
						Running: photonKernelMatchesRunning(version, name, runningKernelVersion),
					})
				}
			}
		} else if platform.IsFamily("suse") {
			// kernel.info[version] == "4.12.14-122.23-default"
			// rpm -qa | grep -i kernel
			// kernel-default-4.12.14-122.23.1.x86_64
			// kernel-firmware-20190618-5.14.1.noarch
			// kernel-default-4.12.14-122.60.1.x86_64
			// cat /proc/version
			// Linux version 4.12.14-122.23-default (geeko@buildhost)
			filterKernel = func(pkg *mqlPackage) {
				name := pkg.Name.Data
				if strings.HasPrefix(name, "kernel-") {
					version := pkg.Version.Data
					res = append(res, KernelVersion{
						Name:    name,
						Version: version + strings.TrimPrefix(name, "kernel"),
						Running: suseKernelMatchesRunning(version, name, runningKernelVersion),
					})
				}
			}
		}

		for i := range mqlPkgs {
			mqlPkg := mqlPkgs[i]
			pkg := mqlPkg.(*mqlPackage)
			filterKernel(pkg)
		}
	}

	// empty when there is no kernel information found
	return convert.JsonToDictSlice(res)
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
