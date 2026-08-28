// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/providers/os/resources/updates"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// lastUpdateCache resolves the asset's newest update install once and shares it
// between lastUpdate, lastUpdateAge and lastUpdateSource, which would otherwise
// each pay for the same log read or package listing. It is embedded in both
// mqlOsInternal and mqlOsBaseInternal, since `os` and `os.base` carry the same
// three fields.
type lastUpdateCache struct {
	once   sync.Once
	update *updates.LastInstalledUpdate
	err    error
}

// get resolves the newest update install once and hands the same outcome to
// every field that asks.
//
// sync.Once rather than a mutex guarding a "fetched" flag: the executor resolves
// a resource's fields in separate goroutines, and reading such a flag outside
// the lock races with the write inside it. There is no happens-before edge
// between the two, so a reader can observe the flag set before the value it
// guards is visible.
//
// A failure is cached alongside a success. Each of the three fields resolves
// once through the runtime's own field cache, so retrying would buy at most two
// further attempts at a failure that is deterministic within a scan (an
// unreadable package database, a missing permission) while paying for the full
// package listing again.
func (c *lastUpdateCache) get(runtime *plugin.Runtime) (*updates.LastInstalledUpdate, error) {
	c.once.Do(func() {
		c.update, c.err = resolveLastInstalledUpdate(runtime)
	})
	return c.update, c.err
}

type mqlOsInternal struct {
	lastUpdateCache
}

type mqlOsBaseInternal struct {
	lastUpdateCache
}

// resolveLastInstalledUpdate finds the newest operating system update install
// recorded on the asset. rpm-based platforms and Windows are answered with
// help from resources that already hold data the record alone lacks (the
// vendor of every rpm, the update agent history); everything else is read
// from its own files by the updates package.
//
// Whatever the source, the resolved timestamp passes one validation before
// any field sees it: a zero time or a time materially in the future is
// dropped, so lastUpdate, lastUpdateAge and lastUpdateSource all read null
// together instead of a broken clock reporting the asset as freshly patched.
func resolveLastInstalledUpdate(runtime *plugin.Runtime) (*updates.LastInstalledUpdate, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil, nil
	}
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return nil, nil
	}

	// Containers are out of scope, and the check comes before the dispatch so
	// no rpm listing or PowerShell round trip is paid for an asset that is
	// going to read null anyway.
	if isContainerAsset(conn, asset.Platform) {
		return nil, nil
	}

	var update *updates.LastInstalledUpdate
	var err error
	switch {
	case isRpmPlatform(asset.Platform):
		update, err = lastInstalledRpm(runtime, conn, asset.Platform)
	case asset.Platform.Name == "windows":
		update, err = lastInstalledWindows(runtime)
	default:
		update, err = updates.ResolveLastInstalledUpdate(conn)
	}
	if err != nil {
		return nil, err
	}
	return updates.ValidateLastInstalledUpdate(update, time.Now()), nil
}

// isContainerAsset reports whether the asset is a container or a container
// image.
//
// A container is not patched, it is rebuilt, so the age of the newest install
// recorded inside it is the age of the image build rather than a statement
// about whether anyone is maintaining the workload. Reporting that as patch age
// would let a base image that has not moved in a year read as freshly patched
// on the day it was pulled, so these fields read null instead and the question
// is left to image provenance.
//
// Three signals because each covers what the others miss: Kind is what the
// platform resolver sets for a docker connection, the device type additionally
// catches an os-release VARIANT_ID of container (an image reached over a
// filesystem or tar connection, where Kind may be unset), and the connection
// types cover registry scans.
//
// Type_Tar and Type_FileSystem are deliberately absent. A tar can be a virtual
// machine export and a filesystem connection is routinely a mounted host root,
// so excluding them would null the field on assets that genuinely are patched.
func isContainerAsset(conn shared.Connection, pf *inventory.Platform) bool {
	return isContainerPlatform(pf) || isContainerConnection(conn.Type())
}

// isContainerPlatform reports whether the detected platform is a container or a
// container image.
func isContainerPlatform(pf *inventory.Platform) bool {
	if pf == nil {
		return false
	}
	if pf.Kind == "container" || pf.Kind == "container-image" {
		return true
	}
	return pf.Metadata[detector.MetadataDeviceType] == detector.DeviceTypeContainer
}

// isContainerConnection reports whether a connection type can only ever reach a
// container or a container image.
//
// Type_Tar and Type_FileSystem are deliberately absent: a tar can be a virtual
// machine export and a filesystem connection is routinely a mounted host root.
func isContainerConnection(t shared.ConnectionType) bool {
	switch t {
	case shared.Type_DockerContainer, shared.Type_DockerImage, shared.Type_DockerSnapshot,
		shared.Type_DockerRegistry, shared.Type_ContainerRegistry, shared.Type_RegistryImage,
		shared.Type_DockerFile:
		return true
	}
	return false
}

// isRpmPlatform reports whether the asset's packages come from rpm, mirroring
// the platforms packages.ResolveSystemPkgManagers hands to RpmPkgManager.
// altlinux and opencloudos are rpm based but live outside the redhat family
// (neither ships a usable /etc/redhat-release, so each resolves as a platform
// of its own), which is why they are named here rather than caught by a
// family check.
func isRpmPlatform(pf *inventory.Platform) bool {
	switch pf.Name {
	case "amazonlinux", "photon", "wrlinux", "bottlerocket", "azurelinux", "mageia",
		"altlinux", "opencloudos":
		return true
	}
	return pf.IsFamily("redhat") || pf.IsFamily("euler") || pf.IsFamily("suse")
}

// isImageBasedRpmPlatform reports whether the asset updates by swapping the
// operating system image rather than by upgrading packages: Bottlerocket, and
// the rpm-ostree family (OpenShift's RHCOS is its own platform, Fedora CoreOS
// is Fedora carrying VARIANT_ID=coreos). Their rpm database describes the
// image build, and no dnf transaction log exists, so "when was a package last
// upgraded" has no answer on them: the honest reading is null until a
// reliable OS deployment timestamp (an ostree deployment, a Bottlerocket
// update record) is wired up as its own source.
func isImageBasedRpmPlatform(pf *inventory.Platform) bool {
	switch pf.Name {
	case "bottlerocket", "rhcos":
		return true
	}
	return strings.EqualFold(pf.Labels["variant-id"], "coreos") ||
		strings.EqualFold(pf.Metadata["variant-id"], "coreos")
}

// rpmVendorAnchors are packages that only ever come from the operating system
// vendor. Their %{VENDOR} is what the vendor calls itself on this asset, which
// is how the OS vendor is identified without shipping a distribution-to-vendor
// table that goes stale and silently nulls the field on a distribution nobody
// added to it.
//
// Several anchors, unioned, because a distribution can ship more than one
// vendor string across its own packages (Amazon Linux uses both "Amazon Linux"
// and "Amazon.com"). Trusting a single anchor would drop the other spelling.
var rpmVendorAnchors = []string{"glibc", "bash", "coreutils", "systemd", "filesystem"}

// lastInstalledRpm takes the newest vendor package upgrade recorded in dnf's
// rpm transaction log.
//
// The rpm database itself cannot answer. It records one %{INSTALLTIME} per
// package, and that time reads the same for an upgrade and for an operator
// installing a vendor rpm for the first time, so `dnf install vim` would make
// the machine look freshly patched. The transaction log is what separates the
// two: dnf writes an Upgrade/Upgraded line pair only when a package moved to
// a newer build. A platform that keeps no such log (SUSE's zypper, yum-era
// RHEL, Photon's tdnf) reads null rather than borrowing the install-time
// answer, because "installed recently" is not "updated recently".
//
// The vendor match is what makes the timestamp mean patch state. Without it a
// third-party rpm upgraded through dnf - Docker CE, Grafana, a vendor's agent
// - counts as an operating system update, and those move far more often than
// a distribution does. The vendor comes from the packages resource, which
// already parses %{VENDOR} on both the command path and the static rpmdb
// path, so attributing the log lines costs no extra read.
func lastInstalledRpm(runtime *plugin.Runtime, conn shared.Connection, pf *inventory.Platform) (*updates.LastInstalledUpdate, error) {
	// An image-based system is updated by swapping the image, which no
	// package transaction records; see isImageBasedRpmPlatform.
	if isImageBasedRpmPlatform(pf) {
		return nil, nil
	}

	// Without the transaction log there is no upgrade evidence to attribute,
	// so skip the package listing the attribution would need. This is what a
	// SUSE or Photon host answers: their package managers never write it.
	if !updates.DnfRpmLogPresent(conn.FileSystem()) {
		return nil, nil
	}

	obj, err := CreateResource(runtime, "packages", nil)
	if err != nil {
		return nil, err
	}

	list := obj.(*mqlPackages).GetList()
	if list.Error != nil {
		return nil, list.Error
	}

	isVendor := rpmVendorPackageMatcher(list.Data)
	if isVendor == nil {
		// No anchor resolved a vendor, so no upgrade can be attributed. An
		// unattributable answer is not a coarser answer, it is none.
		return nil, nil
	}
	return updates.LastInstalledRpm(conn.FileSystem(), isVendor)
}

// rpmVendorPackageMatcher returns a predicate reporting whether a package name
// belongs to this asset's operating system vendor, or nil when no vendor could
// be derived. The name is the lookup key because a dnf log line carries
// nothing else; the vendor comes from the rpm database entry the name still
// points at, since an upgraded package keeps its name across builds.
func rpmVendorPackageMatcher(list []any) func(name string) bool {
	vendors := rpmOSVendors(list)
	if len(vendors) == 0 {
		return nil
	}

	vendorPackages := make(map[string]bool, len(list))
	for i := range list {
		pkg, ok := list[i].(*mqlPackage)
		if !ok {
			continue
		}
		// A rpm host can also carry snap, nix or flatpak packages, whose
		// names must not vouch for a log line.
		if pkg.Format.Data != packages.RpmPkgFormat {
			continue
		}
		if _, ok := vendors[normalizeVendor(pkg.Vendor.Data)]; ok {
			vendorPackages[pkg.Name.Data] = true
		}
	}
	return func(name string) bool { return vendorPackages[name] }
}

// rpmOSVendors returns the set of vendor strings the anchor packages carry on
// this asset.
func rpmOSVendors(list []any) map[string]struct{} {
	vendors := map[string]struct{}{}
	for i := range list {
		pkg, ok := list[i].(*mqlPackage)
		if !ok || pkg.Format.Data != packages.RpmPkgFormat {
			continue
		}
		name := pkg.Name.Data
		anchor := false
		for _, a := range rpmVendorAnchors {
			if name == a {
				anchor = true
				break
			}
		}
		if !anchor {
			continue
		}
		if v := normalizeVendor(pkg.Vendor.Data); v != "" {
			vendors[v] = struct{}{}
		}
	}
	return vendors
}

// normalizeVendor folds the case and trims the padding rpm vendor strings carry
// so that two spellings of the same vendor compare equal.
func normalizeVendor(vendor string) string {
	return strings.ToLower(strings.TrimSpace(vendor))
}

// lastInstalledWindows takes the newest Windows Update Agent history entry that
// patched the operating system itself.
//
// The registry's last-successful-install time is not used as a fallback. It is
// a bare timestamp with no classification attached, so it counts the Defender
// signature updates that land daily and the .NET and Office servicing this pass
// excludes; a host years behind on Windows would read as patched this morning.
// A connection that cannot reach the agent history reads null instead.
func lastInstalledWindows(runtime *plugin.Runtime) (*updates.LastInstalledUpdate, error) {
	obj, err := CreateResource(runtime, "windows.update", nil)
	if err != nil {
		return nil, err
	}
	wu := obj.(*mqlWindowsUpdate)

	installed := wu.GetInstalled()
	if installed.Error != nil {
		// A connection that cannot reach the agent history has no answer, and
		// no answer is null rather than an error: one Windows host that cannot
		// run PowerShell must not fail a fleet query. Log it, because without
		// that a permission problem or a blocked PowerShell looks identical to
		// a host that genuinely has no history.
		log.Debug().Err(installed.Error).
			Msg("mql[os.lastUpdate]> windows update agent history unavailable")
		return nil, nil
	}

	var newest time.Time
	for i := range installed.Data {
		entry, ok := installed.Data[i].(*mqlWindowsUpdateEntry)
		if !ok {
			continue
		}
		if !windows.IsOperatingSystemUpdate(entryCategories(entry), entry.Title.Data) {
			continue
		}
		date := entry.Date.Data
		if date == nil || date.IsZero() {
			continue
		}
		if date.After(newest) {
			newest = *date
		}
	}

	if newest.IsZero() {
		return nil, nil
	}
	return &updates.LastInstalledUpdate{Time: newest.UTC(), Source: updates.LastUpdateSourceWindowsUpdate}, nil
}

// entryCategories converts a history entry's categories to the string slice the
// classifier takes. A non-string element is skipped rather than stringified,
// since a category that is not a string is not a product name.
func entryCategories(entry *mqlWindowsUpdateEntry) []string {
	out := make([]string, 0, len(entry.Categories.Data))
	for _, c := range entry.Categories.Data {
		if s, ok := c.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// lastUpdateAge turns an install time into the duration-typed time MQL uses for
// durations, matching how uptime is reported. Central validation has already
// dropped any materially future timestamp before it reaches this point; what
// can still land here is the few minutes of clock skew inside that tolerance,
// which clamps to zero rather than rendering a negative age.
func lastUpdateAge(installed time.Time) *time.Time {
	age := time.Now().Unix() - installed.Unix()
	if age < 0 {
		age = 0
	}
	return MqlTime(llx.DurationToTime(age))
}

func (p *mqlOs) lastUpdate() (*time.Time, error) {
	update, err := p.get(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if update == nil {
		// Mark the field resolved-and-null so the runtime does not treat it as
		// unresolved and re-invoke this accessor on every read.
		p.LastUpdate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return MqlTime(update.Time), nil
}

func (p *mqlOs) lastUpdateAge() (*time.Time, error) {
	update, err := p.get(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if update == nil {
		p.LastUpdateAge.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return lastUpdateAge(update.Time), nil
}

func (p *mqlOs) lastUpdateSource() (string, error) {
	update, err := p.get(p.MqlRuntime)
	if err != nil {
		return "", err
	}
	if update == nil {
		p.LastUpdateSource.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return update.Source, nil
}

func (p *mqlOsBase) lastUpdate() (*time.Time, error) {
	update, err := p.get(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if update == nil {
		p.LastUpdate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return MqlTime(update.Time), nil
}

func (p *mqlOsBase) lastUpdateAge() (*time.Time, error) {
	update, err := p.get(p.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if update == nil {
		p.LastUpdateAge.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return lastUpdateAge(update.Time), nil
}

func (p *mqlOsBase) lastUpdateSource() (string, error) {
	update, err := p.get(p.MqlRuntime)
	if err != nil {
		return "", err
	}
	if update == nil {
		p.LastUpdateSource.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return update.Source, nil
}
