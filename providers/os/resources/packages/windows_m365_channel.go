// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/purl"
)

// Microsoft 365 Apps (Click-to-Run) update channel collection.
//
// M365 Apps has the same shape as an RPM modular package: one package name with
// several concurrently-valid version tracks (Current / Monthly Enterprise /
// Semi-Annual Enterprise channels) whose builds must not be compared against
// each other's fixed-version ranges. Microsoft can ship the same marketing
// Version number on several channels in the same month at different build
// revisions (July 2026's Version 2606 shipped as 20131.20154 / .20152 / .20150),
// and without a channel signal a matcher has to collapse them.
//
// We attach the channel the same way rpm_packages.go attaches modularity: as a
// purl qualifier (`?channel=current`), never by rewriting the display name. A
// package without the qualifier keeps matching the plain, unqualified purl, so
// an asset whose registry read fails or is denied simply degrades to the
// version-only match instead of dropping out.
//
// The qualifier is collected here first; the vulnerability matching side
// consumes it separately, and until it does the extra qualifier is inert.
const m365ChannelQualifier = "channel"

// officeC2RConfigHivePaths are the Click-to-Run configuration keys, relative to
// the SOFTWARE hive root. Click-to-Run writes its configuration to the 64-bit
// view on 64-bit Windows, and to the Wow6432Node view when 32-bit Office is
// installed on a 64-bit OS, so both are probed in that order.
var officeC2RConfigHivePaths = []string{
	"Microsoft\\Office\\ClickToRun\\Configuration",
	"WOW6432Node\\Microsoft\\Office\\ClickToRun\\Configuration",
}

// officeC2RConfigKeys are the same keys as fully-qualified paths, for the
// readers that address the live registry rather than a mounted hive. Derived
// from the list above so the two can't drift apart and make the channel depend
// on how the asset was scanned.
var officeC2RConfigKeys = func() []string {
	keys := make([]string, len(officeC2RConfigHivePaths))
	for i := range officeC2RConfigHivePaths {
		keys[i] = "HKLM\\SOFTWARE\\" + officeC2RConfigHivePaths[i]
	}
	return keys
}()

// m365ChannelValueNames are the ClickToRun\Configuration values that can name
// the update channel, in the order we trust them for the build that is actually
// INSTALLED:
//
//   - CDNBaseUrl is written when Office installs from a channel, so it describes
//     the provenance of the bits on disk. That is what a fixed-build comparison
//     needs. It is also the value Configuration Manager's own channel detection
//     reads.
//   - UpdateChannel / UpdateUrl / UnmanagedUpdateURL describe the ASSIGNED
//     channel, i.e. where the next update will come from. During a channel
//     switch they move ahead of the installed build (Microsoft: "the client
//     device's user interface will display the updated channel only after
//     installing a build from the new channel"), so they are a fallback for
//     installs that have no CDNBaseUrl rather than a preferred source.
//
// Either way the value can lag reality during a transition, so consumers must
// treat the qualifier as a hint that scopes a match group, not as ground truth.
//
// Ref: https://learn.microsoft.com/microsoft-365-apps/updates/change-update-channels
var m365ChannelValueNames = []string{
	"CDNBaseUrl",
	"UpdateChannel",
	"UpdateUrl",
	"UnmanagedUpdateURL",
}

// m365ChannelByAudience maps Microsoft's stable per-channel audience IDs to the
// normalized channel token used in the purl qualifier. The same IDs key the
// server-side channel list, so both sides agree on what a channel is without
// exchanging display names.
//
// Ref: https://learn.microsoft.com/intune/configmgr/sum/deploy-use/manage-office-365-proplus-updates#update-channels-for-microsoft-365-apps
var m365ChannelByAudience = map[string]string{
	"492350f6-3a01-4f97-b9c0-c7c6ddf67d60": "current",
	"64256afe-f5d9-4f86-8936-8840a6a4f5be": "current-preview",
	"55336b82-a18d-4dd6-b5f6-9e5095c314a6": "monthly-enterprise",
	"7ffbc6bf-bc32-4f92-8982-f9dd17fd3114": "semi-annual-enterprise",
	"b8f9b850-328d-4355-9145-c59439a0c4cf": "semi-annual-enterprise-preview",
	"5440fd1f-7ecb-4221-8110-145efaa6372f": "beta",
}

// m365AudienceRegExp matches a bare audience id (a GUID). The ClickToRun values
// we read hold either an Office CDN url ending in one, or the id by itself.
var m365AudienceRegExp = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// m365AppsNameRegExp matches the Click-to-Run Microsoft 365 Apps SKUs, which is
// the product family the channel-scoped advisory data covers.
//
// Deliberately not matched: MSI-installed Office (Office 2016 and earlier),
// which has no update channel at all, and the Click-to-Run Perpetual VL SKUs
// (Office LTSC 2019/2021/2024). The LTSC SKUs do have a channel, but their
// PerpetualVL audience ids aren't in m365ChannelByAudience, so recognizing them
// here would only produce packages we resolve no channel for. Extending to LTSC
// means adding those ids first.
var m365AppsNameRegExp = regexp.MustCompile(`(?i)^Microsoft (365 Apps\b|365 - |Office 365\b)`)

// isM365AppsPackage reports whether a Windows app display name is a
// Click-to-Run Microsoft 365 Apps SKU.
func isM365AppsPackage(name string) bool {
	return m365AppsNameRegExp.MatchString(name)
}

// m365ChannelFromValue resolves one raw ClickToRun value to a normalized channel
// token. It accepts an Office CDN url ("http://officecdn.microsoft.com/pr/<id>")
// and a bare audience id.
//
// The second return reports whether the value names a channel AT ALL, which is
// not the same as resolving one. It is false for an absent value and for a value
// that points at something other than a channel, e.g. an UpdateUrl pointing at
// an internal update share — those carry no channel information and the caller
// should keep looking. It is true with an empty channel for an audience id we
// don't know (one Microsoft introduces after this build ships): that value does
// name a channel, we just can't name it, and the caller must not fall back to a
// lower-priority value, which would report a channel the installed build did not
// come from. No qualifier is the correct answer there.
func m365ChannelFromValue(value string) (string, bool) {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if value == "" {
		return "", false
	}

	// a CDN url carries the audience id in its last path segment
	audience := value
	if _, after, ok := strings.CutLast(audience, "/"); ok {
		audience = after
	}
	audience = strings.ToLower(audience)
	if !m365AudienceRegExp.MatchString(audience) {
		return "", false
	}

	return m365ChannelByAudience[audience], true
}

// m365ChannelFromRegistryItems resolves the update channel from the values of a
// ClickToRun\Configuration key. Value names are matched case-insensitively, the
// way the registry itself treats them.
func m365ChannelFromRegistryItems(items []registry.RegistryKeyItem) string {
	for _, name := range m365ChannelValueNames {
		for i := range items {
			if !strings.EqualFold(items[i].Key, name) {
				continue
			}
			if channel, isChannel := m365ChannelFromValue(items[i].Value.String); isChannel {
				return channel
			}
			break
		}
	}
	return ""
}

// m365ChannelFromKeys probes the Click-to-Run configuration keys with `read` and
// returns the first channel it resolves. `read` returns all values of one key,
// so each key costs a single read.
func m365ChannelFromKeys(paths []string, read func(path string) ([]registry.RegistryKeyItem, error)) string {
	for _, path := range paths {
		items, err := read(path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("could not read the ClickToRun configuration")
			continue
		}
		if channel := m365ChannelFromRegistryItems(items); channel != "" {
			return channel
		}
	}
	return ""
}

// applyM365ChannelQualifier stamps the `channel` purl qualifier onto every
// Click-to-Run Microsoft 365 Apps package in pkgs.
//
// `resolve` is only called when there is something to stamp, so assets without
// Office never pay for the registry probe. When it yields no channel the
// packages are left untouched and keep their plain purl — the fallback tier for
// agents that cannot read the ClickToRun configuration.
func applyM365ChannelQualifier(pkgs []Package, platform *inventory.Platform, resolve func() string) {
	targets := []int{}
	for i := range pkgs {
		if isM365AppsPackage(pkgs[i].Name) {
			targets = append(targets, i)
		}
	}
	if len(targets) == 0 {
		return
	}

	channel := resolve()
	if channel == "" {
		log.Debug().Msg("could not determine the Microsoft 365 Apps update channel, falling back to the unqualified package url")
		return
	}

	for _, i := range targets {
		pkgs[i].PUrl = purl.NewPackageURL(
			platform, purl.TypeWindows, pkgs[i].Name, pkgs[i].Version,
			purl.WithQualifiers(map[string]string{m365ChannelQualifier: channel}),
		).String()
		log.Debug().Str("package", pkgs[i].Name).Str("channel", channel).Msg("detected Microsoft 365 Apps update channel")
	}
}

// m365ChannelFromNativeRegistry reads the Click-to-Run update channel via the
// native registry API. Only valid on a local Windows host.
func (w *WinPkgManager) m365ChannelFromNativeRegistry() string {
	return m365ChannelFromKeys(officeC2RConfigKeys, registry.GetNativeRegistryKeyItems)
}

// m365ChannelFromPowershell reads the Click-to-Run update channel over the
// active connection, so it works for remote connections such as SSH and WinRM.
func (w *WinPkgManager) m365ChannelFromPowershell() string {
	return m365ChannelFromKeys(officeC2RConfigKeys, w.readRegistryItems)
}

// m365ChannelFromHive reads the Click-to-Run update channel from a mounted
// SOFTWARE hive. The handler must already have that hive loaded.
func (w *WinPkgManager) m365ChannelFromHive(rh *registry.RegistryHandler) string {
	return m365ChannelFromKeys(officeC2RConfigHivePaths, func(path string) ([]registry.RegistryKeyItem, error) {
		return rh.GetNativeRegistryKeyItems(registry.Software, path)
	})
}
