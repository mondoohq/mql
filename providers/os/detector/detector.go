// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"runtime"
	"slices"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector/crowdstrike"
)

func DetectOS(conn shared.Connection) (*inventory.Platform, bool) {
	var res *inventory.Platform
	var ok bool
	switch {
	case conn.Type() == shared.Type_Local && runtime.GOOS == "windows":
		res, ok = resolveWindows(conn)
	case isWindowsSSHServer(conn):
		// Resolve Windows first, and fall back to the full tree only if that
		// fails. The unix families probe with uname, and on Windows every
		// probe is a PowerShell process that fails to find the command,
		// which costs 30-60s each while PowerShell searches every module.
		res, ok = resolveWindows(conn)
		if !ok {
			res, ok = OperatingSystems.Resolve(conn)
		}
	default:
		res, ok = OperatingSystems.Resolve(conn)
	}

	addTechnologyUrl(res)
	if ok {
		DetectDeviceType(res, conn)
		crowdstrike.ApplyLabels(conn, res)
	}
	return res, ok
}

// resolveWindows resolves only the Windows family.
func resolveWindows(conn shared.Connection) (*inventory.Platform, bool) {
	res, ok := WindowsFamily.Resolve(conn)
	// WindowsFamily.Resolve stops one level short of the OperatingSystems
	// wrapper, so the Family chain ends at "windows" instead of
	// ["windows", "os"]. Downstream consumers treat `family` containing
	// "os" as the "asset has installed software" marker; without this
	// append, the Windows shortcut diverges from the equivalent
	// OperatingSystems.Resolve path (which the rest of the cases — and
	// the TestWindows* mocks — go through) and produces a different
	// Family chain. Append "os" explicitly so the shortcut matches.
	if ok && res != nil && !slices.Contains(res.Family, OperatingSystems.Name) {
		res.Family = append(res.Family, OperatingSystems.Name)
	}
	return res, ok
}

// sshServerVersioner is implemented by SSH connections. ServerVersion
// returns the identification string the server sent, such as
// "SSH-2.0-OpenSSH_for_Windows_9.5".
type sshServerVersioner interface {
	ServerVersion() string
}

// isWindowsSSHServer reports whether conn is an SSH connection to the
// OpenSSH server that ships with Windows. That server announces itself as
// OpenSSH_for_Windows; OpenSSH on other systems does not.
func isWindowsSSHServer(conn shared.Connection) bool {
	if conn.Type() != shared.Type_SSH {
		return false
	}
	v, ok := conn.(sshServerVersioner)
	if !ok {
		return false
	}
	return strings.Contains(v.ServerVersion(), "OpenSSH_for_Windows")
}

// returns a primary family for the platform, e.g. linux, windows, osx, etc
// platform must be non-nil
func primaryFamily(platform *inventory.Platform) string {
	families := platform.Family
	for len(families) != 0 {
		last := families[0]
		switch last {
		case "windows":
			return "windows"
		case "linux":
			return "linux"
		case "darwin":
			return "darwin"
		case "unix":
			return "unix"
		}

		families = families[1:]
	}

	return "other"
}

func addTechnologyUrl(platform *inventory.Platform) {
	if platform == nil {
		return
	}

	if platform.Kind == "container-image" {
		platform.TechnologyUrlSegments = []string{
			// technology, kind
			"container", platform.Kind,
		}
	} else {
		platform.TechnologyUrlSegments = []string{"os"}
	}

	// The URL needs a value in every segment, so an unnamed or unversioned
	// platform gets a placeholder here. The placeholder stays local to the URL:
	// writing it back onto the platform reports it as the asset's real name and
	// version, and a rolling release without a VERSION_ID (arch, endeavouros)
	// then keys its package PURLs to distro=<name>-unknown instead of falling
	// back to the build id.
	name := platform.Name
	if name == "" {
		name = "unknown"
	}
	version := platform.Version
	if version == "" {
		version = "unknown"
	}

	platform.TechnologyUrlSegments = append(platform.TechnologyUrlSegments,
		primaryFamily(platform), name, version)
}

// map that is organized by platform name, to quickly determine its families
var osTree = platformParents(OperatingSystems)

func platformParents(r *PlatformResolver) map[string][]string {
	return traverseFamily(r, []string{})
}

func traverseFamily(r *PlatformResolver, parents []string) map[string][]string {
	if r.IsFamily {
		// make sure we completely copy the values, otherwise they are going to overwrite themselves
		p := make([]string, len(parents))
		copy(p, parents)
		// add the current family
		p = append(p, r.Name)
		res := map[string][]string{}

		// iterate over children
		for i := range r.Children {
			child := r.Children[i]
			// recursively walk through the tree
			collect := traverseFamily(child, p)
			for k := range collect {
				res[k] = collect[k]
			}
		}
		return res
	}

	// return child (no family), under every name it can emit
	names := r.Emits
	if names == nil {
		names = []string{r.Name}
	}

	res := map[string][]string{}
	for _, name := range names {
		res[name] = parents
	}
	return res
}

func Family(platform string) []string {
	parents, ok := osTree[platform]
	if !ok {
		return []string{}
	}
	return parents
}

// gathers the family for the provided platform
// NOTE: at this point only operating systems have families
func IsFamily(platform string, family string) bool {
	// 1. determine the families of the platform
	parents, ok := osTree[platform]
	if !ok {
		return false
	}

	// 2. check that the platform is part of the family
	for i := range parents {
		if parents[i] == family {
			return true
		}
	}
	return false
}
