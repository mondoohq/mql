// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func namedPkg(name, version, arch, format string) *mqlPackage {
	return &mqlPackage{
		Name:    plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		Version: plugin.TValue[string]{Data: version, State: plugin.StateIsSet},
		Arch:    plugin.TValue[string]{Data: arch, State: plugin.StateIsSet},
		Format:  plugin.TValue[string]{Data: format, State: plugin.StateIsSet},
	}
}

func resolveByName(t *testing.T, name string, list ...*mqlPackage) *mqlPackage {
	t.Helper()
	all := make([]any, len(list))
	for i := range list {
		all[i] = list[i]
	}
	x := &mqlPackages{}
	require.NoError(t, x.refreshCache(all))
	return x.packagesByName[name]
}

// Ubuntu installs snapd both as a deb and as a snap. list() puts the snap
// manager after dpkg, so the snap used to win package("snapd").
func TestPackageByNamePrefersSystemManagerOverSnap(t *testing.T) {
	deb := namedPkg("snapd", "2.73+ubuntu24.04", "amd64", "deb")
	snap := namedPkg("snapd", "2.76.3", "", "snap")
	other := namedPkg("bash", "5.2.21-2ubuntu4", "amd64", "deb")

	assert.Same(t, deb, resolveByName(t, "snapd", other, deb, snap))
	assert.Same(t, deb, resolveByName(t, "snapd", snap, other, deb))
	// a name only a snap has still resolves to the snap
	core := namedPkg("core22", "20260824", "", "snap")
	assert.Same(t, core, resolveByName(t, "core22", other, deb, core))
}

// A multi-arch package installed for amd64 and i386 is listed twice under one
// name, in status-file order. The native build wins in either order.
func TestPackageByNamePrefersNativeArch(t *testing.T) {
	natives := []*mqlPackage{
		namedPkg("bash", "5.2", "amd64", "deb"),
		namedPkg("coreutils", "9.4", "amd64", "deb"),
		namedPkg("tzdata", "2024a", "all", "deb"),
	}
	amd := namedPkg("g03-ma", "1.0-1", "amd64", "deb")
	i386 := namedPkg("g03-ma", "1.0-1", "i386", "deb")

	assert.Same(t, amd, resolveByName(t, "g03-ma", append([]*mqlPackage{amd, i386}, natives...)...))
	assert.Same(t, amd, resolveByName(t, "g03-ma", append([]*mqlPackage{i386, amd}, natives...)...))

	// a package installed only for the foreign arch still resolves
	only := namedPkg("libfoo", "1.0", "i386", "deb")
	assert.Same(t, only, resolveByName(t, "libfoo", append([]*mqlPackage{only}, natives...)...))
}

// Several installed versions of one rpm name (kernel) keep the previous
// last-wins behavior.
func TestPackageByNameSameArchKeepsLastEntry(t *testing.T) {
	k1 := namedPkg("kernel", "5.14.0-1", "x86_64", "rpm")
	k2 := namedPkg("kernel", "5.14.0-2", "x86_64", "rpm")
	assert.Same(t, k2, resolveByName(t, "kernel", k1, k2))
}
