// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// updateTestProvider builds a minimal Provider for selectProvidersToUpdate
// tests. A non-empty path marks an installed (external) provider; an empty path
// marks a builtin one compiled into the binary.
func updateTestProvider(name, path string) *providers.Provider {
	return &providers.Provider{Provider: &plugin.Provider{Name: name}, Path: path}
}

func updateProviderNames(ps []*providers.Provider) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

func TestSelectProvidersToUpdate_NoNamesReturnsAllInstalledSorted(t *testing.T) {
	all := []*providers.Provider{
		updateTestProvider("os", "/p/os"),
		updateTestProvider("aws", "/p/aws"),
		updateTestProvider("core", ""), // builtin, must be excluded
	}

	toUpdate, notInstalled := selectProvidersToUpdate(all, nil)

	assert.Equal(t, []string{"aws", "os"}, updateProviderNames(toUpdate), "all installed providers, sorted, builtin excluded")
	assert.Empty(t, notInstalled)
}

func TestSelectProvidersToUpdate_NamedSubset(t *testing.T) {
	all := []*providers.Provider{
		updateTestProvider("aws", "/p/aws"),
		updateTestProvider("gcp", "/p/gcp"),
		updateTestProvider("os", "/p/os"),
	}

	toUpdate, notInstalled := selectProvidersToUpdate(all, []string{"aws", "os"})

	assert.Equal(t, []string{"aws", "os"}, updateProviderNames(toUpdate))
	assert.Empty(t, notInstalled)
}

func TestSelectProvidersToUpdate_MissingNameReportedNotFatal(t *testing.T) {
	all := []*providers.Provider{updateTestProvider("aws", "/p/aws")}

	toUpdate, notInstalled := selectProvidersToUpdate(all, []string{"aws", "notreal"})

	assert.Equal(t, []string{"aws"}, updateProviderNames(toUpdate))
	assert.Equal(t, []string{"notreal"}, notInstalled, "unknown names are reported, not selected")
}

func TestSelectProvidersToUpdate_BuiltinNameIsNotUpdatable(t *testing.T) {
	all := []*providers.Provider{
		updateTestProvider("core", ""), // builtin
		updateTestProvider("aws", "/p/aws"),
	}

	// A builtin provider is compiled into the binary, so naming it is treated
	// the same as an uninstalled provider: reported and skipped, never selected.
	toUpdate, notInstalled := selectProvidersToUpdate(all, []string{"core"})

	assert.Empty(t, toUpdate)
	assert.Equal(t, []string{"core"}, notInstalled)
}
