// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
//
// The providers that are always compiled into the binary. Maintained by hand:
// 'make providers/config' writes builtin_dev.go, not this file, and
// providers.yaml only covers providers that are normally NOT builtin.

package providers

// This is primarily useful for debugging purposes, if you want to
// trace into any provider without having to debug the plugin
// connection separately.

import (
	_ "embed"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	coreconf "go.mondoo.com/mql/providers/core/config"
	core "go.mondoo.com/mql/providers/core/provider"
	iacconf "go.mondoo.com/mql/providers/iac/config"
)

//go:embed core/resources/core.resources.json
var coreInfo []byte

//go:embed iac/resources/iac.resources.json
var iacInfo []byte

var builtinProviders = map[string]*builtinProvider{
	coreconf.Config.ID: {
		Runtime: &RunningProvider{
			Name:     coreconf.Config.Name,
			ID:       coreconf.Config.ID,
			Plugin:   core.Init(),
			Schema:   MustLoadSchema("core", coreInfo),
			isClosed: false,
		},
		Config: &coreconf.Config,
	},
	mockProvider.ID: {
		Runtime: &RunningProvider{
			Name:     mockProvider.Name,
			ID:       mockProvider.ID,
			Plugin:   &mockProviderService{},
			isClosed: false,
		},
		Config: mockProvider.Provider,
	},
	sbomProvider.ID: {
		Runtime: &RunningProvider{
			Name:     sbomProvider.Name,
			ID:       sbomProvider.ID,
			Plugin:   &sbomProviderService{},
			Schema:   &resources.Schema{},
			isClosed: false,
		},
		Config: sbomProvider.Provider,
	},
	iacconf.Config.ID: {
		Runtime: &RunningProvider{
			Name: iacconf.Config.Name,
			ID:   iacconf.Config.ID,
			// Version, Root and Requires have to be set here. Only the plugin
			// path in unsafeStartProvider copies them off the config; a builtin
			// is returned as-is. Without Root, `_` does not resolve for an iac
			// asset; without Requires, every `asset` read is logged as an
			// undeclared cross-provider call (ADR 042).
			Version:  iacconf.Config.Version,
			Root:     iacconf.Config.Root,
			Requires: iacconf.Config.Requires,
			Plugin:   &iacProviderService{Service: plugin.NewService()},
			Schema:   MustLoadSchema("iac", iacInfo),
			isClosed: false,
		},
		Config: iacProvider.Provider,
	},
	recordingProviderInstance.ID: {
		Runtime: &RunningProvider{
			Name:     recordingProviderInstance.Name,
			ID:       recordingProviderInstance.ID,
			Plugin:   &recordingProvider{},
			Schema:   &resources.Schema{},
			isClosed: false,
		},
		Config: recordingProviderInstance.Provider,
	},
}

func GetBuiltinProviderNames() []string {
	names := []string{}
	for _, v := range builtinProviders {
		names = append(names, v.Config.Name)
	}

	return names
}
