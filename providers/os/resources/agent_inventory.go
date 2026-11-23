// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/edr"
)

// agentInventory is the asset state an agent catalog (edr, rmm) is matched
// against, together with the live resources each slice was built from. The
// index slices of an edr.Detection point into both, so a product hands out the
// package, service and process resources the scan already built instead of
// rebuilding them from names.
type agentInventory struct {
	edr.Inventory
	packages  []any
	services  []any
	processes []any
	sysExts   []any
}

// agentPlatform maps the asset's platform onto the catalog's platform keys. An
// asset that is none of the three has no catalog entries and is not scanned.
func agentPlatform(runtime *plugin.Runtime) string {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return ""
	}
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return ""
	}
	switch {
	case asset.Platform.IsFamily(inventory.FAMILY_WINDOWS):
		return edr.PlatformWindows
	case asset.Platform.IsFamily(inventory.FAMILY_DARWIN):
		return edr.PlatformMacOS
	case asset.Platform.IsFamily(inventory.FAMILY_LINUX):
		return edr.PlatformLinux
	}
	return ""
}

// readAgentInventory gathers the asset state the catalog reads. Each source is
// fetched once, and the packages and services resources are cached by the
// runtime, so the edr and rmm resources share one read. A source that cannot
// be read leaves its slice empty rather than failing the resource: a missing
// service manager must not hide the agents that packages and paths still prove
// are installed.
func readAgentInventory(runtime *plugin.Runtime, platform string, catalog []edr.Product) agentInventory {
	inv := agentInventory{Inventory: edr.Inventory{
		Platform:   platform,
		PathExists: pathExistsFunc(runtime),
	}}
	inv.Packages, inv.packages = readAgentPackages(runtime)
	inv.Services, inv.services = readAgentServices(runtime)

	// Processes and system extensions are only read when a catalog entry for
	// this platform asks for them, since listing processes is not free.
	if catalogNeedsProcesses(catalog, platform) {
		inv.Processes, inv.processes = readAgentProcesses(runtime)
	}
	if catalogNeedsSystemExtensions(catalog, platform) {
		inv.SystemExtensions, inv.sysExts = readAgentSystemExtensions(runtime)
	}
	return inv
}

func readAgentPackages(runtime *plugin.Runtime) ([]edr.Package, []any) {
	raw, err := CreateResource(runtime, "packages", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[agents]> could not read packages")
		return nil, nil
	}
	list := raw.(*mqlPackages).GetList()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("mql[agents]> could not read package list")
		return nil, nil
	}

	packages := make([]edr.Package, 0, len(list.Data))
	resources := make([]any, 0, len(list.Data))
	for i := range list.Data {
		pkg, ok := list.Data[i].(*mqlPackage)
		if !ok {
			continue
		}
		packages = append(packages, edr.Package{
			Name:    pkg.Name.Data,
			Version: pkg.Version.Data,
		})
		resources = append(resources, pkg)
	}
	return packages, resources
}

func readAgentServices(runtime *plugin.Runtime) ([]edr.Service, []any) {
	raw, err := CreateResource(runtime, "services", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[agents]> could not read services")
		return nil, nil
	}
	list := raw.(*mqlServices).GetList()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("mql[agents]> could not read service list")
		return nil, nil
	}

	services := make([]edr.Service, 0, len(list.Data))
	resources := make([]any, 0, len(list.Data))
	for i := range list.Data {
		svc, ok := list.Data[i].(*mqlService)
		if !ok {
			continue
		}
		services = append(services, edr.Service{
			Name:      svc.Name.Data,
			Installed: svc.Installed.Data,
			Running:   svc.Running.Data,
			Enabled:   svc.Enabled.Data,
		})
		resources = append(resources, svc)
	}
	return services, resources
}

func readAgentProcesses(runtime *plugin.Runtime) ([]edr.Process, []any) {
	raw, err := CreateResource(runtime, "processes", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[agents]> could not read processes")
		return nil, nil
	}
	list := raw.(*mqlProcesses).GetList()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("mql[agents]> could not read process list")
		return nil, nil
	}

	processes := make([]edr.Process, 0, len(list.Data))
	resources := make([]any, 0, len(list.Data))
	for i := range list.Data {
		proc, ok := list.Data[i].(*mqlProcess)
		if !ok {
			continue
		}
		processes = append(processes, edr.Process{
			Executable: proc.GetExecutable().Data,
			State:      proc.GetState().Data,
		})
		resources = append(resources, proc)
	}
	return processes, resources
}

func readAgentSystemExtensions(runtime *plugin.Runtime) ([]edr.SystemExtension, []any) {
	raw, err := CreateResource(runtime, "macos", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[agents]> could not read macos")
		return nil, nil
	}
	list := raw.(*mqlMacos).GetSystemExtensions()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("mql[agents]> could not read system extensions")
		return nil, nil
	}

	extensions := make([]edr.SystemExtension, 0, len(list.Data))
	resources := make([]any, 0, len(list.Data))
	for i := range list.Data {
		ext, ok := list.Data[i].(*mqlMacosSystemExtension)
		if !ok {
			continue
		}
		extensions = append(extensions, edr.SystemExtension{
			Identifier: ext.Identifier.Data,
			Version:    ext.Version.Data,
			Enabled:    ext.GetEnabled().Data,
			Active:     ext.GetActive().Data,
		})
		resources = append(resources, ext)
	}
	return extensions, resources
}

func pathExistsFunc(runtime *plugin.Runtime) func(string) bool {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return func(string) bool { return false }
	}
	afs := &afero.Afero{Fs: conn.FileSystem()}
	return func(path string) bool {
		exists, err := afs.Exists(path)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("mql[agents]> could not stat path")
			return false
		}
		return exists
	}
}

func catalogNeedsProcesses(catalog []edr.Product, platform string) bool {
	for i := range catalog {
		if sig, ok := catalog[i].Platforms[platform]; ok && sig.ProcessPattern != nil {
			return true
		}
	}
	return false
}

func catalogNeedsSystemExtensions(catalog []edr.Product, platform string) bool {
	for i := range catalog {
		if sig, ok := catalog[i].Platforms[platform]; ok && len(sig.SystemExtensions) > 0 {
			return true
		}
	}
	return false
}

func pickResources(all []any, idx []int) []any {
	picked := make([]any, 0, len(idx))
	for _, i := range idx {
		if i >= 0 && i < len(all) {
			picked = append(picked, all[i])
		}
	}
	return picked
}
