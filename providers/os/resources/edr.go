// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/edr"
	"go.mondoo.com/mql/types"
)

// The cache fields carry a prefix because the generated accessors already own
// the bare names (products, services, packages, processes).
type mqlEdrInternal struct {
	lock           sync.Mutex
	cacheResolved  bool
	cacheProducts  []any
	cachePackages  []any
	cacheServices  []any
	cacheProcesses []any
	cacheSysExts   []any
}

type mqlEdrProductInternal struct {
	cacheServices  []any
	cachePackages  []any
	cacheProcesses []any
	cacheSysExts   []any
}

func (e *mqlEdr) id() (string, error) {
	return "edr", nil
}

func (e *mqlEdr) products() ([]any, error) {
	return e.detect()
}

func (e *mqlEdr) installed() (bool, error) {
	products, err := e.detect()
	if err != nil {
		return false, err
	}
	return len(products) > 0, nil
}

func (e *mqlEdr) healthy() (bool, error) {
	products, err := e.detect()
	if err != nil {
		return false, err
	}
	// An asset with no agent is not healthy. Reporting true here would make
	// the assertion pass on exactly the asset it exists to find.
	if len(products) == 0 {
		return false, nil
	}
	for i := range products {
		if !products[i].(*mqlEdrProduct).Healthy.Data {
			return false, nil
		}
	}
	return true, nil
}

// detect resolves the catalog against the asset once and memoizes the result,
// so products, installed and healthy share a single pass over the package and
// service lists rather than taking one each.
func (e *mqlEdr) detect() ([]any, error) {
	e.lock.Lock()
	defer e.lock.Unlock()

	if e.cacheResolved {
		return e.cacheProducts, nil
	}

	platform := edrPlatform(e.MqlRuntime)
	if platform == "" {
		e.cacheResolved = true
		e.cacheProducts = []any{}
		return e.cacheProducts, nil
	}

	inv := e.inventory(platform)

	products := []any{}
	for _, d := range edr.Detect(inv) {
		product, err := e.newProduct(d)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	e.cacheProducts = products
	e.cacheResolved = true
	return e.cacheProducts, nil
}

// edrPlatform maps the asset's platform onto the catalog's platform keys. An
// asset that is none of the three has no catalog entries and is not scanned.
func edrPlatform(runtime *plugin.Runtime) string {
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

// inventory gathers the asset state the catalog reads. Each source is fetched
// once for every product, and a source that cannot be read leaves its slice
// empty rather than failing the resource: a missing service manager must not
// hide the agents that packages and paths still prove are installed.
func (e *mqlEdr) inventory(platform string) edr.Inventory {
	inv := edr.Inventory{
		Platform:   platform,
		Packages:   e.packageInventory(),
		Services:   e.serviceInventory(),
		PathExists: pathExistsFunc(e.MqlRuntime),
	}

	// Processes and system extensions are only read when a catalog entry for
	// this platform asks for them, since listing processes is not free.
	if catalogNeedsProcesses(platform) {
		inv.Processes = e.processInventory()
	}
	if catalogNeedsSystemExtensions(platform) {
		inv.SystemExtensions = e.systemExtensionInventory()
	}

	return inv
}

func (e *mqlEdr) packageInventory() []edr.Package {
	raw, err := CreateResource(e.MqlRuntime, "packages", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[edr]> could not read packages")
		return nil
	}
	list := raw.(*mqlPackages).GetList()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("mql[edr]> could not read package list")
		return nil
	}

	e.cachePackages = list.Data
	packages := make([]edr.Package, 0, len(list.Data))
	for i := range list.Data {
		pkg, ok := list.Data[i].(*mqlPackage)
		if !ok {
			continue
		}
		packages = append(packages, edr.Package{
			Name:    pkg.Name.Data,
			Version: pkg.Version.Data,
		})
	}
	return packages
}

func (e *mqlEdr) serviceInventory() []edr.Service {
	raw, err := CreateResource(e.MqlRuntime, "services", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[edr]> could not read services")
		return nil
	}
	list := raw.(*mqlServices).GetList()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("mql[edr]> could not read service list")
		return nil
	}

	e.cacheServices = list.Data
	services := make([]edr.Service, 0, len(list.Data))
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
	}
	return services
}

func (e *mqlEdr) processInventory() []edr.Process {
	raw, err := CreateResource(e.MqlRuntime, "processes", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[edr]> could not read processes")
		return nil
	}
	list := raw.(*mqlProcesses).GetList()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("mql[edr]> could not read process list")
		return nil
	}

	e.cacheProcesses = list.Data
	processes := make([]edr.Process, 0, len(list.Data))
	for i := range list.Data {
		proc, ok := list.Data[i].(*mqlProcess)
		if !ok {
			continue
		}
		processes = append(processes, edr.Process{
			Executable: proc.GetExecutable().Data,
			State:      proc.GetState().Data,
		})
	}
	return processes
}

func (e *mqlEdr) systemExtensionInventory() []edr.SystemExtension {
	raw, err := CreateResource(e.MqlRuntime, "macos", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[edr]> could not read macos")
		return nil
	}
	list := raw.(*mqlMacos).GetSystemExtensions()
	if list.Error != nil {
		log.Debug().Err(list.Error).Msg("mql[edr]> could not read system extensions")
		return nil
	}

	e.cacheSysExts = list.Data
	extensions := make([]edr.SystemExtension, 0, len(list.Data))
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
	}
	return extensions
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
			log.Debug().Err(err).Str("path", path).Msg("mql[edr]> could not stat path")
			return false
		}
		return exists
	}
}

func catalogNeedsProcesses(platform string) bool {
	for i := range edr.Catalog {
		if sig, ok := edr.Catalog[i].Platforms[platform]; ok && sig.ProcessPattern != nil {
			return true
		}
	}
	return false
}

func catalogNeedsSystemExtensions(platform string) bool {
	for i := range edr.Catalog {
		if sig, ok := edr.Catalog[i].Platforms[platform]; ok && len(sig.SystemExtensions) > 0 {
			return true
		}
	}
	return false
}

func (e *mqlEdr) newProduct(d edr.Detection) (*mqlEdrProduct, error) {
	var enabled *bool
	if d.EnabledReported {
		enabled = &d.Enabled
	}

	var version *string
	if d.Version != "" {
		version = &d.Version
	}

	args := map[string]*llx.RawData{
		"__id":       llx.StringData(d.Product.ID),
		"id":         llx.StringData(d.Product.ID),
		"name":       llx.StringData(d.Product.Name),
		"vendor":     llx.StringData(d.Product.Vendor),
		"category":   llx.StringData(d.Product.Category),
		"installed":  llx.BoolData(true),
		"running":    llx.BoolData(d.Running),
		"enabled":    llx.BoolDataPtr(enabled),
		"healthy":    llx.BoolData(d.Healthy),
		"version":    llx.StringDataPtr(version),
		"detectedBy": llx.ArrayData(stringsToAny(d.DetectedBy), types.String),
	}
	e.enrich(d, args)

	raw, err := CreateResource(e.MqlRuntime, "edr.product", args)
	if err != nil {
		return nil, err
	}

	product := raw.(*mqlEdrProduct)
	product.cacheServices = pickResources(e.cacheServices, d.ServiceIdx)
	product.cachePackages = pickResources(e.cachePackages, d.PackageIdx)
	product.cacheProcesses = pickResources(e.cacheProcesses, d.ProcessIdx)
	product.cacheSysExts = pickResources(e.cacheSysExts, d.SystemExtensionIdx)
	return product, nil
}

// enrich fills the fields only the product itself can report. A product that
// publishes none of them leaves them null, so a check reading signatureAge on
// such an agent fails rather than passing against a zero nobody measured.
func (e *mqlEdr) enrich(d edr.Detection, args map[string]*llx.RawData) {
	args["mode"] = llx.NilData
	args["signatureAge"] = llx.NilData
	args["signatureUpdatedAt"] = llx.NilData
	args["signatureVersion"] = llx.NilData

	if d.Product.ID != "microsoft-defender" {
		return
	}

	status := e.defenderStatus()
	if status == nil {
		return
	}

	if mode := defenderMode(status.GetAmRunningMode().Data); mode != "" {
		args["mode"] = llx.StringData(mode)
	}
	if age := status.GetAntivirusSignatureAge(); age.Error == nil && age.State&plugin.StateIsNull == 0 {
		args["signatureAge"] = llx.IntData(age.Data)
	}
	if updated := status.GetAntivirusSignatureLastUpdated(); updated.Error == nil && updated.Data != nil {
		args["signatureUpdatedAt"] = llx.TimeDataPtr(updated.Data)
	}
	if version := status.GetAntivirusSignatureVersion(); version.Error == nil && version.Data != "" {
		args["signatureVersion"] = llx.StringData(version.Data)
	}
}

func (e *mqlEdr) defenderStatus() *mqlWindowsDefenderStatus {
	raw, err := CreateResource(e.MqlRuntime, "windows.defender", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("mql[edr]> could not read windows.defender")
		return nil
	}
	status := raw.(*mqlWindowsDefender).GetStatus()
	if status.Error != nil || status.Data == nil {
		log.Debug().Err(status.Error).Msg("mql[edr]> could not read windows.defender status")
		return nil
	}
	return status.Data
}

// defenderMode translates the running mode Defender reports into the catalog's
// vocabulary. Passive and EDR-block modes both report the antimalware service
// as enabled while remediating little or nothing, which is why the mode is
// worth reporting separately from running.
func defenderMode(amRunningMode string) string {
	switch amRunningMode {
	case "Normal":
		return "active"
	case "Passive Mode", "SxS Passive Mode":
		return "passive"
	case "EDR Block Mode":
		return "blockOnly"
	}
	return ""
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

func (p *mqlEdrProduct) id() (string, error) {
	return p.Id.Data, nil
}

func (p *mqlEdrProduct) services() ([]any, error) {
	return p.cacheServices, nil
}

func (p *mqlEdrProduct) packages() ([]any, error) {
	return p.cachePackages, nil
}

func (p *mqlEdrProduct) processes() ([]any, error) {
	return p.cacheProcesses, nil
}

func (p *mqlEdrProduct) systemExtensions() ([]any, error) {
	return p.cacheSysExts, nil
}
