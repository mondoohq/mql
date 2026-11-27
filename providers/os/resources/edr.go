// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/detector/crowdstrike"
	"go.mondoo.com/mql/providers/os/detector/defender"
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

	platform := agentPlatform(e.MqlRuntime)
	if platform == "" {
		e.cacheResolved = true
		e.cacheProducts = []any{}
		return e.cacheProducts, nil
	}

	inv := readAgentInventory(e.MqlRuntime, platform, edr.Catalog)
	e.cachePackages = inv.packages
	e.cacheServices = inv.services
	e.cacheProcesses = inv.processes
	e.cacheSysExts = inv.sysExts

	products := []any{}
	for _, d := range edr.Detect(inv.Inventory) {
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
	args["agentId"] = llx.NilData
	args["tenantId"] = llx.NilData

	if d.Product.ID == "crowdstrike-falcon" {
		e.enrichFalconIdentity(args)
		return
	}
	if d.Product.ID != "microsoft-defender" {
		return
	}

	e.enrichDefenderIdentity(args)

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

// enrichFalconIdentity reports the Falcon sensor's agent and customer IDs.
// crowdstrike.Resolve is the same helper the platform labels and the platform
// ID come from: it reads the IDs platform detection recorded, and reads them
// from the host only when the platform carries none. So these fields and the
// labels cannot disagree. An unregistered sensor has a customer ID and no
// agent ID yet, which leaves agentId null.
func (e *mqlEdr) enrichFalconIdentity(args map[string]*llx.RawData) {
	conn, ok := e.MqlRuntime.Connection.(shared.Connection)
	if !ok || conn.Asset() == nil {
		return
	}
	applyFalconIdentity(crowdstrike.Resolve(conn, conn.Asset().Platform), args)
}

func applyFalconIdentity(id *crowdstrike.Identity, args map[string]*llx.RawData) {
	if id == nil {
		return
	}
	if id.AID != "" {
		args["agentId"] = llx.StringData(id.AID)
	}
	if id.CID != "" {
		args["tenantId"] = llx.StringData(id.CID)
	}
}

// enrichDefenderIdentity reports the Defender for Endpoint machine ID and the
// organization the sensor is onboarded to. Both stay null on a device that is
// not onboarded, since Defender Antivirus runs without the sensor.
func (e *mqlEdr) enrichDefenderIdentity(args map[string]*llx.RawData) {
	conn, ok := e.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return
	}
	applyDefenderIdentity(defender.Detect(conn), args)
}

func applyDefenderIdentity(id *defender.Identity, args map[string]*llx.RawData) {
	if id == nil {
		return
	}
	args["agentId"] = llx.StringData(id.MachineID)
	if id.OrgID != "" {
		args["tenantId"] = llx.StringData(id.OrgID)
	}
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
