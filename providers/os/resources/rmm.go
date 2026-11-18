// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/edr"
	"go.mondoo.com/mql/providers/os/resources/rmm"
	"go.mondoo.com/mql/types"
)

// The cache fields carry a prefix because the generated accessors already own
// the bare names (products, services, packages, processes).
type mqlRmmInternal struct {
	lock           sync.Mutex
	cacheResolved  bool
	cacheProducts  []any
	cachePackages  []any
	cacheServices  []any
	cacheProcesses []any
}

type mqlRmmProductInternal struct {
	cacheServices  []any
	cachePackages  []any
	cacheProcesses []any
}

func (r *mqlRmm) id() (string, error) {
	return "rmm", nil
}

func (r *mqlRmm) products() ([]any, error) {
	return r.detect()
}

func (r *mqlRmm) installed() (bool, error) {
	products, err := r.detect()
	if err != nil {
		return false, err
	}
	return len(products) > 0, nil
}

func (r *mqlRmm) healthy() (bool, error) {
	products, err := r.detect()
	if err != nil {
		return false, err
	}
	// An asset with no agent is not healthy. Reporting true here would make
	// the assertion pass on exactly the asset it exists to find.
	if len(products) == 0 {
		return false, nil
	}
	for i := range products {
		if !products[i].(*mqlRmmProduct).Healthy.Data {
			return false, nil
		}
	}
	return true, nil
}

// detect resolves the catalog against the asset once and memoizes the result,
// so products, installed and healthy share a single pass over the package and
// service lists rather than taking one each.
func (r *mqlRmm) detect() ([]any, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.cacheResolved {
		return r.cacheProducts, nil
	}

	platform := agentPlatform(r.MqlRuntime)
	if platform == "" {
		r.cacheResolved = true
		r.cacheProducts = []any{}
		return r.cacheProducts, nil
	}

	inv := readAgentInventory(r.MqlRuntime, platform, rmm.Catalog)
	r.cachePackages = inv.packages
	r.cacheServices = inv.services
	r.cacheProcesses = inv.processes

	products := []any{}
	for _, d := range rmm.Detect(inv.Inventory) {
		product, err := r.newProduct(d)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	r.cacheProducts = products
	r.cacheResolved = true
	return r.cacheProducts, nil
}

func (r *mqlRmm) newProduct(d edr.Detection) (*mqlRmmProduct, error) {
	var enabled *bool
	if d.EnabledReported {
		enabled = &d.Enabled
	}

	var version *string
	if d.Version != "" {
		version = &d.Version
	}

	raw, err := CreateResource(r.MqlRuntime, "rmm.product", map[string]*llx.RawData{
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
	})
	if err != nil {
		return nil, err
	}

	product := raw.(*mqlRmmProduct)
	product.cacheServices = pickResources(r.cacheServices, d.ServiceIdx)
	product.cachePackages = pickResources(r.cachePackages, d.PackageIdx)
	product.cacheProcesses = pickResources(r.cacheProcesses, d.ProcessIdx)
	return product, nil
}

func (p *mqlRmmProduct) id() (string, error) {
	return p.Id.Data, nil
}

func (p *mqlRmmProduct) services() ([]any, error) {
	return p.cacheServices, nil
}

func (p *mqlRmmProduct) packages() ([]any, error) {
	return p.cachePackages, nil
}

func (p *mqlRmmProduct) processes() ([]any, error) {
	return p.cacheProcesses, nil
}
