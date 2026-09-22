// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package edr

import "strings"

// Package is an installed package as the matcher needs to see it.
type Package struct {
	Name    string
	Version string
}

// Service is a service as the matcher needs to see it. Enabled carries the
// service manager's boot-start setting, which is only meaningful where the
// platform's Signature sets BootStartReported.
type Service struct {
	Name      string
	Installed bool
	Running   bool
	Enabled   bool
}

// Process is a running process as the matcher needs to see it.
type Process struct {
	Executable string
	State      string
}

// SystemExtension is a registered macOS system extension.
type SystemExtension struct {
	Identifier string
	Version    string
	Enabled    bool
	Active     bool
}

// Inventory is everything the matcher reads about an asset. PathExists is a
// function rather than a list so that a path is only stat'ed when a catalog
// entry for the asset's platform asks for it.
type Inventory struct {
	Platform         string
	Packages         []Package
	Services         []Service
	Processes        []Process
	SystemExtensions []SystemExtension
	PathExists       func(path string) bool
}

// Detection is one recognized agent. The index slices point back into the
// Inventory that produced it, so the caller can hand out the live resources it
// already built instead of rebuilding them from names.
type Detection struct {
	Product Product

	DetectedBy         []string
	PackageIdx         []int
	ServiceIdx         []int
	ProcessIdx         []int
	SystemExtensionIdx []int

	Version string

	Running bool
	// Enabled is only meaningful when EnabledReported is true.
	Enabled         bool
	EnabledReported bool
	Healthy         bool
}

// Detect returns every catalog product found on the asset, in catalog order.
// A product with no signature for the asset's platform is never considered, so
// a Linux asset is never reported as running a Windows-only agent.
func Detect(inv Inventory) []Detection {
	var found []Detection
	for i := range Catalog {
		product := Catalog[i]
		sig, ok := product.Platforms[inv.Platform]
		if !ok {
			continue
		}
		if d, ok := match(product, sig, inv); ok {
			found = append(found, d)
		}
	}
	return found
}

func match(product Product, sig Signature, inv Inventory) (Detection, bool) {
	d := Detection{Product: product}

	for i := range inv.Packages {
		if matchesPackage(sig, inv.Packages[i].Name) {
			d.PackageIdx = append(d.PackageIdx, i)
			if d.Version == "" {
				d.Version = inv.Packages[i].Version
			}
		}
	}

	pathFound := false
	if inv.PathExists != nil {
		for _, p := range sig.Paths {
			if inv.PathExists(p) {
				pathFound = true
				break
			}
		}
	}

	for i := range inv.SystemExtensions {
		for _, id := range sig.SystemExtensions {
			if inv.SystemExtensions[i].Identifier == id {
				d.SystemExtensionIdx = append(d.SystemExtensionIdx, i)
				if d.Version == "" {
					d.Version = inv.SystemExtensions[i].Version
				}
				break
			}
		}
	}

	named, namedFound := matchNamedServices(sig, inv)
	patterned := matchPatternedServices(sig, inv)
	d.ServiceIdx = append(append([]int{}, named...), patterned...)
	if len(d.ServiceIdx) == 0 {
		d.ServiceIdx = nil
	}

	for i := range inv.Processes {
		if sig.ProcessPattern != nil && sig.ProcessPattern.MatchString(inv.Processes[i].Executable) {
			d.ProcessIdx = append(d.ProcessIdx, i)
		}
	}

	// Install evidence, recorded in a fixed order so the field reads the same
	// across runs.
	if len(d.PackageIdx) > 0 {
		d.DetectedBy = append(d.DetectedBy, SignalPackage)
	}
	if pathFound {
		d.DetectedBy = append(d.DetectedBy, SignalPath)
	}
	if len(d.SystemExtensionIdx) > 0 {
		d.DetectedBy = append(d.DetectedBy, SignalSystemExtension)
	}
	if anyInstalled(inv, d.ServiceIdx) {
		d.DetectedBy = append(d.DetectedBy, SignalService)
	}
	if len(d.ProcessIdx) > 0 {
		d.DetectedBy = append(d.DetectedBy, SignalProcess)
	}
	if len(d.DetectedBy) == 0 {
		return Detection{}, false
	}

	switch sig.RunVia {
	case RunViaSystemExtensions:
		d.Running = anyExtension(inv, d.SystemExtensionIdx, func(e SystemExtension) bool {
			return e.Enabled && e.Active
		})
		d.Enabled = anyExtension(inv, d.SystemExtensionIdx, func(e SystemExtension) bool {
			return e.Enabled
		})
	case RunViaProcesses:
		for _, i := range d.ProcessIdx {
			// A zombie has exited and is only waiting to be reaped, so it
			// proves nothing about the agent still running.
			if inv.Processes[i].State != "zombie" {
				d.Running = true
				break
			}
		}
	default:
		d.Running, d.Enabled = runState(sig, inv, named, namedFound, patterned)
	}

	d.EnabledReported = sig.BootStartReported
	d.Healthy = d.Running && (!d.EnabledReported || d.Enabled)

	return d, true
}

// runState reports whether every component the agent needs is running, and
// whether every one is set to start at boot. A named service that is not
// present at all cannot be proven to run, so its absence is a false rather
// than a skipped requirement.
func runState(sig Signature, inv Inventory, named []int, namedFound bool, patterned []int) (running, enabled bool) {
	if len(sig.Services) == 0 && sig.ServicePattern == nil {
		return false, false
	}

	running, enabled = true, true

	if len(sig.Services) > 0 {
		if !namedFound {
			return false, false
		}
		for _, i := range named {
			if !inv.Services[i].Running {
				running = false
			}
			if !inv.Services[i].Enabled {
				enabled = false
			}
		}
	}

	// A pattern stands for a family of services whose exact names carry a
	// version or instance suffix, so one healthy member satisfies it.
	if sig.ServicePattern != nil {
		if len(patterned) == 0 {
			return false, false
		}
		anyRunning, anyEnabled := false, false
		for _, i := range patterned {
			if inv.Services[i].Running {
				anyRunning = true
			}
			if inv.Services[i].Enabled {
				anyEnabled = true
			}
		}
		running = running && anyRunning
		enabled = enabled && anyEnabled
	}

	return running, enabled
}

// matchNamedServices resolves every name in sig.Services. namedFound is false
// when any of them is missing from the inventory.
func matchNamedServices(sig Signature, inv Inventory) (idx []int, namedFound bool) {
	for _, name := range sig.Services {
		found := false
		for i := range inv.Services {
			if sameServiceName(inv.Platform, inv.Services[i].Name, name) {
				idx = append(idx, i)
				found = true
				break
			}
		}
		if !found {
			return idx, false
		}
	}
	return idx, true
}

// matchPatternedServices applies the pattern to the same normalized name that
// matchNamedServices compares against, so a pattern anchored at the end still
// matches a systemd unit written with its optional .service suffix. Case is
// left to the pattern, which can ask for (?i) where a platform needs it.
func matchPatternedServices(sig Signature, inv Inventory) []int {
	if sig.ServicePattern == nil {
		return nil
	}
	var idx []int
	for i := range inv.Services {
		if sig.ServicePattern.MatchString(normalizeServiceName(inv.Services[i].Name)) {
			idx = append(idx, i)
		}
	}
	return idx
}

func matchesPackage(sig Signature, name string) bool {
	for _, want := range sig.Packages {
		if strings.EqualFold(name, want) {
			return true
		}
	}
	return sig.PackagePattern != nil && sig.PackagePattern.MatchString(name)
}

func anyInstalled(inv Inventory, idx []int) bool {
	for _, i := range idx {
		if inv.Services[i].Installed {
			return true
		}
	}
	return false
}

func anyExtension(inv Inventory, idx []int, pred func(SystemExtension) bool) bool {
	for _, i := range idx {
		if pred(inv.SystemExtensions[i]) {
			return true
		}
	}
	return false
}

// sameServiceName compares service names the way the service resource looks
// them up: systemd's optional .service suffix is not part of the identity, and
// only Windows service names are case insensitive. systemd units and launchd
// labels are case sensitive, so folding there could claim the wrong unit.
func sameServiceName(platform, a, b string) bool {
	a, b = normalizeServiceName(a), normalizeServiceName(b)
	if platform == PlatformWindows {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// normalizeServiceName drops systemd's optional unit suffix, which the service
// resource also treats as no part of a service's identity.
func normalizeServiceName(name string) string {
	return strings.TrimSuffix(name, ".service")
}
