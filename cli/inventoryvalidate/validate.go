// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package inventoryvalidate checks an inventory file against the schema of the
// providers that handle its connections. A connection's option keys must match
// the long names of the flags its provider declares; an option key that no
// provider accepts is almost always a typo (e.g. "tenantId" instead of
// "tenant-id") that would otherwise be silently ignored at connect time.
package inventoryvalidate

import (
	"fmt"
	"sort"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Severity classifies a finding. Unknown option keys and uninstalled
// connection types are warnings by default and become errors under strict mode.
type Severity int

const (
	SeverityWarning Severity = iota
	SeverityError
)

func (s Severity) String() string {
	if s == SeverityError {
		return "error"
	}
	return "warning"
}

// Finding is a single validation problem with one connection.
type Finding struct {
	// Asset is a human-readable label for the asset (its id, name, or index).
	Asset string
	// Connection is the index of the connection within the asset.
	Connection int
	// Type is the connection type that was validated.
	Type string
	// Severity is error or warning.
	Severity Severity
	// Message describes the problem.
	Message string
}

// Schema is the set of option keys each connection type accepts, derived from
// installed providers' static plugin metadata. It is built once and reused
// across connections.
type Schema struct {
	// optionKeys maps a connection type to the set of option keys (flag long
	// names) the resolving provider accepts. The value is the union of the
	// provider's connector flags, which avoids false positives when a provider
	// exposes several connectors for the same type.
	optionKeys map[string]map[string]struct{}
}

// BuildSchema derives the option-key schema from the given providers' static
// metadata. No provider is connected to; only the declared connectors and
// flags are read, so this works offline.
//
// A connection type is associated with a provider through the provider's
// ConnectionTypes list and through each connector's Name and Aliases — the
// same resolution the CLI uses to attach a provider to a connection.
func BuildSchema(provs []*plugin.Provider) *Schema {
	s := &Schema{optionKeys: map[string]map[string]struct{}{}}
	for _, p := range provs {
		if p == nil {
			continue
		}

		// The union of every connector flag long name this provider declares.
		keys := map[string]struct{}{}
		for i := range p.Connectors {
			for _, f := range p.Connectors[i].Flags {
				if f.Long != "" {
					keys[f.Long] = struct{}{}
				}
			}
		}

		// Every connection type string this provider answers to.
		types := map[string]struct{}{}
		for _, t := range p.ConnectionTypes {
			if t != "" {
				types[t] = struct{}{}
			}
		}
		for i := range p.Connectors {
			if p.Connectors[i].Name != "" {
				types[p.Connectors[i].Name] = struct{}{}
			}
			for _, a := range p.Connectors[i].Aliases {
				if a != "" {
					types[a] = struct{}{}
				}
			}
		}

		for t := range types {
			allowed, ok := s.optionKeys[t]
			if !ok {
				allowed = map[string]struct{}{}
				s.optionKeys[t] = allowed
			}
			for k := range keys {
				allowed[k] = struct{}{}
			}
		}
	}
	return s
}

// Check validates every connection in the inventory against the schema. Option
// keys not accepted by the connection's provider, and connection types not
// handled by any installed provider, are returned as findings. Findings are
// warnings unless strict is set, in which case they are errors. The result is
// ordered (by asset, then connection, then message) for stable output.
func Check(inv *inventory.Inventory, schema *Schema, strict bool) []Finding {
	var findings []Finding
	if inv == nil || inv.Spec == nil || schema == nil {
		return findings
	}

	sev := SeverityWarning
	if strict {
		sev = SeverityError
	}

	for ai, asset := range inv.Spec.Assets {
		if asset == nil {
			continue
		}
		label := assetLabel(asset, ai)
		for ci, conn := range asset.Connections {
			if conn == nil {
				continue
			}

			allowed, known := schema.optionKeys[conn.Type]
			if !known {
				findings = append(findings, Finding{
					Asset:      label,
					Connection: ci,
					Type:       conn.Type,
					Severity:   sev,
					Message: fmt.Sprintf(
						"connection type %q is not provided by any installed provider; its options cannot be validated (is the provider installed?)",
						conn.Type),
				})
				continue
			}

			// Sort the keys so the findings are deterministic.
			keys := make([]string, 0, len(conn.Options))
			for k := range conn.Options {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if _, ok := allowed[k]; !ok {
					findings = append(findings, Finding{
						Asset:      label,
						Connection: ci,
						Type:       conn.Type,
						Severity:   sev,
						Message:    fmt.Sprintf("unknown option %q for connection type %q", k, conn.Type),
					})
				}
			}
		}
	}
	return findings
}

func assetLabel(asset *inventory.Asset, idx int) string {
	if asset.Id != "" {
		return asset.Id
	}
	if asset.Name != "" {
		return asset.Name
	}
	return fmt.Sprintf("#%d", idx)
}
