// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"slices"

	"github.com/rs/zerolog/log"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// Apply copies the static fields of the descriptor onto a runtime platform.
//
// Name and Family always come from the descriptor. Title is only set as a
// default (a title already set at runtime wins). Kind and Runtime are set only
// when the descriptor declares exactly one possible value; when several are
// possible (the OS case) the connection-set value is left untouched, since the
// connection is the sole authority for which one applies.
func (pi *PlatformInfo) Apply(p *inventory.Platform) {
	if pi == nil {
		// A nil descriptor means a caller passed a platform name that is not in
		// the provider's catalog (typically a typo in a PlatformByName argument).
		// Log it and fall back to an unknown platform instead of crashing.
		log.Error().Msg("plugin.PlatformInfo.Apply called on a nil descriptor: the platform name is not present in the provider catalog")
		p.Name = "unknown"
		p.Title = "Unknown"
		p.Kind = "unknown"
		p.Runtime = "unknown"
		return
	}
	p.Name = pi.Name
	if p.Title == "" {
		p.Title = pi.Title
	}
	if len(pi.Family) > 0 {
		p.Family = slices.Clone(pi.Family)
	}
	if len(pi.Kind) == 1 {
		p.Kind = pi.Kind[0]
	}
	if len(pi.Runtime) == 1 {
		p.Runtime = pi.Runtime[0]
	}
}

// Consistent reports whether a runtime platform matches this descriptor: its
// kind must be a member of the possible Kind set and its runtime a member of
// the possible Runtime set. An empty set means that field is unconstrained.
// Used by per-provider tests to guard against drift between the catalog and the
// platforms the runtime actually emits.
func (pi *PlatformInfo) Consistent(p *inventory.Platform) bool {
	if len(pi.Kind) > 0 && p.Kind != "" && !slices.Contains(pi.Kind, p.Kind) {
		return false
	}
	if len(pi.Runtime) > 0 && p.Runtime != "" && !slices.Contains(pi.Runtime, p.Runtime) {
		return false
	}
	return true
}

// PlatformsByName indexes a platform catalog by name. Helper for providers that
// want a lookup map from their declared Platforms slice.
func PlatformsByName(platforms []*PlatformInfo) map[string]*PlatformInfo {
	m := make(map[string]*PlatformInfo, len(platforms))
	for _, p := range platforms {
		m[p.Name] = p
	}
	return m
}
