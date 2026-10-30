// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// AssetSource is implemented by a resource that stands for another asset:
// `claude.code.mcpServer` for the MCP server it configures, `docker.container`
// for the container it describes (ADR 031).
//
// A query reaches such an asset through a field typed `asset<root>`, whose value
// is only the anchor `(resourceType, resourceId)` - identity, and nothing else,
// because that value persists into recordings and upstream (ADR 030). Actually
// connecting needs to know how to *reach* the asset, which is not identity and
// is not stored. The host asks for it here, at the moment it connects.
//
// Only the owning provider can answer, and that is the point: it builds the
// connection from the resource with the same code its discovery uses, so the
// asset a query resolves into and the asset discovery would have produced
// cannot drift apart.
//
// Return a nil asset with no error when this particular instance has nothing to
// connect to - an MCP server config with neither a command nor a url, say. That
// is an ordinary state, not a failure.
type AssetSource interface {
	// MqlAsset returns the asset this resource stands for, carrying the
	// connection needed to reach it. No secrets: a connection config says how
	// to start or reach a target, and credentials are supplied per-connect by
	// whoever is doing the connecting.
	MqlAsset() (*inventory.Asset, error)
}

// ResolveAsset answers for any provider whose resources implement AssetSource.
//
// It reads the resource out of the connection's own resource cache rather than
// creating one: the caller is resolving an anchor it got from reading a field on
// that exact instance, so it is already there, and re-creating it could run an
// init and hit the target again for data we already have.
func (s *Service) ResolveAsset(req *ResolveAssetReq) (*ResolveAssetRes, error) {
	if req == nil || req.ResourceType == "" {
		return &ResolveAssetRes{}, nil
	}

	runtime, err := s.GetRuntime(req.Connection)
	if err != nil {
		return nil, err
	}

	resource, ok := runtime.Resources.Get(req.ResourceType + "\x00" + req.ResourceId)
	if !ok {
		// Not an error: the anchor may belong to a different connection of this
		// same provider, or to a resource that has since been evicted. The
		// caller reports what it could not reach.
		return &ResolveAssetRes{}, nil
	}

	source, ok := resource.(AssetSource)
	if !ok {
		return &ResolveAssetRes{}, nil
	}

	asset, err := source.MqlAsset()
	if err != nil {
		return nil, err
	}
	return &ResolveAssetRes{Asset: asset}, nil
}
