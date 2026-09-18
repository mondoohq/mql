// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// DetectionResourceType is the anchor's resource type on both sides of the
// ADR 030 edge: the reverse edge written onto every discovered asset, and the
// forward answer `iac.detection.asset` serves. It is a constant rather than a
// literal in two places because the whole point of the edge is that both sides
// name the same thing.
const DetectionResourceType = "iac.detection"

// Detection is one entry point in the tree: a place a tool accepted as its own,
// or one it failed on for a reason other than not matching.
type Detection struct {
	// Tool is the opt-in's Discovery name, i.e. what --discover takes.
	Tool string
	// Path is the entry point relative to the root of the tree. The root of the
	// tree itself is "".
	Path string
	// Files are the tree-relative paths that matched.
	Files []string
	// Err is what the tool reported, empty when it connected. A tool that
	// simply did not want the candidate produces no Detection at all.
	Err string

	// asset is unexported so Asset() is the only way to it: everything that
	// needs the asset -- the inventory entry, the reverse edge, the
	// plugin.AssetSource answer -- has to come from this one field, or the edge
	// names one object and the query resolves to another.
	asset *inventory.Asset
}

// AnchorID is the detection's __id, and the anchor id on both sides of the
// edge. The opt-in's discovery name plus the tree-relative path, which is
// unique within one tree because the walk probes each opt-in at each path at
// most once -- and within one tree is all an anchor id has to be, since the
// reverse edge also names the project asset it hangs off.
func AnchorID(tool, treePath string) string {
	return tool + "\x00" + treePath
}

// AnchorID is this detection's anchor id.
func (d *Detection) AnchorID() string {
	return AnchorID(d.Tool, d.Path)
}

// NewDetection records one probe result, and is the only place the reverse edge
// is written.
//
// Forward and reverse both come out of here, which is ADR 030's one invariant:
// the asset the edge names and the asset a `detection.asset` read resolves to
// are one object rather than two descriptions of one. Drift between them is a
// silent orphan, so there is deliberately no second constructor.
//
// A non-nil err records the failure and leaves the asset nil; the caller has
// already decided that err is not a plain mismatch, which produces no detection
// at all.
func NewDetection(tool, treePath string, files []string, child *inventory.Asset, rootRef *inventory.Asset, err error) *Detection {
	d := &Detection{Tool: tool, Path: treePath, Files: files}
	if err != nil {
		d.Err = err.Error()
		return d
	}
	d.asset = child
	d.Attach(rootRef)
	return d
}

// Attach adds this detection's reverse edge to the asset it produced.
//
// Separate from NewDetection because two detections can resolve to one asset
// identity -- a folder holding both Terraform and OpenTofu files yields one
// asset, since terraform's platform ID is deliberately dialect-agnostic. The
// second detection then points at the asset the first produced and attaches its
// own anchor, so the asset carries both and either detection resolves into it.
func (d *Detection) Attach(rootRef *inventory.Asset) {
	if d.asset == nil {
		return
	}
	d.asset.Relationships = append(d.asset.Relationships, &inventory.AssetRelationship{
		Asset:        rootRef,
		ResourceType: DetectionResourceType,
		ResourceId:   d.AnchorID(),
	})
}

// AdoptAsset points this detection at an asset another detection already
// produced, and records this detection's anchor on it.
func (d *Detection) AdoptAsset(asset *inventory.Asset, rootRef *inventory.Asset) {
	d.asset = asset
	d.Attach(rootRef)
}

// Asset is the one answer to "which asset did this detection produce": the
// inventory entry the discovery layer connects, and the plugin.AssetSource
// answer for this detection's anchor. Nil when the tool reported an error.
func (d *Detection) Asset() *inventory.Asset {
	return d.asset
}

// RootRef reduces the connected project to the identity a relationship needs.
// Identity and nothing else: a relationship says which asset the edge points
// back at, never how to reach it (ADR 030).
func RootRef(root *inventory.Asset) *inventory.Asset {
	if root == nil {
		return nil
	}
	return &inventory.Asset{
		Id:          root.GetId(),
		Mrn:         root.GetMrn(),
		PlatformIds: root.GetPlatformIds(),
	}
}
