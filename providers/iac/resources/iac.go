// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/iac/connection"
	"go.mondoo.com/mql/types"
)

// mqlIacDetectionInternal carries the walk's own record for this detection.
//
// The resource reads the asset from here rather than rebuilding one, so the
// asset the reverse edge names and the asset a `detection.asset` read resolves
// to are the same object (ADR 030).
type mqlIacDetectionInternal struct {
	detection *connection.Detection
}

func iacConnection(runtime *plugin.Runtime) (*connection.IacConnection, error) {
	conn, ok := runtime.Connection.(*connection.IacConnection)
	if !ok {
		return nil, errors.New("wrong connection type for the iac resource")
	}
	return conn, nil
}

// id is stable across a connection because the project's platform ID is the
// hash of the tree's absolute path.
func (c *mqlIac) id() (string, error) {
	conn, err := iacConnection(c.MqlRuntime)
	if err != nil {
		return "", err
	}
	return "iac/" + conn.Source().Origin, nil
}

func (c *mqlIac) source() (*mqlIacSource, error) {
	conn, err := iacConnection(c.MqlRuntime)
	if err != nil {
		return nil, err
	}

	source := conn.Source()
	res, err := CreateResource(c.MqlRuntime, "iac.source", map[string]*llx.RawData{
		"__id":   llx.StringData("iac.source/" + source.Origin),
		"kind":   llx.StringData(source.Kind),
		"origin": llx.StringData(source.Origin),
		"ref":    llx.StringData(source.Ref),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlIacSource), nil
}

func (c *mqlIac) detections() ([]any, error) {
	conn, err := iacConnection(c.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, detection := range conn.Detections() {
		resource, err := newDetectionResource(c.MqlRuntime, detection)
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

// newDetectionResource creates the resource for one detection. Connect calls it
// for every detection up front, so an anchor resolves through
// plugin.Service.ResolveAsset whatever the query happened to read: ResolveAsset
// looks the resource up in the cache and never creates one.
//
// CreateResource returns the cached instance for a repeated __id, so building
// the same detections again from `iac.detections` is idempotent.
func newDetectionResource(runtime *plugin.Runtime, detection *connection.Detection) (*mqlIacDetection, error) {
	resource, err := CreateResource(runtime, "iac.detection", map[string]*llx.RawData{
		"__id":  llx.StringData(detection.AnchorID()),
		"tool":  llx.StringData(detection.Tool),
		"path":  llx.StringData(detection.Path),
		"files": llx.ArrayData(convert.SliceAnyToInterface(detection.Files), types.String),
		"error": llx.StringData(detection.Err),
	})
	if err != nil {
		return nil, err
	}

	res := resource.(*mqlIacDetection)
	res.detection = detection
	return res, nil
}

// asset is the anchor for the asset this tool made of the entry point.
//
// It answers with the anchor and nothing else -- identity, never how to reach
// the thing -- because this value persists into recordings and upstream (ADR
// 030). The connection is asked for at connect time, in MqlAsset.
//
// A detection the tool failed on has no asset, so it answers null:
// `iac.detections.where(asset == null)` is how you ask which entry points could
// not be read.
func (c *mqlIacDetection) asset() (*llx.AssetValue, error) {
	if c.detection == nil || c.detection.Asset() == nil {
		// Without this the runtime does not know the field resolved, and the
		// read is reported as a provider that returned neither data nor error.
		c.Asset.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return &llx.AssetValue{
		ResourceType: c.MqlName(),
		ResourceId:   c.MqlID(),
	}, nil
}

// MqlAsset implements plugin.AssetSource: the asset behind this detection's
// anchor, with the connection needed to reach it.
//
// It is the same object the inventory carried, because both come from the one
// Detection the walk built (ADR 030's invariant). A detection that failed has
// nothing to connect to, which is an ordinary state rather than an error.
func (c *mqlIacDetection) MqlAsset() (*inventory.Asset, error) {
	if c.detection == nil {
		return nil, nil
	}
	return c.detection.Asset(), nil
}

// CreateDetectionResources builds the resource for every detection up front.
//
// It is called from Connect rather than left to the first read of
// `iac.detections`, because plugin.Service.ResolveAsset answers an anchor from
// the resource cache and never creates: without this, `detection.asset` would
// resolve only when a query happened to have listed the detections first. The
// data is already computed, so this costs nothing, and CreateResource returns
// the cached instance for a repeated __id, so a later `iac.detections` read
// builds the same objects rather than a second set.
func CreateDetectionResources(runtime *plugin.Runtime, detections []*connection.Detection) error {
	for _, detection := range detections {
		if _, err := newDetectionResource(runtime, detection); err != nil {
			return err
		}
	}
	return nil
}
