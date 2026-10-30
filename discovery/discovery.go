// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"fmt"
	"maps"

	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"google.golang.org/protobuf/proto"
)

type AssetWithRuntime struct {
	Asset   *inventory.Asset
	Runtime *providers.Runtime
}

type AssetWithError struct {
	Asset *inventory.Asset
	Err   error
}

// mergeConnectionFeatures unions the process-global CLI features
// (cli/config.Features, populated from local config/MONDOO_FEATURES) with any
// caller-supplied features (e.g. platform/server-activated ones). Both must
// reach the provider connection: connection-level features are read at Connect
// time, and the global alone never carries server-activated features.
func mergeConnectionFeatures(extra []byte) []byte {
	out := make([]byte, 0, len(config.Features)+len(extra))
	seen := make(map[byte]bool, len(config.Features)+len(extra))
	for _, f := range config.Features {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	for _, f := range extra {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func createRuntimeForAsset(asset *inventory.Asset, upstream *upstream.UpstreamConfig, recording llx.Recording, features []byte) (*AssetWithRuntime, error) {
	var runtime *providers.Runtime
	var err error
	// Close the runtime if an error occurred
	defer func() {
		if err != nil && runtime != nil {
			runtime.Close()
		}
	}()

	runtime, err = providers.Coordinator.RuntimeFor(asset, providers.DefaultRuntime())
	if err != nil {
		return nil, err
	}

	// If the runtime already has a connection, it means we have a duplicate asset
	if runtime.Provider.Connection != nil {
		return nil, nil
	}

	if err = runtime.SetRecording(recording); err != nil {
		return nil, err
	}

	err = runtime.Connect(&plugin.ConnectReq{
		Features: mergeConnectionFeatures(features),
		Asset:    asset,
		Upstream: upstream,
	})
	if err != nil {
		// Keep the provider's own message -- it says *why* this is not a match,
		// which is the only useful half -- and add the sentinel callers branch
		// on. Signalling it as a nil runtime is not available: callers read
		// that as ErrDuplicateAsset.
		if plugin.IsNoMatchError(err) {
			err = fmt.Errorf("%s: %w", err.Error(), ErrNoMatch)
		}
		return nil, err
	}

	// Clone the asset to create an independent snapshot. The runtime's connection
	// asset may be subject to mutation during subsequent provider connections, so
	// we ensure each discovered asset has its own copy of the platform metadata.
	connAsset := runtime.Provider.Connection.Asset
	clonedAsset := proto.Clone(connAsset).(*inventory.Asset)

	return &AssetWithRuntime{Asset: clonedAsset, Runtime: runtime}, nil
}

// prepareAsset prepares the asset for further processing by adding mondoo-specific labels and annotations
func prepareAsset(a *inventory.Asset, rootAsset *inventory.Asset, runtimeLabels map[string]string) {
	a.AddMondooLabels(rootAsset)
	a.AddAnnotations(rootAsset.GetAnnotations())
	a.ManagedBy = rootAsset.ManagedBy
	a.TraceId = rootAsset.TraceId
	if platform := a.GetPlatform(); platform != nil {
		a.KindString = platform.GetKind()
	}
	if a.Labels == nil {
		a.Labels = map[string]string{}
	}
	maps.Copy(a.Labels, runtimeLabels)
}
