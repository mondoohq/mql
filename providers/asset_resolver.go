// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/recording"
)

// Cross-asset resolution (ADR 031). A query reaches another asset through a
// typed `asset<root>` value, and llx hands it here because llx cannot connect:
// a builtin sees only its runtime, which has no coordinator. This file is the
// host side of that - find the target asset, get a runtime for it, hand back
// its root resource.
//
// The backing is not a second mechanism. Recorded and live resolution are the
// same `RuntimeFor` + `Connect` path with a different connection on the target
// asset; this phase builds the recorded one, where the target carries a `mock`
// connection and answers from the recording the parent already holds.

// maxAssetResolveDepth bounds a chain of resolutions. A per-runtime cache stops
// a single asset being connected twice, but not an A -> B -> A cycle across
// runtimes, because each hop is a legitimate cache miss on a different runtime.
const maxAssetResolveDepth = 5

// defaultAssetReachTimeout bounds each step of reaching another asset: asking
// its provider how to get there, and connecting to it.
//
// This is a backstop, not the primary bound. A provider that talks to something
// remote is expected to bound its own connect - the ai provider gives an MCP
// server 60s - and it can say far more about what went wrong than a caller
// counting seconds. What this stops is a provider that bounds nothing taking a
// query down with it: the field read that reached for the asset is blocked on
// this call, and above it sits a whole scan.
//
// So it is deliberately generous: long enough that a provider's own timeout
// fires first and reports the real reason, short enough to be a bound.
const defaultAssetReachTimeout = 2 * time.Minute

// ResolveAssetRoot implements llx.AssetResolver.
func (r *Runtime) ResolveAssetRoot(v *llx.AssetValue, root string) (llx.Resource, error) {
	if v == nil {
		return nil, errors.New("cannot resolve an empty asset reference")
	}
	if root == "" {
		return nil, errors.New("cannot resolve asset " + anchorLabel(v) + ": no root resource requested")
	}

	sub, err := r.runtimeForAnchor(v)
	if err != nil {
		return nil, err
	}

	resource, err := sub.CreateResource(root, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read "+root+" on asset "+anchorLabel(v))
	}

	// The resource carries the runtime that answers it, so every field read
	// above this point routes to the target asset without llx knowing anything
	// about assets.
	return llx.BindResource(resource, sub), nil
}

// runtimeForAnchor returns the runtime for the asset an anchor points at,
// connecting it on first use.
//
// The cache is keyed on the anchor rather than on asset identity because a
// discovered asset has neither an MRN nor platform ids until its provider's
// Connect assigns them - so coordinator dedupe (coordinator.go:191) cannot see
// that two resolutions mean the same asset, and `mcpServers.map(running.tools)`
// would open one connection per server without this.
func (r *Runtime) runtimeForAnchor(v *llx.AssetValue) (*Runtime, error) {
	return r.connectedRuntime(v.ResourceType+"\x00"+v.ResourceId, anchorLabel(v),
		func() (*inventory.Asset, error) { return r.targetAssetForAnchor(v) })
}

// RuntimeForAsset connects another asset and returns a runtime for it, owned by
// this one.
//
// This is the same path a query takes when it resolves an `asset<root>` value,
// for a caller that already has the asset and needs no anchor to find it: an
// embedder correlating two systems, a tool that discovered something and wants
// to query it. It is exposed rather than reimplemented because a second connect
// path would skip everything this one guarantees - one connection per target
// however many times it is asked for, recording-first ordering, teardown with
// the parent, and a bound on a target that never answers. Assets reached by a
// parallel path would also be invisible to replay.
//
// `key` is what two calls meaning the same asset must agree on. It is not
// derived from the asset because a freshly built one often has no identity yet:
// an MRN and platform ids are assigned by the connect this call is about to
// make, so keying on them would connect the same target once per call. A
// resource anchor, a container id, an image digest - anything stable to the
// caller - is the right key.
//
// A provider that wants to expose another asset to *queries* should not use
// this. Declare a field typed `asset<root>` and implement plugin.AssetSource;
// the engine then reaches it the same way, and the value stays queryable and
// chainable rather than being a Go object only its author can see.
func (r *Runtime) RuntimeForAsset(key string, asset *inventory.Asset) (*Runtime, error) {
	if key == "" {
		return nil, errors.New("cannot connect an asset without a key to dedupe it by")
	}
	if asset == nil || len(asset.Connections) == 0 {
		return nil, errors.New("cannot connect asset " + key + ": no connection to reach it by")
	}
	return r.connectedRuntime(key, assetLabel(asset), func() (*inventory.Asset, error) { return asset, nil })
}

// connectedRuntime is the one implementation behind both: find the target, get a
// runtime for it, connect it, and hand it to the parent to own.
func (r *Runtime) connectedRuntime(key string, label string, find func() (*inventory.Asset, error)) (*Runtime, error) {
	r.mu.Lock()
	if sub, ok := r.resolvedAssets[key]; ok {
		r.mu.Unlock()
		return sub, nil
	}
	// Copied, not aliased: the error below appends to this, and appending to a
	// slice that shares another runtime's backing array writes into storage we
	// no longer hold the lock for. Nothing observes that write today - it lands
	// past every reader's length - but it is one growth of the chain away from
	// being a real race, and the write side already copies for the same reason.
	chain := append([]string{}, r.resolveChain...)
	r.mu.Unlock()

	if len(chain) >= maxAssetResolveDepth {
		return nil, errors.New("cannot resolve asset " + label + ": resolution nested too deeply (" +
			strings.Join(append(chain, label), " -> ") + ")")
	}

	var target *inventory.Asset
	err := r.bounded("resolving", label, func() error {
		var err error
		target, err = find()
		return err
	})
	if err != nil {
		return nil, err
	}

	sub, err := r.coordinator.RuntimeFor(target, r)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create a runtime for asset "+label)
	}

	// RuntimeFor may hand back an already-connected runtime when the target
	// deduped onto one the coordinator knows.
	if sub.Provider == nil || sub.Provider.Connection == nil {
		if err := r.connectTarget(sub, target, label); err != nil {
			return nil, err
		}
	}

	sub.mu.Lock()
	sub.resolveChain = append(append([]string{}, chain...), label)
	sub.mu.Unlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	// Another goroutine may have resolved the same anchor while this one was
	// connecting. Keep the first and drop ours rather than leaking it.
	if existing, ok := r.resolvedAssets[key]; ok {
		go sub.Close()
		return existing, nil
	}
	if r.resolvedAssets == nil {
		r.resolvedAssets = map[string]*Runtime{}
	}
	r.resolvedAssets[key] = sub
	// Sub-runtimes are owned by the parent and torn down with it, rather than
	// left for the coordinator to reap.
	r.subRuntimes = append(r.subRuntimes, sub)
	return sub, nil
}

// targetAssetForAnchor finds the asset an anchor points at and builds the stub
// to connect it with.
//
// The lookup runs over the **reverse edge**: discovery writes an
// inventory.AssetRelationship on the discovered asset naming the resource on
// its parent that anchors it (ADR 030), and this is the first consumer of that
// edge at runtime. Nothing about the parent's own tree is consulted, which is
// what keeps forward and reverse in agreement by construction.
func (r *Runtime) targetAssetForAnchor(v *llx.AssetValue) (*inventory.Asset, error) {
	target, err := r.recordedTargetForAnchor(v)
	if err != nil || target != nil {
		return target, err
	}

	// Nothing recorded, so ask the provider that owns the anchor resource. Only
	// it can say how to reach the asset: the value carries identity and never
	// reachability (ADR 030), so reachability is fetched at the moment it is
	// needed and is not stored.
	return r.liveTargetForAnchor(v)
}

// recordedTargetForAnchor finds a target asset in the recording, over the
// **reverse edge**: discovery writes an inventory.AssetRelationship on the
// discovered asset naming the resource on its parent that anchors it (ADR 030),
// and this is the first consumer of that edge at runtime. Nothing about the
// parent's own tree is consulted, which is what keeps forward and reverse in
// agreement by construction.
//
// Returns nil, nil when the recording holds no such asset, which includes every
// live scan. Recording first: a replayed asset must answer from what was
// recorded rather than reconnecting to something that may no longer exist.
func (r *Runtime) recordedTargetForAnchor(v *llx.AssetValue) (*inventory.Asset, error) {
	multi, ok := r.Recording().(recording.MultiAsset)
	if !ok {
		return nil, nil
	}

	self := r.asset()
	var matches []*inventory.Asset
	var exact *inventory.Asset
	for _, candidate := range multi.GetAssetRecordings() {
		if candidate == nil || candidate.Asset == nil {
			continue
		}
		for _, rel := range candidate.Asset.Relationships {
			if rel == nil || rel.ResourceType != v.ResourceType || rel.ResourceId != v.ResourceId {
				continue
			}
			matches = append(matches, candidate.Asset)
			if self != nil && rel.Asset != nil && sameAsset(rel.Asset, self) {
				exact = candidate.Asset
			}
			break
		}
	}

	// An anchor id is only unique within one parent, so several recorded assets
	// can carry the same anchor when the recording holds several hosts. The edge
	// that names *this* asset as the parent is the right one.
	target := exact
	if target == nil {
		switch len(matches) {
		case 0:
			// Not recorded. The caller asks the provider instead.
			return nil, nil
		case 1:
			target = matches[0]
		default:
			// Ambiguity is an error rather than a fall-through to a live
			// connect: the recording does hold the answer, we just cannot tell
			// which one it is, and guessing would connect the wrong asset.
			return nil, errors.New("cannot resolve asset " + anchorLabel(v) +
				": several recorded assets are anchored on it and none names this asset as its parent")
		}
	}

	// A mock connection is what makes this the recorded leg: the mock provider
	// looks the asset up in the recording the parent already holds and mock-
	// connects the provider that actually owns it. The live leg is the same
	// call with the target's real connection instead.
	return &inventory.Asset{
		Name:        target.Name,
		Mrn:         target.Mrn,
		PlatformIds: target.PlatformIds,
		Connections: []*inventory.Config{{
			Type: "mock",
		}},
	}, nil
}

// liveTargetForAnchor asks the provider that owns the anchor resource for the
// asset it stands for.
//
// This is the half that cannot come from the value. An `asset` value carries the
// anchor and nothing else, because it persists into recordings and upstream and
// identity is all that belongs in the stored data model (ADR 030). Reaching the
// asset needs a connection config, which is not identity - so it is asked for
// here, once, immediately before connecting, and never stored.
//
// The provider answers from the resource instance the caller just read the
// anchor off, using the same code its discovery uses, so the asset a query
// resolves into and the asset a scan would have discovered are the same asset.
func (r *Runtime) liveTargetForAnchor(v *llx.AssetValue) (*inventory.Asset, error) {
	provider, _, err := r.lookupResourceProvider(v.ResourceType)
	if err != nil {
		return nil, errors.Wrap(err, "cannot resolve asset "+anchorLabel(v))
	}
	if provider == nil || provider.Connection == nil {
		return nil, errors.New("cannot resolve asset " + anchorLabel(v) +
			": no connected provider owns " + v.ResourceType)
	}

	res, err := provider.Instance.Plugin.ResolveAsset(&plugin.ResolveAssetReq{
		Connection:   provider.Connection.Id,
		ResourceType: v.ResourceType,
		ResourceId:   v.ResourceId,
	})
	if err != nil {
		return nil, errors.Wrap(err, "cannot resolve asset "+anchorLabel(v))
	}

	target := res.GetAsset()
	if target == nil {
		return nil, errors.New("cannot resolve asset " + anchorLabel(v) +
			": " + v.ResourceType + " has no asset to connect to")
	}
	if len(target.Connections) == 0 {
		return nil, errors.New("cannot resolve asset " + anchorLabel(v) +
			": the provider returned an asset with no connection")
	}
	return target, nil
}

// closeSubRuntimes tears down the runtimes this one opened for other assets.
func (r *Runtime) closeSubRuntimes() {
	r.mu.Lock()
	subs := r.subRuntimes
	r.subRuntimes = nil
	r.resolvedAssets = nil
	r.mu.Unlock()

	for _, sub := range subs {
		if sub == nil || sub == r {
			continue
		}
		log.Debug().Msg("closing a runtime opened for cross-asset resolution")
		sub.Close()
	}
}

// sameAsset reports whether two asset references describe the same asset, using
// the identifiers the coordinator dedupes on (coordinator.go:191) and falling
// back to the name for a stub that carries neither.
func sameAsset(a *inventory.Asset, b *inventory.Asset) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Mrn != "" && a.Mrn == b.Mrn {
		return true
	}
	for _, id := range a.PlatformIds {
		if slices.Contains(b.PlatformIds, id) {
			return true
		}
	}
	if a.Mrn != "" || b.Mrn != "" || len(a.PlatformIds) > 0 || len(b.PlatformIds) > 0 {
		// Both sides carry a real identifier and they did not match. Falling
		// through to the name here would let two different assets that happen
		// to share a display name look like one.
		return false
	}
	return a.Name != "" && a.Name == b.Name
}

// anchorLabel names an anchor for an error message.
func anchorLabel(v *llx.AssetValue) string {
	if v == nil {
		return "<none>"
	}
	if v.ResourceId == "" {
		return v.ResourceType
	}
	return v.ResourceType + " (" + v.ResourceId + ")"
}

// connectTarget connects sub to the target asset, bounded.
//
// On timeout the connect is still running and still owns sub, so closing it
// here would race a provider that is mid-handshake. Ownership passes to a
// watcher that closes it once the connect finally returns - which is the whole
// point of bounding rather than abandoning: the caller stops waiting, but the
// runtime and the provider process behind it still get torn down.
func (r *Runtime) connectTarget(sub *Runtime, target *inventory.Asset, label string) error {
	done := make(chan error, 1)
	go func() {
		// SetRecording after the provider is selected and before connecting, as
		// discovery does (discovery.go:71): the sub-runtime resolves the target
		// asset out of the recording its parent already holds.
		//
		// Nothing needs serializing here. The builtin mock service is one
		// instance shared by every runtime, but it takes the runtime from the
		// connect callback rather than from a field, so two resolutions can
		// connect at once without reading each other's state.
		err := sub.SetRecording(r.Recording())
		if err == nil {
			err = sub.Connect(&plugin.ConnectReq{
				Asset:    target,
				Features: r.features,
				Upstream: r.UpstreamConfig,
			})
		}
		done <- err
	}()

	timeout := r.assetReachTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		if err != nil {
			sub.Close()
			return errors.Wrap(err, "cannot connect to asset "+label)
		}
		return nil
	case <-timer.C:
		go func() {
			<-done
			sub.Close()
		}()
		return errors.New("cannot connect to asset " + label + ": timed out after " + timeout.String())
	}
}

// bounded runs one step of reaching another asset under the same bound.
//
// A step that overruns is abandoned rather than cancelled: the plugin interface
// carries no context, so there is nothing to cancel through. The goroutine ends
// when the provider finally answers. That is acceptable for a backstop - it
// leaks one goroutine on a provider that was already misbehaving - and is why
// connecting, which leaves a runtime and a process behind, gets the cleanup in
// connectTarget instead of this.
func (r *Runtime) bounded(what string, label string, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()

	timeout := r.assetReachTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		return err
	case <-timer.C:
		return errors.New("timed out after " + timeout.String() + " " + what + " asset " + label)
	}
}

// assetReachTimeout is the bound for one step of reaching another asset,
// overridable per runtime so a caller with a slower fleet - or a test - can say
// so.
func (r *Runtime) assetReachTimeout() time.Duration {
	if r.assetReachTimeoutOverride > 0 {
		return r.assetReachTimeoutOverride
	}
	return defaultAssetReachTimeout
}
