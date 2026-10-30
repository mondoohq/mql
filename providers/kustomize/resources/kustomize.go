// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/kustomize/connection"
	"go.mondoo.com/mql/types"
	kustomizeTypes "sigs.k8s.io/kustomize/api/types"
)

func (r *mqlKustomize) id() (string, error) {
	return "kustomize", nil
}

func (r *mqlKustomize) kustomizations() ([]any, error) {
	conn, ok := r.MqlRuntime.Connection.(*connection.KustomizeConnection)
	if !ok {
		return nil, errors.New("kustomize: connection is not a KustomizeConnection")
	}
	entries := conn.Kustomizations()

	var mqlKusts []any
	for _, entry := range entries {
		mqlK, err := newMqlKustomization(r.MqlRuntime, entry)
		if err != nil {
			return nil, err
		}
		mqlKusts = append(mqlKusts, mqlK)
	}
	return mqlKusts, nil
}

type mqlKustomizeKustomizationInternal struct {
	kustomization *kustomizeTypes.Kustomization
	kustPath      string
	rendered      []map[string]any
	renderedErr   error
	renderedOnce  sync.Once
	// stampOnce guards the post-construction write of kustomization
	// and kustPath. CreateResource may return a cached instance for
	// concurrent callers with the same __id; stampOnce ensures the
	// stamp happens exactly once across those goroutines.
	stampOnce sync.Once
}

// mergedLabels gathers every label pair the kustomization adds to its
// rendered objects. There are two declaration slots and both are live:
// the legacy `commonLabels` mapping (types.Kustomization.CommonLabels) and
// the current `labels` list (types.Kustomization.Labels), which is what
// `kustomize edit fix` writes and what the docs recommend. FixKustomization,
// which the connection runs after unmarshalling, does not fold one into the
// other — that fold lives in FixKustomizationPreMarshalling and runs the
// other direction — so reading only CommonLabels reported {} for an overlay
// that does label everything it renders.
//
// Precedence: the legacy mapping seeds the result and `labels` pairs are
// merged on top, with a later `labels` entry winning over an earlier one.
// Kustomize rejects a key that appears in both slots, so the overlap only
// arises on input kustomize would refuse anyway.
//
// The fold is deliberately lossy in one respect. A `labels` entry also carries
// IncludeSelectors and IncludeTemplates, both defaulting to false, whereas the
// legacy CommonLabels is documented as applying "to all objects and selectors"
// and so always rewrites selectors. Flattening to one map therefore cannot
// distinguish a metadata-only label from one that also rewrites a workload's
// selector. That is the right trade here: commonLabels is the field policies
// already reference, and every pair in it really is added to the rendered
// objects. Exposing the two booleans needs its own field rather than a
// kustomize.label sub-resource, which would carry no natural key and no
// reference to another resource.
func mergedLabels(k *kustomizeTypes.Kustomization) map[string]any {
	size := len(k.CommonLabels)
	for _, l := range k.Labels {
		size += len(l.Pairs)
	}
	labels := make(map[string]any, size)
	for key, val := range k.CommonLabels {
		labels[key] = val
	}
	for _, l := range k.Labels {
		for key, val := range l.Pairs {
			labels[key] = val
		}
	}
	return labels
}

func newMqlKustomization(runtime *plugin.Runtime, entry *connection.KustomizationEntry) (*mqlKustomizeKustomization, error) {
	if entry == nil || entry.Kustomization == nil {
		return nil, errors.New("kustomize: entry has no parsed kustomization")
	}
	k := entry.Kustomization

	commonLabels := mergedLabels(k)
	commonAnnotations := make(map[string]any, len(k.CommonAnnotations))
	for key, val := range k.CommonAnnotations {
		commonAnnotations[key] = val
	}

	resourceRefs := convert.SliceAnyToInterface(k.Resources)
	componentRefs := convert.SliceAnyToInterface(k.Components)

	res, err := CreateResource(runtime, "kustomize.kustomization", map[string]*llx.RawData{
		"__id":              llx.StringData("kustomize.kustomization:" + entry.Path),
		"path":              llx.StringData(entry.Path),
		"apiVersion":        llx.StringData(k.APIVersion),
		"kind":              llx.StringData(k.Kind),
		"namespace":         llx.StringData(k.Namespace),
		"namePrefix":        llx.StringData(k.NamePrefix),
		"nameSuffix":        llx.StringData(k.NameSuffix),
		"commonLabels":      llx.MapData(commonLabels, types.String),
		"commonAnnotations": llx.MapData(commonAnnotations, types.String),
		"resourceRefs":      llx.ArrayData(resourceRefs, types.String),
		"componentRefs":     llx.ArrayData(componentRefs, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlK := res.(*mqlKustomizeKustomization)
	// CreateResource may return an already-cached instance when two
	// callers ask for the same __id; stampOnce keeps the write
	// race-free under concurrent newMqlKustomization calls and
	// happens-before any subsequent reader on the returned pointer.
	mqlK.stampOnce.Do(func() {
		mqlK.kustomization = k
		mqlK.kustPath = entry.Path
	})
	return mqlK, nil
}

// initKustomizeKustomization handles selector-style lookups
// (`kustomize.kustomization(path: "...")`). It locates the matching entry
// on the connection and routes through newMqlKustomization so Internal
// state stays populated — without this, field accessors would nil-deref
// on a bare resource constructed only from the `path` arg.
//
// No args, or an empty path, keeps returning `args, nil, nil`: a bare
// resource is a valid empty state. A path that matches nothing is a
// different thing entirely and returns a not-found error — falling
// through there would have the runtime build the resource from the
// partial args, leaving every other field UNSET, which surfaces
// client-side as "primitive with no type information" with nothing
// pointing at the cause.
func initKustomizeKustomization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) == 0 {
		return args, nil, nil
	}
	pathArg, ok := args["path"]
	if !ok || pathArg == nil {
		return args, nil, nil
	}
	path, _ := pathArg.Value.(string)
	if path == "" {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.KustomizeConnection)
	if !ok {
		return args, nil, nil
	}
	for _, entry := range conn.Kustomizations() {
		if entry.Path == path {
			mqlK, err := newMqlKustomization(runtime, entry)
			if err != nil {
				return nil, nil, err
			}
			return args, mqlK, nil
		}
	}
	return nil, nil, fmt.Errorf("kustomize: no kustomization loaded for path %q", path)
}

func (k *mqlKustomizeKustomization) id() (string, error) {
	return "kustomize.kustomization:" + k.Path.Data, nil
}

// resolveEntry returns the parsed kustomization, repopulating Internal
// state from the connection when needed (e.g., when the resource was
// constructed without going through newMqlKustomization). Each accessor
// calls this first instead of dereferencing k.kustomization directly.
func (k *mqlKustomizeKustomization) resolveEntry() (*kustomizeTypes.Kustomization, string, error) {
	if k.kustomization != nil {
		return k.kustomization, k.kustPath, nil
	}
	conn, ok := k.MqlRuntime.Connection.(*connection.KustomizeConnection)
	if !ok {
		return nil, "", errors.New("kustomize: connection is not a KustomizeConnection")
	}
	path := k.Path.Data
	for _, entry := range conn.Kustomizations() {
		if entry.Path == path {
			k.stampOnce.Do(func() {
				k.kustomization = entry.Kustomization
				k.kustPath = entry.Path
			})
			return k.kustomization, k.kustPath, nil
		}
	}
	return nil, "", errors.New("kustomize: no kustomization loaded for path " + path)
}

func (k *mqlKustomizeKustomization) patches() ([]any, error) {
	kust, kustPath, err := k.resolveEntry()
	if err != nil {
		return nil, err
	}
	var mqlPatches []any
	idx := 0
	// Modern unified patches: classify each by inspecting its content shape.
	for i := range kust.Patches {
		p := kust.Patches[i]
		mqlP, err := newMqlKustomizePatch(k.MqlRuntime, kustPath, idx, &p, hintNone)
		if err != nil {
			return nil, err
		}
		mqlPatches = append(mqlPatches, mqlP)
		idx++
	}
	// Legacy patchesJson6902: format is unambiguous, force json6902.
	for i := range kust.PatchesJson6902 {
		p := kust.PatchesJson6902[i]
		mqlP, err := newMqlKustomizePatch(k.MqlRuntime, kustPath, idx, &p, hintJSON6902)
		if err != nil {
			return nil, err
		}
		mqlPatches = append(mqlPatches, mqlP)
		idx++
	}
	// Legacy patchesStrategicMerge: each entry is EITHER a file path or an
	// inline patch body, so it has to be disambiguated. Format is unambiguous.
	for i := range kust.PatchesStrategicMerge {
		p := strategicMergePatchEntry(kustPath, string(kust.PatchesStrategicMerge[i]))
		mqlP, err := newMqlKustomizePatch(k.MqlRuntime, kustPath, idx, &p, hintStrategicMerge)
		if err != nil {
			return nil, err
		}
		mqlPatches = append(mqlPatches, mqlP)
		idx++
	}
	return mqlPatches, nil
}

func (k *mqlKustomizeKustomization) configMapGenerators() ([]any, error) {
	kust, kustPath, err := k.resolveEntry()
	if err != nil {
		return nil, err
	}
	return newMqlConfigMapGenerators(k.MqlRuntime, kustPath, kust.ConfigMapGenerator)
}

func (k *mqlKustomizeKustomization) secretGenerators() ([]any, error) {
	kust, kustPath, err := k.resolveEntry()
	if err != nil {
		return nil, err
	}
	return newMqlSecretGenerators(k.MqlRuntime, kustPath, kust.SecretGenerator)
}

func (k *mqlKustomizeKustomization) images() ([]any, error) {
	kust, kustPath, err := k.resolveEntry()
	if err != nil {
		return nil, err
	}
	var mqlImages []any
	for i, img := range kust.Images {
		mqlImg, err := newMqlKustomizeImage(k.MqlRuntime, kustPath, i, img)
		if err != nil {
			return nil, err
		}
		mqlImages = append(mqlImages, mqlImg)
	}
	return mqlImages, nil
}

func (k *mqlKustomizeKustomization) replacements() ([]any, error) {
	kust, kustPath, err := k.resolveEntry()
	if err != nil {
		return nil, err
	}
	var mqlReplacements []any
	for i := range kust.Replacements {
		r := kust.Replacements[i]
		// One entry can expand into several rows: a `- path:` declaration
		// names a file that may hold a list of replacements.
		mqlRs, err := newMqlKustomizeReplacements(k.MqlRuntime, kustPath, i, &r)
		if err != nil {
			return nil, err
		}
		mqlReplacements = append(mqlReplacements, mqlRs...)
	}
	return mqlReplacements, nil
}
