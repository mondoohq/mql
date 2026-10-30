// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

func (k *mqlKustomizeKustomization) resources() ([]any, error) {
	rendered, err := k.fetchRendered()
	if err != nil {
		// Propagate render failures so a broken overlay surfaces in
		// audits rather than silently passing checks that count
		// resources. Matches the helm.template.resources contract.
		return nil, err
	}

	allResources := make([]any, 0, len(rendered))
	for idx, obj := range rendered {
		mqlRes, err := newMqlKustomizeResource(k.MqlRuntime, k.kustPath, idx, obj)
		if err != nil {
			log.Warn().Err(err).Msg("skipping rendered kustomize resource")
			continue
		}
		allResources = append(allResources, mqlRes)
	}
	return allResources, nil
}

func (k *mqlKustomizeKustomization) fetchRendered() ([]map[string]any, error) {
	// Trigger the same lazy-resolve path as the other accessors so the
	// rendered fetch works on resources constructed via init (no Internal
	// state set yet).
	if _, _, err := k.resolveEntry(); err != nil {
		return nil, err
	}
	k.renderedOnce.Do(func() {
		fSys := filesys.MakeFsOnDisk()
		kustomizer := krusty.MakeKustomizer(krusty.MakeDefaultOptions())

		resMap, err := kustomizer.Run(fSys, k.kustPath)
		if err != nil {
			k.renderedErr = err
			return
		}

		resources := make([]map[string]any, 0, len(resMap.Resources()))
		for _, res := range resMap.Resources() {
			yamlBytes, err := res.AsYAML()
			if err != nil {
				log.Warn().Err(err).Msg("skipping kustomize resource: failed to convert to YAML")
				continue
			}
			var obj map[string]any
			if err := yaml.Unmarshal(yamlBytes, &obj); err != nil {
				log.Warn().Err(err).Msg("skipping kustomize resource: failed to unmarshal YAML")
				continue
			}
			resources = append(resources, obj)
		}
		k.rendered = resources
	})
	return k.rendered, k.renderedErr
}

func newMqlKustomizeResource(runtime *plugin.Runtime, kustPath string, idx int, obj map[string]any) (*mqlKustomizeResource, error) {
	kind, _ := obj["kind"].(string)
	apiVersion, _ := obj["apiVersion"].(string)
	name := ""
	namespace := ""
	labels := map[string]any{}
	annotations := map[string]any{}

	if metadata, ok := obj["metadata"].(map[string]any); ok {
		name, _ = metadata["name"].(string)
		namespace, _ = metadata["namespace"].(string)
		if l, ok := metadata["labels"].(map[string]any); ok {
			labels = l
		}
		if a, ok := metadata["annotations"].(map[string]any); ok {
			annotations = a
		}
	}

	// Kubernetes requires label and annotation values to be strings,
	// but the YAML parser can hand us ints/bools/etc. when the
	// manifest is non-compliant (e.g. an unquoted `replicas: 3` under
	// labels). Coerce non-strings via fmt.Sprintf so audits can see
	// the offending value rather than silently dropping it.
	labelsStr := coerceStringMap(labels)
	annotationsStr := coerceStringMap(annotations)

	manifest, err := convert.JsonToDict(obj)
	if err != nil {
		return nil, err
	}

	// idx makes the cache key unique even when two manifests in the
	// same overlay share apiVersion+kind+namespace+name — possible for
	// cluster-scoped resources without `name`, or for malformed
	// overlays. Without it CreateResource silently dedupes them.
	id := "kustomize.resource:" + kustPath + ":" + apiVersion + ":" + kind + ":" + namespace + "/" + name + ":" + strconv.Itoa(idx)

	res, err := CreateResource(runtime, "kustomize.resource", map[string]*llx.RawData{
		"__id":        llx.StringData(id),
		"apiVersion":  llx.StringData(apiVersion),
		"kind":        llx.StringData(kind),
		"name":        llx.StringData(name),
		"namespace":   llx.StringData(namespace),
		"labels":      llx.MapData(labelsStr, types.String),
		"annotations": llx.MapData(annotationsStr, types.String),
		"manifest":    llx.DictData(manifest),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlKustomizeResource), nil
}

// coerceStringMap converts every value in src to a string, preserving
// non-string entries that the YAML parser may have left as ints, bools,
// or nested values. Empty input returns an empty (non-nil) map so
// downstream MapData calls don't get a nil slot.
func coerceStringMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		switch val := v.(type) {
		case string:
			out[k] = val
		case nil:
			out[k] = ""
		default:
			out[k] = fmt.Sprintf("%v", val)
		}
	}
	return out
}
