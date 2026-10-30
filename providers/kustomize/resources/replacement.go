// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	kustomizeTypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/yaml"
)

type mqlKustomizeReplacementInternal struct {
	replacementTargets []*kustomizeTypes.TargetSelector
	kustPath           string
	// stampOnce guards the post-construction Internal-field write.
	// CreateResource can return a cached instance to concurrent callers
	// with the same __id; stampOnce keeps the write race-free under those
	// goroutines and matches the pattern in newMqlKustomization.
	stampOnce sync.Once
}

// newMqlKustomizeReplacements turns one `replacements:` entry into its rows.
//
// A types.ReplacementField is a types.Replacement plus a Path. When the entry
// is declared as `- path: file.yaml` the inline Source and Targets are both
// nil and Path is the only field carrying information, so reading just the
// inline shape produced a row that reported a replacement injecting nothing,
// from nowhere, into nothing — and an audit over `replacements` passed
// vacuously on it.
//
// The referenced file holds either a single replacement mapping or a list of
// them (kustomize accepts both, see ReplacementTransformerPlugin.Config), so
// one entry can expand into several rows. `path` stays populated on every row,
// including the ones produced when the file can't be read, so a dangling
// reference is visible rather than reading as an empty replacement.
func newMqlKustomizeReplacements(runtime *plugin.Runtime, kustPath string, index int, rf *kustomizeTypes.ReplacementField) ([]any, error) {
	baseID := "kustomize.replacement:" + kustPath + ":" + strconv.Itoa(index)

	// An inline declaration (kustomize refuses an entry that carries both a
	// path and inline content).
	if rf.Path == "" || rf.Source != nil || len(rf.Targets) > 0 {
		mqlR, err := newMqlKustomizeReplacement(runtime, kustPath, baseID, rf.Path, &rf.Replacement)
		if err != nil {
			return nil, err
		}
		return []any{mqlR}, nil
	}

	repls, err := loadReplacementFile(kustPath, rf.Path)
	if err != nil {
		log.Warn().Err(err).Str("path", rf.Path).Str("kustomization", kustPath).
			Msg("kustomize: could not read replacement file; reporting the reference only")
		// Still emit a row so the file reference itself is queryable.
		mqlR, cerr := newMqlKustomizeReplacement(runtime, kustPath, baseID, rf.Path, &kustomizeTypes.Replacement{})
		if cerr != nil {
			return nil, cerr
		}
		return []any{mqlR}, nil
	}

	mqlReplacements := make([]any, 0, len(repls))
	for j := range repls {
		id := baseID + ":" + strconv.Itoa(j)
		mqlR, err := newMqlKustomizeReplacement(runtime, kustPath, id, rf.Path, &repls[j])
		if err != nil {
			return nil, err
		}
		mqlReplacements = append(mqlReplacements, mqlR)
	}
	return mqlReplacements, nil
}

// loadReplacementFile reads a `- path:` replacement declaration. The read is
// constrained to the kustomization directory by the same containment guard the
// patch reader uses, so `path: ../../etc/passwd` is refused.
func loadReplacementFile(kustPath, relPath string) ([]kustomizeTypes.Replacement, error) {
	target, ok := resolveContainedPath(kustPath, relPath)
	if !ok {
		return nil, fmt.Errorf("replacement path %q escapes the kustomization directory", relPath)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	return decodeReplacementFile(data)
}

// decodeReplacementFile decodes a replacement file, which holds either a
// single replacement mapping or a list of them. Kustomize decodes it with
// sigs.k8s.io/yaml (YAML through JSON), which is what makes the inlined ResId
// inside a source or target selector resolve; use the same decoder so the
// provider's reading matches what kustomize actually applies.
func decodeReplacementFile(data []byte) ([]kustomizeTypes.Replacement, error) {
	var probe any
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, err
	}

	switch probe.(type) {
	case []any:
		var repls []kustomizeTypes.Replacement
		if err := yaml.Unmarshal(data, &repls); err != nil {
			return nil, err
		}
		return repls, nil
	case map[string]any:
		var repl kustomizeTypes.Replacement
		if err := yaml.Unmarshal(data, &repl); err != nil {
			return nil, err
		}
		return []kustomizeTypes.Replacement{repl}, nil
	default:
		return nil, fmt.Errorf("unsupported replacement file content: expected a mapping or a list")
	}
}

func newMqlKustomizeReplacement(runtime *plugin.Runtime, kustPath, id, path string, r *kustomizeTypes.Replacement) (*mqlKustomizeReplacement, error) {
	sourcePath := ""
	sourceKind := ""
	sourceName := ""

	if r.Source != nil {
		sourcePath = r.Source.FieldPath
		sourceKind = r.Source.Gvk.Kind
		sourceName = r.Source.Name
	}

	res, err := CreateResource(runtime, "kustomize.replacement", map[string]*llx.RawData{
		"__id":       llx.StringData(id),
		"path":       llx.StringData(path),
		"sourcePath": llx.StringData(sourcePath),
		"sourceKind": llx.StringData(sourceKind),
		"sourceName": llx.StringData(sourceName),
	})
	if err != nil {
		return nil, err
	}

	mqlR := res.(*mqlKustomizeReplacement)
	mqlR.stampOnce.Do(func() {
		mqlR.kustPath = kustPath
		mqlR.replacementTargets = r.Targets
	})
	return mqlR, nil
}

func (r *mqlKustomizeReplacement) targets() ([]any, error) {
	var mqlTargets []any
	for i, t := range r.replacementTargets {
		// A bare `- ` list entry in the source YAML produces a nil
		// element here; skip it before touching t.Select.
		if t == nil {
			continue
		}
		kind := ""
		name := ""
		if t.Select != nil {
			kind = t.Select.Gvk.Kind
			name = t.Select.Name
		}

		// A target may specify a Select but omit fieldPaths; emit one target
		// row with an empty fieldPath rather than dropping the target entirely.
		fieldPaths := t.FieldPaths
		if len(fieldPaths) == 0 {
			fieldPaths = []string{""}
		}
		for j, fp := range fieldPaths {
			// Prefix with the parent replacement's __id, the way
			// kustomize.patch.operation does. Keyed only on the target index
			// plus kind/name/fieldPath, two replacements whose first targets
			// share those selectors produced the same __id and the second was
			// served the first's cached instance.
			id := r.__id + "/target[" + strconv.Itoa(i) + "][" + strconv.Itoa(j) + "]"

			res, err := CreateResource(r.MqlRuntime, "kustomize.replacementTarget", map[string]*llx.RawData{
				"__id":      llx.StringData(id),
				"fieldPath": llx.StringData(fp),
				"kind":      llx.StringData(kind),
				"name":      llx.StringData(name),
			})
			if err != nil {
				return nil, err
			}
			mqlTargets = append(mqlTargets, res)
		}
	}
	return mqlTargets, nil
}
