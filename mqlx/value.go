// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx

import (
	"fmt"
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// FieldError is an error attached to an individual value inside a query
// result, e.g. one unreadable file in a list query. The path locates the
// value within Result.Value, e.g. "users[3].name"; it is empty when the
// query's top-level value itself errored.
type FieldError struct {
	Path string
	Err  error
}

func (e FieldError) Error() string {
	if e.Path == "" {
		return e.Err.Error()
	}
	return e.Path + ": " + e.Err.Error()
}

func (e FieldError) Unwrap() error {
	return e.Err
}

// normalizer converts raw execution output into plain Go values: blocks
// become maps keyed by their field labels, arrays become []any, and per-field
// errors are collected instead of silently dropped.
type normalizer struct {
	bundle *llx.CodeBundle
	errs   []FieldError
}

func normalize(bundle *llx.CodeBundle, raw map[string]*llx.RawResult) (any, []FieldError) {
	n := &normalizer{bundle: bundle}

	results := llx.ReturnValuesV2(bundle, func(checksum string) (*llx.RawResult, bool) {
		res, ok := raw[checksum]
		return res, ok
	})

	switch len(results) {
	case 0:
		// Queries consisting only of assignments produce no values.
		return nil, nil

	case 1:
		res := results[0]
		if res.Data.Error != nil {
			n.errs = append(n.errs, FieldError{Path: "", Err: res.Data.Error})
			return nil, n.errs
		}
		return n.value(res.Data, ""), n.errs

	default:
		// Multiple top-level values (e.g. "asset.name asset.version") are
		// returned as a map keyed by each value's label, matching how the
		// CLI reports them.
		out := make(map[string]any, len(results))
		seen := make(map[string]int, len(results))
		for _, res := range results {
			key := dedupKey(n.label(res.CodeID), seen)
			if res.Data.Error != nil {
				n.errs = append(n.errs, FieldError{Path: key, Err: res.Data.Error})
				out[key] = nil
				continue
			}
			out[key] = n.value(res.Data, key)
		}
		return out, n.errs
	}
}

func (n *normalizer) value(data *llx.RawData, path string) any {
	if data == nil || data.Value == nil {
		return nil
	}

	switch data.Type.Underlying() {
	case types.Block:
		return n.block(data.Value.(map[string]any), path)

	case types.ArrayLike:
		return n.array(data.Type, data.Value.([]any), path)

	case types.MapLike:
		if data.Type.Key() == types.String {
			return n.stringMap(data.Type, data.Value.(map[string]any), path)
		}
		return data.Value

	case types.Dict:
		return n.dict(data.Value, path)

	default:
		// Scalars and special leaf values (*time.Time, llx.RawIP,
		// llx.Resource, llx.Range, ...) pass through unchanged.
		return data.Value
	}
}

func (n *normalizer) block(data map[string]any, path string) map[string]any {
	keys := make([]string, 0, len(data))
	for k := range data {
		// Blocks carry their binding and bookkeeping under reserved keys.
		if k == "_" || k == "__t" || k == "__s" {
			continue
		}
		keys = append(keys, k)
	}
	// Sort for deterministic duplicate-label numbering.
	sort.Strings(keys)

	res := make(map[string]any, len(keys))
	seen := make(map[string]int, len(keys))
	for _, k := range keys {
		key := dedupKey(n.label(k), seen)
		childPath := joinPath(path, key)

		child, ok := data[k].(*llx.RawData)
		if !ok || child == nil {
			res[key] = nil
			continue
		}
		if child.Error != nil {
			n.errs = append(n.errs, FieldError{Path: childPath, Err: child.Error})
			res[key] = nil
			continue
		}
		res[key] = n.value(child, childPath)
	}
	return res
}

func (n *normalizer) array(typ types.Type, data []any, path string) []any {
	childType := typ.Child()
	res := make([]any, len(data))
	for i := range data {
		res[i] = n.value(&llx.RawData{Type: childType, Value: data[i]}, fmt.Sprintf("%s[%d]", path, i))
	}
	return res
}

func (n *normalizer) stringMap(typ types.Type, data map[string]any, path string) map[string]any {
	childType := typ.Child()
	res := make(map[string]any, len(data))
	for k := range data {
		res[k] = n.value(&llx.RawData{Type: childType, Value: data[k]}, joinPath(path, k))
	}
	return res
}

func (n *normalizer) dict(data any, path string) any {
	switch v := data.(type) {
	case []any:
		res := make([]any, len(v))
		for i := range v {
			res[i] = n.dict(v[i], fmt.Sprintf("%s[%d]", path, i))
		}
		return res
	case map[string]any:
		res := make(map[string]any, len(v))
		for k := range v {
			res[k] = n.dict(v[k], joinPath(path, k))
		}
		return res
	default:
		return v
	}
}

// label resolves a checksum to its human-readable field label.
func (n *normalizer) label(checksum string) string {
	if n.bundle != nil && n.bundle.Labels != nil {
		if l, ok := n.bundle.Labels.Labels[checksum]; ok && l != "" {
			return l
		}
	}
	return checksum
}

// dedupKey disambiguates labels that occur more than once in the same scope
// (e.g. package("a").installed and package("b").installed both label as
// "package.installed") by numbering repeats: "label", "label (2)", ...
func dedupKey(base string, seen map[string]int) string {
	n := seen[base]
	seen[base]++
	if n == 0 {
		return base
	}
	return fmt.Sprintf("%s (%d)", base, n+1)
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
