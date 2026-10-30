// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import "go.mondoo.com/mql/types"

// SourceContext describes where a resource is defined in source: a file path,
// the line/column range it spans, and the raw text within that range. It is
// produced from the `@context` auto-expand data that the engine collects for
// failing resources. See terraform.context for the canonical producer.
type SourceContext struct {
	Path    string
	Range   Range
	Content string
}

// FailingResourceContexts walks the failed items of an assessment and returns
// the source context (path/range/content) of every failing resource that
// carries `@context` data.
//
// It is intentionally generic across resources: it keys off the "context"
// label and the {path, range, content} field labels rather than any specific
// resource type, so any resource that gains a `@context` annotation is
// supported here without changes.
func (bundle *CodeBundle) FailingResourceContexts(assessment *Assessment) []SourceContext {
	if bundle == nil || assessment == nil || bundle.Labels == nil {
		return nil
	}

	var out []SourceContext
	for i := range assessment.Results {
		item := assessment.Results[i]
		if item == nil || item.Success {
			continue
		}

		// Actual holds the failing resource(s) for list/value assertions. Data
		// holds @msg datapoints, which may also carry resource blocks.
		if item.Actual != nil {
			bundle.collectSourceContexts(item.Actual.RawData(), &out)
		}
		for j := range item.Data {
			if item.Data[j] != nil {
				bundle.collectSourceContexts(item.Data[j].RawData(), &out)
			}
		}
	}
	return out
}

// collectSourceContexts recursively searches a decoded value tree for context
// blocks. The tree is a mix of *RawData nodes, []any arrays (whose elements are
// unwrapped values), and map[string]any blocks (whose values are *RawData).
func (bundle *CodeBundle) collectSourceContexts(value any, out *[]SourceContext) {
	switch v := value.(type) {
	case *RawData:
		if v != nil {
			bundle.collectSourceContexts(v.Value, out)
		}
	case []any:
		for i := range v {
			bundle.collectSourceContexts(v[i], out)
		}
	case map[string]any:
		for key, raw := range v {
			rd, ok := raw.(*RawData)
			if !ok {
				continue
			}
			// Best-effort detection of a resource context: a field labeled
			// "context" whose value is a block. This mirrors the printer's
			// auto-expand handling.
			if bundle.Labels.Labels[key] == "context" && types.Type(rd.Type) == types.Block {
				if sc, ok := parseSourceContext(bundle, rd.Value); ok {
					*out = append(*out, sc)
					continue
				}
			}
			bundle.collectSourceContexts(rd.Value, out)
		}
	}
}

// parseSourceContext extracts the path/range/content fields out of a decoded
// context block (a map[string]any keyed by checksum). It is shared with the
// printer so the structured and string renderings can't drift.
func parseSourceContext(bundle *CodeBundle, data any) (SourceContext, bool) {
	m, ok := data.(map[string]any)
	if !ok || bundle.Labels == nil {
		return SourceContext{}, false
	}

	var sc SourceContext
	for k, v := range m {
		label, ok := bundle.Labels.Labels[k]
		if !ok {
			continue
		}
		rd, ok := v.(*RawData)
		if !ok {
			continue
		}

		switch label {
		case "content":
			if rd.Type == types.String {
				sc.Content, _ = rd.Value.(string)
			}
		case "range":
			if rd.Type == types.Range {
				sc.Range, _ = rd.Value.(Range)
			}
		case "path", "file.path":
			if rd.Type == types.String {
				sc.Path, _ = rd.Value.(string)
			}
		}
	}

	if sc.Path == "" && sc.Range.IsEmpty() && sc.Content == "" {
		return SourceContext{}, false
	}
	return sc, true
}

// ParseSourceContext extracts the path/range/content fields from a decoded
// context block value. It is exported for renderers (e.g. the CLI printer) that
// already hold the decoded block and want the structured context.
func (bundle *CodeBundle) ParseSourceContext(data any) (SourceContext, bool) {
	if bundle == nil {
		return SourceContext{}, false
	}
	return parseSourceContext(bundle, data)
}
