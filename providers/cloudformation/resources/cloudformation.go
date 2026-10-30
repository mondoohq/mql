// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"gopkg.in/yaml.v3"
)

// maxAliasDepth bounds alias resolution. YAML requires an anchor to be defined
// before it is referenced, so a cycle cannot occur in a well-formed document,
// but a hand-crafted tree must not be able to spin a scan forever.
const maxAliasDepth = 100

// resolveAlias follows a YAML alias to the node it points at. The parser
// records the anchor target on the alias node itself, so this resolves
// references that live elsewhere in the document.
func resolveAlias(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < maxAliasDepth; i++ {
		n = n.Alias
	}
	return n
}

// isMergeKey reports whether a mapping key is the YAML merge key `<<`, whose
// value contributes another mapping's keys to this one.
func isMergeKey(n *yaml.Node) bool {
	return n != nil && (n.Tag == "!!merge" || n.Value == "<<")
}

// scalarValue returns the text of a scalar node, resolving an alias first and
// yielding "" for anything that is not a scalar (a mapping, a sequence, or a
// missing node). Callers read CloudFormation attributes such as Type and
// DeletionPolicy through it, so `Type: *sharedType` reports the anchored value
// instead of an empty string.
func scalarValue(n *yaml.Node) string {
	n = resolveAlias(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func gatherMapValue(n *yaml.Node, key string) (*yaml.Node, *yaml.Node, error) {
	n = resolveAlias(n)
	if n == nil {
		return nil, nil, status.Error(codes.InvalidArgument, "node is nil for key "+key)
	}

	// check that we have a map
	if n.Kind != yaml.MappingNode {
		return nil, nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid node kind %v for key %s", n.Kind, key))
	}

	// check if content is even
	if len(n.Content)%2 != 0 {
		return nil, nil, status.Error(codes.InvalidArgument, fmt.Sprintf("uneven length %v for key %s", len(n.Content), key))
	}

	// search for key
	var merges []*yaml.Node
	for i := 0; i < len(n.Content); i += 2 {
		keyNode := n.Content[i]
		valueNode := n.Content[i+1]

		if keyNode.Value == key {
			return keyNode, valueNode, nil
		}
		if isMergeKey(keyNode) {
			merges = append(merges, valueNode)
		}
	}

	// A merge key contributes the keys of another mapping, but only where this
	// mapping does not define them itself, so merges are searched after the
	// whole map. Within a merge sequence the earlier entry wins. Without this,
	// a resource written as `<<: *base` reports no Type at all and every
	// type-scoped policy silently skips it.
	for _, merge := range merges {
		source := resolveAlias(merge)
		if source == nil {
			continue
		}
		if source.Kind == yaml.SequenceNode {
			for _, item := range source.Content {
				if k, v, err := gatherMapValue(item, key); err == nil {
					return k, v, nil
				}
			}
			continue
		}
		if k, v, err := gatherMapValue(source, key); err == nil {
			return k, v, nil
		}
	}

	return nil, nil, status.Error(codes.NotFound, fmt.Sprintf("key %s not found", key))
}

// isAbsentKey reports whether a gatherMapValue error means "this field has no
// value here", covering both a mapping that lacks the key (NotFound) and a
// body that is not a mapping at all (InvalidArgument: a null resource body, a
// scalar parameter body). Both leave the single field empty; neither is a
// reason to drop the row, let alone every other row in the section.
func isAbsentKey(err error) bool {
	code := status.Code(err)
	return code == codes.NotFound || code == codes.InvalidArgument
}

func convertYamlToDict(valueNode *yaml.Node) (map[string]any, error) {
	v, err := convertYamlNodeToValue(valueNode)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return map[string](any){}, nil
	}
	dict, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected a mapping, got %T", v)
	}
	return dict, nil
}

// nodeToDict resolves the child node under `key` to a Go value suitable for
// `llx.DictData`. Returns nil when the key is absent. The field stays `dict`
// in the schema because CloudFormation values can be scalars (literal default,
// intrinsic function evaluating to a string), lists, or full mapping bodies.
func nodeToDict(parent *yaml.Node, key string) (any, error) {
	_, val, err := gatherMapValue(parent, key)
	if err != nil {
		if isAbsentKey(err) {
			return nil, nil
		}
		return nil, err
	}
	return convertYamlNodeToValue(val)
}

// nodeToInt extracts a YAML integer scalar at `key`, returning nil when the key
// is absent so callers can distinguish "no constraint" from an explicit 0 (a
// legitimate CloudFormation MinValue). Non-integer scalars return an error so
// callers see malformed input rather than silently defaulting.
func nodeToInt(parent *yaml.Node, key string) (*int64, error) {
	_, val, err := gatherMapValue(parent, key)
	if err != nil {
		if isAbsentKey(err) {
			return nil, nil
		}
		return nil, err
	}
	val = resolveAlias(val)
	if val == nil || val.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("expected scalar for %s", key)
	}
	if n, err := strconv.ParseInt(val.Value, 10, 64); err == nil {
		return &n, nil
	}
	// CloudFormation `Number` parameters may be integers or floats, so
	// `MinValue: 1.0` and `MinValue: 1e3` are legal. An integral float is
	// exactly representable by the int-typed field, so accept it; a genuinely
	// fractional bound is not, and reporting a truncated value would be worse
	// than reporting none, so it stays an error for the caller to degrade on.
	f, err := strconv.ParseFloat(val.Value, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid number for %s: %w", key, err)
	}
	if f != math.Trunc(f) || f > math.MaxInt64 || f < math.MinInt64 {
		return nil, fmt.Errorf("%s is not representable as an integer: %s", key, val.Value)
	}
	n := int64(f)
	return &n, nil
}

// optionalIntConstraint reads an integer parameter constraint, degrading to nil
// (an absent constraint) when the value can't be represented rather than
// failing. `param` names the owning parameter so the warning is actionable.
//
// The alternative — propagating the error — takes down the whole parameter
// list: one `MinValue: 0.5` on one parameter would erase every other
// parameter in the template, so a policy looking for an unrelated NoEcho
// credential parameter would find nothing at all.
func optionalIntConstraint(parent *yaml.Node, key, param string) *int64 {
	n, err := nodeToInt(parent, key)
	if err != nil {
		log.Warn().Err(err).Str("parameter", param).Str("constraint", key).
			Msg("cloudformation: unrepresentable parameter constraint; reporting it as absent")
		return nil
	}
	return n
}

// nodeToDictList walks the sequence at `key` and returns each entry as a
// dict (so heterogeneous strings/numbers/objects survive the round-trip).
func nodeToDictList(parent *yaml.Node, key string) ([]any, error) {
	_, val, err := gatherMapValue(parent, key)
	if err != nil {
		if isAbsentKey(err) {
			return nil, nil
		}
		return nil, err
	}
	val = resolveAlias(val)
	if val == nil || val.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("expected sequence for %s", key)
	}
	out := make([]any, 0, len(val.Content))
	for _, item := range val.Content {
		dict, err := convertYamlNodeToValue(item)
		if err != nil {
			return nil, err
		}
		out = append(out, dict)
	}
	return out, nil
}

// convertYamlNodeToValue handles a single YAML node (scalar, sequence, or
// mapping) and returns the matching Go value, normalized for the llx dict
// primitive (ints become float64, nested maps become map[string]any). Decoding
// the node rather than re-parsing its serialized form resolves anchors,
// aliases, and merge keys, whose definitions live elsewhere in the document
// and are therefore absent from the serialized subtree.
func convertYamlNodeToValue(n *yaml.Node) (any, error) {
	if n == nil {
		return nil, nil
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, err
	}
	jsonBytes, err := json.Marshal(normalizeYamlKeys(v))
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(jsonBytes, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// normalizeYamlKeys rewrites mapping keys that YAML allows but JSON does not.
// A Mappings section keyed on `true`/`false`/`2`/`null` decodes to a
// map[any]any, which json.Marshal rejects outright, and that rejection takes
// down every other member of the section with it. Such a key becomes its
// string spelling instead.
func normalizeYamlKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = normalizeYamlKeys(val)
		}
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[yamlKeyToString(k)] = normalizeYamlKeys(val)
		}
		return out
	case []any:
		for i, val := range t {
			t[i] = normalizeYamlKeys(val)
		}
		return t
	}
	return v
}

func yamlKeyToString(k any) string {
	switch t := k.(type) {
	case nil:
		return "null"
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

// optionalDict reads a dict-valued field, degrading a value we cannot
// represent to null (an absent field) rather than failing. `owner` names the
// enclosing resource/output/parameter so the warning is actionable.
//
// The alternative, propagating the error, erases every sibling row: one
// malformed Value on one output would drop the whole outputs list.
func optionalDict(parent *yaml.Node, key, owner string) any {
	v, err := nodeToDict(parent, key)
	if err != nil {
		log.Warn().Err(err).Str("owner", owner).Str("field", key).
			Msg("cloudformation: unreadable field; reporting it as absent")
		return nil
	}
	return v
}

// optionalDictList is optionalDict for a list-valued field, e.g. a parameter
// whose AllowedValues is written as a bare scalar instead of a list.
func optionalDictList(parent *yaml.Node, key, owner string) []any {
	v, err := nodeToDictList(parent, key)
	if err != nil {
		log.Warn().Err(err).Str("owner", owner).Str("field", key).
			Msg("cloudformation: unreadable list field; reporting it as absent")
		return nil
	}
	return v
}
