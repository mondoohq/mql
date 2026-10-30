// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"bytes"
	"strings"

	"gopkg.in/yaml.v3"
)

// SourcePosition is the location of a single resource within a manifest file.
type SourcePosition struct {
	Path      string
	StartLine int
	EndLine   int
}

// ObjectID builds the identity key used to correlate a manifest document with
// the modeled resource. It mirrors objIdFromFields in the resources package so
// a lookup by a resource's id succeeds.
func ObjectID(kind, namespace, name string) string {
	kind = strings.ToLower(kind)
	if namespace == "" {
		return kind + ":" + name
	}
	return kind + ":" + namespace + ":" + name
}

// NamespaceResolver returns the namespace an object of the given apiVersion and
// kind, written with the given metadata.namespace, is placed in.
type NamespaceResolver func(apiVersion, kind, namespace string) string

// BuildManifestPositionIndex parses a (possibly multi-document) manifest and
// returns a map from object identity to its source position. `kind: *List`
// wrapper documents are expanded to their items, each of which carries its own
// kind/metadata. Documents without an identifiable kind and name are skipped.
// resolveNamespace, when not nil, maps the namespace written in a document to
// the one the object is identified by, so that an object that names no
// namespace is found under the namespace it was defaulted to.
func BuildManifestPositionIndex(content []byte, path string, resolveNamespace NamespaceResolver) map[string]SourcePosition {
	index := map[string]SourcePosition{}
	if len(content) == 0 {
		return index
	}

	dec := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			// EOF or a malformed document: stop and keep what we have. A parse
			// failure here only means no source context, not a scan failure.
			break
		}
		root := &doc
		if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
			root = doc.Content[0]
		}
		addNodePositions(root, path, resolveNamespace, index)
	}
	return index
}

// addNodePositions records the position of a single resource mapping, or
// recurses into the items of a List wrapper.
func addNodePositions(root *yaml.Node, path string, resolveNamespace NamespaceResolver, index map[string]SourcePosition) {
	if root == nil || root.Kind != yaml.MappingNode {
		return
	}

	kind := mappingScalar(root, "kind")
	if strings.HasSuffix(kind, "List") {
		if items := mappingValueNode(root, "items"); items != nil && items.Kind == yaml.SequenceNode {
			for _, item := range items.Content {
				addNodePositions(item, path, resolveNamespace, index)
			}
			return
		}
	}
	if kind == "" {
		return
	}

	meta := mappingValueNode(root, "metadata")
	name := mappingScalar(meta, "name")
	if name == "" {
		return
	}
	namespace := mappingScalar(meta, "namespace")
	if resolveNamespace != nil {
		namespace = resolveNamespace(mappingScalar(root, "apiVersion"), kind, namespace)
	}

	index[ObjectID(kind, namespace, name)] = SourcePosition{
		Path:      path,
		StartLine: root.Line,
		EndLine:   nodeEndLine(root),
	}
}

// mappingValueNode returns the value node for a key in a mapping node, or nil.
func mappingValueNode(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// mappingScalar returns the scalar value for a key in a mapping node.
func mappingScalar(node *yaml.Node, key string) string {
	if v := mappingValueNode(node, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

// nodeEndLine returns the last source line spanned by a node, computed as the
// maximum start line over the node and all of its descendants. yaml.v3 records
// only the start position of each node, so this approximates the block end from
// its deepest child.
//
// Limitation: when the last descendant is a multi-line block scalar (a folded
// `>` or literal `|` value), the reported end is that scalar's start line, so
// the excerpt can stop a few lines short. Acceptable for a line-range v1;
// revisit if end positions become available upstream.
func nodeEndLine(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	end := n.Line
	for _, c := range n.Content {
		if e := nodeEndLine(c); e > end {
			end = e
		}
	}
	return end
}
