// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"encoding/xml"
	"io"
	"maps"
	"strconv"
	"strings"
)

// Node is a single element of an XML document.
//
// Unlike a generic map-based decoding, a Node keeps every child in document
// order and never collapses a repeated element into a scalar or a single
// element into a map. That is what lets the Tomcat resources present each
// collection as a list regardless of how many elements the file happens to
// contain.
type Node struct {
	// Name is the local element name, with any namespace prefix stripped.
	Name string
	// Attrs holds the element's attributes keyed by their local name.
	Attrs map[string]string
	// Children holds the child elements, in document order.
	Children []*Node
	// Text is the concatenated character data directly inside the element,
	// trimmed of surrounding whitespace.
	Text string
}

// ParseXML decodes an XML document into a Node tree. It returns nil (and no
// error) for empty input so that a missing or empty configuration file reads
// as "nothing declared" rather than a parse failure.
func ParseXML(data []byte) (*Node, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}

	dec := xml.NewDecoder(strings.NewReader(string(data)))
	// Tomcat configuration files carry a DOCTYPE and, in the case of web.xml,
	// namespace declarations pointing at jakarta.ee schemas. Neither is
	// fetched, and unknown character sets should not abort the parse.
	dec.Strict = false
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	var root *Node
	stack := []*Node{}

	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch elem := token.(type) {
		case xml.StartElement:
			node := &Node{Name: elem.Name.Local}
			if len(elem.Attr) > 0 {
				node.Attrs = make(map[string]string, len(elem.Attr))
				for _, attr := range elem.Attr {
					// Skip namespace declarations; they are never configuration.
					if attr.Name.Space == "xmlns" || attr.Name.Local == "xmlns" {
						continue
					}
					node.Attrs[attr.Name.Local] = attr.Value
				}
			}
			if len(stack) == 0 {
				if root == nil {
					root = node
				}
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			text := strings.TrimSpace(string(elem))
			if text == "" {
				continue
			}
			cur := stack[len(stack)-1]
			if cur.Text == "" {
				cur.Text = text
			} else {
				cur.Text += " " + text
			}
		}
	}

	return root, nil
}

// Elements returns the direct children with the given element name. It always
// returns a slice, empty when there is no match.
func (n *Node) Elements(name string) []*Node {
	if n == nil {
		return nil
	}
	res := []*Node{}
	for _, child := range n.Children {
		if child.Name == name {
			res = append(res, child)
		}
	}
	return res
}

// Element returns the first direct child with the given name, or nil.
func (n *Node) Element(name string) *Node {
	if n == nil {
		return nil
	}
	for _, child := range n.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}

// ChildText returns the trimmed character data of the first direct child with
// the given name, or the empty string when there is no such child.
func (n *Node) ChildText(name string) string {
	child := n.Element(name)
	if child == nil {
		return ""
	}
	return child.Text
}

// Attr returns the value of an attribute by its exact name.
func (n *Node) Attr(name string) (string, bool) {
	if n == nil || n.Attrs == nil {
		return "", false
	}
	v, ok := n.Attrs[name]
	return v, ok
}

// AttrFold returns the first attribute matching any of the given names,
// compared without regard to case. Tomcat spells the same setting differently
// across versions — `SSLEnabledProtocols` became `sslEnabledProtocols`, and
// `SSLEnabled` is capitalized where every neighboring attribute is not — so a
// case-sensitive lookup silently misses valid configuration.
func (n *Node) AttrFold(names ...string) (string, bool) {
	if n == nil || n.Attrs == nil {
		return "", false
	}
	for _, name := range names {
		if v, ok := n.Attrs[name]; ok {
			return v, true
		}
	}
	for _, name := range names {
		lower := strings.ToLower(name)
		for k, v := range n.Attrs {
			if strings.ToLower(k) == lower {
				return v, true
			}
		}
	}
	return "", false
}

// AttrString returns an attribute value, or the empty string when absent.
func (n *Node) AttrString(names ...string) string {
	v, _ := n.AttrFold(names...)
	return v
}

// AttrBool returns an attribute parsed as a boolean, falling back to def when
// the attribute is absent or cannot be parsed. Tomcat accepts only "true" and
// "false", but is lenient about case.
func (n *Node) AttrBool(def bool, names ...string) bool {
	v, ok := n.AttrFold(names...)
	if !ok {
		return def
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(strings.ToLower(v)))
	if err != nil {
		return def
	}
	return parsed
}

// AttrInt returns an attribute parsed as an integer, falling back to def when
// the attribute is absent or cannot be parsed.
func (n *Node) AttrInt(def int64, names ...string) int64 {
	v, ok := n.AttrFold(names...)
	if !ok {
		return def
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return def
	}
	return parsed
}

// Params returns the element's attributes as a map, always non-nil.
func (n *Node) Params() map[string]string {
	res := map[string]string{}
	if n == nil {
		return res
	}
	maps.Copy(res, n.Attrs)
	return res
}

// AttrsDict returns the element's attributes as a dict value, always non-nil.
func (n *Node) AttrsDict() map[string]any {
	res := map[string]any{}
	if n == nil {
		return res
	}
	for k, v := range n.Attrs {
		res[k] = v
	}
	return res
}
