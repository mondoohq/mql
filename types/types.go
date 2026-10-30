// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package types

import (
	"encoding/json"
	"strings"
	"time"
)

// Type information
type Type string

// MarshalJSON generates escapes the \u0000 string for postgres
// Otherwise we are not able to store the compile code as json blob in pg since
// llx and type use \x00 or \u0000. This is not allowed in Postgres json blobs
// see https://www.postgresql.org/docs/9.4/release-9-4-1.html
func (typ Type) MarshalJSON() ([]byte, error) {
	newVal := strings.ReplaceAll(string(typ), "\u0000", "\\u0000")
	return json.Marshal(newVal)
}

// UnmarshalJSON reverts MarshalJSON data arrays to its base type.
func (typ *Type) UnmarshalJSON(data []byte) error {
	var d string
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	reverted := strings.ReplaceAll(d, "\\u0000", "\u0000")
	*typ = Type(reverted)
	return nil
}

const (
	byteUnset byte = iota
	byteAny
	byteNil
	byteRef
	byteBool
	byteInt
	byteFloat
	byteString
	byteRegex
	byteTime
	byteDict
	byteScore
	byteBlock
	byteEmpty
	byteVersion
	byteIP
	byteArray = 1<<4 + iota - 7 // set to 25 to avoid breaking changes
	byteMap
	byteResource
	byteFunction
	byteStringSlice
	byteRange
	byteAsset
)

// NoType type is one whose type information is not available at all
const NoType Type = ""

const (
	// Unset type indicates that the type has not yet been set
	Unset = Type(rune(byteUnset))
	// Any type indicating an untyped value that can have any type
	Any = Type(rune(byteAny))
	// Nil for the empty type
	Nil = Type(rune(byteNil))
	// Ref for internal code chunk references
	Ref = Type(rune(byteRef))
	// Bool for the booleans true and false
	Bool = Type(rune(byteBool))
	// Int for integers
	Int = Type(rune(byteInt))
	// Float for any decimal values
	Float = Type(rune(byteFloat))
	// String for strings
	String = Type(rune(byteString))
	// Regex for regular expressions
	Regex = Type(rune(byteRegex))
	// Time for date and time
	Time = Type(rune(byteTime))
	// Dict for storing hierarchical simple key-value assignments
	Dict = Type(rune(byteDict))
	// Score for evaluations
	Score = Type(rune(byteScore))
	// Block evaluation results
	Block = Type(rune(byteBlock))
	// Empty value
	Empty = Type(rune(byteEmpty))
	// Version value
	Version = Type(rune(byteVersion))
	// IP address and subnet
	IP = Type(rune(byteIP))
	// ArrayLike is the underlying type of all arrays
	ArrayLike = Type(rune(byteArray))
	// MapLike is the underlying type of all maps
	MapLike = Type(rune(byteMap))
	// ResourceLike is the underlying type of all resources
	ResourceLike = Type(rune(byteResource))
	// FunctionLike is the underlying type of all functions
	FunctionLike = Type(rune(byteFunction))

	// StringSlice is used to represent special function for searching strings.
	// Users are never exposed to this type directly and it is not documented
	// as a primitive. It serves as a way to array functions on top of strings,
	// which is required for cases where a `dict` can represent both an array
	// and a string (as well as other things) at the same time. Functions like
	// `contains` are defined on both arrays and strings with different behavior.
	// This types allows us to keep the compiler and execution simple, while
	// handling the runtime distinction for dict.
	StringSlice = Type(rune(byteStringSlice))

	// Range represents a range of content. This can be a number of lines
	// or lines and columns combined. We use a special type for a very
	// efficient storage and transmission structure.
	Range = Type(rune(byteRange))

	// AssetLike is the underlying type of all asset references. A bare
	// AssetLike carries no root, i.e. nothing can be chained off it.
	AssetLike = Type(rune(byteAsset))
)

// All returns a list of all types available
func All() []Type {
	return []Type{
		Unset,
		Any,
		Nil,
		Ref,
		Bool,
		Int,
		Float,
		String,
		Regex,
		Time,
		Dict,
		Score,
		Block,
		Empty,
		Version,
		IP,
		ArrayLike,
		MapLike,
		ResourceLike,
		FunctionLike,
		AssetLike,
	}
}

// NotSet returns true if the type has no information
func (typ Type) NotSet() bool {
	return typ == ""
}

// Array for list of values
func Array(typ Type) Type {
	return ArrayLike + typ
}

// IsArray checks if this type is an array
func (typ Type) IsArray() bool {
	return typ[0] == byteArray
}

// Map for an association of keys and values
func Map(key, value Type) Type {
	if key != String && key != Int {
		panic("Unsupported map on key type " + key.Label())
	}
	return MapLike + key + value
}

// IsMap checks if this type is a map
func (typ Type) IsMap() bool {
	return typ[0] == byteMap
}

// Resource for complex data structures
func Resource(name string) Type {
	return ResourceLike + Type(name)
}

// IsResource checks if this type is a map
func (typ Type) IsResource() bool {
	if typ.NotSet() {
		return false
	}
	return typ[0] == byteResource
}

// Asset is a native value pointing at another asset by the resource that anchors
// it in the current asset's resource tree. Its payload is an llx.AssetValue
// holding the anchor `(resourceType, resourceId)`. See ADR 030.
//
// It is parameterized by the resource type that is the root of the referenced
// asset's tree, which is what makes chaining off it type-check: `asset<mcp>`
// resolves `.tools` against the `mcp` schema. The root is a *name*, referenced
// without the referenced schema being present (a forward reference), so a
// provider can declare `running asset<mcp>` without depending on the provider
// that defines `mcp`. See ADR 031.
func Asset(root string) Type {
	return AssetLike + Type(root)
}

// IsAsset checks if this type is a native asset reference
func (typ Type) IsAsset() bool {
	if typ.NotSet() {
		return false
	}
	return typ[0] == byteAsset
}

// ContainsResource checks if this or any child type has a resource
func (typ Type) ContainsResource() bool {
	for {
		if typ.IsResource() {
			return true
		}

		if !typ.IsArray() && !typ.IsMap() {
			return false
		}

		typ = typ.Child()
	}
}

// Function for creating a function type signature
func Function(required rune, args []Type) Type {
	var sig strings.Builder
	for _, arg := range args {
		sig.WriteString(string(arg) + "\x00")
	}
	return FunctionLike + Type(required) + Type(sig.String())
}

// IsFunction checks if this type is a map
func (typ Type) IsFunction() bool {
	return typ[0] == byteFunction
}

// Underlying returns the basic type, e.g. types.MapLike instead of types.Map(..)
func (typ Type) Underlying() Type {
	return Type(typ[0])
}

// Enforce makes sure that both types are the same, and returns the common
// type and true if they are, false otherwise (and the right type).
// - if one of the types is not yet set, use the other type instead.
// - if neither are set return the unset type.
// - goes into child types to see if either is unset
func Enforce(left, right Type) (Type, bool) {
	var i int
	for ; i < len(left) && i < len(right); i++ {
		if left[i] == right[i] {
			continue
		}

		if right[i] == byteUnset || right[i] == byteNil {
			return left, true
		}
		if left[i] == byteUnset || left[i] == byteNil {
			return right, true
		}
	}

	return right, len(left) == len(right)
}

// CoalesceArrays returns whichever of two array types carries a usable element
// type. An empty array literal has none: `[]` compiles to []unset. Without this,
// `[] + ["a"]` would keep the left type and yield an []unset result that fails
// to compile downstream, while `["a"] + []` works, making operand order matter.
//
// Only a genuinely unknown element type is replaced. Mismatched but known types
// keep the left one, preserving the existing behavior of `["a"] + [1]`.
// Non-array types are returned unchanged, so arithmetic on scalars is unaffected.
func CoalesceArrays(left, right Type) Type {
	if left.IsArray() && right.IsArray() && arrayElemUnset(left) && !arrayElemUnset(right) {
		return right
	}
	return left
}

// arrayElemUnset reports whether an array type lacks a usable element type,
// either because it carries none at all (bare ArrayLike) or because the element
// type is unset/null. Only call this on array types.
func arrayElemUnset(typ Type) bool {
	if len(typ) < 2 {
		return true
	}
	child := typ.Child()
	return child == Unset || child == Nil
}

// Child returns the child type of arrays and maps
func (typ Type) Child() Type {
	switch typ[0] {
	case byteDict:
		return Dict
	case byteArray:
		return typ[1:]
	case byteMap:
		return typ[2:]
	}
	panic("cannot determine child type of " + typ.Label())
}

// Key returns the key type of a map
func (typ Type) Key() Type {
	if typ[0] != byteMap {
		panic("cannot retrieve key type of non-map type " + typ.Label())
	}
	return Type(typ[1])
}

// ResourceName return the name of a resource. Has to be a resource type,
// otherwise this call panics.
func (typ Type) ResourceName() string {
	if typ[0] == byteResource {
		return string(typ[1:])
	}
	panic("cannot determine type name of " + typ.Label())
}

// AssetRootName returns the name of the resource that roots the referenced
// asset's tree, or an empty string for a bare asset reference that declares no
// root. Has to be an asset type, otherwise this call panics.
func (typ Type) AssetRootName() string {
	if typ[0] == byteAsset {
		return string(typ[1:])
	}
	panic("cannot determine asset root of " + typ.Label())
}

var labels = map[byte]string{
	byteUnset:       "unset",
	byteAny:         "any",
	byteNil:         "null",
	byteRef:         "ref",
	byteBool:        "bool",
	byteInt:         "int",
	byteFloat:       "float",
	byteString:      "string",
	byteRegex:       "regex",
	byteTime:        "time",
	byteDict:        "dict",
	byteScore:       "score",
	byteBlock:       "block",
	byteEmpty:       "empty",
	byteVersion:     "version",
	byteIP:          "ip",
	byteStringSlice: "stringslice",
	byteRange:       "range",
}

var labelfun map[byte]func(Type) string

func init() {
	labelfun = map[byte]func(Type) string{
		byteArray: func(s Type) string {
			if s == "" {
				return "[]"
			}
			return "[]" + s.Label()
		},
		byteMap: func(s Type) string {
			if s == "" {
				return "map"
			}
			return "map[" + Type(s[0]).Label() + "]" + s[1:].Label()
		},
		byteResource: func(s Type) string {
			if s == "" {
				return "resource"
			}
			return string(s)
		},
		byteFunction: func(f Type) string { return "func()" },
		byteAsset: func(s Type) string {
			if s == "" {
				return "asset"
			}
			return "asset<" + string(s) + ">"
		},
	}
}

// Label provides a user-friendly type label
func (typ Type) Label() string {
	if typ == "" {
		return "EMPTY"
	}

	h, ok := labels[typ[0]]
	if ok {
		return h
	}

	hf, ok := labelfun[typ[0]]
	if !ok {
		panic("cannot find label for type " + typ)
	}
	return hf(typ[1:])
}

// Equal provides a set of function for a range of types to test if 2 values
// of that type are equal.
//
// A null array element surfaces here as a nil interface, so every comparator
// guards against it: two nils are equal, a nil and a value are not. Without
// this the type assertions below panic (e.g. `interface {} is nil, not
// string`), which crashes the entire scan instead of failing one comparison.
var Equal = map[Type]func(any, any) bool{
	Bool: func(left, right any) bool {
		if left == nil || right == nil {
			return left == nil && right == nil
		}
		return left.(bool) == right.(bool)
	},
	Int: func(left, right any) bool {
		if left == nil || right == nil {
			return left == nil && right == nil
		}
		return left.(int64) == right.(int64)
	},
	Float: func(left, right any) bool {
		if left == nil || right == nil {
			return left == nil && right == nil
		}
		return left.(float64) == right.(float64)
	},
	String: func(left, right any) bool {
		if left == nil || right == nil {
			return left == nil && right == nil
		}
		return left.(string) == right.(string)
	},
	Regex: func(left, right any) bool {
		if left == nil || right == nil {
			return left == nil && right == nil
		}
		return left.(string) == right.(string)
	},
	Time: func(left, right any) bool {
		if left == nil || right == nil {
			return left == nil && right == nil
		}
		l := left.(*time.Time)
		r := right.(*time.Time)
		// The guard above only catches an untyped nil interface; a typed
		// (*time.Time)(nil) element still reaches here, so keep checking the
		// pointer before dereferencing it.
		if l == nil || r == nil {
			return false
		}
		return l.Equal(*r)
	},
	// types.Dict: func(left, right any) bool {},
	Score: func(left, right any) bool {
		if left == nil || right == nil {
			return left == nil && right == nil
		}
		return left.(int32) == right.(int32)
	},
}

// ResourceOf returns the resource a type names, descending through the
// containers a field may wrap it in (a list of resources, a map of them). It
// returns "" for every type that names no resource.
//
// Unlike ResourceName it never panics: callers walk types that arrive from
// bytecode and from provider schemas, where an unexpected shape is a reason to
// skip the value rather than to crash the query.
func ResourceOf(typ Type) string {
	for range 8 {
		if typ.NotSet() {
			return ""
		}
		if typ.IsResource() {
			return typ.ResourceName()
		}
		switch typ.Underlying() {
		case ArrayLike:
			typ = typ[1:]
		case MapLike:
			if len(typ) < 2 {
				return ""
			}
			typ = typ[2:]
		default:
			return ""
		}
	}
	return ""
}
