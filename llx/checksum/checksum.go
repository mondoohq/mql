// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package checksum computes canonical, structural content checksums over llx
// values. They exist so that the client and the server can both tell, one
// row at a time, whether a scan's content is identical to the previous
// upload — and skip re-transferring or re-processing what hasn't changed
// (the ScanContentMode* features). This package owns
// everything expressible in llx terms: the hash writer, the canonicalization
// of llx primitives/results, and the data/resource row checksums. Checksums
// over types that live outside mql (cnspec's scores and risk factors) build
// on this package from cnspec's policy/scandb/checksum. Consumers never
// re-implement any of this: two implementations of one algorithm drift, and
// checksum drift silently reports identical scans as changed (or worse).
//
// Canonicalization is structural and explicit: every hashed message has a
// hand-written canon function that names each field it folds in. There is
// deliberately no reflection walk (protoreflect) and no hashing of marshaled
// proto bytes. Marshaled bytes are out because proto serialization (even
// Deterministic) is not guaranteed stable across library versions; a
// reflection walk is out because it changes meaning silently the moment a
// message grows a field — an explicit canon makes "is this field content?"
// a reviewed decision, visible in a diff.
//
// Every variable-length write is length-prefixed, so concatenation ambiguity
// ("ab"+"c" vs "a"+"bc") cannot collide. Domain literals separate the hash
// spaces. Lists whose order is not content are hashed as multisets: sorted
// per-element sub-checksums, so the same set in a different enumeration
// order produces the same checksum while duplicates still count.
package checksum

import (
	"encoding/binary"
	"fmt"
	"hash"
	"hash/fnv"
	"math"
	"slices"
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// AlgoVersion identifies the canonicalization algorithm. It is a fold input:
// checksums produced by different versions never compare equal. Bump on any
// change to the canonicalization rules below.
//
// v1: FNV-1a 64 (stdlib hash/fnv — no third-party dependency),
// length-prefixed writes, explicit canonicalization of the fixed message
// set, arrays hashed as multisets (sorted per-element sub-checksums —
// provider enumeration order is not content), floats normalized (-0.0
// folds as +0.0, every NaN as one canonical bit pattern), nesting bounded
// at maxCanonDepth.
const AlgoVersion = "1"

// maxCanonDepth bounds primitive nesting during canonicalization. Each Dict
// layer is a proto-encoded Primitive whose Value is another Primitive, so a
// hostile or corrupted payload could otherwise recurse without limit. Real
// llx values are a handful of levels deep; exceeding this is corruption and
// errors out (the caller fails open to a full upload, never a wrong skip).
const maxCanonDepth = 64

// canonicalNaN is the single bit pattern every NaN folds to: two NaNs are
// semantically the same "no value" even when their payload bits differ, and
// hashing payload bits would report identical scans as changed.
const canonicalNaN = 0x7FF8000000000001

// Hasher is a length-prefixed, domain-separated hash writer over FNV-1a 64.
// AlgoVersion covers a later switch to a stronger or wider hash.
//
// Write errors are recorded, not ignored: the first error sticks, later
// writes become no-ops, and Err surfaces it. The row-level Hash* functions
// and the exported canon helpers check it before returning a sum, so a
// failed write can never silently produce a valid-looking checksum.
type Hasher struct {
	h   hash.Hash64
	err error
}

// NewHasher returns a Hasher domain-separated by the given literal.
func NewHasher(domain string) *Hasher {
	h := &Hasher{h: fnv.New64a()}
	h.Str(domain)
	return h
}

// write funnels every hash write through one error-checked path.
func (h *Hasher) write(b []byte) {
	if h.err != nil {
		return
	}
	if _, err := h.h.Write(b); err != nil {
		h.err = err
	}
}

func (h *Hasher) writeLen(n int) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(n))
	h.write(buf[:])
}

// Str writes a length-prefixed string.
func (h *Hasher) Str(s string) *Hasher {
	h.writeLen(len(s))
	h.write([]byte(s))
	return h
}

// Bytes writes a length-prefixed byte slice.
func (h *Hasher) Bytes(b []byte) *Hasher {
	h.writeLen(len(b))
	h.write(b)
	return h
}

// U64 writes a fixed-width uint64.
func (h *Hasher) U64(v uint64) *Hasher {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	h.write(buf[:])
	return h
}

// U32 writes a fixed-width uint32 (widened).
func (h *Hasher) U32(v uint32) *Hasher { return h.U64(uint64(v)) }

// I64 writes a fixed-width int64.
func (h *Hasher) I64(v int64) *Hasher { return h.U64(uint64(v)) }

// F64 writes a float64 by normalized bit pattern: +0.0 and -0.0 fold
// identically, and every NaN folds to canonicalNaN — bit-level noise in
// semantically equal values must not read as content change.
func (h *Hasher) F64(v float64) *Hasher {
	if v == 0 { // true for both +0.0 and -0.0
		return h.U64(0)
	}
	if math.IsNaN(v) {
		return h.U64(canonicalNaN)
	}
	return h.U64(math.Float64bits(v))
}

// Bool writes a single canonical byte.
func (h *Hasher) Bool(v bool) *Hasher {
	if v {
		return h.U64(1)
	}
	return h.U64(0)
}

// Sum64 finalizes the hash. Callers that reached it through the Hash* row
// functions or the exported canon helpers have already had Err checked;
// direct users must check Err themselves.
func (h *Hasher) Sum64() uint64 { return h.h.Sum64() }

// Err returns the first write error, if any. A Hasher with a non-nil Err
// must not have its sum used.
func (h *Hasher) Err() error { return h.err }

// Multiset hashes a list as a multiset: each element hashed independently
// under domain, the sorted element checksums folded in. Element order is not
// content — the same set in a different order must produce the same
// checksum. Duplicates still count (multiset, not set). Exported so
// downstream canon functions (cnspec's score checksums) fold their lists
// with the exact same encoding.
func Multiset[T any](h *Hasher, domain string, items []T, canon func(*Hasher, T) error) error {
	h.writeLen(len(items))
	if len(items) == 0 {
		return h.Err()
	}
	sums := make([]uint64, len(items))
	for i, el := range items {
		eh := NewHasher(domain)
		if err := canon(eh, el); err != nil {
			return err
		}
		if err := eh.Err(); err != nil {
			return err
		}
		sums[i] = eh.Sum64()
	}
	slices.Sort(sums)
	for _, s := range sums {
		h.U64(s)
	}
	return h.Err()
}

// CanonResultMap hashes a key/result map key-sorted. Exported for the same
// reason as Multiset: downstream canon functions carry result maps too.
func CanonResultMap(h *Hasher, m map[string]*llx.Result) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h.writeLen(len(keys))
	for _, k := range keys {
		h.Str(k)
		if err := CanonResult(h, m[k]); err != nil {
			return err
		}
	}
	return h.Err()
}

// CanonPrimitive hashes an llx.Primitive structurally. Scalar Value bytes
// are hashed as-is (they are llx's own canonical scalar encodings, not
// proto-marshaled messages). Dict and Asset primitives carry nested encoded
// messages in Value; those are decoded and re-walked, never hashed raw.
// Arrays are hashed as multisets; maps key-sorted. Nesting deeper than
// maxCanonDepth is corruption and errors out.
func CanonPrimitive(h *Hasher, p *llx.Primitive) error {
	return canonPrimitive(h, p, 0)
}

func canonPrimitive(h *Hasher, p *llx.Primitive, depth int) error {
	if depth > maxCanonDepth {
		return fmt.Errorf("canon: primitive nesting exceeds depth %d", maxCanonDepth)
	}
	if p == nil {
		h.Str("<nil>")
		return h.Err()
	}
	h.Str(p.Type)

	// Matched with predicates rather than as an exact switch: an asset type
	// carries its root (`asset<mcp>`), so an equality case would miss every
	// typed asset and hash its payload as opaque bytes.
	typ := types.Type(p.Type)
	switch {
	case typ == types.Nil:
		// Explicit sentinel: a Nil primitive's Value bytes are not content,
		// and must never become content by accident if a future encoder
		// stores something there.
		h.Str("nil")
	case typ == types.Dict:
		if len(p.Value) > 0 {
			inner := &llx.Primitive{}
			if err := inner.UnmarshalVT(p.Value); err != nil {
				return fmt.Errorf("canon: failed to decode dict payload: %w", err)
			}
			h.Str("dict")
			if err := canonPrimitive(h, inner, depth+1); err != nil {
				return err
			}
		} else {
			h.Str("dict:empty")
		}
	case typ.IsAsset():
		if len(p.Value) > 0 {
			av := &llx.AssetValue{}
			if err := av.UnmarshalVT(p.Value); err != nil {
				return fmt.Errorf("canon: failed to decode asset payload: %w", err)
			}
			h.Str("asset")
			h.Str(av.ResourceType).Str(av.ResourceId)
		} else {
			h.Str("asset:empty")
		}
	default:
		h.Bytes(p.Value)
	}

	if err := Multiset(h, "array_element", p.Array, func(eh *Hasher, el *llx.Primitive) error {
		return canonPrimitive(eh, el, depth+1)
	}); err != nil {
		return err
	}

	if len(p.Map) > 0 {
		keys := make([]string, 0, len(p.Map))
		for k := range p.Map {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		h.writeLen(len(keys))
		for _, k := range keys {
			h.Str(k)
			if err := canonPrimitive(h, p.Map[k], depth+1); err != nil {
				return err
			}
		}
	} else {
		h.writeLen(0)
	}

	return h.Err()
}

// CanonResult hashes an llx.Result's error and data. The CodeId is NOT
// hashed here — callers hash the row key themselves (it is the map key /
// primary key at every call site).
//
// A nil Result folds exactly like the zero Result. proto3 maps cannot
// represent a nil message value, so a nil inside an in-memory result map
// round-trips through marshal/unmarshal as a non-nil empty Result: nil and
// zero are one value on the wire, and hashing them differently would make
// the same logical row checksum differently before and after storage — the
// exact divergence that breaks write-time emission against a recompute
// from the stored row. The fold direction (nil adopts the zero encoding,
// never the reverse) is deliberate: decoded rows can never contain a nil,
// so no checksum of stored data moves and AlgoVersion stays at "1".
func CanonResult(h *Hasher, r *llx.Result) error {
	if r == nil {
		r = &llx.Result{}
	}
	h.Str(r.Error)
	return CanonPrimitive(h, r.Data)
}

// HashDataRow computes the row checksum for a data row:
// H("row:data" ‖ code_id ‖ error ‖ canon(data)).
func HashDataRow(codeID string, r *llx.Result) (uint64, error) {
	h := NewHasher("row:data")
	h.Str(codeID)
	if r == nil {
		h.Str("<nil>")
		return h.Sum64(), nil
	}
	h.Str(r.Error)
	if err := CanonPrimitive(h, r.Data); err != nil {
		return 0, err
	}
	return h.Sum64(), nil
}

// HashResourceRow computes the row checksum for a resource row. Created and
// Updated are wall-clock noise and deliberately excluded.
func HashResourceRow(rec *llx.ResourceRecording) (uint64, error) {
	h := NewHasher("row:resource")
	if rec == nil {
		h.Str("<nil>")
		return h.Sum64(), nil
	}
	h.Str(rec.Resource).Str(rec.Id)
	if err := CanonResultMap(h, rec.Fields); err != nil {
		return 0, err
	}
	return h.Sum64(), nil
}
