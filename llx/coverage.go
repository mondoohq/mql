// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"go.mondoo.com/mql/types"
)

// Partial results (ADR 046 §8).
//
// A list assembled from several partitions can succeed in some and be refused
// in others. The value that was read is true and the parts that were not are
// missing; neither half is disposable. The error slot on RawData already means
// "this failed" to every consumer, so the missing parts ride in their own
// slot, RawData.CoverageGaps, and on the wire in Result.coverage_gaps and
// DataRes.coverage_gaps. A consumer that does not read them sees the value
// exactly as it did before they existed.

// partialError is what Partial returns. It is an error only so that an
// accessor can hand it back through the (T, error) signature generated code
// already has; plugin.GetOrCompute recognizes it and keeps the data.
type partialError struct {
	gaps []*Error
}

func (p *partialError) Error() string {
	msgs := make([]string, len(p.gaps))
	for i := range p.gaps {
		msgs[i] = p.gaps[i].Error()
	}
	return "incomplete result: " + strings.Join(msgs, "; ")
}

// Partial marks the value returned beside it as incomplete: each err is a part
// that could not be read. Classify each one and name its partition:
//
//	llx.Forbidden(err,
//	    llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, region),
//	    llx.WithPermissions("ec2:DescribeAddresses"))
//
// An unclassified error is kept as an unclassified gap. Nil errors are
// dropped, and with none left Partial returns nil, so a loop can return it
// unconditionally:
//
//	return res, llx.Partial(errs...)
func Partial(errs ...error) error {
	gaps := CoverageGapsFrom(errs...)
	if len(gaps) == 0 {
		return nil
	}
	return &partialError{gaps: gaps}
}

// CoverageGapsOf returns the gaps a Partial carries, and whether err is one.
// It unwraps, so a Partial wrapped for context is still recognized.
func CoverageGapsOf(err error) ([]*Error, bool) {
	var p *partialError
	if !errors.As(err, &p) {
		return nil, false
	}
	return p.gaps, true
}

// CoverageGapsFrom turns errors into coverage gaps, deduplicated. Nil errors
// are dropped and unclassified errors stay unclassified.
func CoverageGapsFrom(errs ...error) []*Error {
	var res []*Error
	for _, err := range errs {
		if err == nil {
			continue
		}
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{err: err}
		}
		res = append(res, e)
	}
	return UnionCoverageGaps(res)
}

// UnionCoverageGaps merges gap lists, deduplicated on (kind, scope, scope_id,
// permissions). The first gap for a key keeps its message. It returns nil when
// there are no gaps at all, so a complete result carries nothing.
func UnionCoverageGaps(lists ...[]*Error) []*Error {
	var res []*Error
	var seen map[string]struct{}
	for _, list := range lists {
		for _, gap := range list {
			if gap == nil {
				continue
			}
			if seen == nil {
				seen = map[string]struct{}{}
			}
			key := coverageGapKey(gap)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			res = append(res, gap)
		}
	}
	return res
}

func coverageGapKey(gap *Error) string {
	perms := slices.Clone(gap.Permissions)
	slices.Sort(perms)
	return gap.Kind.String() + "\x00" + gap.Scope.String() + "\x00" + gap.ScopeID + "\x00" + strings.Join(perms, "\x00")
}

// CoverageGapsToProto renders gaps into their wire form. Unlike
// ErrorDetailOf, the detail is kept for an unclassified gap too, since the
// partition it names is still worth knowing.
func CoverageGapsToProto(gaps []*Error) []*CoverageGap {
	if len(gaps) == 0 {
		return nil
	}
	res := make([]*CoverageGap, len(gaps))
	for i, gap := range gaps {
		res[i] = &CoverageGap{
			Error: gap.Error(),
			Detail: &ErrorDetail{
				Kind:         gap.Kind,
				Scope:        gap.Scope,
				ScopeId:      gap.ScopeID,
				Permissions:  gap.Permissions,
				RetryAfterMs: gap.RetryAfter.Milliseconds(),
			},
		}
	}
	return res
}

// CoverageGapsFromProto rebuilds gaps from the wire, keeping each message
// verbatim.
func CoverageGapsFromProto(gaps []*CoverageGap) []*Error {
	if len(gaps) == 0 {
		return nil
	}
	res := make([]*Error, 0, len(gaps))
	for _, gap := range gaps {
		if gap == nil {
			continue
		}
		d := gap.GetDetail()
		var inner error
		if gap.GetError() != "" {
			inner = errors.New(gap.GetError())
		}
		res = append(res, &Error{
			Kind:        d.GetKind(),
			Scope:       d.GetScope(),
			ScopeID:     d.GetScopeId(),
			Permissions: d.GetPermissions(),
			RetryAfter:  time.Duration(d.GetRetryAfterMs()) * time.Millisecond,
			err:         inner,
		})
	}
	return res
}

// coverageGapJSON is a coverage gap as JSON output writes it. Kind and scope
// use their machine names; an unclassified gap has kind "unspecified".
type coverageGapJSON struct {
	Kind         string   `json:"kind"`
	Scope        string   `json:"scope,omitempty"`
	ScopeID      string   `json:"scopeId,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	RetryAfterMs int64    `json:"retryAfterMs,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// sortedPermissions returns a sorted copy, so output names the same grants in
// the same order whatever order the call site used. The gap itself is shared
// and keeps its order.
func sortedPermissions(perms []string) []string {
	if len(perms) == 0 {
		return nil
	}
	res := slices.Clone(perms)
	slices.Sort(res)
	return res
}

// CoverageGapsJSONfield renders r's coverage gaps as a JSON field, keyed by
// the same label JSONfield gives the value, or nil when r is complete. JSON
// output writes it beside the value, never inside it, so the value keeps the
// shape anything parsing it relies on (ADR 046 §8).
func (r *RawData) CoverageGapsJSONfield(codeID string, bundle *CodeBundle) []byte {
	if r == nil || len(r.CoverageGaps) == 0 {
		return nil
	}
	gaps := make([]coverageGapJSON, len(r.CoverageGaps))
	for i, gap := range r.CoverageGaps {
		cur := coverageGapJSON{
			Kind:         gap.Kind.Name(),
			ScopeID:      gap.ScopeID,
			Permissions:  sortedPermissions(gap.Permissions),
			RetryAfterMs: gap.RetryAfter.Milliseconds(),
		}
		if gap.Scope != ErrorScope_ERROR_SCOPE_UNSPECIFIED {
			cur.Scope = gap.Scope.Name()
		}
		// A classified gap without an upstream error has only its kind's label
		// as a message, which the kind already says.
		if msg := gap.Error(); msg != gap.Kind.Label() || gap.Kind == ErrorKind_ERROR_KIND_UNSPECIFIED {
			cur.Error = msg
		}
		gaps[i] = cur
	}
	value, err := json.Marshal(gaps)
	if err != nil {
		return JSONerror(err)
	}
	key, err := string2json(label(codeID, bundle, true))
	if err != nil {
		return JSONerror(err)
	}
	return []byte(key + ":" + string(value))
}

// WithCoverageGaps returns r with gaps added to the ones it already carries.
// It never modifies r: a RawData is shared through the runtime's field cache
// and can be one of the package singletons (NilData, UnsetData), so a gap set
// in place would show up on every other read. With no gaps to add, r itself
// is returned.
func (r *RawData) WithCoverageGaps(gaps []*Error) *RawData {
	if r == nil || len(gaps) == 0 {
		return r
	}
	res := *r
	res.CoverageGaps = UnionCoverageGaps(r.CoverageGaps, gaps)
	return &res
}

// Propagation through the executor.
//
// A result computed from a partial input is partial too: eips.where(…),
// eips.length and eips.all(…) carry the gaps of eips. The executor does not
// write gaps onto the values it computes. Values are shared through the step
// cache and the runtime's field cache, and no builtin has to know gaps exist.
// Instead, when a result is handed to a consumer, the gaps of everything it
// was computed from are collected along the code graph: the chunk's own
// value, its binding, its arguments, and whatever the blocks it ran reported.

// resultWithCoverageGaps returns data carrying the gaps of everything ref was
// computed from, for delivery to a consumer.
func (e *blockExecutor) resultWithCoverageGaps(ref uint64, data *RawData) *RawData {
	if data == nil {
		return nil
	}
	return data.WithCoverageGaps(e.coverageGapsOf(ref, map[uint64]struct{}{}))
}

func (e *blockExecutor) coverageGapsOf(ref uint64, visited map[uint64]struct{}) []*Error {
	if ref == 0 {
		return nil
	}
	if _, ok := visited[ref]; ok {
		return nil
	}
	visited[ref] = struct{}{}

	if !e.isInMyBlock(ref) {
		if e.parent == nil {
			return nil
		}
		return e.parent.coverageGapsOf(ref, visited)
	}

	var res []*Error
	if sc, ok := e.cache.Load(ref); ok && sc != nil && sc.Result != nil {
		res = sc.Result.CoverageGaps
	}
	if blockGaps, ok := e.blockCoverageGaps.Load(ref); ok {
		res = UnionCoverageGaps(res, blockGaps.([]*Error))
	}

	block := e.ctx.code.Block(ref)
	idx := int(uint32(ref)) - 1
	if block == nil || idx < 0 || idx >= len(block.Chunks) {
		return res
	}
	chunk := block.Chunks[idx]
	if chunk.Primitive != nil {
		res = UnionCoverageGaps(res, e.coverageGapsOfPrimitive(chunk.Primitive, visited))
	}
	if f := chunk.Function; f != nil {
		res = UnionCoverageGaps(res, e.coverageGapsOf(f.Binding, visited))
		for _, arg := range f.Args {
			res = UnionCoverageGaps(res, e.coverageGapsOfPrimitive(arg, visited))
		}
	}
	return res
}

func (e *blockExecutor) coverageGapsOfPrimitive(p *Primitive, visited map[uint64]struct{}) []*Error {
	switch types.Type(p.Type).Underlying() {
	case types.Ref:
		ref, ok := p.RefV2()
		if !ok {
			return nil
		}
		return e.coverageGapsOf(ref, visited)
	case types.ArrayLike:
		var res []*Error
		for _, v := range p.Array {
			res = UnionCoverageGaps(res, e.coverageGapsOfPrimitive(v, visited))
		}
		return res
	case types.MapLike:
		var res []*Error
		for _, v := range p.Map {
			res = UnionCoverageGaps(res, e.coverageGapsOfPrimitive(v, visited))
		}
		return res
	default:
		return nil
	}
}
