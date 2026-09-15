// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/versionx"
)

// MQL's `version` type is a thin wrapper over utils/versionx: this file wires the
// operators to it and does nothing clever of its own. Parsing, ordering and range
// semantics live in that package so a version orders the same way in MQL, in an
// inventory listing, and in any service that has to sort the same strings — which was
// not true while llx carried its own semver-with-lexical-fallback comparator.
//
// Note that `==` and `!=` stay TEXTUAL (versionEqVersion below). Ordering is semantic,
// so version('1.2') < version('1.2.1'), but equality answers "is this the same version
// string", which is what a policy asserting an exact pinned version means.

// versionCompare wraps a comparison of two version strings into a builtin operator,
// guarding the operands: a bare type assertion on runtime data panics the executor, and
// a panic in a comparator takes down the whole scan rather than one query.
func versionCompare(keep func(cmp int) bool) func(left, right any) *RawData {
	return func(left, right any) *RawData {
		l, lIsStr := left.(string)
		r, rIsStr := right.(string)
		if !lIsStr || !rIsStr {
			return &RawData{
				Type:  types.Bool,
				Error: errors.New("version comparison expects version strings"),
			}
		}
		return BoolData(keep(versionx.Compare(l, r)))
	}
}

var (
	versionLT  = versionCompare(func(c int) bool { return c < 0 })
	versionGT  = versionCompare(func(c int) bool { return c > 0 })
	versionLTE = versionCompare(func(c int) bool { return c <= 0 })
	versionGTE = versionCompare(func(c int) bool { return c >= 0 })
)

func versionCmpVersion(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left, right any) *RawData {
		return BoolData(left == right)
	})
}

func versionNotVersion(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left, right any) *RawData {
		return BoolData(left != right)
	})
}

func versionLTversion(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, versionLT)
}

func versionGTversion(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, versionGT)
}

func versionLTEversion(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, versionLTE)
}

func versionGTEversion(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, versionGTE)
}

func versionEpoch(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int, Error: bind.Error}, 0, nil
	}

	raw, ok := bind.Value.(string)
	if !ok {
		return &RawData{Type: types.Int, Error: errors.New("`epoch` expects a version")}, 0, nil
	}

	return IntData(int64(versionx.Parse(raw).Epoch())), 0, nil
}

// versionInRange implements `version(x).inRange(lower, upper)`. Each argument is a
// bound: a bare version is read as inclusive (">=" for the first, "<=" for the rest),
// and an argument that already names an operator is passed through.
//
// Both bounds and the version itself go through versionx, so this now answers for
// version shapes the old semver-only implementation had to refuse outright — an epoch'd
// deb version, a four-component build. A version with nothing numeric in it ("latest")
// is still an error rather than a silent false.
func versionInRange(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	raw, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("`inRange` expects a version")
	}

	base := versionx.Parse(raw)
	if base.Kind() == versionx.KindUnknown {
		return nil, 0, errors.New("inRange is only supported on comparable versions (semver or similar)")
	}

	conditions := make([]string, 0, len(chunk.Function.Args))
	for i := range chunk.Function.Args {
		argRef := chunk.Function.Args[i]

		arg, rref, err := e.resolveValue(argRef, ref)
		if err != nil || rref > 0 {
			return nil, rref, err
		}

		s, ok := arg.Value.(string)
		if !ok {
			return nil, 0, errors.New("incorrect type for argument in `inRange` call (expected string)")
		}
		ts := strings.TrimSpace(s)
		if ts == "" {
			return nil, 0, errors.New("inRange was called with an empty bound")
		}
		// A BARE bound is inclusive, and which side it bounds depends on its position:
		// the first argument is the floor, everything after it the ceiling. A bound
		// that already carries an operator or is a range of its own ("^1.2.3", "1.2.x")
		// must be passed through untouched — prefixing it would stack two operators.
		if versionx.NeedsOperator(ts) {
			if i == 0 {
				ts = ">= " + ts
			} else {
				ts = "<= " + ts
			}
		}

		conditions = append(conditions, ts)
	}

	res, err := versionx.Satisfies(base, conditions...)
	if err != nil {
		return nil, 0, errors.New("inRange was called with an invalid constraint: " + err.Error())
	}
	if !res {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}
