// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx

import (
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
)

// Result holds the output of one query evaluation. Value returns the data as
// plain Go values, Decode unmarshals it into native structs, and Raw exposes
// the untouched execution output for advanced use.
type Result struct {
	bundle *llx.CodeBundle
	raw    map[string]*llx.RawResult

	once      sync.Once
	value     any
	fieldErrs []FieldError
}

func newResult(bundle *llx.CodeBundle, raw map[string]*llx.RawResult) *Result {
	return &Result{bundle: bundle, raw: raw}
}

func (r *Result) normalize() {
	r.once.Do(func() {
		r.value, r.fieldErrs = normalize(r.bundle, r.raw)
	})
}

// Value returns the query result as plain Go values: scalars as-is, blocks
// as map[string]any keyed by field labels, and lists as []any. A query with
// multiple top-level values returns a map keyed by each value's label.
// Values that errored during execution are nil; inspect Err or FieldErrors.
func (r *Result) Value() any {
	r.normalize()
	return r.value
}

// Err reports errors that occurred while producing individual values, joined
// into one error. It is nil when every value resolved cleanly. Evaluation
// failures (compile errors, connection loss) are returned by Eval itself,
// not here.
func (r *Result) Err() error {
	r.normalize()
	if len(r.fieldErrs) == 0 {
		return nil
	}
	errs := make([]error, len(r.fieldErrs))
	for i := range r.fieldErrs {
		errs[i] = r.fieldErrs[i]
	}
	return errors.Join(errs...)
}

// FieldErrors lists errors attached to individual values, each with the path
// of the value inside Value.
func (r *Result) FieldErrors() []FieldError {
	r.normalize()
	return r.fieldErrs
}

// Decode unmarshals the query result into target, which must be a non-nil
// pointer to a struct, slice, map, or scalar. Struct fields are matched by
// the `mql` tag, then the `json` tag, then the field name (exact, then
// case-insensitive). Fields of anonymous (embedded) structs are promoted, as
// with encoding/json.
//
// If any value carried an execution error, Decode fills target with the data
// that is available and returns those errors, so missing data is never
// silently zero-valued.
func (r *Result) Decode(target any) error {
	r.normalize()
	if err := decode(r.value, target); err != nil {
		return err
	}
	return r.Err()
}

// Raw exposes the untouched execution output: the checksum-keyed results and
// the compiled code bundle that maps checksums to labels.
func (r *Result) Raw() (map[string]*llx.RawResult, *llx.CodeBundle) {
	return r.raw, r.bundle
}
