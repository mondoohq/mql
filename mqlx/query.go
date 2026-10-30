// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
)

// Query is a compiled MQL query. It is immutable and safe to share across
// goroutines: compile once, evaluate many times — in expression mode or
// against any number of connections.
type Query struct {
	env    *Env
	src    string
	bundle *llx.CodeBundle
	props  map[string]*llx.Primitive
}

// CompileOption configures a compilation.
type CompileOption func(*compileOptions) error

type compileOptions struct {
	props map[string]any
}

// WithProps declares the properties a query may reference as props.<name>.
// The values serve two purposes: they declare each property's type to the
// compiler, and they act as default values at evaluation time. Override them
// per evaluation with WithPropValues.
func WithProps(props map[string]any) CompileOption {
	return func(o *compileOptions) error {
		o.props = props
		return nil
	}
}

// Compile compiles an MQL query against the currently loaded provider
// schemas. The returned Query is reusable and safe for concurrent
// evaluation.
func (e *Env) Compile(src string, opts ...CompileOption) (*Query, error) {
	var options compileOptions
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	props, err := ToPrimitiveMap(options.props)
	if err != nil {
		return nil, err
	}

	conf := mqlc.NewConfig(e.schema(), e.features)
	conf.Strict = e.strict
	bundle, err := mqlc.Compile(src, mqlc.SimpleProps(props), conf)
	if err != nil {
		return nil, &CompileError{Source: src, Err: err}
	}

	return &Query{
		env:    e,
		src:    src,
		bundle: bundle,
		props:  props,
	}, nil
}

// MustCompile is like Compile but panics on error. Use it for query
// constants whose validity is guaranteed by tests.
func (e *Env) MustCompile(src string, opts ...CompileOption) *Query {
	q, err := e.Compile(src, opts...)
	if err != nil {
		panic(err.Error())
	}
	return q
}

// Source returns the original MQL source of the query.
func (q *Query) Source() string {
	return q.src
}

// Bundle exposes the compiled code for advanced use (printing, persistence).
func (q *Query) Bundle() *llx.CodeBundle {
	return q.bundle
}
