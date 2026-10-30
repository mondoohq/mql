// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx

import (
	"context"
	"maps"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// EvalOption configures a single evaluation.
type EvalOption func(*evalOptions) error

type evalOptions struct {
	props map[string]any
}

// WithPropValues overrides property values declared at compile time with
// WithProps. Every key must be declared and its value must match the
// declared type.
func WithPropValues(props map[string]any) EvalOption {
	return func(o *evalOptions) error {
		o.props = props
		return nil
	}
}

// Eval evaluates the query in expression mode: against the environment's
// internal runtime, which provides MQL's operators and core resources but no
// infrastructure. Use it to run MQL over values passed in via props. For
// queries against an asset, use EvalOn.
func (q *Query) Eval(ctx context.Context, opts ...EvalOption) (*Result, error) {
	rt, err := q.env.exprRuntime()
	if err != nil {
		return nil, err
	}
	return q.eval(ctx, rt, opts)
}

// EvalOn evaluates the query against a connected asset.
func (q *Query) EvalOn(ctx context.Context, conn *Conn, opts ...EvalOption) (*Result, error) {
	if conn == nil {
		return nil, errors.New("cannot evaluate query: no connection provided")
	}
	return q.eval(ctx, conn.runtime, opts)
}

func (q *Query) eval(ctx context.Context, rt llx.Runtime, opts []EvalOption) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var options evalOptions
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	props, err := q.mergeProps(options.props)
	if err != nil {
		return nil, err
	}

	// Queries without entrypoints (e.g. assignments only) produce no values;
	// the executor cannot run them.
	if len(q.bundle.CodeV2.Entrypoints()) == 0 {
		return newResult(q.bundle, nil), nil
	}

	raw, err := exec.ExecuteCode(rt, q.bundle, props, q.env.features)
	if err != nil {
		return nil, err
	}

	return newResult(q.bundle, raw), nil
}

// mergeProps combines the compile-time property defaults with per-evaluation
// overrides, enforcing that overrides are declared and type-correct.
func (q *Query) mergeProps(overrides map[string]any) (map[string]*llx.Primitive, error) {
	if len(overrides) == 0 {
		return q.props, nil
	}

	props := make(map[string]*llx.Primitive, len(q.props))
	maps.Copy(props, q.props)

	for k, v := range overrides {
		declared, ok := props[k]
		if !ok {
			return nil, errors.New("property '" + k + "' was not declared at compile time (use WithProps)")
		}
		prim, err := ToPrimitive(v)
		if err != nil {
			return nil, errors.Wrap(err, "failed to convert property '"+k+"'")
		}
		if prim.Type != declared.Type {
			return nil, errors.New("property '" + k + "' must be of type " +
				types.Type(declared.Type).Label() + ", got " + types.Type(prim.Type).Label())
		}
		props[k] = prim
	}

	return props, nil
}
