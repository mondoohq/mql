// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestServiceGateRecordWinsTheOnce pins the interaction between the two entry
// points. recordEnabled stores the answer the gcp.project.<service>() accessor
// already computed; resolveEnabled computes it for the paths that did not go
// through that accessor. Both claim the same sync.Once, which is what makes
// them race-free against each other.
//
// The nil runtime is the assertion: if the recorded answer did not win the
// once, resolveEnabled would go build a gcp.project resource and panic.
func TestServiceGateRecordWinsTheOnce(t *testing.T) {
	var gate serviceGate
	gate.recordEnabled(true)

	enabled, err := gate.resolveEnabled(nil, plugin.TValue[string]{Data: "some-project"}, "compute.googleapis.com")
	require.NoError(t, err)
	require.True(t, enabled)
}

// TestServiceGateRecordsDisabled is the same in the other direction: a recorded
// `false` must also short-circuit. The predecessor of this type re-resolved on
// a recorded false, because it could not tell "checked, disabled" apart from
// "never checked".
func TestServiceGateRecordsDisabled(t *testing.T) {
	var gate serviceGate
	gate.recordEnabled(false)

	enabled, err := gate.resolveEnabled(nil, plugin.TValue[string]{Data: "some-project"}, "compute.googleapis.com")
	require.NoError(t, err)
	require.False(t, enabled)
}

// TestServiceGatePropagatesProjectIdError checks that an unresolvable project
// surfaces as an error rather than as `false`.
//
// This is the whole point of the gate returning (bool, error). A failed
// resolution folded into `false` reports "this project has nothing" for a
// project that was never successfully checked, and every assertion over the
// resulting empty collection passes vacuously.
func TestServiceGatePropagatesProjectIdError(t *testing.T) {
	boom := errors.New("project id unavailable")
	var gate serviceGate

	enabled, err := gate.resolveEnabled(nil, plugin.TValue[string]{Error: boom}, "compute.googleapis.com")
	require.ErrorIs(t, err, boom)
	require.False(t, enabled)

	// a later recordEnabled must not paper over a resolution that already failed
	gate.recordEnabled(true)
	enabled, err = gate.resolveEnabled(nil, plugin.TValue[string]{Data: "p"}, "compute.googleapis.com")
	require.ErrorIs(t, err, boom)
	require.False(t, enabled)
}

// TestServiceGateResolvesOnce guards the memoization: repeated reads must not
// re-resolve. A nil runtime on the second call would panic if they did.
func TestServiceGateResolvesOnce(t *testing.T) {
	var gate serviceGate
	gate.recordEnabled(true)
	for range 3 {
		enabled, err := gate.resolveEnabled(nil, plugin.TValue[string]{Data: "p"}, "compute.googleapis.com")
		require.NoError(t, err)
		require.True(t, enabled)
	}
}

// TestServiceGateIsTheOnlyEnabledMechanism replaces the two AST tests that used
// to police the hand-copied version of this gate.
//
// Those tests existed because the mechanism was 25 lines duplicated into every
// service file, so it could be copied wrong or forgotten entirely -- and the
// failure mode (an unresolved flag reading as `false`) is an authoritative
// empty collection, which no compiler and no live query complains about. The
// embedded serviceGate makes the resolution impossible to omit, so what is left
// to check is that nobody grows a second mechanism alongside it.
func TestServiceGateIsTheOnlyEnabledMechanism(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	// Fields the hand-rolled gates used. serviceGate owns this state now; a
	// resource that re-declares any of them has grown a parallel mechanism
	// that the gate cannot keep consistent.
	banned := []string{"serviceEnabled bool", "serviceOnce", "serviceChecked", "serviceErr"}

	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		raws, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := string(raws)

		for _, field := range banned {
			if strings.Contains(src, field) {
				t.Errorf("%s: declares %q; serviceGate owns the service-enabled state. "+
					"Embed serviceGate in the Internal struct and forward isEnabled() to "+
					"resolveEnabled instead", path, field)
			}
		}

		// every isEnabled() must be a forwarder -- a hand-written body can
		// reintroduce the zero-value bug the gate exists to prevent
		for _, decl := range raw.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "isEnabled" || fn.Recv == nil || fn.Body == nil {
				continue
			}
			if !isResolveEnabledForwarder(fn) {
				t.Errorf("%s: isEnabled() is hand-written; it must be a single "+
					"`return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_x)` so "+
					"every construction path resolves the gate identically",
					fset.Position(fn.Pos()))
			}
		}
	}
}

// isResolveEnabledForwarder reports whether fn's body is exactly
// `return g.resolveEnabled(...)`.
func isResolveEnabledForwarder(fn *ast.FuncDecl) bool {
	if len(fn.Body.List) != 1 {
		return false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "resolveEnabled"
}

// TestGatedServiceCollectionsConsultTheGate closes the gap the two tests above
// leave open.
//
// They police the gate's mechanism -- that nobody grows a parallel one, that
// isEnabled() stays a forwarder. Neither notices a service that embeds the gate
// and then never asks it. That is not hypothetical: vertexai carried 25
// collections and monitoring 7, none of which consulted any gate, so on a
// project with the API switched off every one of them spent a doomed call per
// region and returned an authoritative empty list.
//
// Scope is deliberately narrow. Only resources whose Internal struct embeds
// serviceGate are checked -- those are the ones that opted in, so there is no
// judgement call about which services ought to be gated and no false failure on
// one that should not be.
func TestGatedServiceCollectionsConsultTheGate(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".lr.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files[path] = f
	}

	// Resource types whose Internal struct embeds serviceGate.
	gated := map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !strings.HasSuffix(ts.Name.Name, "Internal") {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range st.Fields.List {
				if len(field.Names) != 0 {
					continue // named field, not an embed
				}
				if id, ok := field.Type.(*ast.Ident); ok && id.Name == "serviceGate" {
					gated[strings.TrimSuffix(ts.Name.Name, "Internal")] = true
				}
			}
			return true
		})
	}
	require.NotEmpty(t, gated, "no gated services found; this test would pass vacuously")

	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || len(fn.Recv.List) != 1 {
				continue
			}
			star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			recv, ok := star.X.(*ast.Ident)
			if !ok || !gated[recv.Name] {
				continue
			}
			// Only collections: func() ([]any, error).
			if !returnsAnySliceAndError(fn) {
				continue
			}
			if fn.Name.Name == "isEnabled" || callsIsEnabled(fn) {
				continue
			}
			t.Errorf("%s: %s.%s() lists without consulting the service gate. "+
				"On a project with the API disabled it spends calls that cannot "+
				"succeed and returns an empty list as fact. Start it with "+
				"`enabled, err := g.isEnabled()`.",
				fset.Position(fn.Pos()), recv.Name, fn.Name.Name)
		}
	}
}

func returnsAnySliceAndError(fn *ast.FuncDecl) bool {
	// Collections take no arguments. A shared helper that happens to return the
	// same pair (vertexai listAcrossRegions) is not an accessor, and is reached
	// only from ones that are already gated.
	if fn.Type.Params != nil && len(fn.Type.Params.List) != 0 {
		return false
	}
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
		return false
	}
	arr, ok := fn.Type.Results.List[0].Type.(*ast.ArrayType)
	if !ok {
		return false
	}
	elem, ok := arr.Elt.(*ast.Ident)
	if !ok || elem.Name != "any" {
		return false
	}
	errIdent, ok := fn.Type.Results.List[1].Type.(*ast.Ident)
	return ok && errIdent.Name == "error"
}

func callsIsEnabled(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "isEnabled" {
			found = true
		}
		return true
	})
	return found
}
