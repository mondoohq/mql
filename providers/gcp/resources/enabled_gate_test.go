// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoBareGetEnabledDataGate pins the service-enabled ERROR contract, the
// companion to TestNoBareServiceEnabledGate in service_gate_test.go.
//
// The compute service resolves its gate through a real `enabled()` accessor
// that builds gcp.project and calls isServiceEnabled. Both steps can fail: a
// missing serviceusage.services.list permission, the Service Usage API itself
// disabled, a transient error, or the phantom empty-project-id discovery asset.
// On failure plugin.GetOrCompute returns
//
//	TValue[bool]{Data: false, Error: err}
//
// so a guard written as
//
//	if !g.GetEnabled().Data { return nil, nil }
//
// discards the error and reports an authoritative EMPTY COLLECTION for a
// project that was never successfully checked. That is the most dangerous wrong
// answer for a posture check: `instances.all(...)`, `firewalls.all(...)` and
// every other assertion pass vacuously instead of failing or erroring.
//
// 40 accessors across compute.go, compute_networking.go, compute_enrichments.go,
// compute_instance_groups_firewall_policies.go and compute_instance_templates.go
// had this shape. Every gate must go through serviceEnabled(), which propagates
// the error.
func TestNoBareGetEnabledDataGate(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".lr.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Data" {
				return true
			}
			// match `<recv>.GetEnabled().Data`
			call, ok := sel.X.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || fn.Sel.Name != "GetEnabled" {
				return true
			}
			t.Errorf("%s: reads GetEnabled().Data directly, discarding the "+
				"resolution error; a failed service-enabled check then reports an "+
				"empty collection for a project it never checked. Use the "+
				"serviceEnabled() helper (compute.go), which propagates the error",
				fset.Position(sel.Pos()))
			return true
		})
	}
}

// TestServiceEnabledHelperPropagatesError guards the helper itself: if it ever
// stops returning the TValue's Error, every one of the 40 call sites silently
// reverts to the bug above.
func TestServiceEnabledHelperPropagatesError(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "compute.go", nil, 0)
	if err != nil {
		t.Fatalf("parse compute.go: %v", err)
	}

	var found bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "serviceEnabled" || fn.Recv == nil {
			continue
		}
		found = true

		var readsError bool
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
				readsError = true
			}
			return true
		})
		if !readsError {
			t.Error("compute.go: serviceEnabled() never inspects the TValue's " +
				"Error; a failed service-enabled resolution would silently read " +
				"as 'service disabled' and return an empty collection")
		}
	}
	if !found {
		t.Error("compute.go: serviceEnabled() helper is gone; the 40 gate call " +
			"sites depend on it to propagate the resolution error")
	}
}
