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

// TestNoStringifiedAPIErrors pins the invariant the error classifiers depend on.
//
// isServiceDisabled / isSkippable / isInapplicable classify by unwrapping to the
// transport error: a *googleapi.Error carrying an HTTP status, or a gRPC
// status.Status carrying a code. Flatten either one into a string and the
// classification is gone for good -- all that survives is prose.
//
// That is not hypothetical. initGcpOrganization used to answer a 403 with
//
//	return nil, nil, errors.New("403: permission denied")
//
// and discovery had to compensate by substring-matching "403:",
// "permission denied" and "has not been used" against message text, which then
// silently failed for every service that phrased its denial differently.
//
// So: an error may be wrapped with %w, which preserves the chain, but never
// rendered with %s / %v and never rebuilt from err.Error().
func TestNoStringifiedAPIErrors(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			pkg, fn, ok := qualifiedCallName(call.Fun)
			if !ok {
				return true
			}

			switch {
			case pkg == "errors" && fn == "New":
				// errors.New(err.Error()) and friends
				if len(call.Args) == 1 && callsErrorMethod(call.Args[0]) {
					t.Errorf("%s: errors.New rebuilt from err.Error(); the transport "+
						"status is discarded and the error can no longer be classified. "+
						"Return the original error, or wrap it with fmt.Errorf(\"...: %%w\", err)",
						fset.Position(call.Pos()))
				}
			case pkg == "fmt" && (fn == "Errorf"):
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if strings.Contains(lit.Value, "%w") {
					return true // properly wrapped
				}
				for _, arg := range call.Args[1:] {
					if isErrorIdent(arg) || callsErrorMethod(arg) {
						t.Errorf("%s: fmt.Errorf renders an error with %%s/%%v instead of "+
							"%%w; the transport status is discarded and the error can no "+
							"longer be classified. Use %%w", fset.Position(call.Pos()))
						break
					}
				}
			}
			return true
		})
	}
}

// qualifiedCallName splits a `pkg.Fn` call target.
func qualifiedCallName(fun ast.Expr) (pkg, fn string, ok bool) {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	return ident.Name, sel.Sel.Name, true
}

// isErrorIdent reports whether the expression is an identifier that by
// convention holds an error (`err`, `listErr`, `serviceErr`).
func isErrorIdent(e ast.Expr) bool {
	ident, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "err" || strings.HasSuffix(ident.Name, "Err")
}

// callsErrorMethod reports whether the expression is an `x.Error()` call.
func callsErrorMethod(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Error"
}
