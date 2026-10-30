// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A lister fanned out over every compartment must ask each one about itself.
//
// ociCollect hands its lister the compartment to query. A lister that ignores
// that argument and passes conn.TenantID() instead asks the root the same
// question once per compartment, and ociJoinCompartmentJobs concatenates the
// answers without deduplicating - so the root's resources are returned N times
// while every child compartment is still never looked at. That is strictly
// worse than the root-only scope it replaced, and nothing about it fails: it
// compiles, it returns data, and the data looks plausible.
//
// The compiler cannot see this because the argument is simply unused, which Go
// permits for function parameters. So it is checked here, by parsing the
// package and walking the lambda passed to each ociCollect call.
//
// Sites that are still deliberately root-scoped are not covered, and do not
// need to be: asking the root about the root is what they mean. This test is
// what stops one of them being flipped to the compartment scope without the
// hardcoded tenancy id being removed at the same time.
func TestCompartmentScopedListersUseTheirCompartment(t *testing.T) {
	fset := gotoken.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)

	var checked int
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				var lambda *ast.FuncLit
				switch {
				case ident.Name == "ociCollect" && len(call.Args) >= 3:
					scope, ok := call.Args[1].(*ast.Ident)
					if !ok || scope.Name != "ociScopeAllCompartments" {
						return true
					}
					lambda, _ = call.Args[2].(*ast.FuncLit)
				case ident.Name == "ociCollectGlobal" && len(call.Args) >= 2:
					// Always a compartment fan-out.
					lambda, _ = call.Args[1].(*ast.FuncLit)
				}
				if lambda == nil {
					return true
				}

				checked++
				pos := fset.Position(call.Pos())
				where := filepath.Base(name) + ":" + strconv.Itoa(pos.Line)

				if callsTenantID(lambda.Body) {
					t.Errorf("%s: this lister runs under ociScopeAllCompartments but calls "+
						"conn.TenantID() in its body. It will ask the tenancy root once per "+
						"compartment and return the root's resources N times, while every child "+
						"compartment goes unread. Use the compartmentID argument ociCollect "+
						"passes in.", where)
				}
				return true
			})
		}
	}

	// A filter that matched nothing would let this test pass while checking
	// nothing at all, which is the failure mode the guard itself is guarding
	// against.
	require.Greater(t, checked, 20,
		"expected to find the compartment-scoped listers; the AST match is probably broken")
	t.Logf("checked %d compartment-scoped listers", checked)
}

// callsTenantID reports whether the body contains a call to TenantID().
func callsTenantID(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "TenantID" {
			found = true
			return false
		}
		return true
	})
	return found
}
