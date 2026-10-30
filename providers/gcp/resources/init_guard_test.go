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

// TestInitGuardsProjectIdBeforeParentConstruction guards a whole class of
// scan-crashing panic.
//
// Most init functions resolve their resource by first building the parent
// service from args["projectId"]:
//
//	CreateResource(runtime, "gcp.project.pubsubService", map[string]*llx.RawData{
//	    "projectId": args["projectId"],
//	})
//
// A map lookup for an absent key yields a nil *llx.RawData, and the generated
// setter dereferences it unconditionally. So a partial query such as
// `gcp.project.pubsubService.topic(name: "x")` panics inside the provider
// instead of returning an error -- and because the executor runs blocks in
// goroutines, that panic is unrecoverable and takes down the whole scan.
//
// A nil-guard placed *after* the parent construction is dead code. This test
// walks the package's own source and fails when any init function reaches a
// CreateResource/NewResource carrying args["projectId"] without having checked
// it first.
func TestInitGuardsProjectIdBeforeParentConstruction(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		{
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "init") {
					continue
				}

				guardPos := token.NoPos
				violation := token.NoPos

				ast.Inspect(fn.Body, func(n ast.Node) bool {
					switch node := n.(type) {
					case *ast.BinaryExpr:
						// args["projectId"] == nil / != nil, either operand order.
						// Matching only the left-hand form would let a reversed
						// `nil == args["projectId"]` silently bypass the detector.
						guarded := (isArgsIndex(node.X, "projectId") && isNilIdent(node.Y)) ||
							(isArgsIndex(node.Y, "projectId") && isNilIdent(node.X))
						if guarded && !guardPos.IsValid() {
							guardPos = node.Pos()
						}
					case *ast.CallExpr:
						name := calleeName(node.Fun)
						if name != "CreateResource" && name != "NewResource" {
							return true
						}
						if !callCarriesProjectIdArg(node) {
							return true
						}
						if !guardPos.IsValid() || guardPos > node.Pos() {
							if !violation.IsValid() {
								violation = node.Pos()
							}
						}
					}
					return true
				})

				if violation.IsValid() {
					t.Errorf("%s: %s passes args[\"projectId\"] into %s before any nil-guard; "+
						"a partial query would panic the provider. Move the guard above the call.",
						fset.Position(violation), fn.Name.Name, "CreateResource/NewResource")
				}
			}
		}
	}
}

// isArgsIndex reports whether e is the expression args["<key>"].
func isArgsIndex(e ast.Expr, key string) bool {
	idx, ok := e.(*ast.IndexExpr)
	if !ok {
		return false
	}
	ident, ok := idx.X.(*ast.Ident)
	if !ok || ident.Name != "args" {
		return false
	}
	lit, ok := idx.Index.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && strings.Trim(lit.Value, `"`) == key
}

func isNilIdent(e ast.Expr) bool {
	ident, ok := e.(*ast.Ident)
	return ok && ident.Name == "nil"
}

func calleeName(e ast.Expr) string {
	switch f := e.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// callCarriesProjectIdArg reports whether any argument of the call references
// args["projectId"], directly or inside a composite literal.
func callCarriesProjectIdArg(call *ast.CallExpr) bool {
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if isArgsIndex(exprOf(n), "projectId") {
				found = true
				return false
			}
			return true
		})
	}
	return found
}

func exprOf(n ast.Node) ast.Expr {
	e, _ := n.(ast.Expr)
	return e
}

// TestInitGuardsEveryDereferencedArg generalizes the projectId guard above to
// every args key an init function dereferences.
//
// `args["name"]` on an absent key yields a nil *llx.RawData, so `.Value` or
// `.Data` on it panics inside the provider. Because the executor runs blocks
// in goroutines that panic is unrecoverable: it kills the whole scan, not one
// query. A partial lookup such as
//
//	gcp.project.computeService.network(projectId: "p")
//
// is a perfectly natural query and must return an error, not crash.
//
// A key counts as guarded once the function has compared it (or a variable
// bound to it) against nil, or bound it with the comma-ok form.
func TestInitGuardsEveryDereferencedArg(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "init") {
				continue
			}

			guardedAt := map[string]token.Pos{} // key -> first guard position
			varToKey := map[string]string{}     // local var -> args key it holds
			type deref struct {
				key string
				pos token.Pos
			}
			var derefs []deref

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.AssignStmt:
					// v := args["k"]  /  v, ok := args["k"]
					if node.Tok == token.DEFINE && len(node.Rhs) == 1 {
						for _, key := range argsKeys(node.Rhs[0]) {
							if id, ok := node.Lhs[0].(*ast.Ident); ok {
								varToKey[id.Name] = key
							}
							// the comma-ok form is itself a presence check
							if len(node.Lhs) == 2 {
								if _, seen := guardedAt[key]; !seen {
									guardedAt[key] = node.Pos()
								}
							}
						}
					}
				case *ast.BinaryExpr:
					for _, e := range []ast.Expr{node.X, node.Y} {
						other := node.Y
						if e == node.Y {
							other = node.X
						}
						if !isNilIdent(other) {
							continue
						}
						var key string
						if k := argsKeys(e); len(k) == 1 {
							key = k[0]
						} else if id, ok := e.(*ast.Ident); ok {
							key = varToKey[id.Name]
						}
						if key == "" {
							continue
						}
						if _, seen := guardedAt[key]; !seen {
							guardedAt[key] = node.Pos()
						}
					}
				case *ast.SelectorExpr:
					// args["k"].Value / args["k"].Data, or v.Value where v holds one
					if node.Sel.Name != "Value" && node.Sel.Name != "Data" {
						return true
					}
					var key string
					if k := argsKeys(node.X); len(k) == 1 {
						key = k[0]
					} else if id, ok := node.X.(*ast.Ident); ok {
						key = varToKey[id.Name]
					}
					if key != "" {
						derefs = append(derefs, deref{key: key, pos: node.Pos()})
					}
				}
				return true
			})

			for _, d := range derefs {
				guard, ok := guardedAt[d.key]
				if !ok || guard > d.pos {
					t.Errorf("%s: %s dereferences args[%q] without a nil-guard; "+
						"a partial query would panic the provider and kill the scan",
						fset.Position(d.pos), fn.Name.Name, d.key)
				}
			}
		}
	}
}

// TestInitDoesNotRedirectACallerSuppliedProject pins the invariant that makes
// the unconditional `args["projectId"] = llx.StringData(conn.ResourceID())`
// assignments safe.
//
// NewResource runs an init before the resource-cache lookup, so an init that
// overwrites projectId redirects every caller-scoped reference
// (gcp.projects.list { compute.instances }) at the connection's own project.
// On an organization- or folder-scoped connection ResourceID() is not a
// project id at all, so the reference resolves to nothing.
//
// Two shapes prevent that, and an init must use one of them:
//
//   - wrap the assignment in a check on args["projectId"], or
//   - return early on `len(args) > 0`, which a caller-supplied projectId
//     always trips.
//
// The second is what most service inits rely on, and it is invisible at the
// assignment. Raising that threshold to `> 1` or `> 2` while adding a second
// argument is an easy and silent way to reintroduce the redirection, so the
// pairing is asserted here rather than left to review.
func TestInitDoesNotRedirectACallerSuppliedProject(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "init") {
				continue
			}
			// Only the top-level statements matter: an assignment nested in an
			// if is guarded by that if, which the walk below treats separately.
			for _, stmt := range fn.Body.List {
				assign, ok := stmt.(*ast.AssignStmt)
				if !ok || !assignsProjectIdFromResourceID(assign) {
					continue
				}
				if !returnsEarlyOnAnyArg(fn.Body, assign.Pos()) {
					t.Errorf("%s: %s overwrites args[\"projectId\"] with the connection's own "+
						"resource id without an earlier `if len(args) > 0` return, so a "+
						"caller-supplied project is silently redirected. Guard the assignment "+
						"with `if pid, ok := args[\"projectId\"]; !ok || pid == nil`.",
						fset.Position(assign.Pos()), fn.Name.Name)
				}
			}
		}
	}
}

// assignsProjectIdFromResourceID reports whether stmt is
// args["projectId"] = <...conn.ResourceID()...>.
func assignsProjectIdFromResourceID(stmt *ast.AssignStmt) bool {
	if len(stmt.Lhs) != 1 || !isArgsIndex(stmt.Lhs[0], "projectId") {
		return false
	}
	found := false
	for _, rhs := range stmt.Rhs {
		ast.Inspect(rhs, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && calleeName(call.Fun) == "ResourceID" {
				found = true
				return false
			}
			return true
		})
	}
	return found
}

// returnsEarlyOnAnyArg reports whether body contains, before pos, an
// `if len(args) > 0 { ... return ... }`. A threshold above zero does not
// count: it lets a caller pass projectId and still fall through.
func returnsEarlyOnAnyArg(body *ast.BlockStmt, pos token.Pos) bool {
	guarded := false
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Pos() >= pos {
			return true
		}
		cond, ok := ifStmt.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.GTR || !isLenOfArgs(cond.X) {
			return true
		}
		lit, ok := cond.Y.(*ast.BasicLit)
		if !ok || lit.Kind != token.INT || lit.Value != "0" {
			return true
		}
		for _, stmt := range ifStmt.Body.List {
			if _, isReturn := stmt.(*ast.ReturnStmt); isReturn {
				guarded = true
				return false
			}
		}
		return true
	})
	return guarded
}

// isLenOfArgs reports whether e is the expression len(args).
func isLenOfArgs(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || calleeName(call.Fun) != "len" || len(call.Args) != 1 {
		return false
	}
	ident, ok := call.Args[0].(*ast.Ident)
	return ok && ident.Name == "args"
}

// argsKeys returns the args key referenced by e, if e is args["<key>"].
func argsKeys(e ast.Expr) []string {
	idx, ok := e.(*ast.IndexExpr)
	if !ok {
		return nil
	}
	ident, ok := idx.X.(*ast.Ident)
	if !ok || ident.Name != "args" {
		return nil
	}
	lit, ok := idx.Index.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil
	}
	return []string{strings.Trim(lit.Value, `"`)}
}
