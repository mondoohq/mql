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

// TestEveryProjectAccessorTargetHasAnInit covers the resources that
// TestEveryGatedServiceHasAnInit cannot see because they do not embed
// serviceGate. Any resource returned by a no-argument gcp.project accessor is
// also reachable by its own type name, and on that path it is built from no
// arguments. Without an init its projectId is empty and its API calls go to
// "projects/": App Engine answers 404, Cloud Build and Cloud Tasks answer
// InvalidArgument, Dataflow answers 400.
func TestEveryProjectAccessorTargetHasAnInit(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	targets := map[string]token.Position{} // resource type name -> accessor position
	inits := map[string]bool{}

	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".lr.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Recv == nil {
				if strings.HasPrefix(fn.Name.Name, "init") {
					inits[fn.Name.Name] = true
				}
				continue
			}
			if !receiverIs(fn, "mqlGcpProject") || fn.Type.Params.NumFields() != 0 ||
				fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
				continue
			}
			star, ok := fn.Type.Results.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			id, ok := star.X.(*ast.Ident)
			if !ok || !strings.HasPrefix(id.Name, "mqlGcpProject") {
				continue
			}
			targets[id.Name] = fset.Position(fn.Pos())
		}
	}

	if len(targets) == 0 {
		t.Fatal("found no gcp.project accessors; the scan is broken, not the code")
	}

	for resource, pos := range targets {
		want := "init" + strings.TrimPrefix(resource, "mql")
		if !inits[want] {
			t.Errorf("%s: the gcp.project accessor returns %s, which has no %s. Reached by "+
				"its own type name the resource is built with no project and its API calls "+
				"target \"projects/\".", pos, resource, want)
		}
	}
}

func receiverIs(fn *ast.FuncDecl, name string) bool {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	return ok && id.Name == name
}
