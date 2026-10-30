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

// TestEveryGatedServiceHasAnInit pins the other half of the serviceEnabled
// contract. serviceGate guarantees the "is this API enabled" answer resolves on
// every construction path, but it resolves it *from the resource's projectId* --
// so a service resource that can be built without one is still broken.
//
// A gcp.project.<x>Service resource is reachable two ways: through the
// gcp.project.<x>() accessor, which passes the project down, and by its own type
// name (gcp.project.<x>Service.things), which builds it from no arguments at
// all. On that second path the resource needs an init to fill projectId in from
// the connection. Without one, projectId is empty, the gate asks Service Usage
// about "projects/", and the query fails with
//
//	InvalidArgument: The resource id projects/ is invalid
//
// for the whole scan -- not for one field. This was found live against
// gcp.project.gkeService.clusters, and cloudScheduler and redis had the same
// hole; every other service already carried the init, which is exactly why the
// omission was invisible.
func TestEveryGatedServiceHasAnInit(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	gated := map[string]token.Position{} // resource type name -> where it is declared
	inits := map[string]bool{}

	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && strings.HasPrefix(d.Name.Name, "init") {
					inits[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || !strings.HasSuffix(ts.Name.Name, "Internal") {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok || !embedsServiceGate(st) {
						continue
					}
					resource := strings.TrimSuffix(ts.Name.Name, "Internal")
					gated[resource] = fset.Position(ts.Pos())
				}
			}
		}
	}

	if len(gated) == 0 {
		t.Fatal("found no serviceGate-embedding resources; the scan is broken, not the code")
	}

	for resource, pos := range gated {
		// mqlGcpProjectGkeService -> initGcpProjectGkeService
		want := "init" + strings.TrimPrefix(resource, "mql")
		if !inits[want] {
			t.Errorf("%s: %s embeds serviceGate but has no %s. Reached by its own type "+
				"name the resource is built with an empty projectId, and the gate then "+
				"queries Service Usage for \"projects/\", failing the whole scan. Add an "+
				"init that sets args[\"projectId\"] from conn.ResourceID().",
				pos, resource, want)
		}
	}
}

// embedsServiceGate reports whether the struct embeds serviceGate.
func embedsServiceGate(st *ast.StructType) bool {
	for _, f := range st.Fields.List {
		if len(f.Names) != 0 {
			continue // named field, not an embed
		}
		if id, ok := f.Type.(*ast.Ident); ok && id.Name == "serviceGate" {
			return true
		}
	}
	return false
}
