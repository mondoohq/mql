// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// TestCreateResourceArgsExistInSchema pins the invariant that every key a
// lister passes to CreateResource is a field the resource actually declares.
//
// CreateResource funnels its args through SetAllData, which fails the whole
// call on the first unknown key with
//
//	[azure] cannot set 'tenantId' in resource '...', field not found
//
// That error replaces the entire list with an error string - the caller does
// not get a partial resource, it gets nothing. Nothing catches it at build
// time, and a lister for a service nobody has provisioned can carry the bug
// for a long time before anyone notices.
//
// Six resources shipped exactly that way after principalId/tenantId moved onto
// the resourceIdentity sub-resource and the old args were left behind on the
// parent: dataFactory factory, elasticSan volumeGroup, netApp account,
// recoveryServices vault, storageCache amlFilesystem and synapse workspace.
func TestCreateResourceArgsExistInSchema(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	// Resource name constants generated into azure.lr.go: ResourceX string = "azure...."
	names := map[string]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
						continue
					}
					lit, ok := vs.Values[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if v, err := strconv.Unquote(lit.Value); err == nil {
						names[vs.Names[0].Name] = v
					}
				}
			}
		}
	}

	type use struct {
		resource string
		field    string
		pos      token.Position
	}
	var uses []use

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) < 3 {
					return true
				}
				fn, ok := call.Fun.(*ast.Ident)
				if !ok || fn.Name != "CreateResource" {
					return true
				}

				var resource string
				switch a := call.Args[1].(type) {
				case *ast.Ident:
					resource = names[a.Name]
				case *ast.BasicLit:
					if a.Kind == token.STRING {
						resource, _ = strconv.Unquote(a.Value)
					}
				}
				if resource == "" {
					return true
				}

				lit, ok := call.Args[2].(*ast.CompositeLit)
				if !ok {
					return true
				}
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					k, ok := kv.Key.(*ast.BasicLit)
					if !ok || k.Kind != token.STRING {
						continue
					}
					field, err := strconv.Unquote(k.Value)
					if err != nil || field == "__id" {
						continue
					}
					uses = append(uses, use{resource, field, fset.Position(k.Pos())})
				}
				return true
			})
		}
	}

	if len(uses) == 0 {
		t.Fatal("found no CreateResource arg maps - the AST walk is not doing its job")
	}

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	for _, u := range uses {
		factory, ok := resourceFactories[u.resource]
		if !ok || factory.Create == nil {
			continue
		}
		res, err := factory.Create(runtime, map[string]*llx.RawData{"__id": llx.StringData("probe")})
		if err != nil || res == nil {
			continue
		}
		// Only the "field not found" outcome matters here; a type mismatch
		// from the probe value is not what this test is about.
		if err := SetData(res, u.field, llx.StringData("probe")); err != nil &&
			strings.Contains(err.Error(), "field not found") {
			t.Errorf("%s: CreateResource(%s) passes %q, which the resource does not declare\n\t%v",
				u.pos, u.resource, u.field, err)
		}
	}
}
