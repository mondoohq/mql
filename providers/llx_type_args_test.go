// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// llxTypedConstructors are the llx constructors whose type argument is a
// types.Type. types.Type is a string type, so an untyped string literal
// compiles there: "string" or "dict" (not type codes at all), "\x02"
// (types.Nil), or a bare resource name without types.Resource. The value
// still reaches the resource, so nothing fails until the RawData is
// serialized, for example when CreateSharedResource sends the args to another
// provider, and types.Type.Label panics on the unknown code.
var llxTypedConstructors = map[string]struct{}{
	"ArrayData":      {},
	"MapData":        {},
	"MapIntData":     {},
	"ArrayPrimitive": {},
	"MapPrimitive":   {},
}

const llxImportPath = "go.mondoo.com/mql/llx"

// TestLlxTypeArgsAreNotStringLiterals fails on any provider source that passes
// a string literal as the type of an llx array or map constructor. Use the
// types package instead: types.String, types.Dict, types.Resource("...").
func TestLlxTypeArgsAreNotStringLiterals(t *testing.T) {
	var found []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, ".lr.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Contains(src, []byte(llxImportPath)) {
			return nil
		}
		found = append(found, llxTypeLiteralArgs(t, path, src)...)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, found, "pass a types.Type value (types.String, types.Dict, types.Resource(\"...\")), not a string literal, as the llx type argument")
}

// llxTypeLiteralArgs returns "file:line: llx.Fn(..., literal)" for every call
// in src whose type argument is a string literal.
func llxTypeLiteralArgs(t *testing.T, path string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	require.NoError(t, err, path)

	pkgName := ""
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == llxImportPath {
			pkgName = "llx"
			if imp.Name != nil {
				pkgName = imp.Name.Name
			}
		}
	}
	if pkgName == "" || pkgName == "_" {
		return nil
	}

	var res []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != pkgName {
			return true
		}
		if _, ok := llxTypedConstructors[sel.Sel.Name]; !ok {
			return true
		}
		lit, ok := call.Args[len(call.Args)-1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		res = append(res, fset.Position(lit.Pos()).String()+": "+pkgName+"."+sel.Sel.Name+"(..., "+lit.Value+")")
		return true
	})
	return res
}

func TestLlxTypeLiteralArgs(t *testing.T) {
	// Synthetic: each call shape the guard has to tell apart.
	src := []byte(`package x

import (
	l "go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

var (
	a = l.ArrayData(nil, "string")
	b = l.MapData(nil, "\x02")
	c = l.ArrayData(nil, types.String)
	d = l.ArrayData(nil, types.Resource("aws.vpc"))
	e = l.StringData("dict")
	f = l.MapIntData(nil, "dict")
)
`)
	got := llxTypeLiteralArgs(t, "x.go", src)
	require.Equal(t, []string{
		`x.go:9:23: l.ArrayData(..., "string")`,
		`x.go:10:21: l.MapData(..., "\x02")`,
		`x.go:14:24: l.MapIntData(..., "dict")`,
	}, got)
}
