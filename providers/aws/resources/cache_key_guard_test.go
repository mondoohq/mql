// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Account-level singletons: exactly one instance exists per connection, so the
// empty cache key is both correct and desirable -- it is what makes the
// account-wide fetch behind them happen once.
var cacheKeySingletons = map[string]bool{
	"aws":                    true,
	"aws.efs":                true,
	"aws.iam.accessAnalyzer": true,
}

// TestEveryConstructionSiteHasACacheKey fails when a resource is built without
// anything to key it on.
//
// createXxx sets __id from an explicit "__id" arg and, only when that leaves it
// empty, falls back to the resource's id() method. A resource with neither ends
// up on the key "<name>\x00", which every instance of that resource then shares
// -- so the first one built is handed back for all of them, carrying the first
// one's data. Nothing errors; the wrong answer just looks like a right one.
//
// This is how aws.eventbridge.eventBus and aws.batch.jobQueue reached MQL from
// aws.eventbridge.pipe: neither has an id() method, and the typed accessor
// passed only "arn", so every pipe reported the first pipe's bus and queue.
//
// Only inline argument literals are checked. A site whose args come from a
// variable or a helper is skipped rather than guessed at, so this test reports
// no false failures -- it is a floor, not a full audit.
func TestEveryConstructionSiteHasACacheKey(t *testing.T) {
	fset := token.NewFileSet()

	gen, err := os.ReadFile("aws.lr.go")
	if err != nil {
		t.Fatalf("read generated schema: %v", err)
	}
	genSrc := string(gen)

	// Resource* constants, so a site that names the resource by constant is
	// resolved the same as one that spells out the string.
	constResource := map[string]string{}
	reConst := regexp.MustCompile(`(?m)^\t(Resource[A-Za-z0-9_]+)\s+string = "([a-zA-Z0-9_.]+)"`)
	for _, m := range reConst.FindAllStringSubmatch(genSrc, -1) {
		constResource[m[1]] = m[2]
	}

	// A registered Init resolves the resource before createXxx is reached, and
	// the resource it returns carries its own key -- so an init-backed resource
	// is out of scope here. (An init that falls through on a lookup miss is a
	// separate defect, class 4, and not what this test is for.)
	registered := map[string]bool{}
	hasInit := map[string]bool{}
	reEntry := regexp.MustCompile(`(?m)^\t\t"([a-zA-Z0-9_.]+)": \{\n((?:\t\t\t.*\n)+?)\t\t\},`)
	for _, m := range reEntry.FindAllStringSubmatch(genSrc, -1) {
		registered[m[1]] = true
		hasInit[m[1]] = strings.Contains(m[2], "Init:")
	}

	// A resource has an id() method exactly when its generated constructor
	// falls back to it.
	genFile, err := parser.ParseFile(fset, "aws.lr.go", nil, 0)
	if err != nil {
		t.Fatalf("parse generated schema: %v", err)
	}
	hasIDMethod := map[string]bool{}
	for _, decl := range genFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "create") {
			continue
		}
		var resource string
		callsID := false
		ast.Inspect(fn, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && resource == "" {
				if v, err := strconv.Unquote(lit.Value); err == nil && registered[v] {
					resource = v
				}
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "id" {
				callsID = true
			}
			return true
		})
		if resource != "" {
			hasIDMethod[resource] = callsID
		}
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list package files: %v", err)
	}

	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".lr.go") {
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
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || (fn.Name != "CreateResource" && fn.Name != "NewResource") || len(call.Args) < 3 {
				return true
			}

			var resource string
			switch arg := call.Args[1].(type) {
			case *ast.BasicLit:
				if arg.Kind != token.STRING {
					return true
				}
				resource, _ = strconv.Unquote(arg.Value)
			case *ast.Ident:
				resource = constResource[arg.Name]
			}
			if resource == "" || !registered[resource] {
				return true
			}
			if hasIDMethod[resource] || hasInit[resource] || cacheKeySingletons[resource] {
				return true
			}

			// Only inline literals can be judged; anything else is skipped.
			lit, ok := call.Args[2].(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.BasicLit)
				if !ok {
					continue
				}
				if name, _ := strconv.Unquote(key.Value); name == "__id" {
					return true
				}
			}

			pos := fset.Position(call.Pos())
			t.Errorf("%s:%d: %s(%q) passes no \"__id\" and %s has no id() method, "+
				"so every instance shares the cache key %q and resolves to the first one built. "+
				"Pass an explicit \"__id\", or give the resource an id() method.",
				path, pos.Line, fn.Name, resource, resource, resource+"\x00")
			return true
		})
	}
}
