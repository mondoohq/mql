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

// generatedSchemaFile is the only provider-specific name in this file, so the
// guards port to another provider by changing it alone.
const generatedSchemaFile = "gcp.lr.go"

// cacheKeySingletons names resources for which the empty cache key is correct:
// exactly one instance exists per connection, so sharing one key is what makes
// the account-wide fetch behind them happen once.
//
// It is intentionally empty. No resource in this provider needs the exemption
// today -- every construction site supplies a key. It exists so that a future
// exception has to be written down here with a reason, rather than the checks
// below being quietly widened to let it through.
var cacheKeySingletons = map[string]bool{}

// schemaFacts is everything the two guards need to know about the generated
// schema. Both read it from the same source so they cannot disagree about what
// counts as a resource.
type schemaFacts struct {
	// registered is every resource name in the generated factory registry. It
	// is the authority on what is a resource name; nothing else is.
	registered map[string]bool
	// hasInit reports whether a resource has an Init in the registry.
	hasInit map[string]bool
	// hasIDMethod reports whether a resource's generated constructor falls back
	// to an id() method. That fallback is emitted only when the Go method
	// exists at codegen time, so it is the real signal, not the .lr schema.
	hasIDMethod map[string]bool
	// resourceOfInit maps an init function name to the resource it builds.
	resourceOfInit map[string]string
	// constResource maps a generated Resource* constant to its resource name,
	// so a site naming its resource by constant is judged like a literal one.
	constResource map[string]string
}

var (
	reRegistryEntry = regexp.MustCompile(`(?m)^\t\t"([a-zA-Z0-9_.]+)": \{\n((?:\t\t\t.*\n)+?)\t\t\},`)
	reRegistryInit  = regexp.MustCompile(`Init:\s+(init[A-Za-z0-9_]+)`)
	reResourceConst = regexp.MustCompile(`(?m)^\t(Resource[A-Za-z0-9_]+)\s+string = "([a-zA-Z0-9_.]+)"`)
)

func loadSchemaFacts(t *testing.T, fset *token.FileSet) schemaFacts {
	t.Helper()

	raw, err := os.ReadFile(generatedSchemaFile)
	if err != nil {
		t.Fatalf("read %s: %v", generatedSchemaFile, err)
	}
	src := string(raw)

	facts := schemaFacts{
		registered:     map[string]bool{},
		hasInit:        map[string]bool{},
		hasIDMethod:    map[string]bool{},
		resourceOfInit: map[string]string{},
		constResource:  map[string]string{},
	}

	for _, m := range reRegistryEntry.FindAllStringSubmatch(src, -1) {
		name, body := m[1], m[2]
		facts.registered[name] = true
		if init := reRegistryInit.FindStringSubmatch(body); init != nil {
			facts.hasInit[name] = true
			facts.resourceOfInit[init[1]] = name
		}
	}
	for _, m := range reResourceConst.FindAllStringSubmatch(src, -1) {
		facts.constResource[m[1]] = m[2]
	}

	file, err := parser.ParseFile(fset, generatedSchemaFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", generatedSchemaFile, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "create") {
			continue
		}
		var resource string
		callsID := false
		ast.Inspect(fn, func(n ast.Node) bool {
			// The first string literal that is a registered resource name is
			// the resource this constructor builds. Matching on "is registered"
			// rather than "looks dotted" keeps an unrelated literal -- a
			// package path, an error message -- from being mistaken for one.
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && resource == "" {
				if v, err := strconv.Unquote(lit.Value); err == nil && facts.registered[v] {
					resource = v
				}
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "id" {
				callsID = true
			}
			return true
		})
		if resource != "" {
			facts.hasIDMethod[resource] = callsID
		}
	}

	return facts
}

// packageSourceFiles lists the hand-written Go in this package -- the generated
// schema and the tests are not part of what either guard judges.
func packageSourceFiles(t *testing.T) []string {
	t.Helper()

	all, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list package files: %v", err)
	}
	out := make([]string, 0, len(all))
	for _, path := range all {
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".lr.go") {
			continue
		}
		out = append(out, path)
	}
	return out
}

// keyIsHandled reports whether a resource is exempt from both guards because
// its identity is already settled.
func (f schemaFacts) keyIsHandled(resource string) bool {
	return resource == "" || !f.registered[resource] || f.hasIDMethod[resource] || cacheKeySingletons[resource]
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
// gcp.project.gkeService.cluster.networkPolicy was in exactly this state: it
// passed the parent-qualified value as a public `id` FIELD -- an ordinary
// declared field, which does NOT feed the cache key -- so every cluster's
// network policy resolved to the first cluster's (#10506).
//
// A registered Init is out of scope here: it resolves the resource before
// createXxx is reached, and the resource it returns carries its own key. An
// init that supplies neither is the second guard's job.
//
// Only inline argument literals are checked. A site whose args come from a
// variable or a helper is skipped rather than guessed at, so this test reports
// no false failures -- it is a floor, not a full audit.
func TestEveryConstructionSiteHasACacheKey(t *testing.T) {
	fset := token.NewFileSet()
	facts := loadSchemaFacts(t, fset)

	for _, path := range packageSourceFiles(t) {
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
				resource = facts.constResource[arg.Name]
			}
			if facts.keyIsHandled(resource) || facts.hasInit[resource] {
				return true
			}

			lit, ok := call.Args[2].(*ast.CompositeLit)
			if !ok {
				return true
			}
			if compositeLitHasKey(lit, "__id") {
				return true
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

// TestInitBackedResourcesCanSupplyACacheKey covers the case the test above
// deliberately skips.
//
// A registered Init is normally what supplies a resource's identity: it either
// puts "__id" into args, or it returns an already-built resource that carries
// its own key. An init that does neither, on a resource with no id() method,
// leaves __id empty just as surely as having no init at all -- and it does so
// invisibly, because the presence of an Init reads as "identity handled".
//
// The azure provider shipped exactly that shape: an init that only filled in
// subscriptionId, on a resource with no id(), so every subscription aliased to
// the first. This provider is clean today; the test keeps it that way.
func TestInitBackedResourcesCanSupplyACacheKey(t *testing.T) {
	fset := token.NewFileSet()
	facts := loadSchemaFacts(t, fset)

	for _, path := range packageSourceFiles(t) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			resource, isInit := facts.resourceOfInit[fn.Name.Name]
			if !isInit || facts.keyIsHandled(resource) {
				continue
			}
			if initSuppliesCacheKey(fn) {
				continue
			}

			pos := fset.Position(fn.Pos())
			t.Errorf("%s:%d: %s never supplies a cache key -- it sets no \"__id\" and returns no resource -- "+
				"and %s has no id() method, so every instance shares the key %q and resolves to the first one built. "+
				"Give the resource an id() method, or have the init set \"__id\".",
				path, pos.Line, fn.Name.Name, resource, resource+"\x00")
		}
	}
}

// initSuppliesCacheKey reports whether an init can hand the runtime an identity.
//
// Three shapes count, and the third is why this is a heuristic rather than a
// proof: an init that delegates (`return initFromServiceList(...)`) has its key
// supplied by the callee, which an AST walk of this body cannot see. Delegation
// is recognised wherever it appears, not only as the sole statement, so an init
// that sets up a variable before delegating is still skipped. The cost is that
// an init calling any single-result helper on a return path is treated as
// delegating; the benefit is that the guard reports no false failures.
func initSuppliesCacheKey(fn *ast.FuncDecl) bool {
	supplies := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil && v == "__id" {
				supplies = true
			}
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		switch len(ret.Results) {
		case 1:
			// Delegation: `return someInit(...)`.
			if _, ok := ret.Results[0].(*ast.CallExpr); ok {
				supplies = true
			}
		case 3:
			// An already-built resource carries its own key.
			if id, ok := ret.Results[1].(*ast.Ident); !ok || id.Name != "nil" {
				supplies = true
			}
		}
		return true
	})
	return supplies
}

func compositeLitHasKey(lit *ast.CompositeLit, want string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.BasicLit)
		if !ok || key.Kind != token.STRING {
			continue
		}
		if name, err := strconv.Unquote(key.Value); err == nil && name == want {
			return true
		}
	}
	return false
}
