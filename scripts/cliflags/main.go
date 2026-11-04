// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Command cliflags keeps the CLI flags of the providers from breaking by accident.
// Flags are a public interface: scripts and pipelines use them, and a removed flag
// fails a scan whatever the provider's version says.
//
// Each provider records its connectors and flags in config/cli-flags.json, read
// from config/config.go without building the provider.
//
//	make cli-flags/update   write the records
//	make test/cli-flags     fail when a record differs from its config, or on a
//	                        breaking change against origin/main
//
// -allow-breaking reports breaking changes without failing, for a pull request
// with the `cli-flags: breaking` label.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const recordName = "cli-flags.json"

// Flag is one flag of a connector. The description isn't recorded, as rewording
// it breaks nothing.
type Flag struct {
	Long    string   `json:"long"`
	Short   string   `json:"short,omitempty"`
	Type    string   `json:"type,omitempty"`
	Default string   `json:"default,omitempty"`
	Options []string `json:"options,omitempty"`
}

// Connector is what follows `cnspec scan`.
type Connector struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
	Flags   []Flag   `json:"flags,omitempty"`
}

// Record is a provider's CLI surface. Version is not in the file, as every release
// would change it, but breaking changes compare it.
type Record struct {
	Version    string      `json:"-"`
	Connectors []Connector `json:"connectors"`
}

func (f Flag) has(option string) bool {
	for _, o := range f.Options {
		if o == option {
			return true
		}
	}
	return false
}

func major(version string) int {
	head, _, _ := strings.Cut(strings.TrimPrefix(version, "v"), ".")
	n, err := strconv.Atoi(head)
	if err != nil {
		return 0
	}
	return n
}

// Breaking lists what scripts using the old record would notice.
func Breaking(old, cur Record) []string {
	var out []string
	current := map[string]Connector{}
	for _, c := range cur.Connectors {
		current[c.Name] = c
	}
	for _, o := range old.Connectors {
		n, ok := current[o.Name]
		if !ok {
			out = append(out, fmt.Sprintf("connector %q was removed", o.Name))
			continue
		}
		for _, alias := range o.Aliases {
			if !contains(n.Aliases, alias) {
				out = append(out, fmt.Sprintf("connector %q lost its alias %q", o.Name, alias))
			}
		}
		flags := map[string]Flag{}
		for _, f := range n.Flags {
			flags[f.Long] = f
		}
		for _, f := range o.Flags {
			nf, ok := flags[f.Long]
			if !ok {
				// Deprecating first is the way to remove a flag: a release warns
				// about it, and a later major version drops it.
				if f.has("Deprecated") && major(cur.Version) > major(old.Version) {
					continue
				}
				out = append(out, fmt.Sprintf("connector %q: --%s was removed; mark it deprecated first, and remove it in a later major version", o.Name, f.Long))
				continue
			}
			// The letter may move to another flag of the connector: -u still works.
			if f.Short != "" && nf.Short != f.Short && !hasShort(n.Flags, f.Short) {
				out = append(out, fmt.Sprintf("connector %q: --%s lost its shorthand -%s", o.Name, f.Long, f.Short))
			}
			if nf.Type != f.Type {
				out = append(out, fmt.Sprintf("connector %q: --%s changed type from %s to %s", o.Name, f.Long, f.Type, nf.Type))
			}
			if nf.has("Required") && !f.has("Required") {
				out = append(out, fmt.Sprintf("connector %q: --%s became required", o.Name, f.Long))
			}
		}
		// A new flag that has to be set breaks every existing command line too.
		known := map[string]bool{}
		for _, f := range o.Flags {
			known[f.Long] = true
		}
		for _, f := range n.Flags {
			if !known[f.Long] && f.has("Required") {
				out = append(out, fmt.Sprintf("connector %q: new flag --%s is required", o.Name, f.Long))
			}
		}
	}
	return out
}

// Notable lists changes worth a look that don't fail the check.
func Notable(old, cur Record) []string {
	var out []string
	current := map[string]Connector{}
	for _, c := range cur.Connectors {
		current[c.Name] = c
	}
	for _, o := range old.Connectors {
		n, ok := current[o.Name]
		if !ok {
			continue // Breaking reports the removal
		}
		flags := map[string]Flag{}
		for _, f := range n.Flags {
			flags[f.Long] = f
		}
		for _, f := range o.Flags {
			if nf, ok := flags[f.Long]; ok && nf.Default != f.Default {
				out = append(out, fmt.Sprintf("connector %q: --%s changed its default from %q to %q", o.Name, f.Long, f.Default, nf.Default))
			}
		}
	}
	return out
}

// Clashes lists shorthands that mean different flags in different providers. The
// CLI pre-scans all providers' flags into one set and warns on each command about
// such a clash, so a new one should reuse the long name the letter already has.
func Clashes(records map[string]Record) []string {
	longs := map[string]map[string][]string{}
	for name, r := range records {
		for _, c := range r.Connectors {
			for _, f := range c.Flags {
				if f.Short == "" {
					continue
				}
				if longs[f.Short] == nil {
					longs[f.Short] = map[string][]string{}
				}
				if !contains(longs[f.Short][f.Long], name) {
					longs[f.Short][f.Long] = append(longs[f.Short][f.Long], name)
				}
			}
		}
	}
	var out []string
	for short, byLong := range longs {
		if len(byLong) < 2 {
			continue
		}
		var parts []string
		for long, names := range byLong {
			sort.Strings(names)
			parts = append(parts, fmt.Sprintf("--%s (%s)", long, strings.Join(names, ", ")))
		}
		sort.Strings(parts)
		out = append(out, fmt.Sprintf("-%s means %s", short, strings.Join(parts, " and ")))
	}
	sort.Strings(out)
	return out
}

func hasShort(flags []Flag, short string) bool {
	for _, f := range flags {
		if f.Short == short {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Parse reads a provider's record from the source of its config/config.go. It only
// understands literals and string constants: anything else is an error, not a flag
// silently left out. providerDir is where read looks for the constants.
func Parse(filename string, src any, providerDir string, read goFiles) (Record, error) {
	file, err := parser.ParseFile(token.NewFileSet(), filename, src, 0)
	if err != nil {
		return Record{}, err
	}
	loadConstants(providerDir, file, read)
	loadReturns(file)
	var rec Record
	var parseErr error
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || parseErr != nil || !isSelector(lit.Type, "plugin", "Provider") {
			return true
		}
		for _, field := range fields(lit) {
			switch field.name {
			case "Version":
				// Built-in providers take the version from a call: no major
				// version bump then lets a deprecated flag go.
				if v, err := str(field.value); err == nil {
					rec.Version = v
				}
			case "Connectors":
				rec.Connectors, parseErr = connectors(field.value)
			}
			if parseErr != nil {
				return false
			}
		}
		return false
	})
	if parseErr != nil {
		return Record{}, fmt.Errorf("%s: %w", filename, parseErr)
	}
	sort.Slice(rec.Connectors, func(i, j int) bool { return rec.Connectors[i].Name < rec.Connectors[j].Name })
	return rec, nil
}

type field struct {
	name  string
	value ast.Expr
}

func fields(lit *ast.CompositeLit) []field {
	var out []field
	for _, e := range lit.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok {
				out = append(out, field{id.Name, kv.Value})
			}
		}
	}
	return out
}

func isSelector(e ast.Expr, pkg, name string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != name {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func str(e ast.Expr) (string, error) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			return strconv.Unquote(v.Value)
		}
	case *ast.SelectorExpr:
		// A constant of another package of the provider, as connection.OptionToken.
		if pkg, ok := v.X.(*ast.Ident); ok {
			if value, ok := constants[pkg.Name+"."+v.Sel.Name]; ok {
				return value, nil
			}
		}
		return "", fmt.Errorf("unknown constant %s", exprName(v))
	case *ast.Ident:
		if value, ok := constants[v.Name]; ok {
			return value, nil
		}
		return "", fmt.Errorf("unknown constant %s", v.Name)
	}
	return "", fmt.Errorf("expected a string or a constant, got %T", e)
}

func exprName(s *ast.SelectorExpr) string {
	if id, ok := s.X.(*ast.Ident); ok {
		return id.Name + "." + s.Sel.Name
	}
	return s.Sel.Name
}

// constants holds the string constants a config can name, set by loadConstants.
var constants = map[string]string{}

// returns holds what the config's functions of a single return statement return.
var returns = map[string]ast.Expr{}

func loadReturns(file *ast.File) {
	returns = map[string]ast.Expr{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || len(fn.Body.List) != 1 {
			continue
		}
		if ret, ok := fn.Body.List[0].(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
			returns[fn.Name.Name] = ret.Results[0]
		}
	}
}

// literalVersion reads a config's version without its constants, which only a
// config before records needs. Built-in providers take theirs from a call: none then.
func literalVersion(src []byte) string {
	file, err := parser.ParseFile(token.NewFileSet(), "", src, 0)
	if err != nil {
		return ""
	}
	version := ""
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !isSelector(lit.Type, "plugin", "Provider") {
			return true
		}
		for _, field := range fields(lit) {
			if v, ok := field.value.(*ast.BasicLit); ok && field.name == "Version" && v.Kind == token.STRING {
				version, _ = strconv.Unquote(v.Value)
			}
		}
		return false
	})
	return version
}

// goFiles returns the Go sources of a directory, by path.
type goFiles func(dir string) map[string][]byte

// workingTree reads the sources from disk.
func workingTree(dir string) map[string][]byte {
	files := map[string][]byte{}
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return files
	}
	for _, path := range paths {
		if src, err := os.ReadFile(path); err == nil {
			files[path] = src
		}
	}
	return files
}

// atRef reads the sources from a git ref, for directories relative to root.
func atRef(root, ref string) goFiles {
	return func(dir string) map[string][]byte {
		files := map[string][]byte{}
		cmd := exec.Command("git", "ls-tree", "--name-only", ref, filepath.ToSlash(dir)+"/")
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			return files
		}
		for _, path := range strings.Fields(string(out)) {
			if !strings.HasSuffix(path, ".go") {
				continue
			}
			if src, ok := gitShow(root, ref, path); ok {
				files[path] = src
			}
		}
		return files
	}
}

// loadConstants reads the string constants of a config's own package and of the
// packages of its provider it imports, from their source.
func loadConstants(providerDir string, file *ast.File, sources goFiles) {
	constants = map[string]string{}
	read := func(dir, prefix string) {
		for path, src := range sources(dir) {
			f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
			if err != nil {
				continue
			}
			for _, decl := range f.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if value, err := strconv.Unquote(lit.Value); err == nil {
								constants[prefix+name.Name] = value
							}
						}
					}
				}
			}
		}
	}
	read(filepath.Join(providerDir, "config"), "")
	marker := "/providers/" + filepath.Base(providerDir) + "/"
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		_, sub, ok := strings.Cut(path, marker)
		if !ok {
			continue
		}
		name := filepath.Base(sub)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		read(filepath.Join(providerDir, filepath.FromSlash(sub)), name+".")
	}
}

func strs(e ast.Expr) ([]string, error) {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected a list literal, got %T", e)
	}
	var out []string
	for _, el := range lit.Elts {
		s, err := str(el)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func connectors(e ast.Expr) ([]Connector, error) {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("Connectors: expected a literal, got %T", e)
	}
	var out []Connector
	for _, el := range lit.Elts {
		cl, ok := el.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("Connectors: expected a literal, got %T", el)
		}
		var c Connector
		for _, f := range fields(cl) {
			var err error
			switch f.name {
			case "Name":
				c.Name, err = str(f.value)
			case "Aliases":
				c.Aliases, err = strs(f.value)
			case "Flags":
				c.Flags, err = flags(f.value)
			}
			if err != nil {
				return nil, fmt.Errorf("connector %q: %w", c.Name, err)
			}
		}
		sort.Strings(c.Aliases)
		sort.Slice(c.Flags, func(i, j int) bool { return c.Flags[i].Long < c.Flags[j].Long })
		out = append(out, c)
	}
	return out, nil
}

func flags(e ast.Expr) ([]Flag, error) {
	// A function of the config that only returns the list, shared by connectors.
	if call, ok := e.(*ast.CallExpr); ok && len(call.Args) == 0 {
		if id, ok := call.Fun.(*ast.Ident); ok {
			if body, ok := returns[id.Name]; ok {
				e = body
			}
		}
	}
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("Flags: expected a literal, got %T", e)
	}
	var out []Flag
	for _, el := range lit.Elts {
		cl, ok := el.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("Flags: expected a literal, got %T", el)
		}
		var f Flag
		for _, kv := range fields(cl) {
			var err error
			switch kv.name {
			case "Long":
				f.Long, err = str(kv.value)
			case "Short":
				f.Short, err = str(kv.value)
			case "Default":
				f.Default, err = str(kv.value)
			case "Type":
				f.Type, err = constant(kv.value, "FlagType_")
			case "Option":
				f.Options, err = options(kv.value)
			}
			if err != nil {
				return nil, fmt.Errorf("flag %q: %s: %w", f.Long, kv.name, err)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

func constant(e ast.Expr, prefix string) (string, error) {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(s.Sel.Name, prefix) {
		return "", fmt.Errorf("expected plugin.%s..., got %T", prefix, e)
	}
	return strings.TrimPrefix(s.Sel.Name, prefix), nil
}

// options reads plugin.FlagOption_X, and several joined with |.
func options(e ast.Expr) ([]string, error) {
	if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.OR {
		left, err := options(b.X)
		if err != nil {
			return nil, err
		}
		right, err := options(b.Y)
		if err != nil {
			return nil, err
		}
		out := append(left, right...)
		sort.Strings(out)
		return out, nil
	}
	o, err := constant(e, "FlagOption_")
	if err != nil {
		return nil, err
	}
	return []string{o}, nil
}

func marshal(r Record) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func gitShow(root, ref, path string) ([]byte, bool) {
	cmd := exec.Command("git", "show", ref+":"+path)
	cmd.Dir = root
	out, err := cmd.Output()
	return out, err == nil
}

func run(root, base string, update, allowBreaking bool) error {
	configs, err := filepath.Glob(filepath.Join(root, "providers", "*", "config", "config.go"))
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		return fmt.Errorf("no provider configs under %s", root)
	}

	records := map[string]Record{}
	var failures []string
	for _, cfg := range configs {
		name := filepath.Base(filepath.Dir(filepath.Dir(cfg)))
		providerDir := filepath.Dir(filepath.Dir(cfg))
		rec, err := Parse(cfg, nil, providerDir, workingTree)
		if err != nil {
			return err
		}
		records[name] = rec
		want, err := marshal(rec)
		if err != nil {
			return err
		}
		recordPath := filepath.Join(filepath.Dir(cfg), recordName)
		if update {
			if err := os.WriteFile(recordPath, want, 0o644); err != nil {
				return err
			}
			continue
		}
		have, err := os.ReadFile(recordPath)
		if err != nil || string(have) != string(want) {
			failures = append(failures, fmt.Sprintf("%s: %s doesn't match config.go; run `make cli-flags/update` and review the diff", name, recordName))
		}

		if base == "" {
			continue
		}
		// The record at the base, or the base's config before records existed.
		rel := filepath.ToSlash(filepath.Join("providers", name, "config"))
		baseConfig, ok := gitShow(root, base, rel+"/config.go")
		if !ok {
			continue // a new provider
		}
		var old Record
		if raw, ok := gitShow(root, base, rel+"/"+recordName); ok {
			if err := json.Unmarshal(raw, &old); err != nil {
				return fmt.Errorf("%s at %s: %w", rel, base, err)
			}
		} else if old, err = Parse(rel+"/config.go", baseConfig, filepath.Join("providers", name), atRef(root, base)); err != nil {
			return err
		}
		old.Version = literalVersion(baseConfig)
		for _, b := range Breaking(old, rec) {
			if allowBreaking {
				fmt.Printf("::warning::%s: breaking, allowed by the label: %s\n", name, b)
			} else {
				failures = append(failures, name+": "+b)
			}
		}
		for _, n := range Notable(old, rec) {
			fmt.Printf("::warning::%s: %s\n", name, n)
		}
	}

	if update {
		return nil
	}
	for _, c := range Clashes(records) {
		fmt.Printf("::notice::%s. The CLI warns about this on every command; reuse the letter's long name instead.\n", c)
	}
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Printf("::error::%s\n", f)
		}
		return fmt.Errorf("%d CLI flag problem(s). Flags are a public interface: see \"CLI flags\" in AGENTS.md. An intended break needs the `cli-flags: breaking` label", len(failures))
	}
	return nil
}

func main() {
	root := flag.String("root", ".", "the repository root")
	base := flag.String("base", "", "git ref to compare against for breaking changes")
	update := flag.Bool("update", false, "write the records")
	allow := flag.Bool("allow-breaking", false, "report breaking changes without failing")
	flag.Parse()
	if err := run(*root, *base, *update, *allow); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
