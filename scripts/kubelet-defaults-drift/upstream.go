// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// item is one piece of upstream Kubernetes source that kubelet_defaults.go
// copies: a whole file, one declaration of a file, or the versioned spec of
// one feature gate.
type item struct {
	Path string
	Decl string
	Gate string
}

func (i item) id() string {
	switch {
	case i.Gate != "":
		return i.Path + "#gate:" + i.Gate
	case i.Decl != "":
		return i.Path + "#" + i.Decl
	}
	return i.Path
}

const (
	featuresPath = "pkg/features/kube_features.go"
	// featureGatesVar holds the default of every Kubernetes feature gate by
	// version in featuresPath.
	featureGatesVar = "defaultVersionedKubernetesFeatureGates"
	// absent is recorded for an item a release does not have.
	absent = "absent"
)

// fixedItems are the upstream sources kubelet_defaults.go copies apart from
// the feature gates it reads.
var fixedItems = []item{
	{Path: "pkg/kubelet/apis/config/v1beta1/defaults.go"},
	{Path: "pkg/kubelet/eviction/defaults_linux.go", Decl: "DefaultEvictionHard"},
	{Path: "pkg/kubelet/types/constants.go", Decl: "ResolvConfDefault"},
	{Path: "pkg/cluster/ports/ports.go", Decl: "KubeletPort"},
	{Path: "pkg/cluster/ports/ports.go", Decl: "KubeletReadOnlyPort"},
	{Path: "pkg/cluster/ports/ports.go", Decl: "KubeletHealthzPort"},
	{Path: "pkg/kubelet/qos/policy.go", Decl: "KubeletOOMScoreAdj"},
	{Path: "cmd/kubelet/app/options/options.go", Decl: "applyLegacyDefaults"},
}

// trackedItems returns the fixed items and one item per feature gate.
func trackedItems(gates []string) []item {
	res := append([]item{}, fixedItems...)
	for _, g := range gates {
		res = append(res, item{Path: featuresPath, Gate: g})
	}
	return res
}

var gateRe = regexp.MustCompile(`featureGateEnabled\(\s*\w+\s*,\s*"([A-Za-z0-9]+)"`)

// gatesFrom returns the feature gates kubelet_defaults.go asks about, sorted.
func gatesFrom(src string) []string {
	seen := map[string]bool{}
	res := []string{}
	for _, m := range gateRe.FindAllStringSubmatch(src, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			res = append(res, m[1])
		}
	}
	sort.Strings(res)
	return res
}

// extract returns the normalized source of an item: comments, blank lines and
// formatting are dropped, so that only a change to the code is a change. The
// second value is false when the source has no such item.
func extract(src string, it item) (string, bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, it.Path, src, 0)
	if err != nil {
		return "", false, fmt.Errorf("cannot parse %s: %w", it.Path, err)
	}
	var node any
	switch {
	case it.Gate != "":
		node = findGate(f, it.Gate)
	case it.Decl != "":
		node = findDecl(f, it.Decl)
	default:
		node = f
	}
	if node == nil {
		return "", false, nil
	}
	var buf bytes.Buffer
	cfg := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
	if err := cfg.Fprint(&buf, fset, node); err != nil {
		return "", false, err
	}
	lines := []string{}
	for _, l := range strings.Split(buf.String(), "\n") {
		if l = strings.TrimRight(l, " \t"); l != "" {
			lines = append(lines, collapseSpace(l))
		}
	}
	return strings.Join(lines, "\n") + "\n", true, nil
}

var spaceRun = regexp.MustCompile(`[ \t]+`)

// collapseSpace keeps a line's indentation and turns every other run of
// spaces and tabs into one space, so that gofmt realigning a block, because
// a neighbor was added or removed, is not a change.
func collapseSpace(l string) string {
	body := strings.TrimLeft(l, "\t")
	return l[:len(l)-len(body)] + spaceRun.ReplaceAllString(body, " ")
}

// findDecl returns the function, method, type, variable or constant named
// name, or nil.
func findDecl(f *ast.File, name string) ast.Node {
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.Name == name {
				return d
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					if s.Name.Name == name {
						return s
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.Name == name {
							return s
						}
					}
				}
			}
		}
	}
	return nil
}

// findGate returns the entry of a feature gate in featureGatesVar, or nil.
func findGate(f *ast.File, gate string) ast.Node {
	spec, ok := findDecl(f, featureGatesVar).(*ast.ValueSpec)
	if !ok {
		return nil
	}
	for _, v := range spec.Values {
		lit, ok := v.(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			var key string
			switch k := kv.Key.(type) {
			case *ast.Ident:
				key = k.Name
			case *ast.SelectorExpr:
				key = k.Sel.Name
			}
			if key == gate {
				return kv
			}
		}
	}
	return nil
}

func hashOf(content string, found bool) string {
	if !found {
		return absent
	}
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var releaseRefRe = regexp.MustCompile(`^refs/heads/release-1\.(\d+)$`)

// releaseMinors maps the minor version of every release-1.N branch at or
// after oldest to its commit.
func releaseMinors(refs map[string]string, oldest int) map[int]string {
	res := map[int]string{}
	for ref, sha := range refs {
		m := releaseRefRe.FindStringSubmatch(ref)
		if m == nil {
			continue
		}
		minor, err := strconv.Atoi(m[1])
		if err != nil || minor < oldest {
			continue
		}
		res[minor] = sha
	}
	return res
}

// Baseline is the upstream state kubelet_defaults.go was last checked
// against, by minor version ("1.37").
type Baseline struct {
	Minors map[string]MinorBaseline `json:"minors"`
}

// MinorBaseline is a release branch's commit and the hash of each item.
type MinorBaseline struct {
	Commit string            `json:"commit"`
	Items  map[string]string `json:"items"`
}

func minorKey(minor int) string { return fmt.Sprintf("1.%d", minor) }

// oldest returns the oldest minor version the baseline records, or 0.
func (b Baseline) oldest() int {
	res := 0
	for k := range b.Minors {
		if minor, ok := parseMinorKey(k); ok && (res == 0 || minor < res) {
			res = minor
		}
	}
	return res
}

func parseMinorKey(k string) (int, bool) {
	rest, ok := strings.CutPrefix(k, "1.")
	if !ok {
		return 0, false
	}
	minor, err := strconv.Atoi(rest)
	return minor, err == nil
}

// finding is one difference between the baseline and upstream.
type finding struct {
	Minor int
	// Kind is newMinor, changed or newItem.
	Kind string
	// Item is empty for newMinor.
	Item string
}

const (
	newMinor = "new minor"
	changed  = "changed"
	newItem  = "newly tracked"
)

// drift compares the current hashes, by minor version and item id, with the
// baseline. A minor the baseline does not have is one finding; its items are
// not compared one by one.
func drift(b Baseline, current map[int]map[string]string) []finding {
	minors := make([]int, 0, len(current))
	for m := range current {
		minors = append(minors, m)
	}
	sort.Ints(minors)
	res := []finding{}
	for _, m := range minors {
		base, ok := b.Minors[minorKey(m)]
		if !ok {
			res = append(res, finding{Minor: m, Kind: newMinor})
			continue
		}
		ids := make([]string, 0, len(current[m]))
		for id := range current[m] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			want, ok := base.Items[id]
			switch {
			case !ok:
				res = append(res, finding{Minor: m, Kind: newItem, Item: id})
			case want != current[m][id]:
				res = append(res, finding{Minor: m, Kind: changed, Item: id})
			}
		}
	}
	return res
}
