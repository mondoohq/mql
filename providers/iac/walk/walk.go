// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package walk reads a tree of infrastructure-as-code files and offers each
// candidate to the provider whose opt-in matched it (ADR 045).
//
// It knows nothing about runtimes or the coordinator: probing is a Prober, so
// the walk is testable against an fs.FS with a fake.
package walk

import (
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/iac/connection"
)

// Tree is the file tree being walked.
type Tree struct {
	// FS is what gets read.
	FS fs.FS
	// Root is the absolute local path candidates are built from. Later source
	// kinds that do not materialize a local tree will need more than this.
	Root string
}

// Prober connects one candidate in the provider it belongs to and reports what
// that provider said. The walk never learns how that happens.
type Prober interface {
	Probe(child *inventory.Asset) (*plugin.ConnectRes, error)
}

// Selection is the set of opt-ins this run probes with, resolved from
// --discover before anything is read.
type Selection struct {
	OptIns []plugin.TargetOptIn
	// All offers the root of the tree to every non-PerFile opt-in before
	// matching: the escape hatch for a matcher that is wrong. A PerFile opt-in
	// is left out because it reads one document per asset and can say nothing
	// about a directory -- docker-file handed one builds an asset named
	// "Dockerfile " describing nothing.
	All bool
}

// Options are the walk's own knobs.
type Options struct {
	// Ignore are directory base names to skip, at any depth. Empty means skip
	// nothing; connection.DefaultIgnore is the default the caller applies.
	Ignore []string
}

// Result is what the walk found.
type Result struct {
	// Detections is every entry point, accepted or failed, in a deterministic
	// order.
	Detections []*connection.Detection
	// Assets is one entry per accepted platform identity, in the order first
	// seen. Two detections that resolve to one identity share an asset.
	Assets []*inventory.Asset
}

// candidate is one thing offered to one opt-in.
type candidate struct {
	optIn int
	// site is the directory the match sited at, relative to the tree root; the
	// root itself is "".
	site string
	// target is what is handed to the provider: the site for a directory
	// opt-in, the matching file for a PerFile one.
	target string
	files  []string
}

// Walk reads the tree once and probes what the selected opt-ins matched.
func Walk(tree Tree, sel Selection, opts Options, root *inventory.Asset, prober Prober) (*Result, error) {
	files, err := readTree(tree.FS, opts.Ignore)
	if err != nil {
		return nil, err
	}

	res := &Result{}
	rootRef := connection.RootRef(root)
	// stopped holds, per opt-in, the sites whose provider asked the walk not to
	// descend.
	stopped := make([][]string, len(sel.OptIns))
	// byPlatformID is how two detections that resolve to one identity end up
	// sharing an asset rather than emitting it twice.
	byPlatformID := map[string]*inventory.Asset{}

	probe := func(c candidate) {
		optIn := sel.OptIns[c.optIn]
		if isStoppedBelow(stopped[c.optIn], c.site) {
			return
		}

		child := childAsset(optIn, tree.Root, c.target)
		connectRes, err := prober.Probe(child)
		if err != nil {
			if plugin.IsNoMatchError(err) {
				// Not this provider's. A normal outcome, so nothing is
				// recorded: the tree is full of files some opt-in matched and
				// no provider wanted.
				return
			}
			// A real failure -- a malformed file, a permission problem, a
			// provider that crashed. Record it and keep walking: a broken chart
			// must not hide the terraform next to it.
			res.Detections = append(res.Detections, connection.NewDetection(optIn.Discovery, c.target, c.files, nil, rootRef, err))
			return
		}

		accepted := connectRes.GetAsset()
		detection := connection.NewDetection(optIn.Discovery, c.target, c.files, accepted, rootRef, nil)

		if existing := firstKnownAsset(byPlatformID, accepted); existing != nil {
			// Another opt-in already produced this identity, so this detection
			// adopts that asset and attaches its own anchor to it. Either
			// detection then resolves into the one asset.
			detection.AdoptAsset(existing, rootRef)
		} else {
			setDiscoverAuto(accepted)
			for _, id := range accepted.GetPlatformIds() {
				byPlatformID[id] = accepted
			}
			res.Assets = append(res.Assets, accepted)
		}

		res.Detections = append(res.Detections, detection)

		if !connectRes.GetContinueExploration() {
			stopped[c.optIn] = append(stopped[c.optIn], c.site)
		}
	}

	if sel.All {
		for i, optIn := range sel.OptIns {
			if optIn.PerFile {
				continue
			}
			probe(candidate{optIn: i, site: "", target: "", files: nil})
		}
	}

	for _, c := range candidates(files, sel.OptIns) {
		probe(c)
	}

	return res, nil
}

// readTree lists every file in the tree, slash-separated and relative to its
// root, skipping the ignored directory names at any depth.
func readTree(fsys fs.FS, ignore []string) ([]string, error) {
	ignored := map[string]bool{}
	for _, name := range ignore {
		if name != "" {
			ignored[name] = true
		}
	}

	var files []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		if d.IsDir() {
			if ignored[path.Base(p)] {
				return fs.SkipDir
			}
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(files)
	return files, nil
}

// candidates sites every file against every opt-in and returns what to probe,
// ordered so an ancestor is always probed before anything below it -- which is
// what lets a provider's answer stop the walk from descending.
func candidates(files []string, optIns []plugin.TargetOptIn) []candidate {
	// keyed by opt-in index and target, so one candidate collects every file
	// that put it there.
	type key struct {
		optIn  int
		target string
	}
	sites := map[key]*candidate{}
	var order []key

	for i, optIn := range optIns {
		for _, file := range files {
			site, ok := optIn.Matches(file)
			if !ok {
				continue
			}
			// A directory opt-in is offered the folder the match sited at; a
			// PerFile one is offered the file itself, because it reads one
			// document per asset.
			target := site
			if optIn.PerFile {
				target = file
			}

			k := key{optIn: i, target: target}
			c, seen := sites[k]
			if !seen {
				c = &candidate{optIn: i, site: site, target: target}
				sites[k] = c
				order = append(order, k)
			}
			c.files = append(c.files, file)
		}
	}

	res := make([]candidate, 0, len(order))
	for _, k := range order {
		res = append(res, *sites[k])
	}

	sort.SliceStable(res, func(i, j int) bool {
		di, dj := depth(res[i].site), depth(res[j].site)
		if di != dj {
			return di < dj
		}
		if res[i].site != res[j].site {
			return res[i].site < res[j].site
		}
		if res[i].target != res[j].target {
			return res[i].target < res[j].target
		}
		return res[i].optIn < res[j].optIn
	})
	return res
}

// depth counts the path segments of a tree-relative site; the root is 0.
func depth(site string) int {
	if site == "" {
		return 0
	}
	return strings.Count(site, "/") + 1
}

// isStoppedBelow reports whether site lies strictly below a site this opt-in's
// provider already claimed and asked the walk not to descend.
//
// Strictly below: a provider that took a folder has not said anything about
// that folder's own other candidates, so a PerFile sibling in the same
// directory is still offered, and a stop at a site never retracts the site
// itself.
func isStoppedBelow(stopped []string, site string) bool {
	for _, s := range stopped {
		if s == "" {
			// The whole tree was claimed, so everything but the root itself is
			// below it.
			if site != "" {
				return true
			}
			continue
		}
		if site != s && strings.HasPrefix(site, s+"/") {
			return true
		}
	}
	return false
}

// childAsset builds the asset offered to a provider.
//
// Both Path and Options["path"] carry the candidate, because the providers
// disagree about where to read it: docker-file reads Config.Path and the rest
// read Options["path"].
//
// Discover is deliberately absent. Setting it makes a k8s probe enumerate a
// manifest tree that is about to be thrown away; the accepted asset gets it
// instead, where the discovery layer acts on it.
func childAsset(optIn plugin.TargetOptIn, treeRoot, target string) *inventory.Asset {
	abs := treeRoot
	if target != "" {
		abs = filepath.Join(treeRoot, filepath.FromSlash(target))
	}

	options := map[string]string{"path": abs}
	for k, v := range optIn.Options {
		options[k] = v
	}

	return &inventory.Asset{
		Connections: []*inventory.Config{{
			Type:    optIn.ConnType,
			Path:    abs,
			Options: options,
		}},
	}
}

// setDiscoverAuto asks the discovery layer to discover what the child itself
// holds, which is what reproduces a direct scan of that connector. A provider
// that already had an opinion keeps it.
func setDiscoverAuto(asset *inventory.Asset) {
	for _, conf := range asset.GetConnections() {
		if conf.GetDiscover() == nil {
			conf.Discover = &inventory.Discovery{Targets: []string{"auto"}}
		}
	}
}

// firstKnownAsset returns the asset already emitted for any of this asset's
// platform IDs.
func firstKnownAsset(byPlatformID map[string]*inventory.Asset, asset *inventory.Asset) *inventory.Asset {
	for _, id := range asset.GetPlatformIds() {
		if existing, ok := byPlatformID[id]; ok {
			return existing
		}
	}
	return nil
}
