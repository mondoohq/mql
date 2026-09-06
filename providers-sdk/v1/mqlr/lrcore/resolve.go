// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Resolve parses an .lr file and loads every peer it imports. The providers
// root, under which name-based imports are found, is derived from the file's
// own location: providers/<name>/resources/<name>.lr sits two levels below it.
func Resolve(filePath string, readFile func(path string) ([]byte, error)) (*LR, error) {
	return ResolveWithRoot(filePath, "", readFile)
}

// ResolveWithRoot is Resolve with an explicit providers root, for a tree that
// does not follow the providers/<name>/resources layout. An empty root falls
// back to the derived one.
func ResolveWithRoot(filePath string, providersRoot string, readFile func(path string) ([]byte, error)) (*LR, error) {
	raw, err := readFile(filePath)
	if err != nil {
		return nil, err
	}

	anchorPath := path.Dir(filePath)
	if providersRoot == "" {
		providersRoot = path.Dir(path.Dir(anchorPath))
	}

	res, err := Parse(string(raw))
	if err != nil {
		return nil, err
	}

	res.imports = make(map[string]map[string]struct{})
	res.importedMembers = make(map[string]map[string]struct{})
	res.packPaths = map[string]string{}
	res.packProviders = map[string]string{}
	importMap := map[string]map[string]*Resource{
		"": {},
	}
	for _, r := range res.Resources {
		importMap[""][r.ID] = r
	}
	loadPeer := func(packName string, peerPath string, declaredID string) error {
		// note: we do not recurse into these imports; we only need to know
		// about the things that the import exposes, not about its dependencies
		raw, err := readFile(peerPath)
		if err != nil {
			return err
		}

		childLR, err := Parse(string(raw))
		if err != nil {
			return err
		}

		resources := map[string]struct{}{}
		importMap[packName] = map[string]*Resource{}
		for i := range childLR.Resources {
			resource := childLR.Resources[i]
			resources[resource.ID] = struct{}{}
			importMap[packName][resource.ID] = resource
		}

		res.imports[packName] = resources

		// Record what each peer resource exposes, so a cross-provider
		// `@replaced_by` target can be verified down to the field instead of
		// being accepted because the resource name happened to exist.
		childByID := map[string]*Resource{}
		for i := range childLR.Resources {
			childByID[childLR.Resources[i].ID] = childLR.Resources[i]
		}
		for id := range childByID {
			members := map[string]struct{}{}
			for name := range childLR.exposedMembers(childByID, id, 0) {
				members[name] = struct{}{}
			}
			res.importedMembers[id] = members
		}

		goPkg := childLR.Options["go_package"]
		if goPkg == "" {
			return errors.New("cannot find name of the go package in " + peerPath + " - make sure you set the go_package name")
		}
		res.packPaths[packName] = goPkg

		// The peer's provider ID is what identifies it at runtime, so it has to
		// come from its own `option provider` rather than being derived from
		// go_package. The two happen to be equal today, which is exactly why
		// this must be read explicitly: a derived value would keep looking
		// correct right up until they diverge, and nothing would catch it.
		providerID := childLR.Options["provider"]
		if providerID == "" {
			return errors.New("cannot find the provider ID in " + peerPath + " - make sure you set the provider option")
		}

		// When the import spelled out a provider ID, the peer has to agree.
		// This is the check that keeps the two declarations of a dependency --
		// the import here and the peer's own identity -- from drifting apart,
		// which is exactly how the old CrossProviderTypes list came to name
		// providers that did not exist.
		if declaredID != "" && declaredID != providerID {
			return fmt.Errorf("import %q declares provider %q but %s reports %q",
				packName, declaredID, peerPath, providerID)
		}
		res.packProviders[packName] = providerID

		return nil
	}

	for i := range res.Imports {
		imp := res.Imports[i]
		packName := imp.PackName()

		peerPath := path.Join(anchorPath, imp.Path)
		if imp.Path == "" {
			peer := imp.PeerName()
			peerPath = path.Join(providersRoot, peer, "resources", peer+".lr")
		}

		if err := loadPeer(packName, peerPath, imp.From); err != nil {
			return nil, err
		}
	}

	// `extend core.asset` names the peer the resource comes from, the same way a
	// type reference does. The pack qualifier is stripped once it has been
	// checked, so the extension is recorded against the peer's own resource name
	// and is byte-identical to the bare `extend asset` form.
	//
	// The bare form stays legal and stays unchecked: it is what every existing
	// extension uses, in this repo and in the enterprise providers. The
	// qualified form is the one that can be verified, because naming the peer is
	// what makes its resource list available to check against.
	for _, r := range res.Resources {
		if !r.IsExtension {
			continue
		}
		pack, name, ok := strings.Cut(r.ID, ".")
		if !ok {
			continue
		}
		peer, isPeer := importMap[pack]
		if !isPeer {
			// a local resource whose own name contains dots, e.g. `extend
			// os.unix` inside the os provider
			continue
		}
		if _, exists := peer[name]; !exists {
			return nil, fmt.Errorf("cannot extend %q: %s has no resource %q", r.ID, pack, name)
		}
		delete(importMap[""], r.ID)
		r.ID = name
		importMap[""][r.ID] = r
	}

	res.aliases = map[string]*Resource{}
	for _, a := range res.Aliases {
		var pack string
		var resourceName string

		if _, ok := importMap[""][a.Type.Type]; ok {
			pack = ""
			resourceName = a.Type.Type
		} else {
			pack, resourceName, ok = strings.Cut(a.Type.Type, ".")
			if !ok {
				pack = ""
				resourceName = a.Type.Type
			}
		}

		found := false
		p, ok := importMap[pack]
		if ok {
			r, ok := p[resourceName]
			if ok {
				found = true
			}
			res.aliases[a.Definition.Type] = r
		}

		if !found {
			return nil, fmt.Errorf("%s was aliased but not imported", a.Type.Type)
		}
	}

	res.Imports = nil

	return res, nil
}

// hasLocalResource reports whether the schema defines a resource (or alias) by
// this exact name. Used to tell a local dotted name like `os.unix.sshd` from a
// pack-qualified one whose import is missing.
func (lr *LR) hasLocalResource(name string) bool {
	for _, r := range lr.Resources {
		if r != nil && r.ID == name {
			return true
		}
	}
	_, ok := lr.aliases[name]
	return ok
}
