// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package rebarlock

import (
	"io"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/erlang/termparser"
	"go.mondoo.com/mql/providers/os/resources/languages/hex"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*rebarLock)(nil)
)

// Extractor parses Erlang rebar.lock files using a recursive descent
// Erlang term parser for robust handling of nested structures.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "rebarlock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	lock := &rebarLock{}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	root, err := termparser.Parse(string(data))
	if err != nil {
		log.Debug().Err(err).Msg("could not parse rebar.lock as Erlang terms")
		return lock, nil
	}

	// rebar.lock can be either:
	// - A flat list: [{<<"name">>, {pkg, ...}, level}, ...]
	// - A versioned tuple: {<<"version">>, [{<<"name">>, {pkg, ...}, level}, ...]}
	deps := root
	if root.Type == termparser.NodeTuple && root.Len() >= 2 {
		// Versioned format: {<<"1.2.0">>, [deps...]}
		deps = root.Get(1)
	}

	if deps == nil || deps.Type != termparser.NodeList {
		return lock, nil
	}

	for i := 0; i < deps.Len(); i++ {
		entry := deps.Get(i)
		if entry == nil || entry.Type != termparser.NodeTuple || entry.Len() < 2 {
			continue
		}

		// Entry format: {<<"name">>, {pkg, <<"name">>, <<"version">>, ...}, level}
		name := entry.Get(0).Str()
		pkgTuple := entry.Get(1)

		if name == "" || pkgTuple == nil || pkgTuple.Type != termparser.NodeTuple {
			continue
		}

		// pkg tuple: {pkg, <<"name">>, <<"version">>, ...}
		if pkgTuple.Len() < 3 || pkgTuple.Get(0).Str() != "pkg" {
			continue
		}

		version := pkgTuple.Get(2).Str()
		if version == "" {
			continue
		}

		lock.Packages = append(lock.Packages, rebarPackage{
			Name:    name,
			Version: version,
		})
	}

	return lock, nil
}

// Root returns nil — rebar.lock does not describe the root project.
func (l *rebarLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — rebar.lock does not distinguish direct from transitive.
func (l *rebarLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all resolved packages.
func (l *rebarLock) Transitive() languages.Packages {
	var packages languages.Packages
	for _, pkg := range l.Packages {
		packages = append(packages, &languages.Package{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Purl:         hex.NewPackageUrl(pkg.Name, pkg.Version),
			EvidenceList: hex.NewEvidenceList(l.evidence),
		})
	}
	return packages
}
