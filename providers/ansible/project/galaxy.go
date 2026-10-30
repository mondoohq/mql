// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package project

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Requirements is a parsed Galaxy requirements.yml: the external roles and
// collections a project pulls in, with their sources and pinned versions.
type Requirements struct {
	Path        string
	Roles       []*GalaxyRole
	Collections []*GalaxyCollection
}

// GalaxyRole is an external role dependency.
type GalaxyRole struct {
	Name    string
	Src     string
	Version string
	SCM     string
}

// GalaxyCollection is an external collection dependency.
type GalaxyCollection struct {
	Name    string
	Version string
	Source  string
	Type    string
}

// loadRequirements parses the project's Galaxy requirements file. Returns nil
// when none is found.
func loadRequirements(root string) (*Requirements, error) {
	path := firstExisting(
		filepath.Join(root, "requirements.yml"),
		filepath.Join(root, "requirements.yaml"),
		filepath.Join(root, "roles", "requirements.yml"),
		filepath.Join(root, "collections", "requirements.yml"),
	)
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	req := &Requirements{Path: path}

	// New style: a mapping with `roles:` and/or `collections:` keys.
	var keyed struct {
		Roles       []any `yaml:"roles"`
		Collections []any `yaml:"collections"`
	}
	if err := yaml.Unmarshal(data, &keyed); err == nil && (keyed.Roles != nil || keyed.Collections != nil) {
		for _, r := range keyed.Roles {
			req.Roles = append(req.Roles, parseGalaxyRole(r))
		}
		for _, c := range keyed.Collections {
			req.Collections = append(req.Collections, parseGalaxyCollection(c))
		}
		return req, nil
	}

	// Old style: a bare list of roles.
	var list []any
	if err := yaml.Unmarshal(data, &list); err != nil {
		// An unparseable requirements file should not abort the whole project
		// load; treat it as absent, matching loadPlaybooks' skip behavior.
		return nil, nil
	}
	for _, r := range list {
		req.Roles = append(req.Roles, parseGalaxyRole(r))
	}
	return req, nil
}

// parseGalaxyRole normalizes a role entry, which may be a bare string (the role
// name) or a mapping with src/name/version/scm keys.
func parseGalaxyRole(entry any) *GalaxyRole {
	switch v := entry.(type) {
	case string:
		return &GalaxyRole{Name: v, Src: v}
	case map[string]any:
		role := &GalaxyRole{
			Name:    stringField(v, "name"),
			Src:     stringField(v, "src"),
			Version: stringField(v, "version"),
			SCM:     stringField(v, "scm"),
		}
		if role.Name == "" {
			role.Name = role.Src
		}
		return role
	}
	return &GalaxyRole{}
}

// parseGalaxyCollection normalizes a collection entry, which may be a bare
// string (the collection name) or a mapping with name/version/source/type keys.
func parseGalaxyCollection(entry any) *GalaxyCollection {
	switch v := entry.(type) {
	case string:
		return &GalaxyCollection{Name: v}
	case map[string]any:
		return &GalaxyCollection{
			Name:    stringField(v, "name"),
			Version: stringField(v, "version"),
			Source:  stringField(v, "source"),
			Type:    stringField(v, "type"),
		}
	}
	return &GalaxyCollection{}
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
