// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"path/filepath"
	"sort"
	"strings"
)

// Dialect names the tool a configuration is written for.
//
// Terraform and OpenTofu share the HCL language and the `terraform show -json`
// representation, so they are read by the same resources. What differs is which
// files on disk make up a configuration: OpenTofu additionally reads a
// .tofu-flavored set, and prefers it over the .tf equivalent.
type Dialect string

const (
	DialectTerraform Dialect = "terraform"
	DialectOpenTofu  Dialect = "opentofu"
)

// OptionDialect is the connection option carrying an explicitly chosen dialect.
//
// On the command line it is set from the connector the user invoked: the
// `terraform` connector records Terraform, the `opentofu` connector records
// OpenTofu. An inventory can set it directly. Left unset -- which is what a git
// integration produces, since it names no tool -- an HCL configuration detects
// its dialect from the files on disk.
const OptionDialect = "iac-tool"

// DialectForConnector maps a connector name onto the dialect it selects, and
// reports whether the name was one this provider serves.
//
// The two tools get a connector each, so invoking one is how a user says which
// tool the configuration belongs to. That has to be a distinct signal from "no
// choice was made": a name this provider does not serve leaves the dialect
// unset rather than quietly meaning Terraform, so an unrecognized caller falls
// back to detection instead of forcing a tool it never named.
//
// This is the one place the spellings are matched. ParseDialect is the same
// match with a default, for the callers that have no "unset" to represent.
func DialectForConnector(name string) (Dialect, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "opentofu", "tofu":
		return DialectOpenTofu, true
	case "terraform":
		return DialectTerraform, true
	default:
		return "", false
	}
}

// ParseDialect maps a recorded option value onto a dialect, defaulting to
// Terraform for anything unrecognized.
//
// The option is written from a connector name, so it accepts exactly the
// spellings a connector does; an inventory that sets something else gets the
// default rather than an error, because a connection option is not the place to
// fail a scan over a typo.
func ParseDialect(s string) Dialect {
	if dialect, ok := DialectForConnector(s); ok {
		return dialect
	}
	return DialectTerraform
}

// fileClass groups the configuration file kinds that OpenTofu defines a
// .tofu-flavored override for. Precedence applies within one class: main.tofu
// replaces main.tf, but never main.tf.json, which belongs to a different class.
type fileClass int

const (
	classConfig     fileClass = iota // .tf           / .tofu
	classConfigJSON                  // .tf.json      / .tofu.json
	classVars                        // .tfvars       / .tofuvars
	classVarsJSON                    // .tfvars.json  / .tofuvars.json
)

// configExtensions maps a file suffix onto its class and dialect.
//
// Order matters. The longest suffix has to be tested first, so that
// prod.tofuvars.json is recognized as a variables file rather than falling
// through to a shorter, differently-classed suffix.
var configExtensions = []struct {
	suffix  string
	class   fileClass
	dialect Dialect
}{
	{".tofuvars.json", classVarsJSON, DialectOpenTofu},
	{".tofuvars", classVars, DialectOpenTofu},
	{".tofu.json", classConfigJSON, DialectOpenTofu},
	{".tofu", classConfig, DialectOpenTofu},
	{".tfvars.json", classVarsJSON, DialectTerraform},
	{".tfvars", classVars, DialectTerraform},
	{".tf.json", classConfigJSON, DialectTerraform},
	{".tf", classConfig, DialectTerraform},
}

// configFile is a path recognized as part of a Terraform or OpenTofu
// configuration.
type configFile struct {
	path    string
	class   fileClass
	dialect Dialect

	// dir and stem identify the slot this file occupies. Together with class
	// they are what a .tofu file overrides: same directory, same name, same
	// kind of file.
	dir  string
	stem string
}

// classifyConfigFile recognizes a configuration file by its extension. A file
// whose whole name is the extension (".tf") is not a configuration file, since
// there is no name left to match a .tofu override against.
func classifyConfigFile(path string) (configFile, bool) {
	name := filepath.Base(path)
	for _, ext := range configExtensions {
		if len(name) > len(ext.suffix) && strings.HasSuffix(name, ext.suffix) {
			return configFile{
				path:    path,
				class:   ext.class,
				dialect: ext.dialect,
				dir:     filepath.Dir(path),
				stem:    strings.TrimSuffix(name, ext.suffix),
			}, true
		}
	}
	return configFile{}, false
}

// resolvedConfig is the outcome of applying OpenTofu's precedence rules to a
// set of candidate paths.
type resolvedConfig struct {
	// Configs are the configuration files to parse, sorted.
	Configs []string
	// Vars are the variable definition files to read, sorted.
	Vars []string
	// Dialect is DialectOpenTofu when any .tofu-flavored file is part of the
	// configuration, whether or not it overrode anything.
	Dialect Dialect
	// Overridden lists the .tf files that a .tofu file replaced, sorted. They
	// are reported so a scan can explain why a file on disk was not read.
	Overridden []string
	// Ignored lists the .tofu-flavored files skipped because the dialect was
	// forced to Terraform, sorted. Terraform does not read them, so neither do
	// we, but a scan that found nothing else needs to be able to say that an
	// OpenTofu configuration was sitting there.
	Ignored []string
}

// slot identifies the position a .tofu file competes for.
type slot struct {
	dir   string
	stem  string
	class fileClass
}

// resolveConfigFiles picks the configuration files a given tool would read.
//
// Under DialectOpenTofu, OpenTofu's precedence applies: it loads foo.tofu
// *instead of* foo.tf when both are present, and likewise for the .json,
// .tfvars and .tfvars.json variants. The rule is per directory and per file
// name -- a.tofu overrides a.tf and leaves b.tf alone. Reading the .tf file in
// that situation would describe configuration that OpenTofu never applies.
//
// Under DialectTerraform the .tofu-flavored files are skipped entirely rather
// than allowed to override anything, which is what a repository shared between
// the two tools looks like to Terraform.
//
// An empty dialect detects instead of choosing: any .tofu-flavored file present
// means the configuration is OpenTofu's. That is for callers that name no tool,
// such as a git integration.
//
// Paths that are not configuration files are ignored.
func resolveConfigFiles(paths []string, forced Dialect) resolvedConfig {
	chosen := make(map[slot]configFile, len(paths))
	var overridden, ignored []string

	for _, p := range paths {
		f, ok := classifyConfigFile(p)
		if !ok {
			continue
		}
		if forced == DialectTerraform && f.dialect == DialectOpenTofu {
			ignored = append(ignored, f.path)
			continue
		}

		key := slot{dir: f.dir, stem: f.stem, class: f.class}
		prev, exists := chosen[key]
		if !exists {
			chosen[key] = f
			continue
		}

		// Same slot, so one of the two is the OpenTofu override. Two files of
		// the same dialect cannot collide here: the extension is part of the
		// name, so they would occupy different slots.
		if f.dialect == DialectOpenTofu && prev.dialect == DialectTerraform {
			chosen[key] = f
			overridden = append(overridden, prev.path)
		} else if f.dialect == DialectTerraform && prev.dialect == DialectOpenTofu {
			overridden = append(overridden, f.path)
		}
	}

	res := resolvedConfig{Dialect: DialectTerraform}
	for _, f := range chosen {
		if f.dialect == DialectOpenTofu {
			res.Dialect = DialectOpenTofu
		}
		switch f.class {
		case classConfig, classConfigJSON:
			res.Configs = append(res.Configs, f.path)
		case classVars, classVarsJSON:
			res.Vars = append(res.Vars, f.path)
		}
	}

	if forced != "" {
		res.Dialect = forced
	}

	// map iteration is unordered; sort so a scan is reproducible
	sort.Strings(res.Configs)
	sort.Strings(res.Vars)
	sort.Strings(overridden)
	sort.Strings(ignored)
	res.Overridden = overridden
	res.Ignored = ignored

	return res
}
