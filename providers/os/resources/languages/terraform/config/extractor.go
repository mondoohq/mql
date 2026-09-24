// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

// Package config inventories the dependencies a Terraform configuration
// declares: the modules it calls and the providers it requires.
//
// It complements the lockfile package rather than replacing it. A lock file
// states the providers `terraform init` resolved, at exact versions, and says
// nothing about modules; the configuration states every module the code calls
// and every provider it asks for, and is present whether or not anyone has run
// init — lock files are frequently not committed.
package config

import (
	"io"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/rs/zerolog/log"
	"github.com/zclconf/go-cty/cty"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/terraform"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*terraformConfig)(nil)
)

// Extractor parses Terraform configuration files (*.tf).
type Extractor struct{}

func (e *Extractor) Name() string {
	return "terraform-config"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	cfg := &terraformConfig{}
	if filename != "" {
		cfg.evidence = append(cfg.evidence, filename)
	}

	// Terraform tolerates files it cannot fully understand far better than a
	// strict parse does, and a configuration that references a module we cannot
	// evaluate should still contribute the modules we can. Diagnostics are
	// logged, never fatal: a half-readable file is more inventory than none.
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(data, filename)
	if file == nil || file.Body == nil {
		log.Debug().Str("file", filename).Str("err", diags.Error()).Msg("could not parse Terraform configuration")
		return cfg, nil
	}
	if diags.HasErrors() {
		log.Debug().Str("file", filename).Str("err", diags.Error()).Msg("Terraform configuration parsed with errors")
	}

	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return cfg, nil
	}

	for _, block := range body.Blocks {
		switch block.Type {
		case "module":
			cfg.addModule(block)
		case "terraform":
			cfg.addRequiredProviders(block)
		}
	}

	return cfg, nil
}

type terraformConfig struct {
	modules   []moduleCall
	providers []requiredProvider
	evidence  []string
}

type moduleCall struct {
	source  string
	version string
}

type requiredProvider struct {
	source     string
	constraint string
}

func (c *terraformConfig) addModule(block *hclsyntax.Block) {
	source, ok := literalString(block.Body.Attributes["source"])
	if !ok || source == "" {
		return
	}
	version, _ := literalString(block.Body.Attributes["version"])
	c.modules = append(c.modules, moduleCall{source: source, version: version})
}

func (c *terraformConfig) addRequiredProviders(block *hclsyntax.Block) {
	for _, inner := range block.Body.Blocks {
		if inner.Type != "required_providers" {
			continue
		}
		for localName, attr := range inner.Body.Attributes {
			value, diags := attr.Expr.Value(nil)
			if diags.HasErrors() || value.IsNull() || !value.IsWhollyKnown() {
				continue
			}

			switch {
			case value.Type() == cty.String:
				// The legacy shorthand `aws = "~> 3.74"` states only a version
				// constraint. Terraform then implies the source from the local
				// name in the default namespace, which is what is recorded here
				// — the alternative is dropping the provider entirely.
				c.providers = append(c.providers, requiredProvider{
					source:     "hashicorp/" + localName,
					constraint: value.AsString(),
				})
			case value.Type().IsObjectType():
				p := requiredProvider{}
				if value.Type().HasAttribute("source") {
					if s := value.GetAttr("source"); s.Type() == cty.String && !s.IsNull() {
						p.source = s.AsString()
					}
				}
				if value.Type().HasAttribute("version") {
					if v := value.GetAttr("version"); v.Type() == cty.String && !v.IsNull() {
						p.constraint = v.AsString()
					}
				}
				if p.source == "" {
					p.source = "hashicorp/" + localName
				}
				c.providers = append(c.providers, p)
			}
		}
	}
}

// literalString evaluates an attribute that must be a plain string. An
// expression referencing a variable or a local evaluates to nothing useful
// without a full Terraform evaluation context, so it is skipped rather than
// guessed at.
func literalString(attr *hclsyntax.Attribute) (string, bool) {
	if attr == nil {
		return "", false
	}
	value, diags := attr.Expr.Value(nil)
	if diags.HasErrors() || value.IsNull() || !value.IsWhollyKnown() || value.Type() != cty.String {
		return "", false
	}
	return value.AsString(), true
}

// Root returns nil — a configuration file is not itself a published package.
func (c *terraformConfig) Root() *languages.Package {
	return nil
}

// Direct returns everything the configuration declares. A module call and a
// required_providers entry are both first-order dependencies by definition:
// they are what this code asks for by name.
func (c *terraformConfig) Direct() languages.Packages {
	var packages languages.Packages
	evidence := terraform.NewEvidenceList(c.evidence)

	for _, m := range c.modules {
		source := terraform.ClassifyModuleSource(m.source)
		purl := terraform.NewModulePackageUrl(source, m.version)
		if purl == "" {
			// A local path, or a fetcher with no stable public coordinate.
			continue
		}
		packages = append(packages, &languages.Package{
			Name:         terraform.ModuleName(source),
			Type:         terraform.PackageTypeModule,
			Version:      m.version,
			Purl:         purl,
			Origin:       m.source,
			Scope:        languages.PackageScopeProd,
			EvidenceList: evidence,
		})
	}

	for _, p := range c.providers {
		host, namespace, providerType := terraform.ParseProviderSource(p.source)
		if providerType == "" {
			continue
		}
		name := namespace + "/" + providerType
		if namespace == "" {
			name = providerType
		}
		packages = append(packages, &languages.Package{
			Name: name,
			Type: terraform.PackageTypeProvider,
			// Deliberately no version. required_providers states a constraint
			// ("~> 5.0"), and a constraint in a version field is worse than an
			// empty one: nothing downstream can match it, and it reads as an
			// exact version to anything that does not check. The lock file is
			// where the resolved version comes from.
			Version:      "",
			Purl:         terraform.NewPackageUrl(host, namespace, providerType, ""),
			Origin:       p.source,
			Scope:        languages.PackageScopeProd,
			EvidenceList: evidence,
		})
	}

	return packages
}

// Transitive returns nil. A configuration states what it calls, not what those
// modules call in turn; the expanded tree is what .terraform/modules records.
func (c *terraformConfig) Transitive() languages.Packages {
	return nil
}
