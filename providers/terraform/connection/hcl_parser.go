// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/json"
	"github.com/rs/zerolog/log"
)

func NewHCLFileLoader() *hclFileLoader {
	hclParser := hclparse.NewParser()

	return &hclFileLoader{
		hclParser: hclParser,
	}
}

type hclFileLoader struct {
	hclParser *hclparse.Parser
}

// ParseHclFile parses a single Terraform or OpenTofu configuration file
// (.tf, .tf.json, .tofu or .tofu.json). Anything else is skipped.
//
// The source bytes are read here rather than handed to the parser's
// *File variants on purpose. hclparse.Parser.ParseJSONFile records its result
// in the parser's file map before checking it, and json.ParseFile returns a
// nil *hcl.File when the file cannot be opened — so an unreadable `.tf.json`
// (a dangling symlink in a checkout is enough) left a nil entry in
// Parser().Files(). Every consumer of that map dereferences file.Body, so the
// nil surfaced later as a provider panic that took down the whole scan.
// ParseHCL/ParseJSON always store a real *hcl.File.
func (h *hclFileLoader) ParseHclFile(path string) error {
	f, ok := classifyConfigFile(path)
	if !ok {
		return nil
	}

	var parseFunc func(src []byte, filename string) (*hcl.File, hcl.Diagnostics)
	switch f.class {
	case classConfig:
		parseFunc = h.hclParser.ParseHCL
	case classConfigJSON:
		parseFunc = h.hclParser.ParseJSON
	default:
		// a variables file; ReadTfVarsFromFile handles those
		return nil
	}

	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	log.Debug().Str("path", path).Str("dialect", string(f.dialect)).Msg("parsing hcl file")
	_, diag := parseFunc(src, path)
	if diag != nil && diag.HasErrors() {
		return diag
	}
	return nil
}

func (h *hclFileLoader) GetParser() *hclparse.Parser {
	return h.hclParser
}

// ReadTfVarsFromFile reads a variable definitions file (.tfvars, .tfvars.json,
// .tofuvars or .tofuvars.json) into terraformVars. Anything else is skipped.
//
// The two formats need different parsers. Terraform reads `*.tfvars.json` as
// JSON; running it through the native HCL syntax parser produces only syntax
// errors, so every value in the file was silently dropped and each `var.*`
// reference fell back to the variable block's default. A security-relevant
// override declared in `terraform.tfvars.json` was therefore invisible to a
// scan — a false negative with no error to notice.
func ReadTfVarsFromFile(filename string, terraformVars map[string]*hcl.Attribute) error {
	f, ok := classifyConfigFile(filename)
	if !ok {
		return nil
	}

	var variableFile *hcl.File
	var diags hcl.Diagnostics

	switch f.class {
	case classVarsJSON:
		src, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		variableFile, diags = json.Parse(src, filename)
	case classVars:
		src, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		variableFile, diags = hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	default:
		return nil
	}

	// Parse diagnostics are not fatal — a partially readable tfvars file still
	// contributes the attributes it did parse — but they must not vanish
	// silently, or a typo'd file looks identical to an absent one.
	if diags.HasErrors() {
		log.Warn().Str("path", filename).Str("diagnostics", diags.Error()).Msg("could not fully parse tfvars file")
	}
	if variableFile == nil {
		return nil
	}

	attrs, attrDiags := variableFile.Body.JustAttributes()
	if attrDiags.HasErrors() {
		log.Debug().Str("path", filename).Str("diagnostics", attrDiags.Error()).Msg("tfvars file has non-attribute content")
	}
	for k := range attrs {
		terraformVars[k] = attrs[k]
	}
	return nil
}
