// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
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
func (h *hclFileLoader) ParseHclFile(path string) error {
	f, ok := classifyConfigFile(path)
	if !ok {
		return nil
	}

	var parseFunc func(filename string) (*hcl.File, hcl.Diagnostics)
	switch f.class {
	case classConfig:
		parseFunc = h.hclParser.ParseHCLFile
	case classConfigJSON:
		parseFunc = h.hclParser.ParseJSONFile
	default:
		// a variables file; ReadTfVarsFromFile handles those
		return nil
	}

	log.Debug().Str("path", path).Str("dialect", string(f.dialect)).Msg("parsing hcl file")
	_, diag := parseFunc(path)
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
func ReadTfVarsFromFile(filename string, terraformVars map[string]*hcl.Attribute) error {
	f, ok := classifyConfigFile(filename)
	if !ok || (f.class != classVars && f.class != classVarsJSON) {
		return nil
	}

	src, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	// we ignore the diagnostics information here
	variableFile, _ := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})

	// NOTE: we ignore the diagnostics info
	attrs, _ := variableFile.Body.JustAttributes()
	for k := range attrs {
		v := attrs[k]
		terraformVars[k] = v
	}
	return nil
}
