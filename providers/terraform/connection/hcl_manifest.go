// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func ParseTerraformModuleManifest(manifestPath string) (*ModuleManifest, error) {
	_, err := os.Stat(manifestPath)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(manifestPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var manifest ModuleManifest
	if err := json.NewDecoder(f).Decode(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// e.g. mondoo-operator/.github/terraform/aws/.terraform/modules/vpc/examples/secondary-cidr-blocks/main.tf/1/1
var MODULE_EXAMPLES = regexp.MustCompile(`^.*/modules/.+/examples/.+`)

func NewHclConnection(id uint32, asset *inventory.Asset) (*Connection, error) {
	cc := asset.Connections[0]
	path := cc.Options["path"]
	return newHclConnection(id, path, asset)
}

func newHclConnection(id uint32, path string, asset *inventory.Asset) (*Connection, error) {
	// NOTE: right now we are only supporting to load either state, plan or hcl files but not at the same time
	if len(asset.Connections) != 1 {
		return nil, errors.New("only one connection is supported")
	}

	confOptions := asset.Connections[0].Options
	includeDotTerraform := true
	if confOptions["ignore-dot-terraform"] == "true" {
		includeDotTerraform = false
	}

	// An empty dialect means "detect from the files present". On the command
	// line the connector always names one; an inventory or a git integration
	// may not, and then the files decide.
	var forcedDialect Dialect
	if v := confOptions[OptionDialect]; v != "" {
		forcedDialect = ParseDialect(v)
	}

	var assetType terraformAssetType
	// hcl files
	loader := NewHCLFileLoader()
	tfVars := make(map[string]*hcl.Attribute)
	var modulesManifest *ModuleManifest

	assetType = configurationfiles
	// FIXME: cannot handle relative paths
	stat, err := os.Stat(path)
	if err != nil {
		// Only IsNotExist used to be handled, so every other stat failure --
		// a permission problem, a symlink loop -- left stat nil and panicked on
		// the IsDir below.
		if os.IsNotExist(err) {
			return nil, errors.New("path is not a valid file or directory")
		}
		return nil, errors.Wrapf(err, "cannot read %s", path)
	}

	// Candidate paths are collected first and parsed afterwards. OpenTofu's
	// precedence rules are per directory and per file name, so whether main.tf
	// should be read cannot be decided until the walk has also seen whether
	// main.tofu exists next to it.
	var candidates []string

	if stat.IsDir() {
		// NOTE: the return value of WalkDir is deliberately captured. It used to
		// be discarded, which silently swallowed every HCL parse error raised
		// below and turned a malformed configuration into an empty one.
		walkErr := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// skip terraform module examples
			foundExamples := MODULE_EXAMPLES.FindString(path)
			if foundExamples != "" {
				log.Debug().Str("path", path).Msg("ignoring terraform module example")
				return nil
			}

			// if user asked to ignore .terraform, we skip all files in .terraform
			if strings.Contains(path, ".terraform") && !includeDotTerraform {
				return nil
			}

			if !d.IsDir() {
				if strings.HasSuffix(path, ".terraform/modules/modules.json") {
					modulesManifest, err = ParseTerraformModuleManifest(path)
					if errors.Is(err, os.ErrNotExist) {
						log.Debug().Str("path", path).Msg("no terraform module manifest found")
					} else {
						return errors.Wrap(err, fmt.Sprintf("could not parse terraform module manifest %s", path))
					}
				}

				// we do not want to parse hcl files from terraform modules .terraform files
				if strings.Contains(path, ".terraform") {
					return nil
				}

				candidates = append(candidates, path)
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	} else {
		candidates = append(candidates, path)
	}

	// Apply OpenTofu's precedence rules before reading anything, so a .tofu
	// file replaces the .tf file it overrides rather than being read alongside
	// it.
	resolved := resolveConfigFiles(candidates, forcedDialect)

	for _, overridden := range resolved.Overridden {
		log.Debug().Str("path", overridden).
			Msg("skipping file overridden by its OpenTofu equivalent")
	}

	for _, ignored := range resolved.Ignored {
		log.Debug().Str("path", ignored).
			Msg("skipping OpenTofu file, reading the configuration as Terraform")
	}

	// Every configuration file here belongs to OpenTofu, and the terraform
	// connector does not read those. Scanning it as an empty configuration would
	// pass every policy on a project nothing was ever read from, so say what
	// happened and which connector reads it.
	if len(resolved.Configs) == 0 && len(resolved.Ignored) > 0 {
		return nil, fmt.Errorf(
			"%s holds an OpenTofu configuration (%d file(s), e.g. %s) and no Terraform files; use the opentofu connector to scan it: %w",
			path, len(resolved.Ignored), resolved.Ignored[0], plugin.ErrNoMatch)
	}

	for _, cfg := range resolved.Configs {
		if err := loader.ParseHclFile(cfg); err != nil {
			return nil, errors.Wrap(err, "could not parse hcl file")
		}
	}

	for _, varFile := range resolved.Vars {
		if err := ReadTfVarsFromFile(varFile, tfVars); err != nil {
			return nil, errors.Wrap(err, "could not parse tfvars file")
		}
	}

	// Connecting an empty configuration would pass every policy on a project
	// nothing was ever read from. Variables alone do not rescue it: a .tfvars
	// file with no .tf beside it describes inputs to a configuration that is
	// not here.
	if len(resolved.Configs) == 0 {
		return nil, fmt.Errorf("no Terraform or OpenTofu configuration files found at %s: %w", path, plugin.ErrNoMatch)
	}

	return &Connection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
		assetType:  assetType,

		parsed:          loader.GetParser(),
		tfVars:          tfVars,
		modulesManifest: modulesManifest,
		dialect:         resolved.Dialect,
	}, nil
}

func NewHclGitConnection(id uint32, asset *inventory.Asset) (*Connection, error) {
	path, closer, err := plugin.NewGitClone(asset)
	if err != nil {
		return nil, err
	}
	conn, err := newHclConnection(id, path, asset)
	if err != nil {
		return nil, err
	}
	conn.closer = closer
	return conn, nil
}
