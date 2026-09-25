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
	"sort"
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

// dotTerraformDir is the vendored module cache Terraform writes next to a
// configuration. Its contents are copies of upstream modules, not the code
// under review.
const (
	dotTerraformDir = ".terraform"
	// modulesDir is the only directory under .terraform the walk descends into,
	// because it holds the vendored module manifest.
	modulesDir = "modules"
)

// hasPathSegment reports whether rel — a slash-separated path relative to the
// scan root — contains segment as a whole path element.
//
// Matching a whole segment rather than a substring matters: a substring test
// for ".terraform" also swallows a scan root named `.terraform-configs/`, a
// repository directory called `.terraform-modules/`, and a configuration file
// named `main.terraform.tf`. Those are the user's own code, and skipping them
// reported an empty configuration with no error — every policy over it then
// passed vacuously.
func hasPathSegment(rel, segment string) bool {
	for _, part := range strings.Split(rel, "/") {
		if part == segment {
			return true
		}
	}
	return false
}

// dotTerraformSubdir returns rel's path relative to the .terraform directory it
// sits under, and whether it sits under one at all. An empty subdir means rel is
// the .terraform directory itself.
func dotTerraformSubdir(rel string) (string, bool) {
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		if part == dotTerraformDir {
			return strings.Join(parts[i+1:], "/"), true
		}
	}
	return "", false
}

// MODULE_EXAMPLES matches the `examples/` trees shipped inside modules that
// Terraform vendored into `.terraform/modules/`. Those are upstream sample
// configurations, not deployed code.
//
// The pattern is anchored on the `.terraform/` cache deliberately. Without that
// anchor it also matched `modules/<name>/examples/<case>/`, which is the
// canonical layout of a first-party Terraform module repository — so a
// repository's own examples, including any misconfiguration in them, were
// silently dropped from the scan.
var MODULE_EXAMPLES = regexp.MustCompile(`(^|/)\.terraform/modules/.+/examples/.+`)

func NewHclConnection(id uint32, asset *inventory.Asset) (*Connection, error) {
	if len(asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}
	cc := asset.Connections[0]
	path := cc.Options["path"]
	return newHclConnection(id, path, asset)
}

// tfvarsCandidate is a variable-definitions file found during the walk,
// together with the precedence rank it is applied at.
type tfvarsCandidate struct {
	path string
	rank int
}

// Terraform's variable-definition precedence, lowest first. Files later in this
// order override earlier ones.
//
//	rankExplicit  — `prod.tfvars` and friends. Terraform only loads these when
//	                named with `-var-file`, never automatically. We keep loading
//	                them so a scan of a directory that only carries such files
//	                still sees values, but they must not outrank the files
//	                Terraform does auto-load.
//	rankDefault   — `terraform.tfvars`
//	rankDefaultJSON — `terraform.tfvars.json`
//	rankAuto      — `*.auto.tfvars` / `*.auto.tfvars.json`, applied in lexical order
const (
	rankExplicit = iota
	rankDefault
	rankDefaultJSON
	rankAuto
)

func tfvarsRank(name string) int {
	switch {
	case name == "terraform.tfvars", name == "terraform.tofuvars":
		return rankDefault
	case name == "terraform.tfvars.json", name == "terraform.tofuvars.json":
		return rankDefaultJSON
	case strings.HasSuffix(name, ".auto.tfvars"), strings.HasSuffix(name, ".auto.tfvars.json"),
		strings.HasSuffix(name, ".auto.tofuvars"), strings.HasSuffix(name, ".auto.tofuvars.json"):
		return rankAuto
	default:
		return rankExplicit
	}
}

func isTfVarsFile(name string) bool {
	return strings.HasSuffix(name, ".tfvars") || strings.HasSuffix(name, ".tfvars.json")
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
	var manifestRecords []Record
	seenModuleKeys := map[string]struct{}{}

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
		walkErr := filepath.WalkDir(path, func(entryPath string, d fs.DirEntry, err error) error {
			if err != nil {
				// A subdirectory we cannot read must not abort discovery of
				// everything else in the tree.
				log.Warn().Err(err).Str("path", entryPath).Msg("skipping unreadable path during terraform discovery")
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}

			rel, relErr := filepath.Rel(path, entryPath)
			if relErr != nil {
				rel = entryPath
			}
			rel = filepath.ToSlash(rel)

			// Skip the vendored module cache. `modules.json` inside it is read
			// first, below, because it is the manifest describing what was
			// vendored.
			if hasPathSegment(rel, dotTerraformDir) {
				if d.IsDir() {
					// The manifest lives at .terraform/modules/modules.json, so
					// the cache still has to be walked unless the user opted
					// out; only its *.tf files are skipped.
					if !includeDotTerraform {
						return fs.SkipDir
					}
					// That manifest is the only thing under the cache worth
					// reading, so descend just far enough to reach it. Walking
					// the rest means walking .terraform/providers, which holds
					// the vendored provider binaries and is routinely hundreds
					// of megabytes.
					if sub, _ := dotTerraformSubdir(rel); sub != "" && sub != modulesDir {
						return fs.SkipDir
					}
					return nil
				}

				if includeDotTerraform && strings.HasSuffix(rel, ".terraform/modules/modules.json") {
					manifest, mErr := ParseTerraformModuleManifest(entryPath)
					switch {
					case errors.Is(mErr, os.ErrNotExist):
						log.Debug().Str("path", entryPath).Msg("no terraform module manifest found")
					case mErr != nil:
						log.Warn().Err(mErr).Str("path", entryPath).Msg("could not parse terraform module manifest")
					default:
						// A monorepo has one module cache per stack. Merging
						// their records keeps every stack's modules visible;
						// overwriting reported only the last one walked.
						for _, record := range manifest.Records {
							if _, seen := seenModuleKeys[record.Key]; seen {
								continue
							}
							seenModuleKeys[record.Key] = struct{}{}
							manifestRecords = append(manifestRecords, record)
						}
					}
				}

				// Never parse configuration out of the vendored cache.
				return nil
			}

			// Skip example configurations vendored inside cached modules.
			if MODULE_EXAMPLES.MatchString(rel) {
				log.Debug().Str("path", entryPath).Msg("ignoring terraform module example")
				return nil
			}

			if d.IsDir() {
				return nil
			}

			// Collected rather than parsed here: OpenTofu's precedence is decided
			// per directory and file name, so whether this file should be read is
			// not known until the walk has seen what sits next to it.
			candidates = append(candidates, entryPath)
			return nil
		})
		if walkErr != nil {
			return nil, errors.Wrap(walkErr, "could not walk terraform configuration")
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

	// A single unparseable file must not truncate the scan: the walk used to
	// abort at the broken file and discard the error, so every file ordered
	// after it vanished from a scan that reported success. Parse everything and
	// keep the failures.
	var parseErr error
	parsed := 0
	for _, cfg := range resolved.Configs {
		log.Debug().Str("path", cfg).Msg("parsing hcl file")
		if err := loader.ParseHclFile(cfg); err != nil {
			// An unreadable file (a dangling symlink, a permission problem) is
			// not a syntax problem, and saying "could not parse" about one
			// sends the reader looking at the wrong thing.
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				log.Warn().Err(err).Str("path", cfg).Msg("could not read hcl file; skipping")
			} else {
				log.Warn().Err(err).Str("path", cfg).Msg("could not parse hcl file; skipping")
			}
			if parseErr == nil {
				parseErr = err
			}
			continue
		}
		parsed++
	}

	// Nothing parsed, so there is no configuration to report on. Connecting
	// anyway would pass every policy over a project that was never read.
	if parsed == 0 && parseErr != nil {
		return nil, errors.Wrap(parseErr, "could not parse hcl file")
	}

	// resolveConfigFiles sorts the variable files by path. Applying them in that
	// order let `terraform.tfvars` override an `*.auto.tfvars` that Terraform
	// itself ranks higher, silently inverting a variable's effective value.
	varFiles := make([]tfvarsCandidate, 0, len(resolved.Vars))
	for _, varFile := range resolved.Vars {
		varFiles = append(varFiles, tfvarsCandidate{
			path: varFile,
			rank: tfvarsRank(filepath.Base(varFile)),
		})
	}
	sort.SliceStable(varFiles, func(i, j int) bool {
		if varFiles[i].rank != varFiles[j].rank {
			return varFiles[i].rank < varFiles[j].rank
		}
		return varFiles[i].path < varFiles[j].path
	})

	for _, varFile := range varFiles {
		if err := ReadTfVarsFromFile(varFile.path, tfVars); err != nil {
			log.Warn().Err(err).Str("path", varFile.path).Msg("could not parse tfvars file; skipping")
		}
	}

	// Connecting an empty configuration would pass every policy on a project
	// nothing was ever read from. Variables alone do not rescue it: a .tfvars
	// file with no .tf beside it describes inputs to a configuration that is
	// not here.
	if len(resolved.Configs) == 0 {
		return nil, fmt.Errorf("no Terraform or OpenTofu configuration files found at %s: %w", path, plugin.ErrNoMatch)
	}

	var modulesManifest *ModuleManifest
	if len(manifestRecords) > 0 {
		modulesManifest = &ModuleManifest{Records: manifestRecords}
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
		// The clone succeeded but the connection did not; without this the
		// whole checkout stays behind in the temp dir on every failed scan.
		closer()
		return nil, err
	}
	conn.closer = closer
	return conn, nil
}
