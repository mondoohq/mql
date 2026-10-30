// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"encoding/json"
	"go/format"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.mondoo.com/mql/providers-sdk/v1/mqlr/lrcore"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
)

var goCmd = &cobra.Command{
	Use:   "go",
	Short: "convert LR file to go",
	Long:  `parse an LR file and convert it to go, saving it in the same location with the suffix .go`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dist, err := cmd.Flags().GetString("dist")
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get dist flag")
		}

		failOnDups, _ := cmd.Flags().GetBool("fail-on-duplicates")
		failOnBreaking, _ := cmd.Flags().GetBool("fail-on-breaking")
		headerFile, _ := cmd.Flags().GetString("license-header-file")
		providersRoot, _ := cmd.Flags().GetString("providers-root")
		failOnDepDrift, _ := cmd.Flags().GetBool("fail-on-dep-drift")
		runGoCmd(args[0], dist, headerFile, providersRoot, failOnDups, failOnBreaking, failOnDepDrift)
	},
}

func init() {
	rootCmd.AddCommand(goCmd)
	goCmd.Flags().Bool("fail-on-duplicates", false, "fail if duplicate LR field paths are detected")
	goCmd.Flags().Bool("fail-on-breaking", false, "fail if the schema change is breaking and has no migration (ADR 040 part 5)")
	goCmd.Flags().String("dist", "", "folder for output json generation")
	goCmd.Flags().String("license-header-file", "", "optional file path to read license header from")
	goCmd.Flags().Bool("fail-on-dep-drift", false, "fail if a peer dependency is undeclared or declared below what its references need (ADR 042)")
	goCmd.Flags().String("providers-root", "", "directory holding the providers that name-based imports resolve against (default: derived from the .lr path)")
}

func runGoCmd(lrFile string, dist string, headerFile string, providersRoot string, failOnDups bool, failOnBreaking bool, failOnDepDrift bool) {
	packageName := path.Base(path.Dir(lrFile))
	res, err := lrcore.ResolveWithRoot(lrFile, providersRoot, func(path string) ([]byte, error) {
		return os.ReadFile(path)
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to resolve")
		return
	}

	dups := res.GetDuplicates()
	if failOnDups && len(dups) > 0 {
		log.Fatal().Int("count", len(dups)).Strs("paths", dups).Msg("duplicate field paths detected, exiting")
	} else if len(dups) > 0 {
		log.Warn().Int("count", len(dups)).Strs("paths", dups).Msg("duplicate field paths detected")
	}

	// add license header
	var headerTpl *template.Template
	if headerFile != "" {
		headerRaw, err := os.ReadFile(headerFile)
		if err != nil {
			log.Fatal().Err(err).Msg("could not read license header file")
		}
		headerTpl, err = template.New("license_header").Parse(string(headerRaw))
		if err != nil {
			log.Fatal().Err(err).Msg("could not parse license header template")
		}
	}

	collector := lrcore.NewCollector(lrFile)
	goCode, err := lrcore.Go(packageName, res, collector, headerTpl)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to compile go code")
	}

	fmtGoData, err := format.Source([]byte(goCode))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to format go code")
	}
	err = os.WriteFile(lrFile+".go", fmtGoData, 0o644)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to write to go file")
	}

	schema, err := lrcore.Schema(res)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to generate schema")
	}

	// Auto-detect .lr.versions file and inject version metadata into the schema
	versionsPath := strings.TrimSuffix(lrFile, ".lr") + ".lr.versions"
	versions, err := lrcore.ReadVersions(versionsPath)
	if err == nil {
		lrcore.InjectVersions(schema, versions)
	} else if os.IsNotExist(err) {
		log.Info().Str("path", versionsPath).Msg("no versions file found, ignoring")
	} else {
		log.Fatal().Err(err).Str("path", versionsPath).Msg("failed to read versions file")
	}

	schemaData, err := json.Marshal(schema)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to generate schema json")
	}

	base := path.Base(lrFile)
	base = strings.TrimSuffix(base, ".lr")

	dst := strings.TrimSuffix(lrFile, ".lr") + ".resources.json"

	// ADR 040 part 5: codegen is the one place that holds both the committed
	// schema and the new one, so it is where a breaking change gets caught in
	// the author's PR rather than at runtime on an older client. A warning for
	// now; the hard-fail lands with the migration lenses that would satisfy it.
	if drift := reportPeerDeps(lrFile, providersRoot, res); len(drift) > 0 && failOnDepDrift {
		log.Fatal().Int("count", len(drift)).
			Msg("peer dependency declarations are out of date, exiting")
	}

	if breaking := reportSchemaDiff(dst, schema); len(breaking) > 0 && failOnBreaking {
		log.Fatal().Int("count", len(breaking)).
			Msg("breaking schema changes detected, exiting")
	}

	err = os.WriteFile(dst, []byte(schemaData), 0o644)
	if err != nil {
		log.Fatal().Err(err).Str("dst", dst).Msg("failed to write schema json")
	}

	if dist != "" {
		if err = os.MkdirAll(dist, 0o755); err != nil {
			log.Fatal().Err(err).Msg("failed to create dist folder")
		}
		infoFile := path.Join(dist, base+".resources.json")
		err = os.WriteFile(infoFile, []byte(schemaData), 0o644)
		if err != nil {
			log.Fatal().Err(err).Str("dst", infoFile).Msg("failed to write schema json")
		}
	}
}

// reportSchemaDiff compares the schema about to be written against the one
// already committed and logs what changed. It returns the breaking changes.
//
// A missing or unreadable previous schema is not a finding: that is a new
// provider, or a first generation, and there is nothing to compare against.
func reportSchemaDiff(previousPath string, nu *resources.Schema) []lrcore.Change {
	raw, err := os.ReadFile(previousPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Debug().Err(err).Str("path", previousPath).
				Msg("cannot read the previous schema, skipping the change report")
		}
		return nil
	}

	var previous resources.Schema
	if err := json.Unmarshal(raw, &previous); err != nil {
		log.Warn().Err(err).Str("path", previousPath).
			Msg("cannot parse the previous schema, skipping the change report")
		return nil
	}

	changes := lrcore.DiffSchemas(&previous, nu)
	if len(changes) == 0 {
		return nil
	}

	breaking := lrcore.Breaking(changes)
	log.Info().
		Int("additive", len(changes)-len(breaking)).
		Int("breaking", len(breaking)).
		Msg("schema changed")

	for _, c := range breaking {
		log.Warn().Str("path", c.Path).Msg("breaking schema change: " + c.Detail)
	}
	return breaking
}

// reportPeerDeps computes each declared peer's version floor from its
// .lr.versions and reconciles it with what config.go declares (ADR 042 step 2).
//
// Reported as a warning, like the ADR 040 schema diff: no provider carries a
// Requires block yet, so failing the build would fail every provider at once.
// `--fail-on-dep-drift` turns it into a gate once the declarations exist.
//
// Detection reads two sources. Type references in the .lr are only half of it:
// the largest call group, os -> cpe, appears exclusively as Go string literals,
// so scanning the schema alone computes a floor that misses most references.
func reportPeerDeps(lrFile string, providersRoot string, ast *lrcore.LR) []lrcore.Reconciliation {
	peers := ast.PeerNames()
	if len(peers) == 0 {
		return nil
	}

	if providersRoot == "" {
		providersRoot = path.Dir(path.Dir(path.Dir(lrFile)))
	}

	refs := lrcore.SchemaRefs(ast)
	var unresolved []lrcore.GoCall
	var drift []lrcore.Reconciliation

	resourcesDir := path.Dir(lrFile)
	goFiles, _ := filepath.Glob(filepath.Join(resourcesDir, "*.go"))
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") || strings.HasSuffix(f, ".lr.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		fileRefs, unresolvedInFile := lrcore.GoRefs(ast, filepath.Base(f), src)
		refs = append(refs, fileRefs...)
		unresolved = append(unresolved, unresolvedInFile...)
	}

	// "A call with no import": the provider reaches for a resource that is
	// neither its own nor any declared peer's. Attributing it needs the whole
	// tree, so that scan only runs when there is something to attribute --
	// which today there never is.
	for _, call := range unresolved {
		owner := findResourceOwner(providersRoot, call.Resource)
		if owner == "" {
			log.Warn().Str("resource", call.Resource).Str("origin", call.Origin).
				Msg("shared-resource call names a resource no provider in this tree defines")
			continue
		}
		log.Warn().Str("peer", owner).Str("resource", call.Resource).Str("origin", call.Origin).
			Msg("cross-provider call with no import: add `import " + owner + "` (ADR 042)")
		drift = append(drift, lrcore.Reconciliation{Peer: owner, Action: lrcore.DepCreate})
	}

	versions := map[string]lrcore.LrVersions{}
	for _, peer := range peers {
		v, err := lrcore.ReadVersions(path.Join(providersRoot, peer, "resources", peer+".lr.versions"))
		if err != nil {
			log.Debug().Err(err).Str("peer", peer).
				Msg("cannot read the peer's versions, skipping the dependency report")
			return nil
		}
		versions[peer] = v
	}

	parser := semver.Parser{}
	detected, err := lrcore.MinVersions(refs, versions, parser.Compare)
	if err != nil {
		log.Warn().Err(err).Msg("cannot determine peer version requirements")
		return nil
	}

	detected, err = lrcore.RaiseToBaseline(detected, lrcore.SupportedBaseline, parser.Compare)
	if err != nil {
		log.Warn().Err(err).Msg("cannot apply the supported-version baseline")
		return nil
	}

	configPath := path.Join(providersRoot, path.Base(path.Dir(path.Dir(lrFile))), "config", "config.go")
	var declared []lrcore.DeclaredDep
	if raw, err := os.ReadFile(configPath); err == nil {
		declared, err = lrcore.ParseDeclaredRequires(configPath, raw)
		if err != nil {
			log.Warn().Err(err).Str("path", configPath).Msg("cannot read declared Requires")
		}
	}

	res, err := lrcore.Reconcile(detected, declared, peers, parser.Compare)
	if err != nil {
		log.Warn().Err(err).Msg("cannot reconcile peer dependencies")
		return nil
	}

	for _, r := range res {
		switch r.Action {
		case lrcore.DepAccept:
			log.Debug().Msg("peer dependency ok: " + r.String())
		default:
			log.Warn().Str("peer", r.Peer).Str("action", string(r.Action)).
				Msg("peer dependency: " + r.String())
			drift = append(drift, r)
		}
	}
	return drift
}

// findResourceOwner reports which provider in the tree defines a resource, so a
// call with no import can name the import it needs. Returns "" when nothing
// defines it -- a typo, a dynamic name, or a provider outside this tree.
//
// This parses every provider's .lr, so it is called only for a call that could
// not be attributed to a declared peer.
func findResourceOwner(providersRoot string, resource string) string {
	entries, err := os.ReadDir(providersRoot)
	if err != nil {
		return ""
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		raw, err := os.ReadFile(path.Join(providersRoot, name, "resources", name+".lr"))
		if err != nil {
			continue
		}
		ast, err := lrcore.Parse(string(raw))
		if err != nil {
			continue
		}
		for _, r := range ast.Resources {
			if r != nil && r.ID == resource {
				return name
			}
		}
	}
	return ""
}
