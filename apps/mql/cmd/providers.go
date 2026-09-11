// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/muesli/termenv"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/cli/theme"
	"go.mondoo.com/mql/cli/theme/colors"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/sortx"
)

func init() {
	rootCmd.AddCommand(ProvidersCmd)
	ProvidersCmd.AddCommand(listProvidersCmd)
	ProvidersCmd.AddCommand(installProviderCmd)
	ProvidersCmd.AddCommand(updateProviderCmd)
	ProvidersCmd.AddCommand(deleteProviderCmd)
	ProvidersCmd.AddCommand(infoProviderCmd)
	ProvidersCmd.AddCommand(resourcesProviderCmd)

	ProvidersCmd.Flags().Bool("json", false, "Output in JSON format")
	listProvidersCmd.Flags().Bool("json", false, "Output in JSON format")
	infoProviderCmd.Flags().Bool("json", false, "Output in JSON format")
	resourcesProviderCmd.Flags().Bool("json", false, "Output in JSON format")
	installProviderCmd.Flags().StringP("file", "f", "", "Install a provider via a file")
	installProviderCmd.Flags().String("url", "", "Install a provider via a URL")
	installProviderCmd.Flags().Bool("schema-only", false, "Install only the provider's config and resource schema, without its binary")
	deleteProviderCmd.Flags().Bool("yes", false, "Confirm removal of all providers when using the 'all' target")

	for _, cmd := range []*cobra.Command{installProviderCmd, updateProviderCmd} {
		cmd.Flags().String("channel", "", "Release channel to resolve from: stable or preview (default: the configured update_channel, or the channel this build belongs to)")
	}
}

// applyChannelFlag lets a single command resolve from a different release
// channel without editing mondoo.yml.
//
// A stable install is the case this exists for: trying one pre-release provider
// should not mean reconfiguring the machine and remembering to put it back. The
// override lasts for this process only.
//
// It is applied by setting the config key rather than by threading a parameter
// down to the registry, because the registry reads the channel at fetch time --
// so everything that resolves during this command agrees, including the version
// this command prints back.
func applyChannelFlag(cmd *cobra.Command) error {
	channel, _ := cmd.Flags().GetString("channel")
	if channel == "" {
		return nil
	}

	normalized := strings.ToLower(strings.TrimSpace(channel))
	switch normalized {
	case config.ChannelStable, config.ChannelPreview:
	default:
		// An unknown channel elsewhere falls back to the build, because it came
		// from a config file someone may not be looking at. Here it was just
		// typed on the command line, so say so rather than quietly doing
		// something else.
		return errors.Newf("unknown channel %q, expected %s or %s",
			channel, config.ChannelStable, config.ChannelPreview)
	}

	viper.Set(config.KeyUpdateChannel, normalized)
	log.Info().Str("channel", normalized).Msg("resolving providers from an overridden release channel")
	return nil
}

var ProvidersCmd = &cobra.Command{
	Use:    "providers",
	Short:  "Providers add connectivity to all assets",
	Long:   `Manage your providers. List and install new ones or update existing ones`,
	PreRun: func(cmd *cobra.Command, args []string) {},
	Run: func(cmd *cobra.Command, args []string) {
		listCmd(cmd)
	},
}

var listProvidersCmd = &cobra.Command{
	Use:    "list",
	Short:  "List all providers on the system",
	Long:   "",
	PreRun: func(cmd *cobra.Command, args []string) {},
	Run: func(cmd *cobra.Command, args []string) {
		listCmd(cmd)
	},
}

var installProviderCmd = &cobra.Command{
	Use:   "install <NAME[@VERSION]>",
	Short: "Install or update a provider",
	Long: `Install or update a provider.

With --schema-only, only the provider's config and resource schema are
installed, skipping the (much larger) binary download. That is enough to
compile queries against the provider's resources, but not to connect to
assets; for that, install the provider fully.

--channel resolves this one command from a different release channel, without
changing any configuration. It has no effect when a version is pinned
(NAME@VERSION) or when installing from --file or --url, since none of those
consult a channel.

Examples:
  mql providers install aws                     # the configured channel
  mql providers install aws --channel preview   # one-off, from the pre-release track
  mql providers install aws@13.53.4             # exact version, channel ignored`,
	PreRun: func(cmd *cobra.Command, args []string) {},
	Run: func(cmd *cobra.Command, args []string) {
		if err := applyChannelFlag(cmd); err != nil {
			log.Fatal().Err(err).Msg("invalid channel")
		}

		schemaOnly, _ := cmd.Flags().GetBool("schema-only")

		// Explicit installs of files will ignore version recommendations.
		// So we just take them and roll with it.
		path, _ := cmd.Flags().GetString("file")
		if path != "" {
			if schemaOnly {
				log.Fatal().Msg("--schema-only is not supported together with --file")
			}
			installProviderFile(path)
			return
		}

		url, _ := cmd.Flags().GetString("url")
		if url != "" {
			if schemaOnly {
				log.Fatal().Msg("--schema-only is not supported together with --url")
			}
			installProviderUrl(url)
			return
		}

		if len(args) == 0 {
			log.Fatal().Msg("no provider specified, use the NAME[@VERSION] format to pass in a provider name")
		}

		// if no url or file is specified, we default to installing by name from the default upstream
		installProviderByName(args[0], schemaOnly)
	},
}

var updateProviderCmd = &cobra.Command{
	Use:   "update [<NAME>...]",
	Short: "Update installed providers to their latest versions",
	Long: `Update installed providers to their latest versions.

With no arguments, every installed provider is updated. Pass one or more
provider names to update just those. Providers already on the latest version
are skipped, and naming a provider that isn't installed is reported and skipped
rather than treated as an error.

--channel resolves this one command from a different release channel, without
changing any configuration. On a stable install that is how you try a
pre-release provider: the override lasts for this command only, so the next
update goes back to whatever is configured.

Examples:
  mql providers update              # update every installed provider
  mql providers update aws          # update just the aws provider
  mql providers update aws gcp      # update the aws and gcp providers
  mql providers update aws --channel preview   # one-off, from the pre-release track`,
	Args:   cobra.ArbitraryArgs,
	PreRun: func(cmd *cobra.Command, args []string) {},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := applyChannelFlag(cmd); err != nil {
			return err
		}
		return updateProviders(cmd.Root().Name(), args)
	},
}

var deleteProviderCmd = &cobra.Command{
	Use:   "delete <NAME>",
	Short: "Remove an installed provider from disk",
	Long: `Remove an installed provider plugin from disk. The provider is
re-downloaded automatically the next time it's needed.

Use the special target "all" to remove every installed provider at once. Because
that wipes your whole provider footprint, it requires the --yes flag to confirm.

Examples:
  mql providers delete aws          # remove the aws provider
  mql providers delete all --yes    # remove every installed provider`,
	Args:   cobra.ExactArgs(1),
	PreRun: func(cmd *cobra.Command, args []string) {},
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if name == "all" {
			yes, _ := cmd.Flags().GetBool("yes")
			if !yes {
				return fmt.Errorf("removing all providers wipes your entire provider footprint; re-run with --yes to confirm")
			}
			if err := providers.DeleteAll(); err != nil {
				return err
			}
			log.Info().Msg("removed all installed providers")
			return nil
		}

		if err := providers.Delete(name); err != nil {
			return err
		}
		log.Info().Str("provider", name).Msg("removed installed provider")
		return nil
	},
}

var infoProviderCmd = &cobra.Command{
	Use:    "info <provider> [<provider>...]",
	Short:  "Show detailed information about one or more providers",
	Long:   "Show detailed information about one or more providers including connectors and their flags.",
	Args:   cobra.MinimumNArgs(1),
	PreRun: func(cmd *cobra.Command, args []string) {},
	RunE: func(cmd *cobra.Command, args []string) error {
		return infoProviders(cmd, args)
	},
}

var resourcesProviderCmd = &cobra.Command{
	Use:   "resources <provider> [<resource>]",
	Short: "List resources or show resource details for a provider",
	Long: `List all resources available in a provider, or show detailed field information
for a specific resource. The schema includes core and network resources.

Examples:
  cnspec providers resources aws              # list all resources
  cnspec providers resources aws --json       # list all resources as JSON
  cnspec providers resources aws aws.ec2.instance         # show resource details
  cnspec providers resources aws aws.ec2.instance --json  # show resource details as JSON`,
	Args:   cobra.RangeArgs(1, 2),
	PreRun: func(cmd *cobra.Command, args []string) {},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 {
			return listResources(cmd, args[0])
		}
		return showResource(cmd, args[0], args[1])
	},
}

// --- helpers ---

func isJsonOutput(cmd *cobra.Command) bool {
	j, _ := cmd.Flags().GetBool("json")
	return j
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// maturityTag renders a colored "[deprecated]" style suffix for a resource or
// field maturity level. It returns "" for stable or empty maturity so normal
// output is unchanged. This mirrors the provider-level rendering in
// printProvider.
func maturityTag(maturity string) string {
	label := resources.MaturityLabel(maturity)
	if label == "" {
		return ""
	}
	color := colors.DefaultColorTheme.High
	switch maturity {
	case resources.MaturityExperimental, resources.MaturityPreview:
		color = colors.DefaultColorTheme.Medium
	case resources.MaturityEOL:
		color = colors.DefaultColorTheme.Critical
	case resources.MaturityDeprecated:
		// High (not Critical) is intentional: deprecated is the most common
		// non-stable maturity and reads as a warning, matching printProvider.
		color = colors.DefaultColorTheme.High
	}
	return " " + termenv.String("["+strings.ToLower(label)+"]").Foreground(color).String()
}

func flagTypeString(ft plugin.FlagType) string {
	switch ft {
	case plugin.FlagType_Bool:
		return "bool"
	case plugin.FlagType_Int:
		return "int"
	case plugin.FlagType_String:
		return "string"
	case plugin.FlagType_List:
		return "list"
	case plugin.FlagType_KeyValue:
		return "keyvalue"
	default:
		return "string"
	}
}

// loadProviderSchema loads a provider's schema merged with core and network
// resources, matching the pattern used by the MCP server.
func loadProviderSchema(providerName string) (resources.ResourcesSchema, error) {
	existing, err := providers.ListActive()
	if err != nil {
		return nil, fmt.Errorf("failed to list providers: %w", err)
	}

	baseSchema := &resources.Schema{
		Resources:    map[string]*resources.ResourceInfo{},
		Dependencies: map[string]*resources.ProviderInfo{},
	}

	schema, err := loadSingleProviderSchema(existing, providerName)
	if err != nil {
		return nil, err
	}
	baseSchema.Add(schema)

	// Always include core and network resources, as they are available
	// when querying any provider.
	coreSchema, err := loadSingleProviderSchema(existing, "core")
	if err != nil {
		return nil, err
	}
	baseSchema.Add(coreSchema)

	networkSchema, err := loadSingleProviderSchema(existing, "network")
	if err != nil {
		return nil, err
	}
	baseSchema.Add(networkSchema)

	return baseSchema, nil
}

func loadSingleProviderSchema(existing providers.Providers, providerName string) (resources.ResourcesSchema, error) {
	provider := existing.Lookup(providers.ProviderLookup{ProviderName: providerName})
	if provider == nil {
		return nil, fmt.Errorf("provider %q not found", providerName)
	}
	if provider.HasBinary {
		if err := provider.LoadResources(); err != nil {
			return nil, fmt.Errorf("failed to load resources for provider %q: %w", providerName, err)
		}
	}
	return provider.Schema, nil
}

// --- providers list ---

type providerListEntry struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Connectors []string `json:"connectors"`
}

func listCmd(cmd *cobra.Command) {
	all, err := providers.ListAll()
	if err != nil {
		log.Error().Err(err).Msg("failed to list providers")
	}

	if isJsonOutput(cmd) {
		entries := make([]providerListEntry, 0, len(all))
		for _, p := range all {
			conns := make([]string, 0, len(p.Connectors))
			for _, c := range p.Connectors {
				if !c.IsHidden {
					conns = append(conns, c.Name)
				}
			}
			entries = append(entries, providerListEntry{
				Name:       p.Name,
				Version:    p.Version,
				Connectors: conns,
			})
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name < entries[j].Name
		})
		if err := writeJSON(entries); err != nil {
			log.Fatal().Err(err).Msg("failed to write JSON output")
		}
		return
	}

	printProviders(all)
}

// --- providers info ---

type providerInfoEntry struct {
	Name       string          `json:"name"`
	ID         string          `json:"id"`
	Version    string          `json:"version"`
	Path       string          `json:"path,omitempty"`
	Connectors []connectorInfo `json:"connectors"`
}

type connectorInfo struct {
	Name      string     `json:"name"`
	Short     string     `json:"short,omitempty"`
	Aliases   []string   `json:"aliases,omitempty"`
	Discovery []string   `json:"discovery,omitempty"`
	Flags     []flagInfo `json:"flags,omitempty"`
}

type flagInfo struct {
	Long    string `json:"long"`
	Short   string `json:"short,omitempty"`
	Default string `json:"default,omitempty"`
	Desc    string `json:"desc,omitempty"`
	Type    string `json:"type"`
}

func infoProviders(cmd *cobra.Command, names []string) error {
	existing, err := providers.ListActive()
	if err != nil {
		return fmt.Errorf("failed to list providers: %w", err)
	}

	entries := make([]providerInfoEntry, 0, len(names))
	for _, name := range names {
		p := existing.Lookup(providers.ProviderLookup{ProviderName: name})
		if p == nil {
			return fmt.Errorf("provider %q not found", name)
		}

		conns := make([]connectorInfo, 0, len(p.Connectors))
		for _, c := range p.Connectors {
			if c.IsHidden {
				continue
			}
			flags := make([]flagInfo, 0, len(c.Flags))
			for _, f := range c.Flags {
				if f.Option&plugin.FlagOption_Hidden != 0 {
					continue
				}
				flags = append(flags, flagInfo{
					Long:    f.Long,
					Short:   f.Short,
					Default: f.Default,
					Desc:    f.Desc,
					Type:    flagTypeString(f.Type),
				})
			}
			ci := connectorInfo{
				Name:  c.Name,
				Short: c.Short,
				Flags: flags,
			}
			if len(c.Aliases) > 0 {
				ci.Aliases = c.Aliases
			}
			if len(c.Discovery) > 0 {
				ci.Discovery = c.Discovery
			}
			conns = append(conns, ci)
		}

		entries = append(entries, providerInfoEntry{
			Name:       p.Name,
			ID:         p.ID,
			Version:    p.Version,
			Path:       p.Path,
			Connectors: conns,
		})
	}

	if isJsonOutput(cmd) {
		return writeJSON(entries)
	}

	for i, e := range entries {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("%s %s\n", theme.DefaultTheme.Primary(e.Name), e.Version)
		fmt.Printf("  ID:   %s\n", e.ID)
		if e.Path != "" {
			fmt.Printf("  Path: %s\n", e.Path)
		}
		if len(e.Connectors) > 0 {
			fmt.Println("  Connectors:")
			for _, c := range e.Connectors {
				desc := ""
				if c.Short != "" {
					desc = " - " + c.Short
				}
				fmt.Printf("    %s%s\n", theme.DefaultTheme.Secondary(c.Name), desc)
				for _, f := range c.Flags {
					flagStr := "      --" + f.Long
					if f.Short != "" {
						flagStr += ", -" + f.Short
					}
					flagStr += " (" + f.Type + ")"
					if f.Desc != "" {
						flagStr += "  " + f.Desc
					}
					fmt.Println(flagStr)
				}
			}
		}
	}
	return nil
}

// --- providers resources (list mode) ---

type resourceList struct {
	Provider       string            `json:"provider"`
	TotalResources int               `json:"total_resources"`
	Resources      []resourceSummary `json:"resources"`
}

type resourceSummary struct {
	Name       string   `json:"name"`
	Title      string   `json:"title,omitempty"`
	Desc       string   `json:"desc,omitempty"`
	Private    bool     `json:"private"`
	Maturity   string   `json:"maturity,omitempty"`
	Defaults   []string `json:"defaults,omitempty"`
	FieldCount int      `json:"field_count"`
}

func listResources(cmd *cobra.Command, providerName string) error {
	schema, err := loadProviderSchema(providerName)
	if err != nil {
		return err
	}

	allResources := schema.AllResources()
	summaries := make([]resourceSummary, 0, len(allResources))
	for name, ri := range allResources {
		if ri.Private {
			continue
		}
		// The map key is the canonical resource name (e.g. "aws.ec2.instance").
		// ri.Name may be empty for some resources.
		resourceName := name
		if resourceName == "" {
			resourceName = ri.Name
		}
		var defaults []string
		if ri.Defaults != "" {
			defaults = strings.Split(ri.Defaults, " ")
		}
		summaries = append(summaries, resourceSummary{
			Name:       resourceName,
			Title:      ri.Title,
			Desc:       ri.Desc,
			Private:    ri.Private,
			Maturity:   ri.Maturity,
			Defaults:   defaults,
			FieldCount: len(ri.Fields),
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Name < summaries[j].Name
	})

	if isJsonOutput(cmd) {
		return writeJSON(resourceList{
			Provider:       providerName,
			TotalResources: len(summaries),
			Resources:      summaries,
		})
	}

	fmt.Printf("%s (%d resources)\n\n", theme.DefaultTheme.Primary(providerName), len(summaries))
	for _, r := range summaries {
		title := ""
		if r.Title != "" {
			title = " - " + r.Title
		}
		fmt.Printf("  %s%s%s\n", theme.DefaultTheme.Secondary(r.Name), maturityTag(r.Maturity), title)
	}
	fmt.Println()
	return nil
}

// --- providers resources (detail mode) ---

type resourceDetail struct {
	Name       string        `json:"name"`
	Title      string        `json:"title,omitempty"`
	Desc       string        `json:"desc,omitempty"`
	Private    bool          `json:"private"`
	Maturity   string        `json:"maturity,omitempty"`
	Defaults   []string      `json:"defaults,omitempty"`
	FieldCount int           `json:"field_count"`
	Fields     []fieldDetail `json:"fields"`
}

type fieldDetail struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Title       string `json:"title,omitempty"`
	Desc        string `json:"desc,omitempty"`
	Maturity    string `json:"maturity,omitempty"`
	IsMandatory bool   `json:"is_mandatory,omitempty"`
}

func showResource(cmd *cobra.Command, providerName string, resourceName string) error {
	schema, err := loadProviderSchema(providerName)
	if err != nil {
		return err
	}

	ri := schema.Lookup(resourceName)
	if ri == nil {
		return fmt.Errorf("resource %q not found in provider %q", resourceName, providerName)
	}

	fields := make([]fieldDetail, 0, len(ri.Fields))
	for _, f := range ri.Fields {
		if f.IsPrivate {
			continue
		}
		fields = append(fields, fieldDetail{
			Name:        f.Name,
			Type:        types.Type(f.Type).Label(),
			Title:       f.Title,
			Desc:        f.Desc,
			Maturity:    f.Maturity,
			IsMandatory: f.IsMandatory,
		})
	}
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Name < fields[j].Name
	})

	var defaults []string
	if ri.Defaults != "" {
		defaults = strings.Split(ri.Defaults, " ")
	}

	detail := resourceDetail{
		Name:       ri.Name,
		Title:      ri.Title,
		Desc:       ri.Desc,
		Private:    ri.Private,
		Maturity:   ri.Maturity,
		Defaults:   defaults,
		FieldCount: len(fields),
		Fields:     fields,
	}

	if isJsonOutput(cmd) {
		return writeJSON(detail)
	}

	fmt.Printf("%s%s\n", theme.DefaultTheme.Primary(ri.Name), maturityTag(ri.Maturity))
	if ri.Title != "" {
		fmt.Printf("  %s\n", ri.Title)
	}
	if ri.Desc != "" {
		fmt.Printf("  %s\n", ri.Desc)
	}
	fmt.Println()
	fmt.Printf("  Fields (%d):\n", len(fields))
	for _, f := range fields {
		mandatory := ""
		if f.IsMandatory {
			mandatory = " (required)"
		}
		title := ""
		if f.Title != "" {
			title = " - " + f.Title
		}
		fmt.Printf("    %-30s %s%s%s%s\n",
			theme.DefaultTheme.Secondary(f.Name),
			f.Type, mandatory, maturityTag(f.Maturity), title)
	}
	fmt.Println()
	return nil
}

// --- providers update ---

// selectProvidersToUpdate resolves which installed providers an update run
// should act on. With no names it returns every installed provider (sorted);
// with names it returns the matching installed providers and reports any names
// that aren't installed so the caller can note them without treating them as an
// error. Builtin providers (Path == "") are compiled into the binary and can't
// be updated independently, so they are never selected.
func selectProvidersToUpdate(all []*providers.Provider, names []string) (toUpdate []*providers.Provider, notInstalled []string) {
	installed := map[string]*providers.Provider{}
	ordered := make([]*providers.Provider, 0, len(all))
	for _, p := range all {
		if p.Path == "" {
			continue // builtin, not independently updatable
		}
		installed[p.Name] = p
		ordered = append(ordered, p)
	}

	if len(names) == 0 {
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
		return ordered, nil
	}

	for _, name := range names {
		if p, ok := installed[name]; ok {
			toUpdate = append(toUpdate, p)
		} else {
			notInstalled = append(notInstalled, name)
		}
	}
	return toUpdate, notInstalled
}

// updateProviders updates the named installed providers (or all of them when no
// names are given) to their latest versions. Providers already on the latest
// version are skipped so they aren't re-downloaded, and naming a provider that
// isn't installed is reported and skipped rather than treated as an error.
func updateProviders(binary string, names []string) error {
	if binary == "" {
		binary = "mql"
	}

	all, err := providers.ListAll()
	if err != nil {
		return fmt.Errorf("failed to list providers: %w", err)
	}

	toUpdate, notInstalled := selectProvidersToUpdate(all, names)
	for _, name := range notInstalled {
		// Not an error: there's nothing to update for a provider that isn't
		// installed. Point the user at install if they meant to add it.
		log.Info().Str("provider", name).
			Msg("not installed, skipping (run '" + binary + " providers install " + name + "' to add it)")
	}

	ctx := context.Background()
	var updated []*providers.Provider
	var current, failed int
	for _, p := range toUpdate {
		latest, err := providers.LatestVersion(ctx, p.Name)
		if err != nil {
			log.Warn().Err(err).Str("provider", p.Name).Msg("failed to check for updates")
			failed++
			continue
		}
		if latest == p.Version {
			current++
			continue
		}

		installed, err := providers.Install(p.Name, latest)
		if err != nil {
			log.Warn().Err(err).Str("provider", p.Name).Msg("failed to update provider")
			failed++
			continue
		}
		updated = append(updated, installed)
	}

	if len(updated) > 0 {
		providers.PrintInstallResults(updated)
	}
	log.Info().Msgf("%d updated · %d already current · %d failed", len(updated), current, failed)

	if failed > 0 {
		return fmt.Errorf("%d provider(s) failed to update", failed)
	}
	return nil
}

// --- existing functions ---

func installProviderByName(name string, schemaOnly bool) {
	parts := strings.Split(name, "@")
	if len(parts) > 2 {
		log.Fatal().Msg("invalid provider name")
	}
	name = parts[0]
	version := ""
	if len(parts) == 2 {
		// trim the v prefix, allowing users to specify both 9.0.0 and v9.0.0
		version = strings.TrimPrefix(parts[1], "v")
	}
	install := providers.Install
	if schemaOnly {
		install = providers.InstallSchemaOnly
	}
	installed, err := install(name, version)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to install")
	}
	providers.PrintInstallResults([]*providers.Provider{installed})
}

func installProviderUrl(u string) {
	if i := strings.Index(u, "://"); i == -1 {
		u = "http://" + u
	}
	uUrl, err := url.Parse(u)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid url")
	}

	res, err := http.Get(uUrl.String())
	if err != nil {
		log.Fatal().Err(err).Msg("failed to install")
	}

	installed, err := providers.InstallIO(res.Body, providers.InstallConf{
		Dst: providers.HomePath,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to install")
	}
	providers.PrintInstallResults(installed)
}

func installProviderFile(path string) {
	installed, err := providers.InstallFile(path, providers.InstallConf{
		Dst: providers.HomePath,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to install")
	}
	providers.PrintInstallResults(installed)
}

func printProviders(p []*providers.Provider) {
	if len(p) == 0 {
		log.Info().Msg("No providers found.")
		fmt.Println("No providers found.")
		if providers.SystemPath == "" && providers.HomePath == "" {
			fmt.Println("No paths for providers detected.")
		} else {
			fmt.Println("Was checking: " + providers.SystemPath)
		}
	}

	paths := map[string][]*providers.Provider{}
	for i := range p {
		provider := p[i]
		if provider.Path == "" {
			paths["builtin"] = append(paths["builtin"], provider)
			continue
		}
		dir := filepath.Dir(provider.Path)
		paths[dir] = append(paths[dir], provider)
	}

	printProviderPath("builtin", paths["builtin"], false)
	if providers.CustomProviderPath == "" {
		printProviderPath(providers.HomePath, paths[providers.HomePath], true)
		printProviderPath(providers.SystemPath, paths[providers.SystemPath], true)
	} else {
		printProviderPath(providers.CustomProviderPath, paths[providers.CustomProviderPath], true)
	}
	delete(paths, "builtin")
	delete(paths, providers.HomePath)
	delete(paths, providers.SystemPath)
	delete(paths, providers.CustomProviderPath)

	keys := sortx.Keys(paths)
	for _, path := range keys {
		printProviderPath(path, paths[path], true)
	}

	fmt.Println()
}

func printProviderPath(path string, list []*providers.Provider, printEmpty bool) {
	if list == nil {
		if printEmpty && path != "" {
			fmt.Println("")
			log.Info().Msg(path + " has no providers")
		}
		return
	}

	fmt.Println()
	log.Info().Msg(path + " (found " + strconv.Itoa(len(list)) + " providers)")
	fmt.Println()

	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	for i := range list {
		printProvider(list[i])
	}
}

func printProvider(p *providers.Provider) {
	conns := make([]string, len(p.Connectors))
	for i := range p.Connectors {
		conns[i] = theme.DefaultTheme.Secondary(p.Connectors[i].Name)
	}

	name := theme.DefaultTheme.Primary(p.Name)
	supports := ""
	if len(conns) != 0 {
		supports = " with connectors: " + strings.Join(conns, ", ")
	}
	maturity := ""
	if label := resources.MaturityLabel(p.Maturity); label != "" {
		color := colors.DefaultColorTheme.High
		switch p.Maturity {
		case resources.MaturityExperimental, resources.MaturityPreview:
			color = colors.DefaultColorTheme.Medium
		case resources.MaturityEOL:
			color = colors.DefaultColorTheme.Critical
		}
		maturity = " " + termenv.String("["+strings.ToLower(label)+"]").Foreground(color).String()
	}
	schemaOnly := ""
	if p.Path != "" && !p.HasBinary {
		schemaOnly = " " + theme.DefaultTheme.Disabled("(schema-only)")
	}

	fmt.Println("  " + name + " " + p.Version + supports + maturity + schemaOnly)
}
