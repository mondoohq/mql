// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.mondoo.com/mql/utils/stringx"

	mastermind "github.com/Masterminds/semver"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.mondoo.com/mql/cli/components"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

var rootCmd = &cobra.Command{
	Short: "mql versioning tool",
	Long: `
mql versioning tool allows us to update the version of one or more providers.

The tool will automatically detect the current version of the provider and
suggest a new version. It will also create a commit with the new version and
push it to a new branch.

  $ version update providers/*/ --increment=patch --commit

The tool will also check if the provider go dependencies have changed since the
last version and will suggest to update them as well. To just clean up the go.mod
and go.sum files, run:

  $ version mod-tidy providers/*/

To update all provider go dependencies to the latest patch version, run:

  $ version mod-update providers/*/ --patch

To update all provider go dependencies to the latest version, run:

  $ version mod-update providers/*/ --latest
`,
}

var updateCmd = &cobra.Command{
	Use:   "update [PROVIDERS]",
	Short: "try to update the version of the provider",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		updateVersions(args)
	},
}

var checkCmd = &cobra.Command{
	Use:   "check [PROVIDERS]",
	Short: "checks if providers need updates",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		analyzeProviders(args)
	},
}

var modTidyCmd = &cobra.Command{
	Use:   "mod-tidy [PROVIDERS]",
	Short: "run 'go mod tidy' for all provided providers",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		for i := range args {
			goModTidy(args[i])
		}
	},
}

var modUpdateCmd = &cobra.Command{
	Use:   "mod-update [PROVIDERS]",
	Short: "update all go dependencies for all provided providers",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		updateStrategy := UpdateStrategyNone

		if latestPatchVersion {
			updateStrategy = UpdateStrategyPatch
		} else if latestVersion {
			updateStrategy = UpdateStrategyLatest
		}

		ignorePkgs, _ := cmd.Flags().GetStringSlice("ignore-packages")

		for i := range args {
			checkGoModUpdate(args[i], updateStrategy, ignorePkgs)
		}
	},
}

type UpdateStrategy int

const (
	// UpdateStrategyNone indicates that version should not be updated
	UpdateStrategyNone UpdateStrategy = iota
	// UpdateStrategyLatest indicates that version should be updated to the latest
	UpdateStrategyLatest
	// UpdateStrategyPatch indicates that version should be updated to the latest patch
	UpdateStrategyPatch
)

func checkGoModUpdate(providerPath string, updateStrategy UpdateStrategy, ignorePkgs []string) {
	log.Info().Msgf("Updating dependencies for %s...", providerPath)

	// Define the path to your project's go.mod file
	goModPath := filepath.Join(providerPath, "go.mod")

	// Read the content of the go.mod file
	modContent, err := os.ReadFile(goModPath)
	if err != nil {
		log.Info().Msgf("Error reading go.mod file: %v", err)
		return
	}

	// Parse the go.mod file
	modFile, err := modfile.Parse("go.mod", modContent, nil)
	if err != nil {
		log.Info().Msgf("Error parsing go.mod file: %v", err)
		return
	}

	// Save all dependency versions before updating so we can detect downgrades later.
	beforeVersions := make(map[string]string, len(modFile.Require))
	for _, req := range modFile.Require {
		beforeVersions[req.Mod.Path] = req.Mod.Version
	}

	// Iterate through the require statements and update dependencies
	for _, require := range modFile.Require {
		// Skip indirect dependencies
		if require.Indirect {
			continue
		}

		var modPath string
		switch updateStrategy {
		case UpdateStrategyLatest:
			modPath = require.Mod.Path + "@latest"
		case UpdateStrategyPatch:
			modPath = require.Mod.Path + "@patch" // see https://github.com/golang/go/issues/26812
		default:
			modPath = require.Mod.Path + "@" + require.Mod.Version
		}

		if require.Syntax.Before != nil {
			for i := range require.Syntax.Before {
				comment := require.Syntax.Before[i].Token
				if after, ok := strings.CutPrefix(comment, "// pin"); ok {
					version := strings.TrimSpace(after)
					log.Info().Msgf("Found pin comment for %s: %s", require.Mod.Path, version)
					modPath = require.Mod.Path + "@" + version
				}
			}
		}

		cmd := exec.Command("go", "get", "-u", modPath)

		// Redirect standard output and standard error to the console
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		// Set the working directory for the command
		cmd.Dir = providerPath

		if stringx.Contains(ignorePkgs, require.Mod.Path) {
			log.Info().Msgf("Ignoring %s", require.Mod.Path)
			continue
		}

		log.Info().Msgf("Updating %s to the latest version...", require.Mod.Path)

		// Run the `go get` command to update the dependency
		err := cmd.Run()
		if err != nil {
			log.Info().Msgf("Error updating %s: %v", require.Mod.Path, err)
		}
	}

	// Re-read the content of the go.mod file after updating
	modContent, err = os.ReadFile(goModPath)
	if err != nil {
		fmt.Printf("Error reading go.mod file: %v\n", err)
		return
	}

	// Parse the go.mod file again with the updated content
	modFile, err = modfile.Parse("go.mod", modContent, nil)
	if err != nil {
		fmt.Printf("Error parsing go.mod file: %v\n", err)
		return
	}

	// Write the updated go.mod file
	updatedModContent, err := modFile.Format()
	if err != nil {
		log.Info().Msgf("Error formatting go.mod file: %v", err)
		return
	}

	err = os.WriteFile(goModPath, updatedModContent, 0o644)
	if err != nil {
		log.Info().Msgf("Error writing updated go.mod file: %v", err)
		return
	}

	log.Info().Msgf("All dependencies updated.")

	// Run 'go mod tidy' to clean up the go.mod and go.sum files
	goModTidy(providerPath)

	// Detect and revert any dependency downgrades caused by ordering issues
	// during sequential go get -u calls or go mod tidy. Loop because reverting
	// one downgrade via go get can cause a different transitive dep to be
	// downgraded.
	const maxDowngradeFixPasses = 5
	for pass := range maxDowngradeFixPasses {
		reverted := revertDowngrades(providerPath, goModPath, beforeVersions)
		if reverted == 0 {
			break
		}
		log.Info().Int("pass", pass+1).Int("reverted", reverted).Msg("reverted dependency downgrades, running go mod tidy")
		goModTidy(providerPath)
	}

	log.Info().Msgf("All dependencies updated and cleaned up successfully.")
}

// revertDowngrades compares the current go.mod dependency versions against
// the versions recorded before the update. Any dependency whose version
// decreased is restored to its original version via "go get". It returns
// the number of dependencies that were reverted.
func revertDowngrades(providerPath, goModPath string, beforeVersions map[string]string) int {
	modContent, err := os.ReadFile(goModPath)
	if err != nil {
		log.Error().Err(err).Msg("failed to read go.mod for downgrade check")
		return 0
	}

	modFile, err := modfile.Parse("go.mod", modContent, nil)
	if err != nil {
		log.Error().Err(err).Msg("failed to parse go.mod for downgrade check")
		return 0
	}

	var reverted int
	for _, req := range modFile.Require {
		before, ok := beforeVersions[req.Mod.Path]
		if !ok {
			continue // new dependency, not a downgrade
		}
		if semver.Compare(before, req.Mod.Version) > 0 {
			log.Warn().Str("package", req.Mod.Path).Str("before", before).Str("after", req.Mod.Version).
				Msg("detected downgrade, reverting")

			cmd := exec.Command("go", "get", req.Mod.Path+"@"+before)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Dir = providerPath
			if err := cmd.Run(); err != nil {
				log.Error().Err(err).Str("package", req.Mod.Path).Msg("failed to revert downgrade")
				continue
			}
			reverted++
		}
	}

	return reverted
}

func goModTidy(providerPath string) {
	log.Info().Msgf("Running 'go mod tidy' for %s...", providerPath)

	// Run 'go mod tidy' to clean up the go.mod and go.sum files
	tidyCmd := exec.Command("go", "mod", "tidy")

	// Redirect standard output and standard error
	tidyCmd.Stdout = os.Stdout
	tidyCmd.Stderr = os.Stderr

	// Set the working directory for the command
	tidyCmd.Dir = providerPath

	err := tidyCmd.Run()
	if err != nil {
		log.Error().Msgf("Error running 'go mod tidy': %v", err)
		return
	}
}

var defaultsCmd = &cobra.Command{
	Use:   "defaults [PROVIDERS]",
	Short: "generates the content for the defaults list of providers",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		defaults := parseDefaults(args)
		fmt.Println(defaults)
	},
}

// maxParallel is the number of concurrent provider analyses.
const maxParallel = 4

// providerAnalysis holds the result of analyzing a single provider.
type providerAnalysis struct {
	conf    *providerConf
	path    string
	changes int
	err     error
}

// analyzeProviders runs countChangesSince for each provider path in parallel (up to maxParallel).
// Each goroutine opens its own git.Repository to avoid concurrent map access in go-git's storage.
func analyzeProviders(providerPaths []string) []providerAnalysis {
	results := make([]providerAnalysis, len(providerPaths))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup

	for i, p := range providerPaths {
		results[i].path = p
		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			repo, err := git.PlainOpen(".")
			if err != nil {
				results[idx].err = fmt.Errorf("failed to open git repo: %w", err)
				log.Error().Err(results[idx].err).Str("path", path).Msg("failed to process version")
				return
			}

			conf, err := getConfig(path)
			if err != nil {
				results[idx].err = err
				log.Error().Err(err).Str("path", path).Msg("failed to process version")
				return
			}
			results[idx].conf = conf
			results[idx].changes = countChangesSince(repo, conf, path)
			logChanges(results[idx].changes, conf)
		}(i, p)
	}

	wg.Wait()
	return results
}

func logChanges(changes int, conf *providerConf) {
	if changes == 0 {
		log.Info().Str("version", conf.version).Str("provider", conf.name).Msg("no changes")
	} else if fastMode {
		log.Info().Str("version", conf.version).Str("provider", conf.name).Msg("provider changed")
	} else {
		log.Info().Int("changes", changes).Str("version", conf.version).Str("provider", conf.name).Msg("provider changed")
	}
}

var (
	// \b keeps this from matching the dependencies' `MinVersion:` fields.
	reVersion = regexp.MustCompile(`\bVersion:\s*"([^"]+)"`)
	reName    = regexp.MustCompile(`Name:\s*"([^"]+)",`)
)

const (
	titlePrefix = "🎉 "
)

type providerConf struct {
	path      string
	content   string
	version   string
	name      string
	changelog []string // commit summaries since last version bump
}

func (conf *providerConf) title() string {
	return conf.name + "-" + conf.version
}

func (conf *providerConf) commitTitle() string {
	return titlePrefix + conf.title()
}

type updateConfs []*providerConf

func (confs updateConfs) titles() []string {
	titles := make([]string, len(confs))
	for i := range confs {
		titles[i] = confs[i].title()
	}
	return titles
}

// maxTitleLen is GitHub's maximum length (in characters) for a PR/issue title.
const maxTitleLen = 256

func (confs updateConfs) commitTitle() string {
	title := titlePrefix + strings.Join(confs.titles(), ", ")
	if utf8.RuneCountInString(title) <= maxTitleLen {
		return title
	}
	// Too many providers to enumerate within GitHub's title limit; fall back to
	// a count summary. The full per-provider list is in the PR body.
	return fmt.Sprintf("%sRelease %d providers", titlePrefix, len(confs))
}

func (confs updateConfs) commitBody() string {
	var b strings.Builder
	b.WriteString("This release was created by mql's provider versioning bot.\n\n")
	b.WriteString("You can find me under: `providers-sdk/v1/util/version`.\n")
	for _, conf := range confs {
		if len(conf.changelog) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n### %s (%s)\n", conf.name, conf.version)
		for _, msg := range conf.changelog {
			fmt.Fprintf(&b, "- %s\n", msg)
		}
	}
	return b.String()
}

func (confs updateConfs) branchName() string {
	if len(confs) <= 5 {
		return "version/" + strings.Join(confs.titles(), "+")
	}

	now := time.Now()
	return "versions/" + strconv.Itoa(len(confs)) + "-provider-updates-" + now.Format(time.DateOnly)
}

func getVersion(content string) string {
	m := reVersion.FindStringSubmatch(content)
	if len(m) == 0 {
		return ""
	}
	return m[1]
}

func getConfig(providerPath string) (*providerConf, error) {
	var conf providerConf

	conf.path = filepath.Join(providerPath, "config/config.go")
	raw, err := os.ReadFile(conf.path)
	if err != nil {
		return nil, errors.New("failed to read provider config file")
	}
	conf.content = string(raw)

	// Note: name and version must come first in the config, since
	// we only regex-match, instead of reading the structure properly
	m := reName.FindStringSubmatch(conf.content)
	if len(m) == 0 {
		return nil, errors.New("no provider name found in config")
	}
	conf.name = m[1]

	conf.version = getVersion(conf.content)
	if conf.version == "" {
		return nil, errors.New("no provider version found in config")
	}
	return &conf, nil
}

func updateVersions(providerPaths []string) {
	results := analyzeProviders(providerPaths)
	updated := []*providerConf{}

	for _, r := range results {
		if r.err != nil {
			continue // error already logged in analyzeProviders
		}
		if r.changes == 0 {
			continue
		}

		conf, err := applyVersionBump(r.conf)
		if err != nil {
			log.Error().Err(err).Str("path", r.path).Msg("failed to bump version")
			continue
		}
		if conf == nil {
			continue
		}
		updated = append(updated, conf)
	}

	confs := updateConfs(updated)

	if outputDir != "" {
		if err := writeOutputFiles(confs); err != nil {
			log.Error().Err(err).Msg("failed to write output files")
		}
	}

	if doCommit {
		if err := commitChanges(confs); err != nil {
			log.Error().Err(err).Msg("failed to commit changes")
		}
	}
}

// writeOutputFiles writes the commit title to <outputDir>/title.txt
// and the PR body (with changelog) to <outputDir>/body.md.
func writeOutputFiles(confs updateConfs) error {
	if len(confs) == 0 {
		return nil
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "title.txt"), []byte(confs.commitTitle()), 0o644); err != nil {
		return fmt.Errorf("failed to write title: %w", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "body.md"), []byte(confs.commitBody()), 0o644); err != nil {
		return fmt.Errorf("failed to write body: %w", err)
	}

	log.Info().Str("dir", outputDir).Msg("wrote PR title and body")
	return nil
}

// applyVersionBump bumps the version in the config file on disk.
// The caller must have already verified that the provider has changes.
func applyVersionBump(conf *providerConf) (*providerConf, error) {
	version, err := bumpVersion(conf.version)
	if err != nil || version == "" {
		return nil, err
	}

	raw, err := format.Source([]byte(setVersion(conf.content, version)))
	if err != nil {
		return nil, err
	}

	// no switching config to the new version => gets new commitTitle + branchName!
	log.Info().Str("provider", conf.name).Str("version", version).Str("previous", conf.version).Msg("set new version")
	conf.version = version

	if err = os.WriteFile(conf.path, raw, 0o644); err != nil {
		log.Fatal().Err(err).Str("path", conf.path).Msg("failed to write file")
	}
	log.Info().Str("path", conf.path).Msg("updated config")

	if !doCommit {
		log.Info().Msg("git add " + conf.path + " && git commit -m \"" + conf.commitTitle() + "\"")
	}

	return conf, nil
}

// setVersion replaces the provider's own Version in the config content.
// Dependency MinVersions stay untouched: they name the lowest version of
// another provider this one works with, not this provider's version.
func setVersion(content string, version string) string {
	return reVersion.ReplaceAllString(content, `Version: "`+version+`"`)
}

func bumpVersion(version string) (string, error) {
	v, err := mastermind.NewVersion(version)
	if err != nil {
		return "", errors.New("version '" + version + "' is not a semver")
	}

	patch := v.IncPatch()
	minor := v.IncMinor()
	major := v.IncMajor()

	if increment == "patch" {
		return (&patch).String(), nil
	}
	if increment == "minor" {
		return (&minor).String(), nil
	}
	if increment == "major" {
		return (&major).String(), nil
	}
	if increment != "" {
		return "", errors.New("do not understand --increment=" + increment + ", either pick patch, minor, or major")
	}

	versions := []string{
		v.String() + " - no change, keep developing",
		(&patch).String(),
		(&minor).String(),
	}

	selection := -1
	model := components.NewListModel("Select version", versions, func(s int) {
		selection = s
	})
	_, err = tea.NewProgram(model, tea.WithInputTTY()).Run()
	if err != nil {
		return "", err
	}

	if selection == -1 || selection == 0 {
		return "", nil
	}

	return versions[selection], nil
}

func commitChanges(confs updateConfs) error {
	repo, err := git.PlainOpen(".")
	if err != nil {
		return errors.New("failed to open git: " + err.Error())
	}

	headRef, err := repo.Head()
	if err != nil {
		return errors.New("failed to get git head: " + err.Error())
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return errors.New("failed to get git tree: " + err.Error())
	}

	branchName := confs.branchName()
	branchRef := plumbing.NewBranchReferenceName(branchName)

	// Note: The branch may be local and thus won't be found in repo.Branch(branchName)
	// This is confusing and I couldn't find any further docs on this behavior,
	// but we have to work around it.
	if _, err := repo.Reference(branchRef, true); err == nil {
		err = repo.Storer.RemoveReference(branchRef)
		if err != nil {
			return errors.New("failed to git delete branch " + branchName + ": " + err.Error())
		}
	}

	err = worktree.Checkout(&git.CheckoutOptions{
		Hash:   headRef.Hash(),
		Branch: branchRef,
		Create: true,
		Keep:   true,
	})
	if err != nil {
		return errors.New("failed to git checkout+create " + branchName + ": " + err.Error())
	}

	fmt.Print("Adding providers to commit ")
	for i := range confs {
		_, err = worktree.Add(confs[i].path)
		if err != nil {
			return errors.New("failed to git add: " + err.Error())
		}
		fmt.Print(".")
	}
	fmt.Println(" done")

	commit, err := worktree.Commit(confs.commitTitle()+"\n\n"+confs.commitBody(), &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Mondoo",
			Email: "hello@mondoo.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		return errors.New("failed to commit: " + err.Error())
	}

	_, err = repo.CommitObject(commit)
	if err != nil {
		return errors.New("commit is not in repo: " + err.Error())
	}

	// Getting the GPG key is a hassle, so we use CLI for now...
	err = exec.Command("git", "commit", "--amend", "--no-edit", "-S").Run()
	if err != nil {
		return err
	}

	log.Info().Msg("committed changes for " + strings.Join(confs.titles(), ", "))
	log.Info().Msg("running: git push -u origin " + branchName)

	// Not sure why the auth method doesn't work... so we exec here
	err = exec.Command("git", "push", "-u", "origin", branchName).Run()
	if err != nil {
		return err
	}

	log.Info().Msg("updates pushed successfully, open: \n\t" +
		"https://github.com/mondoohq/mql/compare/" + branchName + "?expand=1")
	return nil
}

// findVersionCommitHash walks the log of the config file and finds the commit
// that introduced the current version string. This is much faster than blame
// because it only reads the config file at each commit (typically 1-3 lookups)
// instead of attributing every line across the full history.
func findVersionCommitHash(repo *git.Repository, conf *providerConf) plumbing.Hash {
	fileName := conf.path
	iter, err := repo.Log(&git.LogOptions{
		PathFilter: func(p string) bool {
			return p == fileName
		},
	})
	if err != nil {
		log.Warn().Err(err).Msg("failed to walk config file history")
		return plumbing.ZeroHash
	}
	defer iter.Close()

	var prev plumbing.Hash
	for c, err := iter.Next(); err == nil; c, err = iter.Next() {
		file, err := c.File(fileName)
		if err != nil {
			break
		}
		contents, err := file.Contents()
		if err != nil {
			break
		}
		if getVersion(contents) != conf.version {
			// The version changed at this commit — the previous commit
			// in our walk (more recent) is the one that bumped it.
			if !prev.IsZero() {
				return prev
			}
			// If prev is zero, HEAD itself has the version bump but
			// the file hasn't been committed yet (local change).
			return plumbing.ZeroHash
		}
		prev = c.Hash
	}

	// Every commit in history has the same version — return the oldest one.
	return prev
}

func countChangesSince(repo *git.Repository, conf *providerConf, repoPath string) int {
	versionHash := findVersionCommitHash(repo, conf)
	if versionHash.IsZero() {
		log.Warn().Msg("could not find version commit via blame => assuming provider needs update")
		return 1
	}

	// Walk commits that touched the provider directory from HEAD,
	// counting how many come before (after in time) the version commit.
	iter, err := repo.Log(&git.LogOptions{
		PathFilter: func(p string) bool {
			return strings.HasPrefix(p, repoPath)
		},
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to iterate git history")
	}
	defer iter.Close()

	var count int
	conf.changelog = nil
	for c, err := iter.Next(); err == nil; c, err = iter.Next() {
		if c.Hash == versionHash {
			break
		}
		count++
		// Collect the first line of the commit message as a changelog entry.
		msg := strings.TrimSpace(c.Message)
		if idx := strings.IndexByte(msg, '\n'); idx != -1 {
			msg = msg[:idx]
		}
		conf.changelog = append(conf.changelog, msg)
		if fastMode {
			return count
		}
	}
	return count
}

func parseDefaults(paths []string) string {
	confs := []*plugin.Provider{}
	for _, path := range paths {
		name := filepath.Base(path)
		data, err := os.ReadFile(filepath.Join(path, "dist", name+".json"))
		if err != nil {
			log.Fatal().Err(err).Msg("failed to read config json")
		}
		var v plugin.Provider
		if err = json.Unmarshal(data, &v); err != nil {
			log.Fatal().Err(err).Msg("failed to parse config json")
		}
		confs = append(confs, &v)
	}

	var res strings.Builder
	for i := range confs {
		conf := confs[i]
		var connectors strings.Builder
		for j := range conf.Connectors {
			conn := conf.Connectors[j]
			fmt.Fprintf(&connectors, `
				{
					Name:  %#v,
					Short: %#v,
				},`, conn.Name, conn.Short)
		}

		fmt.Fprintf(&res, `
	"%s": {
		Provider: &plugin.Provider{
			Name: "%s",
			ConnectionTypes: %#v,
			Connectors: []plugin.Connector{%s
			},
		},
	},`, conf.Name, conf.Name, conf.ConnectionTypes, connectors.String())
	}

	return res.String()
}

var (
	fastMode           bool
	doCommit           bool
	increment          string
	outputDir          string
	latestVersion      bool
	latestPatchVersion bool
)

func init() {
	rootCmd.PersistentFlags().BoolVar(&fastMode, "fast", false, "perform fast checking of git repo (not counting changes)")
	rootCmd.PersistentFlags().BoolVar(&doCommit, "commit", false, "commit the change to git if there is a version bump")
	rootCmd.PersistentFlags().StringVar(&increment, "increment", "", "automatically bump either patch, minor, or major version")
	rootCmd.PersistentFlags().StringVar(&outputDir, "output", "", "write PR title and body files to this directory")

	modUpdateCmd.PersistentFlags().BoolVar(&latestVersion, "latest", false, "update versions to latest")
	modUpdateCmd.PersistentFlags().BoolVar(&latestPatchVersion, "patch", false, "update versions to latest patch")
	modUpdateCmd.PersistentFlags().StringSlice("ignore-packages", []string{}, "ignore go package(s) from update")
	rootCmd.AddCommand(updateCmd, checkCmd, modUpdateCmd, modTidyCmd, defaultsCmd)
}

func main() {
	logger.CliCompactLogger(logger.LogOutputWriter)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
