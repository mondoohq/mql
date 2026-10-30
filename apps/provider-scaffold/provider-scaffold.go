// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
	"unicode"

	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
)

//go:embed template/*
var templates embed.FS

type config struct {
	Path                string
	ProviderID          string
	CamelcaseProviderID string
	ProviderName        string
	GoPackage           string
}

func main() {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	dir := flags.String("path", "", "path directory where you want to generate the files into (default: providers/{provider-id})")
	providerID := flags.String("provider-id", "", "provider id (e.g. digitalocean)")
	providerName := flags.String("provider-name", "", "provider display name (e.g. \"DigitalOcean\")")
	force := flags.Bool("force", false, "overwrite existing provider directory")

	if err := flags.Parse(os.Args); err != nil {
		if err == pflag.ErrHelp {
			os.Exit(0)
		}
		log.Fatal().Err(err).Msg("error: could not parse flags")
	}

	if *providerID == "" {
		log.Fatal().Msg("--provider-id is required")
	}

	if *providerName == "" {
		log.Fatal().Msg("--provider-name is required")
	}

	// Derive path from provider ID if not specified.
	if *dir == "" {
		*dir = filepath.Join("providers", *providerID)
	}

	goPackage := "go.mondoo.com/mql/providers/" + *providerID

	// Overwrite protection: check if directory already has files.
	if !*force {
		if entries, err := os.ReadDir(*dir); err == nil && len(entries) > 0 {
			log.Fatal().Str("path", *dir).Msg("directory already exists and is not empty; use --force to overwrite")
		}
	}

	err := os.MkdirAll(*dir, os.ModePerm)
	if err != nil {
		log.Fatal().Err(err).Msg("could not ensure the provided directory exists")
	}

	cfg := config{
		Path:                *dir,
		ProviderID:          *providerID,
		ProviderName:        *providerName,
		GoPackage:           goPackage,
		CamelcaseProviderID: toCamelCase(*providerID),
	}

	if err := generateProvider(cfg); err != nil {
		log.Fatal().Err(err).Msg("could not generate provider files")
	}

	// Auto-register in Makefile and DEVELOPMENT.md.
	if err := registerInMakefile(*providerID); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update Makefile: %v\n", err)
	}
	if err := registerInDevelopmentMd(*providerID); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update DEVELOPMENT.md: %v\n", err)
	}

	// Print next steps.
	fmt.Println()
	fmt.Printf("Provider scaffolded at %s\n", *dir)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  cd %s && go mod tidy\n", *dir)
	fmt.Printf("  # Edit resources/%s.lr to define your resources\n", *providerID)
	fmt.Println("  # Generate resource code:")
	fmt.Printf("  make providers/mqlr && ./mqlr generate %s/resources/%s.lr --dist %s/resources\n", *dir, *providerID, *dir)
	fmt.Println("  # Build and install:")
	fmt.Printf("  make providers/build/%s && make providers/install/%s\n", *providerID, *providerID)
	fmt.Println("  # Test:")
	fmt.Printf("  mql shell %s\n", *providerID)
}

// toCamelCase converts a hyphen-separated provider ID to CamelCase for Go identifiers.
//
//	"digitalocean"    -> "Digitalocean"
//	"google-workspace" -> "GoogleWorkspace"
//	"my-cool-provider" -> "MyCoolProvider"
func toCamelCase(s string) string {
	parts := strings.Split(s, "-")
	for i := range parts {
		if len(parts[i]) > 0 {
			runes := []rune(parts[i])
			runes[0] = unicode.ToUpper(runes[0])
			parts[i] = string(runes)
		}
	}
	return strings.Join(parts, "")
}

func generateProvider(cfg config) error {
	return fs.WalkDir(templates, ".", func(sourceFile string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		if filepath.Ext(sourceFile) != ".template" {
			return nil
		}

		base, _ := filepath.Rel("template", sourceFile)
		fmt.Println("Render " + base)

		path := strings.TrimSuffix(base, ".template")
		path = strings.ReplaceAll(path, "providerid", cfg.ProviderID)

		rootDir := filepath.Join(cfg.Path, filepath.Dir(path))
		fmt.Println("Create dir " + rootDir)
		err = os.MkdirAll(rootDir, os.ModePerm)
		if err != nil {
			return err
		}

		destinationFile := filepath.Join(cfg.Path, path)
		fmt.Println("Render file " + destinationFile)

		input, err := fs.ReadFile(templates, sourceFile)
		if err != nil {
			return err
		}

		tmpl, err := template.New(destinationFile).Parse(string(input))
		if err != nil {
			return err
		}

		w, err := os.OpenFile(destinationFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			fmt.Println("Error creating", destinationFile)
			return err
		}
		defer w.Close()

		err = tmpl.Execute(w, cfg)
		if err != nil {
			return err
		}

		return nil
	})
}

// registerInMakefile inserts the provider name alphabetically into the PROVIDERS list.
func registerInMakefile(providerID string) error {
	const filename = "Makefile"
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")

	// Find the PROVIDERS := \ block and collect entries.
	startIdx := -1
	endIdx := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PROVIDERS :=") {
			startIdx = i
		}
		if startIdx >= 0 && i > startIdx {
			// Lines in the block end with \, the last one doesn't.
			if !strings.HasSuffix(trimmed, "\\") {
				endIdx = i
				break
			}
		}
	}

	if startIdx < 0 || endIdx < 0 {
		return fmt.Errorf("could not find PROVIDERS block in %s", filename)
	}

	// Extract provider names from the block.
	var providers []string
	for i := startIdx + 1; i <= endIdx; i++ {
		name := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(lines[i]), "\\"))
		if name != "" {
			providers = append(providers, name)
		}
	}

	// Check if already registered.
	if slices.Contains(providers, providerID) {
		fmt.Printf("Makefile: %s already in PROVIDERS list\n", providerID)
		return nil
	}

	// Insert at sorted position, preserving existing order for other entries.
	insertIdx := len(providers)
	for i, p := range providers {
		if providerID < p {
			insertIdx = i
			break
		}
	}
	providers = slices.Insert(providers, insertIdx, providerID)

	// Rebuild the PROVIDERS block.
	var newBlock []string
	newBlock = append(newBlock, "PROVIDERS := \\")
	for i, p := range providers {
		if i < len(providers)-1 {
			newBlock = append(newBlock, "\t"+p+" \\")
		} else {
			newBlock = append(newBlock, "\t"+p)
		}
	}

	// Replace the old block.
	var result []string
	result = append(result, lines[:startIdx]...)
	result = append(result, newBlock...)
	result = append(result, lines[endIdx+1:]...)

	fmt.Printf("Makefile: added %s to PROVIDERS list\n", providerID)
	return os.WriteFile(filename, []byte(strings.Join(result, "\n")), 0o644)
}

// registerInDevelopmentMd inserts the provider path into the go.work use block.
func registerInDevelopmentMd(providerID string) error {
	const filename = "DEVELOPMENT.md"
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	entry := "./mql/providers/" + providerID

	// Check if already present.
	if strings.Contains(string(content), entry) {
		fmt.Printf("DEVELOPMENT.md: %s already present\n", entry)
		return nil
	}

	// Find the go.work use block and insert alphabetically.
	lines := strings.Split(string(content), "\n")
	inserted := false
	var result []string
	inUseBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "use (" {
			inUseBlock = true
			result = append(result, line)
			continue
		}

		if inUseBlock && trimmed == ")" {
			// End of use block -- if not inserted yet, add before closing.
			if !inserted {
				result = append(result, "   "+entry)
				inserted = true
			}
			inUseBlock = false
			result = append(result, line)
			continue
		}

		if inUseBlock && strings.HasPrefix(trimmed, "./mql/providers/") {
			// Insert before this line if our entry sorts before it.
			if !inserted && entry < trimmed {
				result = append(result, "   "+entry)
				inserted = true
			}
		}

		result = append(result, line)
	}

	if !inserted {
		return fmt.Errorf("could not find insertion point in %s", filename)
	}

	fmt.Printf("DEVELOPMENT.md: added %s to go.work use block\n", entry)
	return os.WriteFile(filename, []byte(strings.Join(result, "\n")), 0o644)
}
