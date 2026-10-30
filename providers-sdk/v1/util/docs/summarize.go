// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

func main() {
	if len(os.Args) <= 1 {
		log.Fatal().Msg("usage: summarize ./providers")
	}

	path := os.Args[1]
	providersDir, err := os.ReadDir(path)
	if err != nil {
		log.Fatal().Msg("failed to read folder " + path)
	}

	schemas := map[string]*resources.Schema{}
	connectors := 0
	for i := range providersDir {
		node := providersDir[i]
		if !node.IsDir() {
			continue
		}

		name := node.Name()
		path := filepath.Join(path, name)

		configFile := filepath.Join(path, "dist", name+".json")
		ok, err := exists(configFile)
		if err != nil {
			log.Fatal().Err(err).Str("path", configFile).Msg("can't determine if config file exists")
		}
		if !ok {
			log.Info().Msg("skipping " + name + " (no config)")
			continue
		}
		resourcesFile := filepath.Join(path, "dist", name+".resources.json")
		ok, err = exists(resourcesFile)
		if err != nil {
			log.Fatal().Err(err).Str("path", resourcesFile).Msg("can't determine if resources file exists")
		}
		if !ok {
			log.Info().Msg("skipping " + name + " (no schema)")
			continue
		}

		configRaw, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatal().Str("path", configFile).Err(err).Msg("failed to read config for provider")
		}
		var config plugin.Provider
		err = json.Unmarshal(configRaw, &config)
		if err != nil {
			log.Fatal().Str("path", configFile).Err(err).Msg("failed to unmarshal config for provider")
		}
		connectors += len(config.Connectors)

		schema := providers.MustLoadSchemaFromFile(name, resourcesFile)
		schemas[node.Name()] = schema
	}

	combined := resources.Schema{Resources: map[string]*resources.ResourceInfo{}}
	for _, schema := range schemas {
		combined.Add(schema)
	}

	resources := combined.AllResources()

	fields := 0
	for _, resource := range resources {
		for _, v := range resource.Fields {
			if v.IsImplicitResource {
				continue
			}
			fields++
		}
	}

	fmt.Println()
	fmt.Printf("Total providers:   %d\n", len(schemas))
	fmt.Printf("Total connectors:  %d\n", connectors)
	fmt.Printf("Total resources:   %d\n", len(resources))
	fmt.Printf("Total fields:      %d\n", fields)
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
