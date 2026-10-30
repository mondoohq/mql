// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventoryloader

import (
	"bytes"
	"os"
	"text/template"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/inventory/ansibleinventory"
	"go.mondoo.com/mql/providers-sdk/v1/inventory/domainlist"
	"go.mondoo.com/mql/utils/piped"
)

func renderTemplate(data []byte) ([]byte, error) {
	type InventoryTemplateVariables struct{}
	conf := InventoryTemplateVariables{}

	// allows users to access environment variables in templates
	funcMap := template.FuncMap{
		"getenv": func(varName string) string { return os.Getenv(varName) },
	}

	tmpl, err := template.New("inventory-template").Funcs(funcMap).Parse(string(data))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse inventory template")
	}
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, conf)
	return buf.Bytes(), err
}

// Parse uses the viper flags for `--inventory-file` to load the inventory
// - if `--inventory-file` is set to "-" it will read from stdin
// - if `--inventory-template` is set it injects environment variables into the inventory before execution
func Parse() (*inventory.Inventory, error) {
	var data []byte
	var err error

	// a pre-rendered inventory file has always precedence over the inventory template
	inventoryFilePath := viper.GetString("inventory-file")
	inventoryTemplate := viper.GetString("inventory-template")
	inventorySource := ""

	// check in an inventory file was provided
	if inventoryFilePath == "" && inventoryTemplate == "" {
		return inventory.New(), nil
	}

	if inventoryFilePath == "-" {
		// read data from stdin
		log.Info().Msg("load inventory from piped input")
		var ok bool
		data, ok = piped.LoadDataFromPipe()
		if !ok {
			return nil, errors.New("could not read inventory from piped input")
		}
		inventorySource = "stdin"
	} else if inventoryFilePath != "" {
		// read the data from the input file
		log.Info().Str("inventory-file", inventoryFilePath).Msg("load inventory")
		data, err = os.ReadFile(inventoryFilePath)
		if err != nil {
			return nil, err
		}
		inventorySource = inventoryFilePath
	} else if inventoryTemplate != "" {
		// render inventory template first, then continue with generated inventory file
		log.Info().Str("inventory-template", inventoryTemplate).Msg("load inventory template")
		templateData, err := os.ReadFile(inventoryTemplate)
		if err != nil {
			return nil, err
		}
		data, err = renderTemplate(templateData)
		if err != nil {
			return nil, err
		}
		inventorySource = inventoryTemplate
	} else {
		return nil, errors.New("no inventory file or template provided")
	}

	// force detection
	if viper.GetBool("inventory-format-ansible") {
		log.Debug().Msg("parse ansible inventory")
		inventory, err := parseAnsibleInventory(data)
		if err != nil {
			return nil, err
		}
		return inventory, nil
	}

	if viper.GetBool("inventory-format-domainlist") {
		log.Debug().Msg("parse domainlist inventory")
		inventory, err := parseDomainListInventory(data)
		if err != nil {
			return nil, err
		}
		return inventory, nil
	}

	// load mondoo inventory
	log.Debug().Msg("parse inventory")
	res, err := inventory.InventoryFromYAML(data)
	if err != nil {
		return nil, err
	}
	// we preprocess the content here, to ensure relative paths are
	if res.Metadata.Labels == nil {
		res.Metadata.Labels = map[string]string{}
	}
	res.Metadata.Labels[inventory.InventoryFilePath] = inventorySource
	err = res.PreProcess()
	if err != nil {
		return nil, err
	}

	return res, nil
}

func parseAnsibleInventory(data []byte) (*inventory.Inventory, error) {
	log.Info().Msg("use ansible inventory")
	inventory, err := ansibleinventory.Parse(data)
	if err != nil {
		return nil, err
	}
	return inventory.ToV1Inventory(), nil
}

func parseDomainListInventory(data []byte) (*inventory.Inventory, error) {
	log.Info().Msg("use domainlist inventory")
	inventory, err := domainlist.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return inventory.ToV1Inventory(), nil
}

// explicitInventorySource returns the file path or template path the user
// asked us to load, or "" if no inventory source was set on the command line.
func explicitInventorySource() string {
	if p := viper.GetString("inventory-file"); p != "" {
		return p
	}
	return viper.GetString("inventory-template")
}

// ParseOrUse tries to load the inventory and if nothing exists it
// will instead use the provided asset.
func ParseOrUse(asset *inventory.Asset, insecure bool, annotations map[string]string) (*inventory.Inventory, error) {
	var v1inventory *inventory.Inventory
	var err error

	// parses optional inventory file if inventory was not piped already
	v1inventory, err = Parse()
	if err != nil {
		return nil, errors.Wrap(err, "could not parse inventory")
	}

	// add asset from cli to inventory. When the user explicitly pointed us at
	// an inventory source that produced zero assets, warn before falling back.
	if len(v1inventory.Spec.GetAssets()) == 0 && asset != nil {
		if src := explicitInventorySource(); src != "" {
			log.Warn().
				Str("source", src).
				Msg("inventory source produced 0 assets; falling back to the CLI target.")
		}
		v1inventory.AddAssets(asset)
	}

	for _, asset := range v1inventory.Spec.GetAssets() {
		asset.AddAnnotations(annotations)
	}

	// if the --insecure flag is set, we overwrite the individual setting for the asset
	if insecure {
		v1inventory.MarkConnectionsInsecure()
	}

	return v1inventory, nil
}
