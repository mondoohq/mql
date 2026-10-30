// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// An Azure permission can be used when a resource provider has registered the
// operation with Azure Resource Manager. GET providers/Microsoft.Authorization/
// providerOperations is that registry (what `az provider operation list`
// wraps), and it is exactly what a custom role is validated against: a role
// definition naming an unregistered operation is refused with
// InvalidActionOrNotAction. Any authenticated identity in the tenant can read
// it; the token comes from AZURE_ACCESS_TOKEN (what azure/login followed by
// `az account get-access-token` gives in CI) or, failing that, the local az
// login. Matching is case-insensitive: RBAC matches operation names without
// regard to case, and Microsoft's own casing is inconsistent.
//
// scripts/test-iam-permissions.sh azure-create does the same check the way a
// customer would, by creating a custom role from the manifest at a scope.
const azureProviderOperationsURL = "https://management.azure.com/providers/Microsoft.Authorization/providerOperations?api-version=2022-04-01&$expand=resourceTypes"

func loadAzureCatalog(f *fetcher) (*catalog, error) {
	token, err := azureAccessToken()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, azureProviderOperationsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	fmt.Fprintf(f.log, "  querying the Azure provider operation registry\n")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("providerOperations: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	c := newCatalog()
	if err := parseAzureProviderOperations(data, c); err != nil {
		return nil, err
	}
	return c, nil
}

// parseAzureProviderOperations reads the registry: a list of providers (under
// "value" when it comes from the API), each with operations directly on it
// and under each of its resource types.
func parseAzureProviderOperations(data []byte, into *catalog) error {
	type operation struct {
		Name string `json:"name"`
	}
	type provider struct {
		Name          string      `json:"name"`
		Operations    []operation `json:"operations"`
		ResourceTypes []struct {
			Operations []operation `json:"operations"`
		} `json:"resourceTypes"`
	}
	var providers []provider
	var wrapped struct {
		Value []provider `json:"value"`
	}
	// An object is the API's form, a bare array the other; the object's
	// list is taken as it is, empty included, so an empty answer is reported
	// as such rather than re-read as an array.
	if err := json.Unmarshal(data, &wrapped); err == nil {
		providers = wrapped.Value
	} else if err := json.Unmarshal(data, &providers); err != nil {
		return fmt.Errorf("providerOperations: %w", err)
	}
	if len(providers) == 0 {
		return errors.New("providerOperations: the registry answered with no providers")
	}
	for _, p := range providers {
		for _, op := range p.Operations {
			into.add(op.Name)
		}
		for _, rt := range p.ResourceTypes {
			for _, op := range rt.Operations {
				into.add(op.Name)
			}
		}
	}
	return nil
}

func azureAccessToken() (string, error) {
	if t := os.Getenv("AZURE_ACCESS_TOKEN"); t != "" {
		return t, nil
	}
	out, err := exec.Command("az", "account", "get-access-token", "--resource", "https://management.azure.com", "--query", "accessToken", "-o", "tsv").Output()
	if err != nil {
		return "", fmt.Errorf("azure: no AZURE_ACCESS_TOKEN and `az account get-access-token` failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
