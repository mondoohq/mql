// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/url"
	"strings"
)

// https://github.com/Azure/azure-sdk-for-go/issues/3080
// we need to parse the resource id to extract the individual parts to regenerate the url
type ResourceID struct {
	SubscriptionID string
	ResourceGroup  string
	Provider       string
	Path           map[string]string
}

// ParseResourceID parses a fully qualified ID into its components
// Resources have the following format:
// /subscriptions/{guid}/resourceGroups/{resource-group-name}/{resource-provider-namespace}/{resource-type}/{resource-name}
// @see https://learn.microsoft.com/en-us/rest/api/resources/resources/get-by-id
func ParseResourceID(id string) (*ResourceID, error) {
	// sanitize resource id
	idURL, err := url.ParseRequestURI(id)
	if err != nil {
		return nil, fmt.Errorf("cannot parse Azure resource ID: %s", err)
	}
	path := idURL.Path
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	components := strings.Split(path, "/")

	// check if we have an even number of key-value pairs
	if len(components)%2 != 0 {
		return nil, fmt.Errorf("uneven number of components %q", path)
	}

	// parse key-value pairs
	subscriptionID := ""
	componentMap := make(map[string]string, len(components)/2)
	for current := 0; current < len(components); current += 2 {
		key := components[current]
		value := components[current+1]

		// validate that key and value are properly set
		if key == "" || value == "" {
			return nil, fmt.Errorf("invalid key value pair: '%s' -> '%s'", key, value)
		}

		// some urls use the same component id twice, ensure we store the subscription id
		// e.g. Azure Service Bus subscription resource
		lowerKey := strings.ToLower(key)
		if lowerKey == "subscriptions" && subscriptionID == "" {
			subscriptionID = value
		} else {
			componentMap[lowerKey] = value
		}
	}
	resID := &ResourceID{
		SubscriptionID: subscriptionID,
		Path:           componentMap,
	}

	if len(resID.SubscriptionID) == 0 {
		return nil, fmt.Errorf("no subscription ID found in resource id: %s", path)
	}

	// parse resource group
	if resourceGroup, ok := componentMap["resourcegroups"]; ok {
		resID.ResourceGroup = resourceGroup
		delete(componentMap, "resourcegroups")
	}

	// parse provider
	if provider, ok := componentMap["providers"]; ok {
		resID.Provider = provider
		delete(componentMap, "providers")
	}

	return resID, nil
}

// Component returns a component from parsed resource id.
// The lookup is case-insensitive because Azure ARM resource IDs are case-insensitive.
func (id *ResourceID) Component(name string) (string, error) {
	val, ok := id.Path[strings.ToLower(name)]
	if !ok {
		return "", fmt.Errorf("ID was missing the `%s` element", name)
	}
	return val, nil
}
