// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
)

// newListResourceIdFromArguments generates a new __id for a list resource that has query
// parameters `filter` and/or `search`. We need to use these parameters as the resource id
// so that different query parameters, or no parameter, create different resources.
//
// If none is set, the default id returned is `all`
func newListResourceIdFromArguments(resourceName string, args map[string]*llx.RawData) *llx.RawData {
	filter, filterExist := args["filter"]
	search, searchExist := args["search"]

	if filterExist || searchExist {
		id := resourceName
		if filterExist {
			id += fmt.Sprintf("/filter-%s", filter.Value.(string))
		}
		if searchExist {
			id += fmt.Sprintf("/search-%s", search.Value.(string))
		}
		return llx.StringData(id)
	}

	return llx.StringData(resourceName + "/all")
}

// parseSearch tries to help the user understand the format of Microsoft API searches.
// By default, if the user runs a simple search of one field, we scape it for them,
// though if more complicated searches with ANDs/ORs are provided, we let the user know
// that they need to scape the query on their own.
//
// Simple search:
//
//	resource(search: "property:my value goes here")
//
// Multiple fields search:
//
//	resource(search: '"property1:one value" and "property2:something else and complex"')
func parseSearch(search string) (string, error) {
	if !strings.Contains(search, ":") {
		return "", errors.New("search is not of right format: \"property:value\"")
	}

	if strings.Contains(search, "\"") {
		// the search filter is already escaped
		return search, nil
	}

	if len(strings.Split(search, ":")) > 2 {
		// special case for multi field search like `displayName:foo or mail:bar`
		// without escaping the filters on their own
		return "", errors.New("search with multiple fields is not of right format: " +
			"'\"property:value\" [AND | OR] \"property:value\"'")
	}

	// scape simple search filter like: `displayName:my name`
	return fmt.Sprintf("\"%s\"", search), nil
}

// We do not have a parseFilter function since those query parameters can be passed as is,
// and the APIs return helpful information to the user.
//
// https://learn.microsoft.com/en-us/graph/filter-query-parameter?tabs=http#filter-using-lambda-operators
// func parseFilter(search string) (string, error) {
// return "", nil
// }
