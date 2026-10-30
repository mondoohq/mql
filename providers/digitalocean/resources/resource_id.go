// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"
)

// resourceID builds a resource's cache key from its kind and the parts that
// make one instance distinguishable from another.
//
// It refuses to build a key from an empty part, which is the whole reason it
// exists. Every __id collision found in this provider so far came from a
// component that was empty at runtime and got concatenated anyway: five in
// #9366, then function actions in #9750, which were keyed on a uuid the
// namespace listing never populates. The resulting key still looks
// well-formed, so nothing complains; instances simply alias onto whichever was
// created first and the inventory is quietly wrong.
//
// Returning an error turns that into a visible failure at the creation site,
// where the missing value can actually be traced.
func resourceID(kind string, parts ...string) (string, error) {
	if kind == "" {
		return "", errors.New("resource id needs a kind")
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("%s: resource id needs at least one distinguishing part", kind)
	}
	for i, p := range parts {
		if p == "" {
			return "", fmt.Errorf("%s: resource id part %d is empty, so instances would share a cache key", kind, i)
		}
	}
	return kind + "/" + strings.Join(parts, "/"), nil
}
