// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mapx

import "maps"

// Merge merges two maps of type `map[K]T` giving precedence to the first map.
func Merge[K comparable, V any](m1, m2 map[K]V) map[K]V {
	merged := make(map[K]V)

	// store all key:value's from the second map
	maps.Copy(merged, m2)

	// iterate over the first map to give it preference
	maps.Copy(merged, m1)

	return merged
}
