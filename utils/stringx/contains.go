// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stringx

import "slices"

func Contains(slice []string, entry string) bool {
	return slices.Contains(slice, entry)
}

func ContainsAnyOf(slice []string, entries ...string) bool {
	for _, entry := range entries {
		if Contains(slice, entry) {
			return true
		}
	}
	return false
}

func RemoveEmpty(a []string) []string {
	b := a[:0]
	for _, x := range a {
		if x != "" {
			b = append(b, x)
		}
	}
	for i := len(b); i < len(a); i++ {
		a[i] = "" // or the zero value of T
	}
	return b
}
