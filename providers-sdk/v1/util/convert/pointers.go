// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package convert

// ToPtr returns a pointer to the given value.
//
//go:fix inline
func ToPtr[T any](v T) *T {
	return new(v)
}

// ToValue returns the value of the given pointer.
// If the pointer is `nil`, an empty value is returned.
func ToValue[V any](ptr *V) V {
	if ptr == nil {
		return *new(V)
	}
	return *ptr
}

// ToListFromPtrs returns a list of values of the given list of pointers.
func ToListFromPtrs[V any](ptrs []*V) []V {
	if ptrs == nil {
		return nil
	}
	list := make([]V, len(ptrs))
	for i, ptr := range ptrs {
		list[i] = ToValue(ptr)
	}
	return list
}
