// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package slicesx

func Batch[T any](list []T, batchSize int) [][]T {
	var res [][]T
	for i := 0; i < len(list); i += batchSize {
		end := min(i+batchSize, len(list))
		res = append(res, list[i:end])
	}
	return res
}
