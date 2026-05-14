// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "testing"

func TestNextOffset(t *testing.T) {
	cases := []struct {
		name          string
		currentOffset int
		returned      int
		want          int
	}{
		{"full page from start", 0, pageSize, pageSize},
		{"full page mid-walk", 300, pageSize, 400},
		{"short page ends pagination", 200, pageSize - 1, -1},
		{"empty page ends pagination", 0, 0, -1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextOffset(c.currentOffset, c.returned); got != c.want {
				t.Fatalf("nextOffset(%d, %d) = %d, want %d", c.currentOffset, c.returned, got, c.want)
			}
		})
	}
}
