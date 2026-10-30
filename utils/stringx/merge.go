// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stringx

import (
	"bytes"
	"strings"
)

// MergeSideBySide merges each line for two multiline strings
func MergeSideBySide(layer1 string, layer2 string) string {
	layer1Lines := strings.Split(layer1, "\n")
	layer2Lines := strings.Split(layer2, "\n")

	len1 := len(layer1Lines)
	len2 := len(layer2Lines)
	maxLen := max(len2, len1)

	b := bytes.Buffer{}
	for i := range maxLen {
		if i < len1 {
			b.WriteString(layer1Lines[i])
		}
		if i < len2 {
			b.WriteString(layer2Lines[i])
		}
		b.WriteString("\n")
	}
	return b.String()
}
