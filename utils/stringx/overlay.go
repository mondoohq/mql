// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stringx

import (
	"strings"
	"unicode"
)

func Overlay(base string, layers ...string) string {
	// split layer in rows
	baseLayer := strings.Split(base, "\n")

	layeredRows := make([][]string, len(layers))
	for i := range layers {
		layeredRows[i] = strings.Split(layers[i], "\n")
	}

	output := []string{}

	// iterate over base layer rows and merge all other layers
	for i := range baseLayer {
		row := []rune(baseLayer[i])

		// iterate over each character
		for pos := range row {
			winning := row[pos]

			// iterate over all layers that we want to merge in
			mergeRow := make([]rune, 0)
			for j := range layeredRows {
				layer := layeredRows[j]
				if len(layer) > i {
					mergeRow = []rune(layer[i])
				}
				if len(mergeRow) > pos {
					layerChar := mergeRow[pos]
					if !unicode.IsSpace(layerChar) || layerChar == 0x0 {
						winning = layerChar
					}
				}
			}

			row[pos] = winning
		}
		output = append(output, string(row))
	}

	return strings.Join(output, "\n")
}
