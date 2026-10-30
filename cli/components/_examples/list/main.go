// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"

	"go.mondoo.com/mql/cli/components"
	"go.mondoo.com/mql/cli/theme"
)

type CustomString string

func (s CustomString) PrintableKeys() []string {
	return []string{"string"}
}
func (s CustomString) PrintableValue(_ int) string {
	return string(s)
}

func main() {
	customStrings := []CustomString{"first", "second", "third"}
	list := components.List(theme.OperatingSystemTheme, customStrings)
	fmt.Printf(list)
}
