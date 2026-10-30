// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"

	"go.mondoo.com/mql/cli/components"
)

type CustomString string

func (s CustomString) Display() string {
	return string(s)
}

func main() {
	customStrings := []CustomString{"first", "second", "third"}
	selected := components.Select("Choose a string", customStrings)
	fmt.Printf("You chose the %s string.\n", customStrings[selected])
}
