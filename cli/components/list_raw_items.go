// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package components

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"go.mondoo.com/mql/cli/theme"
)

// ListableItem is the interface that a list need to implement so we can display its items.
type ListableItem interface {
	// PrintableKeys returns the list of keys that will be printed.
	PrintableKeys() []string

	// PrintableValue returns the key value based of the provided index.
	PrintableValue(index int) string
}

// List is a non-interactive function that lists items to the user.
//
// e.g.
// ```go
//
//	type CustomString string
//
//	func (s CustomString) PrintableKeys() []string {
//		return []string{"string"}
//	}
//	func (s CustomString) PrintableValue(_ int) string {
//		return string(s)
//	}
//
//	func main() {
//		customStrings := []CustomString{"first", "second", "third"}
//		list := components.List(theme.OperatingSystemTheme, customStrings)
//		fmt.Printf(list)
//	}
//
// ```
func List[O ListableItem](theme *theme.Theme, list []O) string {
	b := &strings.Builder{}
	w := tabwriter.NewWriter(b, 1, 1, 1, ' ', tabwriter.TabIndent)

	for i := range list {
		assetObj := list[i]

		for i, key := range assetObj.PrintableKeys() {
			fmt.Fprint(w, theme.Primary(key, ":\t"))
			fmt.Fprintln(w, assetObj.PrintableValue(i))
		}

		fmt.Fprintln(w, "")
	}

	w.Flush()

	return b.String()
}
