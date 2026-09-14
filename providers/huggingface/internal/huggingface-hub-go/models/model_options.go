// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

type ModelListOptions struct {
	Author        string
	Search        string
	Filter        string
	SortBy        string
	SortDirection string
	Limit         int
	Full          bool
	// Expand names the fields the response should carry. See ModelListExpand.
	Expand []string
}

func NewModelListOptions() *ModelListOptions {
	return &ModelListOptions{
		SortDirection: "1",
		Limit:         20,
		Full:          false,
		Expand:        ModelListExpand,
	}
}
