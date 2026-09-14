// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
)

// DatasetListExpand names the fields the dataset list endpoint must return.
//
// The Hub's expand[] parameter is restrictive rather than additive: a response
// built with expand[] carries only the listed fields (plus id), so every field
// read off a listed dataset has to appear here or it silently arrives empty.
// Every name is in the allowlist the dataset endpoint enforces; an unlisted
// name fails the whole request with HTTP 400 rather than being ignored.
var DatasetListExpand = []string{
	"author",
	"createdAt",
	"description",
	"disabled",
	"downloads",
	"downloadsAllTime",
	"gated",
	"lastModified",
	"likes",
	"private",
	"sha",
	"tags",
}

type Dataset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Author      string   `json:"author"`
	Downloads   int      `json:"downloads"`
	// DownloadsAllTime counts downloads since the dataset was created, where
	// Downloads counts only the last 30 days.
	DownloadsAllTime int  `json:"downloadsAllTime"`
	Likes            int  `json:"likes"`
	Private          bool `json:"private"`
	// Gated is false, "auto", or "manual" on the wire; see GatedValue.
	Gated        GatedValue `json:"gated"`
	Disabled     bool       `json:"disabled"`
	CreatedAt    string     `json:"createdAt"`
	LastModified string     `json:"lastModified"`
	Sha          string     `json:"sha"`
}

type DatasetListOptions struct {
	Author        string
	Search        string
	Filter        string
	SortBy        string
	SortDirection string
	Limit         int
	Full          bool
	// Expand names the fields the response should carry. See DatasetListExpand.
	Expand []string
}

func NewDatasetListOptions() *DatasetListOptions {
	return &DatasetListOptions{
		SortDirection: "1",
		Limit:         20,
		Full:          false,
		Expand:        DatasetListExpand,
	}
}

type DatasetList struct {
	Datasets []Dataset
}

func (dl *DatasetList) UnmarshalJSON(data []byte) error {
	var datasets []Dataset
	err := json.Unmarshal(data, &datasets)
	if err == nil {
		dl.Datasets = datasets
		return nil
	}
	if isJSONArray(data) {
		return err
	}

	type Alias DatasetList
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(dl),
	}
	return json.Unmarshal(data, aux)
}
