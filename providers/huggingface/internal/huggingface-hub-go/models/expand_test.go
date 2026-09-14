// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The allowlists below are the sets the Hub itself reports. Sending an
// unlisted name returns HTTP 400 and no data at all, so one wrong entry breaks
// every listed repository of that kind rather than dropping a single field.
//
// Each set was read back from the API by sending a name that cannot be valid
// and capturing the rejection, for example:
//
//	GET https://huggingface.co/api/spaces?limit=1&expand[]=__bogus__
//	{"error":"✖ Invalid option: expected one of \"author\"|\"cardData\"|..."}
//
// The allowlists differ per repository kind: "description" is valid on datasets
// but not on Spaces, and "gated" is valid on models and datasets but not on
// Spaces. That asymmetry is why this test exists.
var (
	modelExpandAllowlist = []string{
		"author", "baseModels", "cardData", "config", "createdAt", "disabled",
		"downloads", "downloadsAllTime", "evalResults", "gated", "inference",
		"inferenceProviderMapping", "lastModified", "library_name", "likes",
		"mask_token", "model-index", "pipeline_tag", "private", "safetensors",
		"sha", "siblings", "spaces", "tags", "transformersInfo", "trendingScore",
		"widgetData", "gguf", "resourceGroup", "xetEnabled",
	}
	datasetExpandAllowlist = []string{
		"author", "cardData", "citation", "createdAt", "disabled", "description",
		"downloads", "downloadsAllTime", "gated", "lastModified", "likes",
		"mainSize", "paperswithcode_id", "private", "siblings", "sha", "tags",
		"trendingScore", "resourceGroup", "xetEnabled",
	}
	spaceExpandAllowlist = []string{
		"author", "cardData", "datasets", "disabled", "lastModified", "createdAt",
		"likes", "private", "region", "runtime", "sdk", "siblings", "sha",
		"subdomain", "tags", "trendingScore", "models", "resourceGroup",
		"xetEnabled",
	}
)

func TestExpandListsAreWithinTheAPIAllowlist(t *testing.T) {
	tests := []struct {
		name      string
		expand    []string
		allowlist []string
	}{
		{"models", ModelListExpand, modelExpandAllowlist},
		{"datasets", DatasetListExpand, datasetExpandAllowlist},
		{"spaces", SpaceListExpand, spaceExpandAllowlist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := map[string]bool{}
			for _, f := range tt.allowlist {
				allowed[f] = true
			}
			for _, f := range tt.expand {
				assert.True(t, allowed[f],
					"%q is not in the %s expand allowlist; the Hub answers the whole request with HTTP 400", f, tt.name)
			}
		})
	}
}

// expand[] is restrictive: the response carries only the named fields. Every
// field the provider reads off a listed repository therefore has to be
// requested, or it arrives empty with no error anywhere. These are the fields
// the resource layer reads; dropping one from the expand list fails here rather
// than silently zeroing a shipped MQL field.
func TestExpandListsCoverEveryFieldTheProviderReads(t *testing.T) {
	tests := []struct {
		name   string
		expand []string
		// read lists the wire names the resource layer consumes. "id" is always
		// returned and "modelId" is restored by ModelList.normalize, so neither
		// appears here.
		read []string
	}{
		{
			name:   "models",
			expand: ModelListExpand,
			read: []string{
				"author", "createdAt", "disabled", "downloads", "gated",
				"lastModified", "library_name", "likes", "pipeline_tag",
				"private", "sha", "tags",
			},
		},
		{
			name:   "datasets",
			expand: DatasetListExpand,
			read: []string{
				"author", "createdAt", "description", "disabled", "downloads",
				"downloadsAllTime", "gated", "lastModified", "likes", "private",
				"sha", "tags",
			},
		},
		{
			name:   "spaces",
			expand: SpaceListExpand,
			read: []string{
				"author", "createdAt", "disabled", "lastModified", "likes",
				"private", "region", "runtime", "sdk", "sha", "subdomain", "tags",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requested := map[string]bool{}
			for _, f := range tt.expand {
				requested[f] = true
			}
			for _, f := range tt.read {
				assert.True(t, requested[f],
					"the %s resource reads %q but the list call never asks for it, so it arrives empty", tt.name, f)
			}
		})
	}
}
