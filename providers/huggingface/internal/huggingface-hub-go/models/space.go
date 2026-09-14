// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
)

// SpaceListExpand names the fields the Space list endpoint must return.
//
// The Hub's expand[] parameter is restrictive rather than additive: a response
// built with expand[] carries only the listed fields (plus id), so every field
// read off a listed Space has to appear here or it silently arrives empty.
// Every name is in the allowlist the Space endpoint enforces; an unlisted name
// fails the whole request with HTTP 400 rather than being ignored. The Space
// allowlist has no "description" and no "gated", which is why neither is here.
var SpaceListExpand = []string{
	"author",
	"createdAt",
	"disabled",
	"lastModified",
	"likes",
	"private",
	"region",
	"runtime",
	"sdk",
	"sha",
	"subdomain",
	"tags",
}

// SpaceHardware is the hardware flavor a Space runs on and the flavor it asked
// for. Both are absent while the Space is not running, which is why they are
// pointers: an unreported flavor is not the same as the free tier.
type SpaceHardware struct {
	Current   *string `json:"current"`
	Requested *string `json:"requested"`
}

// SpaceReplicas is the running and configured replica count.
type SpaceReplicas struct {
	Current   ReplicaCount `json:"current"`
	Requested ReplicaCount `json:"requested"`
}

// ReplicaCount is a replica setting. The Hub reports it as a number, as null
// while the Space is not running, or as the string "auto" on a Space that
// scales its replicas automatically.
//
// Decoding never fails. A list response carries many Spaces, and returning an
// error here would abandon every one of them over a single unfamiliar value:
// one autoscaling Space would empty the whole collection rather than degrade
// one field. An unrecognized value leaves the count null and Auto false.
type ReplicaCount struct {
	Count *int
	Auto  bool
}

func (r *ReplicaCount) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		r.Count = &n
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil && s == "auto" {
		r.Auto = true
	}
	return nil
}

// SpaceDomain is one domain a Space answers on, with the provisioning stage of
// that domain.
type SpaceDomain struct {
	Domain string `json:"domain"`
	Stage  string `json:"stage"`
}

// SpaceRuntime is the execution state of the container serving a Space.
type SpaceRuntime struct {
	Stage    string        `json:"stage"`
	Hardware SpaceHardware `json:"hardware"`
	Replicas SpaceReplicas `json:"replicas"`
	// GcTimeout is the idle period in seconds after which the Space sleeps. It
	// is absent on Spaces that never sleep, so a zero value would read as
	// "sleeps immediately"; the pointer keeps absent distinct from zero.
	GcTimeout *int `json:"gcTimeout"`
	// DevMode reports whether developer mode, which grants SSH access into the
	// running container, is enabled. It is absent on Spaces whose plan cannot
	// offer it; a bool would read absent as "off".
	DevMode *bool         `json:"devMode"`
	Domains []SpaceDomain `json:"domains"`
}

type Space struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Author      string   `json:"author"`
	Likes       int      `json:"likes"`
	Private     bool     `json:"private"`
	// SDK is the stack that runs the Space: gradio, streamlit, docker, static.
	SDK string `json:"sdk"`
	// Region is where the Space runs, which governs data residency.
	Region string `json:"region"`
	// Subdomain is the host label the Space is served from under hf.space.
	Subdomain    string        `json:"subdomain"`
	Disabled     bool          `json:"disabled"`
	CreatedAt    string        `json:"createdAt"`
	LastModified string        `json:"lastModified"`
	Sha          string        `json:"sha"`
	Runtime      *SpaceRuntime `json:"runtime"`
}

type SpaceListOptions struct {
	Author        string
	Search        string
	Filter        string
	SortBy        string
	SortDirection string
	Limit         int
	Full          bool
	// Expand names the fields the response should carry. See SpaceListExpand.
	Expand []string
}

func NewSpaceListOptions() *SpaceListOptions {
	return &SpaceListOptions{
		SortDirection: "1",
		Limit:         20,
		Full:          false,
		Expand:        SpaceListExpand,
	}
}

type SpaceList struct {
	Spaces []Space
}

func (sl *SpaceList) UnmarshalJSON(data []byte) error {
	var spaces []Space
	err := json.Unmarshal(data, &spaces)
	if err == nil {
		sl.Spaces = spaces
		return nil
	}
	// The list endpoints answer with a bare array. When one is what arrived,
	// report why it would not decode instead of falling through to the
	// object form and blaming the wrapper type.
	if isJSONArray(data) {
		return err
	}

	type Alias SpaceList
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(sl),
	}
	return json.Unmarshal(data, aux)
}
