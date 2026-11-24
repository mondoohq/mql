// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

// InferenceEndpoint is one entry of the Inference Endpoints v2 list
// (EndpointWithStatus in the Endpoints OpenAPI document). The API names an
// endpoint by its namespace and name and returns no separate id. The deployed
// model and the runtime state are nested objects.
type InferenceEndpoint struct {
	Name   string                 `json:"name"`
	Model  InferenceEndpointModel `json:"model"`
	Status InferenceEndpointState `json:"status"`
}

type InferenceEndpointModel struct {
	Repository string `json:"repository"`
	Framework  string `json:"framework"`
}

type InferenceEndpointState struct {
	State     string `json:"state"`
	URL       string `json:"url"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// InferenceEndpointList is one page of the list. NextCursor is null on the
// last page.
type InferenceEndpointList struct {
	Endpoints  []InferenceEndpoint `json:"items"`
	NextCursor *string             `json:"nextCursor"`
}
