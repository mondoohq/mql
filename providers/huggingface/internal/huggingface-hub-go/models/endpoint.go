// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"sort"
)

// InferenceEndpoint is one entry of the Inference Endpoints v2 list
// (EndpointWithStatus in the Endpoints OpenAPI document). The API names an
// endpoint by its namespace and name and returns no separate id. The deployed
// model and the runtime state are nested objects.
type InferenceEndpoint struct {
	Name string `json:"name"`
	// Type is public, authenticated, or private.
	Type     string                    `json:"type"`
	Model    InferenceEndpointModel    `json:"model"`
	Status   InferenceEndpointState    `json:"status"`
	Provider InferenceEndpointProvider `json:"provider"`
	Compute  InferenceEndpointCompute  `json:"compute"`
}

type InferenceEndpointModel struct {
	Repository string `json:"repository"`
	Framework  string `json:"framework"`
	// Revision is null when the endpoint follows the default branch.
	Revision *string `json:"revision"`
	// Secrets keeps the names of the secret environment variables only.
	Secrets SecretNames `json:"secrets"`
}

type InferenceEndpointProvider struct {
	Vendor string `json:"vendor"`
	Region string `json:"region"`
}

type InferenceEndpointCompute struct {
	InstanceType string                   `json:"instanceType"`
	Scaling      InferenceEndpointScaling `json:"scaling"`
}

type InferenceEndpointScaling struct {
	MinReplica *int64 `json:"minReplica"`
	MaxReplica *int64 `json:"maxReplica"`
}

type InferenceEndpointState struct {
	State     string `json:"state"`
	URL       string `json:"url"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	// LastUsedAt is null on an endpoint that has never been active.
	LastUsedAt *string                  `json:"lastUsedAt"`
	CreatedBy  InferenceEndpointAccount `json:"createdBy"`
	UpdatedBy  InferenceEndpointAccount `json:"updatedBy"`
}

type InferenceEndpointAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SecretNames decodes a map of secret environment variables into its sorted
// keys. The values are discarded during decoding so they are never held.
// Nil when the field was absent or null.
type SecretNames []string

func (s *SecretNames) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m == nil {
		*s = nil
		return nil
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	*s = names
	return nil
}

// InferenceEndpointList is one page of the list. NextCursor is null on the
// last page.
type InferenceEndpointList struct {
	Endpoints  []InferenceEndpoint `json:"items"`
	NextCursor *string             `json:"nextCursor"`
}
