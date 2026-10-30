// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"encoding/json"
	"net/http"
)

// EmailServer is one entry of `/api/v1/email-servers`.
//
// The SDK's own model for this endpoint is not used. It types every value as a
// pointer in one release and as a bare value in the next, and a bare value
// cannot tell an omitted `enabled` or `port` from a configured false or zero.
// The MQL fields these feed report null when Okta does not send a value, so the
// pointers are kept here and the shape is pinned against the wire instead.
type EmailServer struct {
	// Human-readable name for the SMTP server
	Alias *string `json:"alias,omitempty"`
	// If true, the org routes outbound mail through this server
	Enabled *bool `json:"enabled,omitempty"`
	// Hostname or IP address of the SMTP server
	Host *string `json:"host,omitempty"`
	// ID of the SMTP server
	Id *string `json:"id,omitempty"`
	// Port the SMTP server listens on
	Port *int32 `json:"port,omitempty"`
	// Username used to authenticate to the SMTP server
	Username *string `json:"username,omitempty"`
}

// ListEmailServers fetches the org's custom SMTP servers from
// `/api/v1/email-servers`.
//
// The SDK's generated EmailServerAPI.ListEmailServers types the response as an
// EmailServerListResponse object, but the endpoint answers with a bare array of
// servers, so the generated call fails to unmarshal and every org that has
// configured an SMTP server gets an error instead of its servers. Both shapes
// are accepted here: the array the API sends today, and the wrapped object the
// SDK expects, so the resource keeps working whichever one an org is served.
func (m *ApiExtension) ListEmailServers(ctx context.Context) ([]EmailServer, *http.Response, error) {
	var raw json.RawMessage
	resp, err := m.get(ctx, m.url("/api/v1/email-servers"), &raw)
	if err != nil {
		return nil, resp, err
	}

	servers, err := decodeOktaEmailServers(raw)
	if err != nil {
		return nil, resp, err
	}
	return servers, resp, nil
}

// decodeOktaEmailServers accepts either the bare array the API returns or the
// `{"email-servers": [...]}` envelope the SDK's model describes.
func decodeOktaEmailServers(raw json.RawMessage) ([]EmailServer, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var list []EmailServer
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}

	var wrapped struct {
		EmailServers []EmailServer `json:"email-servers"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	return wrapped.EmailServers, nil
}
