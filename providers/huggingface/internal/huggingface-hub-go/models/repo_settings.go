// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

// TrustedPublisher is one entry of
// GET /api/{repoType}/{namespace}/{repo}/settings/trusted-publishers.
type TrustedPublisher struct {
	ID        string `json:"_id"`
	IssuerURL string `json:"issuerUrl"`
	// Claims maps a claim name to {kind: eq|prefix, value}.
	Claims       map[string]any `json:"claims"`
	ConfiguredBy *HubAccount    `json:"configuredBy"`
	CreatedAt    string         `json:"createdAt"`
	LastUsedAt   string         `json:"lastUsedAt"`
	Capabilities []string       `json:"capabilities"`
	Permissions  []string       `json:"permissions"`
}

// HubAccount is the subset of a user or organization summary the provider
// reads.
type HubAccount struct {
	Name string `json:"name"`
}

// AccessRequest is one entry of
// GET /api/{models|datasets}/{namespace}/{repo}/user-access-request/{status}.
// The form answers and the requester's email are not decoded.
type AccessRequest struct {
	RequestID string `json:"requestId"`
	// User is absent when the requester does not share their profile.
	User *AccessRequestUser `json:"user"`
	// GrantedBy can be an empty object, which leaves User empty.
	GrantedBy  *AccessRequestUser `json:"grantedBy"`
	Status     string             `json:"status"`
	Timestamp  string             `json:"timestamp"`
	ReviewedAt string             `json:"reviewedAt"`
}

type AccessRequestUser struct {
	User string `json:"user"`
}

// AccessRequestStatus is the status path segment of the access request list.
type AccessRequestStatus string

const (
	AccessRequestPending  AccessRequestStatus = "pending"
	AccessRequestAccepted AccessRequestStatus = "accepted"
)
